//! murmure — peer-to-peer terminal messaging over Tor onion services.
//!
//! Run it with no arguments. It publishes your address, keeps listening, and
//! takes commands:
//!
//! ```text
//! /add <name> <address>   file a friend under a name
//! /call <name>            call them
//! /contacts               list the book
//! /forget <name>          drop a contact
//! /quit                   leave
//! ```
//!
//! Both sides must be online at the same time. It is a phone call, not a text
//! message.
//!
//! The identity is a 32-byte seed murmure owns; the `.onion` address is derived
//! from it, so it survives restarts and is unforgeable without the seed. The
//! contacts book is sealed under a key derived from that same seed: losing the
//! seed loses the identity *and* the book, by design.

mod chat;
mod contacts;
mod identity;
mod onion;
mod proto;
mod store;
mod transport;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use futures::StreamExt as _;
use safelog::DisplayRedacted as _;
use tokio::io::AsyncBufReadExt as _;
use tokio::sync::mpsc;

use crate::contacts::Contacts;
use crate::identity::Identity;
use crate::transport::tor::{self, KeyHandover};

/// Nickname arti files this service's keys and state under. Fixed: changing it
/// would look like a brand new service to the keystore.
const NICKNAME: &str = "murmure";

/// How long to wait for the service to *confirm* it is reachable before saying
/// so. Advisory only — `tor::wait_until_reachable` under-reports on a service
/// that already answers.
const REACHABLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Total budget for reaching a friend. A rendezvous is 7-50 s per PETS 2025,
/// and a first dial can land before their descriptor has propagated.
const DIAL_TIMEOUT: Duration = Duration::from_secs(240);

/// How many typed lines may queue while something else is running.
const KEYBOARD: usize = 16;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // Arti is chatty at info; the conversation has to stay readable.
                // `RUST_LOG=info` brings the detail back.
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("murmure: could not start the tokio runtime: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("murmure: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let started = Instant::now();
    let run_dir = run_dir();
    std::fs::create_dir_all(&run_dir).with_context(|| format!("creating {}", run_dir.display()))?;

    // ---- identity and book ---------------------------------------------
    let seed_path = run_dir.join("identity.seed");
    let existed = seed_path.exists();
    let identity = Identity::load_or_create(&seed_path)?;
    identity.check_permissions()?;
    let expected = identity.onion_address();
    let mut book = Contacts::open(&run_dir.join("contacts.sealed"), &identity)?;

    stage(
        started,
        &format!(
            "identity {}, {} contact(s)",
            if existed { "loaded" } else { "generated" },
            book.len()
        ),
    );

    // ---- publish --------------------------------------------------------
    let nickname = NICKNAME
        .to_owned()
        .try_into()
        .map_err(|e| anyhow::anyhow!("invalid onion service nickname {NICKNAME:?}: {e}"))?;

    stage(started, "bootstrapping Tor");
    let client = tor::bootstrap_client(
        &run_dir.join("service/state"),
        &run_dir.join("service/cache"),
    )
    .await?;

    stage(started, "publishing your service");
    let (handover, service, requests) =
        tor::launch_with_identity(&client, &nickname, identity.hs_id_keypair())?;
    if handover == KeyHandover::Reused {
        tracing::debug!("the keystore already held this identity; arti did not overwrite it");
    }

    // The address we publish must be the one our seed derives, never one arti
    // generated. A byte comparison, not a log check.
    let published = service
        .onion_address()
        .context("arti published the service but reported no onion address")?;
    if published != expected {
        bail!(identity_mismatch(&run_dir, &seed_path, &published, &expected));
    }
    let my_address = published.display_unredacted().to_string();
    onion::check_address(&my_address)?;

    println!();
    println!("your address — give it to a friend, and compare the fingerprint out loud:");
    println!("  {my_address}");
    println!("  fingerprint: {}", onion::fingerprint(&my_address));
    println!();

    match tor::wait_until_reachable(&service, REACHABLE_TIMEOUT).await {
        Ok(()) => stage(started, "reachable"),
        // Under-reports; an incoming connection is the real test.
        Err(_) => stage(started, "listening (reachability unconfirmed, arti under-reports)"),
    }
    help();

    // ---- the idle loop --------------------------------------------------
    //
    // One stdin reader for the whole program: the idle loop and the
    // conversation both need typed lines, and two readers on stdin lose lines
    // to each other.
    let (typed, mut lines) = mpsc::channel::<String>(KEYBOARD);
    tokio::spawn(async move {
        let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = stdin.next_line().await {
            if typed.send(line).await.is_err() {
                break;
            }
        }
    });

    let incoming = tor::incoming(requests);
    futures::pin_mut!(incoming);

    loop {
        // The select only *picks* the event. Handling it happens after, so that
        // no borrow held by a branch future is still alive while a conversation
        // runs — a conversation needs `lines` for itself.
        let event = tokio::select! {
            stream = incoming.next() => Event::Called(stream.map(Box::new)),
            line = lines.recv() => Event::Typed(line),
        };

        match event {
            Event::Called(Some(stream)) => {
                // An onion service does not tell us who the caller is: a client
                // is anonymous by construction. Naming them is what restricted
                // discovery (see INSTALL.md) will make possible.
                println!("\n-- incoming call --");
                let (reader, writer) = stream.split();
                let ended = chat::run(reader, writer, "them", &mut lines).await?;
                println!("-- call ended ({ended:?}) --\n");
            }
            Event::Called(None) => bail!("the incoming-stream channel closed"),
            // stdin reached EOF: Ctrl-D, or a piped script running out.
            Event::Typed(None) => break,
            Event::Typed(Some(line)) => {
                match command(&line, &mut book, &client, &mut lines, started).await {
                    Ok(Flow::Continue) => {}
                    Ok(Flow::Quit) => break,
                    // A bad command must not end the program.
                    Err(e) => eprintln!("{e:#}"),
                }
            }
        }
    }

    println!("bye.");
    Ok(())
}

/// What woke the idle loop.
enum Event {
    /// Someone dialled our service. [`None`] means the listener died.
    ///
    /// Boxed: a `DataStream` is ~700 bytes against ~24 for a typed line, and
    /// this enum is built on every loop iteration.
    Called(Option<Box<arti_client::DataStream>>),
    /// The operator typed a line. [`None`] means stdin closed.
    Typed(Option<String>),
}

/// What the idle loop does after a command.
enum Flow {
    Continue,
    Quit,
}

/// Run one typed command.
async fn command(
    line: &str,
    book: &mut Contacts,
    client: &tor::Client,
    lines: &mut mpsc::Receiver<String>,
    started: Instant,
) -> Result<Flow> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(Flow::Continue);
    }
    let mut parts = line.split_whitespace();
    let verb = parts.next().unwrap_or_default();

    match verb {
        "/add" => {
            let (Some(name), Some(address)) = (parts.next(), parts.next()) else {
                bail!("usage: /add <name> <address>.onion");
            };
            book.add(name, address)?;
            println!("filed {name} as {}", onion::fingerprint(address));
        }
        "/forget" => {
            let Some(name) = parts.next() else {
                bail!("usage: /forget <name>");
            };
            if book.remove(name)? {
                println!("forgot {name}");
            } else {
                println!("no contact called {name}");
            }
        }
        "/contacts" => {
            if book.len() == 0 {
                println!("(no contacts yet — /add <name> <address>.onion)");
            }
            for (name, address) in book.iter() {
                println!("  {name:<16} {}", onion::fingerprint(address));
            }
        }
        "/call" => {
            let Some(name) = parts.next() else {
                bail!("usage: /call <name>");
            };
            let address = book
                .address_of(name)
                .ok_or_else(|| anyhow::anyhow!("no contact called {name} — /add them first"))?
                .to_owned();
            call(started, client, name, &address, lines).await?;
        }
        "/help" => help(),
        "/quit" => return Ok(Flow::Quit),
        _ => bail!("unknown command {verb} — /help"),
    }
    Ok(Flow::Continue)
}

/// Dial a contact and hold a conversation.
async fn call(
    started: Instant,
    client: &tor::Client,
    name: &str,
    address: &str,
    lines: &mut mpsc::Receiver<String>,
) -> Result<()> {
    let hs_id: tor_hscrypto::pk::HsId = address
        .parse()
        .map_err(|e| anyhow::anyhow!("{address} is not a valid onion address: {e}"))?;

    println!("calling {name} — fingerprint {}", onion::fingerprint(address));
    println!("(7-50 s is normal; /bye to hang up once connected)");

    let stream = tor::dial_retrying(client, hs_id, DIAL_TIMEOUT, |attempt, err| {
        stage(started, &format!("attempt {attempt} failed: {err}"))
    })
    .await?;

    println!("-- connected to {name} --");
    let (reader, writer) = stream.split();
    let ended = chat::run(reader, writer, name, lines).await?;
    println!("-- call ended ({ended:?}) --\n");
    Ok(())
}

fn help() {
    println!("commands:");
    println!("  /add <name> <address>.onion   file a friend");
    println!("  /call <name>                  call them");
    println!("  /contacts                     list the book");
    println!("  /forget <name>                drop a contact");
    println!("  /bye                          hang up (during a call)");
    println!("  /quit                         leave");
    println!();
}

/// The message for the one failure that must never be papered over.
fn identity_mismatch(
    run_dir: &Path,
    seed_path: &Path,
    published: &tor_hscrypto::pk::HsId,
    expected: &tor_hscrypto::pk::HsId,
) -> String {
    format!(
        "IDENTITY MISMATCH — arti published {} but our seed derives {}.\n\
         The keystore at {}/service/state/keystore holds a different key than the seed at {}.\n\
         Nothing was overwritten: delete that keystore directory to republish under our seed, \
         or delete the seed to adopt the stored identity.",
        published.display_unredacted(),
        expected.display_unredacted(),
        run_dir.display(),
        seed_path.display(),
    )
}

/// Where this run keeps its seed, its book and its Tor directories.
///
/// Overridable with `MURMURE_DIR`, which is also how two instances share one
/// machine without colliding.
fn run_dir() -> PathBuf {
    match std::env::var_os("MURMURE_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(".murmure"),
    }
}

/// Print a timestamped stage marker, so a 90-second wait never looks frozen.
fn stage(started: Instant, what: &str) {
    println!("[{:>5.1}s] {what}", started.elapsed().as_secs_f32());
}

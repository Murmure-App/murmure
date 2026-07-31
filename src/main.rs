//! murmure — peer-to-peer terminal messaging over Tor onion services.
//!
//! Run it with no arguments. It publishes your address, keeps listening, and
//! takes commands typed in the input box:
//!
//! ```text
//! /add <name> <address>   file a friend under a name
//! /call <name>            call them
//! /contacts               list the book
//! /forget <name>          drop a contact
//! /bye                    hang up (during a call)
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
mod ui;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use futures::StreamExt as _;
use safelog::DisplayRedacted as _;
use tokio::sync::mpsc;

use crate::contacts::Contacts;
use crate::identity::Identity;
use crate::transport::tor::{self, KeyHandover};
use crate::ui::{Kind, Screen};

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
    let run_dir = run_dir();
    if let Err(e) = std::fs::create_dir_all(&run_dir) {
        eprintln!("murmure: creating {}: {e}", run_dir.display());
        return ExitCode::FAILURE;
    }

    // Logs go to a file, never to stdout: the TUI owns the screen, and a stray
    // log line lands in the middle of a frame and corrupts it. `RUST_LOG` still
    // works — the output is in <run dir>/murmure.log.
    let log_path = run_dir.join("murmure.log");
    match std::fs::File::create(&log_path) {
        Ok(file) => tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_writer(Mutex::new(file))
            .with_ansi(false)
            .init(),
        Err(e) => {
            eprintln!("murmure: creating {}: {e}", log_path.display());
            return ExitCode::FAILURE;
        }
    }

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("murmure: could not start the tokio runtime: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    let outcome = runtime.block_on(run(&run_dir));

    // The terminal event reader lives on a blocking thread. Dropping the
    // runtime waits for blocking tasks, so quitting would hang until the
    // operator pressed one more key. Nothing left to do needs that thread.
    runtime.shutdown_background();

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("murmure: {e:#}");
            eprintln!("murmure: details in {}", log_path.display());
            ExitCode::FAILURE
        }
    }
}

async fn run(run_dir: &Path) -> Result<()> {
    let started = Instant::now();

    // ---- identity and book ---------------------------------------------
    let seed_path = run_dir.join("identity.seed");
    let existed = seed_path.exists();
    let identity = Identity::load_or_create(&seed_path)?;
    identity.check_permissions()?;
    let expected = identity.onion_address();
    let mut book = Contacts::open(&run_dir.join("contacts.sealed"), &identity)?;

    // The address is known before Tor is up, because it comes from the seed —
    // so the interface can show it immediately.
    let my_address = expected.display_unredacted().to_string();
    onion::check_address(&my_address)?;

    // ---- the interface ---------------------------------------------------
    let (screen, updates) = ui::channel();
    let (typed, mut lines) = mpsc::channel::<String>(KEYBOARD);
    let interface = tokio::spawn(ui::run(
        updates,
        typed,
        format!("{} ", onion::fingerprint(&my_address)),
    ));

    screen.system(format!(
        "identity {}, {} contact(s)",
        if existed { "loaded" } else { "generated" },
        book.len()
    ));
    screen.system(format!("your address: {my_address}"));
    screen.system("give it to a friend, and compare the fingerprint out loud.");
    help(&screen);

    // ---- publish ---------------------------------------------------------
    //
    // From here on, every failure has to reach the screen rather than stdout:
    // stdout is the alternate screen now.
    let outcome = serve(started, run_dir, &seed_path, &identity, expected, &screen, &mut book, &mut lines).await;
    if let Err(e) = &outcome {
        screen.error(format!("{e:#}"));
        screen.status("stopped");
        // Leave the message on screen long enough to be read.
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    // Dropping the screen ends the interface task.
    drop(screen);
    let _ = interface.await;
    outcome
}

/// Publish the service, then run the idle loop until the operator quits.
#[allow(clippy::too_many_arguments)]
async fn serve(
    started: Instant,
    run_dir: &Path,
    seed_path: &Path,
    identity: &Identity,
    expected: tor_hscrypto::pk::HsId,
    screen: &Screen,
    book: &mut Contacts,
    lines: &mut mpsc::Receiver<String>,
) -> Result<()> {
    let nickname = NICKNAME
        .to_owned()
        .try_into()
        .map_err(|e| anyhow::anyhow!("invalid onion service nickname {NICKNAME:?}: {e}"))?;

    // Input stays refused until the idle loop below is the one reading it.
    // Anything else queues lines nothing is consuming, which is how a command
    // typed at second three fires at second forty.
    screen.status("bootstrapping Tor (10-40 s)");
    let client = tor::bootstrap_client(
        &run_dir.join("service/state"),
        &run_dir.join("service/cache"),
    )
    .await?;
    stage(screen, started, "Tor is up");

    screen.status("publishing");
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
        bail!(identity_mismatch(run_dir, seed_path, &published, &expected));
    }
    stage(screen, started, "published under our own key");

    screen.status("publishing to the directory");
    if tor::wait_until_reachable(&service, REACHABLE_TIMEOUT)
        .await
        .is_err()
    {
        // Under-reports; an incoming connection is the real test.
        stage(
            screen,
            started,
            "reachability unconfirmed (arti under-reports); listening anyway",
        );
    }

    screen.status("listening");
    screen.system("ready — type a command.");
    screen.accepting(true);

    // ---- the idle loop ---------------------------------------------------
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
                screen.system("-- incoming call --");
                screen.status("in a call");
                let (reader, writer) = stream.split();
                converse(reader, writer, "they", lines, screen).await;
                screen.status("listening");
            }
            Event::Called(None) => bail!("the incoming-stream channel closed"),
            // The interface is gone: Ctrl-C, or the terminal closed.
            Event::Typed(None) => break,
            Event::Typed(Some(line)) => {
                // Echo the command before running it. Without this, pressing
                // Enter only clears the input box and nothing on screen shows
                // the line was received — so a `/call` that is working looks
                // like a `/call` that was swallowed.
                screen.say(Kind::Mine, format!("> {}", line.trim()));
                match command(&line, book, &client, lines, started, screen).await {
                    Ok(Flow::Continue) => {}
                    Ok(Flow::Quit) => break,
                    // A bad command must not end the program.
                    Err(e) => screen.error(format!("{e:#}")),
                }
            }
        }
    }

    Ok(())
}

/// What woke the idle loop.
enum Event {
    /// Someone dialled our service. [`None`] means the listener died.
    ///
    /// Boxed: a `DataStream` is ~700 bytes against ~24 for a typed line, and
    /// this enum is built on every loop iteration.
    Called(Option<Box<arti_client::DataStream>>),
    /// The operator typed a line. [`None`] means the interface closed.
    Typed(Option<String>),
}

/// What the idle loop does after a command.
enum Flow {
    Continue,
    Quit,
}

/// Hold one conversation and report how it ended. Never propagates: a dropped
/// call must not end the program.
async fn converse<R, W>(
    reader: R,
    writer: W,
    peer: &str,
    lines: &mut mpsc::Receiver<String>,
    screen: &Screen,
) where
    R: futures::io::AsyncRead + Unpin + Send + 'static,
    W: futures::io::AsyncWrite + Unpin + Send + 'static,
{
    match chat::run(reader, writer, peer, lines, screen).await {
        Ok(ended) => screen.system(format!("-- {} --", ended.describe(peer))),
        Err(e) => screen.error(format!("-- call dropped: {e:#} --")),
    }
}

/// Run one typed command.
async fn command(
    line: &str,
    book: &mut Contacts,
    client: &tor::Client,
    lines: &mut mpsc::Receiver<String>,
    started: Instant,
    screen: &Screen,
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
            screen.system(format!("filed {name} as {}", onion::fingerprint(address)));
        }
        "/forget" => {
            let Some(name) = parts.next() else {
                bail!("usage: /forget <name>");
            };
            if book.remove(name)? {
                screen.system(format!("forgot {name}"));
            } else {
                screen.system(format!("no contact called {name}"));
            }
        }
        "/contacts" => {
            if book.len() == 0 {
                screen.system("(no contacts yet — /add <name> <address>.onion)");
            }
            for (name, address) in book.iter() {
                screen.system(format!("  {name:<16} {}", onion::fingerprint(address)));
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
            call(started, client, name, &address, lines, screen).await?;
        }
        "/help" => help(screen),
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
    screen: &Screen,
) -> Result<()> {
    let hs_id: tor_hscrypto::pk::HsId = address
        .parse()
        .map_err(|e| anyhow::anyhow!("{address} is not a valid onion address: {e}"))?;

    screen.system(format!(
        "calling {name} — fingerprint {}",
        onion::fingerprint(address)
    ));
    screen.system("7-50 s is normal. /cancel to give up.");
    screen.status(format!("calling {name}"));

    // The keyboard has to stay answered while we dial. Without this, typed
    // lines queue silently for up to four minutes and are then delivered to
    // the peer as messages the moment the call connects — which is how a
    // `/add <name> <address>` ends up sent to whoever answered.
    let dialling = tor::dial_retrying(client, hs_id, DIAL_TIMEOUT, |attempt, err| {
        stage(screen, started, &format!("attempt {attempt} failed: {err}"))
    });
    futures::pin_mut!(dialling);

    let stream = loop {
        tokio::select! {
            outcome = &mut dialling => break outcome.inspect_err(|_| screen.status("listening"))?,
            line = lines.recv() => match line.as_deref().map(str::trim) {
                // The interface is gone.
                None => return Ok(()),
                Some("/cancel") => {
                    screen.system(format!("gave up calling {name}"));
                    screen.status("listening");
                    return Ok(());
                }
                Some("") => {}
                Some(_) => screen.system(format!("still calling {name} — /cancel to give up")),
            },
        }
    };

    screen.system(format!("-- connected to {name} --"));
    screen.status(format!("in a call with {name}"));
    let (reader, writer) = stream.split();
    converse(reader, writer, name, lines, screen).await;
    screen.status("listening");
    Ok(())
}

fn help(screen: &Screen) {
    for line in [
        "commands:",
        "  /add <name> <address>.onion   file a friend",
        "  /call <name>                  call them",
        "  /contacts                     list the book",
        "  /forget <name>                drop a contact",
        "  /bye                          hang up (during a call)",
        "  /quit                         leave",
        "keys:",
        "  up / down                     scroll one line",
        "  Ctrl-B / Ctrl-F               scroll one page",
        "  Ctrl-E                        jump back to the newest line",
        "  Ctrl-U                        clear the input   Ctrl-C  leave",
    ] {
        screen.say(Kind::System, line);
    }
}

/// The message for the one failure that must never be papered over.
fn identity_mismatch(
    run_dir: &Path,
    seed_path: &Path,
    published: &tor_hscrypto::pk::HsId,
    expected: &tor_hscrypto::pk::HsId,
) -> String {
    format!(
        "IDENTITY MISMATCH — arti published {} but our seed derives {}. \
         The keystore at {}/service/state/keystore holds a different key than the seed at {}. \
         Nothing was overwritten: delete that keystore directory to republish under our seed, \
         or delete the seed to adopt the stored identity.",
        published.display_unredacted(),
        expected.display_unredacted(),
        run_dir.display(),
        seed_path.display(),
    )
}

/// Where this run keeps its seed, its book, its log and its Tor directories.
///
/// Overridable with `MURMURE_DIR`, which is also how two instances share one
/// machine without colliding.
fn run_dir() -> PathBuf {
    match std::env::var_os("MURMURE_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(".murmure"),
    }
}

/// A timestamped stage marker, so a 90-second wait never looks frozen.
fn stage(screen: &Screen, started: Instant, what: &str) {
    screen.system(format!("[{:>5.1}s] {what}", started.elapsed().as_secs_f32()));
}

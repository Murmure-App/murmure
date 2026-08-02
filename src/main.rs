//! murmure — peer-to-peer terminal messaging over Tor onion services.
//!
//! Run it with no arguments. It publishes your address, keeps listening, and
//! takes commands typed in the input box:
//!
//! ```text
//! /add <name> <address> <key>   file a friend under a name
//! /call <name>                  call them
//! /contacts                     list the book
//! /forget <name>                drop a contact
//! /quit                         leave
//! ```
//!
//! During a call, `/send <path>` offers a file, `/accept` and `/refuse` answer
//! one, and `/bye` hangs up. An accepted file lands in `<run dir>/incoming/`.
//!
//! Both sides must be online at the same time. It is a phone call, not a text
//! message.
//!
//! The identity is a 32-byte seed murmure owns; the `.onion` address is derived
//! from it, so it survives restarts and is unforgeable without the seed. The
//! contacts book is sealed under a key derived from that same seed: losing the
//! seed loses the identity *and* the book, by design.
//!
//! The `<key>` half of `/add` is that friend's service discovery key, also
//! derived from their seed. Once anyone is filed, murmure runs its service in
//! restricted discovery mode: the descriptor's introduction points are
//! encrypted for the listed contacts, so a stranger holding the `.onion`
//! address cannot even tell whether the service is running. Until the first
//! contact is filed, the service is discoverable by anyone who has the address,
//! because arti will not publish a descriptor nobody can read.

mod chat;
mod contacts;
mod files;
mod identity;
mod onion;
mod proto;
mod store;
mod transport;
mod ui;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use futures::StreamExt as _;
use safelog::DisplayRedacted as _;
use tokio::sync::mpsc;
use tor_hscrypto::pk::{HsClientDescEncKey, HsId};
use tor_hsservice::config::restricted_discovery::HsClientNickname;
use tor_hsservice::{HsNickname, RunningOnionService};

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
    let (typed, mut lines) = mpsc::channel::<ui::Typed>(KEYBOARD);
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
    screen.system(format!("your key:     {}", identity.discovery_key()));
    screen.system("give a friend both lines, and compare the fingerprint out loud.");
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
    lines: &mut mpsc::Receiver<ui::Typed>,
) -> Result<()> {
    let nickname = NICKNAME
        .to_owned()
        .try_into()
        .map_err(|e| anyhow::anyhow!("invalid onion service nickname {NICKNAME:?}: {e}"))?;

    // Input stays refused until the idle loop below is the one reading it.
    // Anything else queues lines nothing is consuming, which is how a command
    // typed at second three fires at second forty.
    // A first run downloads the whole directory cold and takes minutes; a warm
    // cache takes tens of seconds. Say the pessimistic number, then replace it
    // with arti's own progress as soon as there is one.
    screen.status("bootstrapping Tor (first run: several minutes)");
    let client = tor::bootstrap_client(
        &run_dir.join("service/state"),
        &run_dir.join("service/cache"),
        |frac, blocked| match blocked {
            Some(why) => screen.status(format!("bootstrapping Tor — stuck: {why}")),
            None => screen.status(format!("bootstrapping Tor — {:.0}%", frac * 100.0)),
        },
    )
    .await?;
    stage(screen, started, "Tor is up");

    // Where accepted files land. Under the run directory so that `MURMURE_DIR`
    // keeps two instances on one machine apart here too.
    let incoming_dir = run_dir.join("incoming");

    screen.status("publishing");
    let clients = authorized(book)?;
    let (handover, service, requests) =
        tor::launch_with_identity(&client, &nickname, identity.hs_id_keypair(), &clients)?;
    if handover == KeyHandover::Reused {
        tracing::debug!("the keystore already held this identity; arti did not overwrite it");
    }
    let live = Live {
        client: &client,
        service: &service,
        nickname: &nickname,
        identity,
        incoming_dir: &incoming_dir,
    };
    // The descriptor is now readable only by the filed contacts, but reaching
    // *them* needs our own key deposited under each of their addresses.
    live.present_to_contacts(book)?;
    if clients.is_empty() {
        screen.system(
            "no contacts yet, so your service is discoverable by anyone with the address. \
             /add someone and it goes dark.",
        );
    } else {
        stage(
            screen,
            started,
            &format!("restricted to {} authorised contact(s)", clients.len()),
        );
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
                if let Flow::Quit =
                    converse(reader, writer, "they", &incoming_dir, lines, screen).await
                {
                    break;
                }
                screen.status("listening");
            }
            Event::Called(None) => bail!("the incoming-stream channel closed"),
            // The interface is gone: Ctrl-C, or the terminal closed.
            Event::Typed(None) => break,
            Event::Typed(Some(line)) => {
                // A message carrying files only means something during a call:
                // there is nobody to offer them to out here.
                let Some(line) = line.as_line() else {
                    screen.error("files only go somewhere during a call — /call someone first");
                    continue;
                };
                // Echo the command before running it. Without this, pressing
                // Enter only clears the input box and nothing on screen shows
                // the line was received — so a `/call` that is working looks
                // like a `/call` that was swallowed.
                screen.say(Kind::Mine, format!("> {}", line.trim()));
                match command(line, book, &live, lines, started, screen).await {
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

/// Everything a command has to tell when the contacts book changes.
///
/// Grouped rather than passed one by one: adding a contact touches three
/// places at once — the sealed book, the service's authorised-client list, and
/// the keystore — and any of the three left behind is a friend who silently
/// cannot reach us.
struct Live<'a> {
    client: &'a tor::Client,
    service: &'a Arc<RunningOnionService>,
    nickname: &'a HsNickname,
    identity: &'a Identity,
    /// Where a file accepted during a call is written.
    incoming_dir: &'a Path,
}

impl Live<'_> {
    /// Republish the descriptor for exactly the contacts now in the book, and
    /// make sure we hold a key to reach each of them.
    fn resync(&self, book: &Contacts) -> Result<()> {
        tor::authorize(self.service, self.nickname, &authorized(book)?)?;
        self.present_to_contacts(book)
    }

    /// Deposit our discovery key under every contact's address.
    fn present_to_contacts(&self, book: &Contacts) -> Result<()> {
        for (name, contact) in book.iter() {
            let peer: HsId = contact.address.parse().map_err(|e| {
                anyhow::anyhow!("{name}'s address is not a valid onion address: {e}")
            })?;
            tor::present_to(self.client, peer, self.identity.discovery_secret())
                .with_context(|| format!("presenting our key to {name}"))?;
        }
        Ok(())
    }
}

/// The book, in the form arti's restricted discovery config wants.
fn authorized(book: &Contacts) -> Result<Vec<(HsClientNickname, HsClientDescEncKey)>> {
    book.iter()
        .map(|(name, contact)| {
            let key: HsClientDescEncKey = contact
                .discovery
                .parse()
                .map_err(|e| anyhow::anyhow!("{name}'s discovery key is unusable: {e}"))?;
            Ok((tor::client_nickname(&contact.address)?, key))
        })
        .collect()
}

/// What woke the idle loop.
enum Event {
    /// Someone dialled our service. [`None`] means the listener died.
    ///
    /// Boxed: a `DataStream` is ~700 bytes against ~24 for a typed line, and
    /// this enum is built on every loop iteration.
    Called(Option<Box<arti_client::DataStream>>),
    /// The operator typed a line. [`None`] means the interface closed.
    Typed(Option<ui::Typed>),
}

/// What the idle loop does after a command.
enum Flow {
    Continue,
    Quit,
}

/// Hold one conversation and say whether the operator wants out of the program
/// as well as out of the call.
///
/// Never propagates an error: a dropped call must not end the program, so a
/// failure is shown and treated as an ordinary hang-up.
async fn converse<R, W>(
    reader: R,
    writer: W,
    peer: &str,
    incoming_dir: &Path,
    lines: &mut mpsc::Receiver<ui::Typed>,
    screen: &Screen,
) -> Flow
where
    R: futures::io::AsyncRead + Unpin + Send + 'static,
    W: futures::io::AsyncWrite + Unpin + Send + 'static,
{
    match chat::run(reader, writer, peer, incoming_dir, lines, screen).await {
        Ok(ended) => {
            screen.system(format!("-- {} --", ended.describe(peer)));
            if ended.leaves() {
                return Flow::Quit;
            }
        }
        Err(e) => screen.error(format!("-- call dropped: {e:#} --")),
    }
    Flow::Continue
}

/// Run one typed command.
async fn command(
    line: &str,
    book: &mut Contacts,
    live: &Live<'_>,
    lines: &mut mpsc::Receiver<ui::Typed>,
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
            let (Some(name), Some(address), Some(key)) = (parts.next(), parts.next(), parts.next())
            else {
                bail!("usage: /add <name> <address>.onion descriptor:x25519:<key>");
            };
            let first = book.len() == 0;
            book.add(name, address, key)?;
            live.resync(book)?;
            screen.system(format!("filed {name} as {}", onion::fingerprint(address)));
            if first {
                screen.system(
                    "your service is now restricted: only filed contacts can discover it.",
                );
            }
            screen.system("give them a minute — the new descriptor has to reach the directory.");
        }
        "/forget" => {
            let Some(name) = parts.next() else {
                bail!("usage: /forget <name>");
            };
            if book.remove(name)? {
                live.resync(book)?;
                screen.system(format!("forgot {name}"));
                // Upstream is explicit that this is not revocation: the
                // introduction points are not rotated, so a client that already
                // read the descriptor can still reach them.
                screen.system(
                    "they may still reach you until the introduction points rotate on their own.",
                );
            } else {
                screen.system(format!("no contact called {name}"));
            }
        }
        "/contacts" => {
            if book.len() == 0 {
                screen.system("(no contacts yet — /add <name> <address>.onion <key>)");
            }
            for (name, contact) in book.iter() {
                screen.system(format!(
                    "  {name:<16} {}",
                    onion::fingerprint(&contact.address)
                ));
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
            return call(started, live, name, &address, lines, screen).await;
        }
        "/copy" => {
            // Exactly what the other person has to type after `/add <name>`, in
            // that order, so they paste once and are done.
            let both = format!(
                "{} {}",
                live.identity.onion_address().display_unredacted(),
                live.identity.discovery_key()
            );
            screen.copy(both);
            screen.system("your address and key are on the clipboard — send them both.");
            screen.system("(if nothing was copied, your terminal refuses OSC 52; select and copy)");
        }
        "/help" => help(screen),
        "/quit" => return Ok(Flow::Quit),
        // Reachable by dragging a file onto the window outside a call, which is
        // the obvious thing to try first.
        "/send" | "/accept" | "/refuse" => {
            bail!("{verb} only works during a call — /call someone first")
        }
        _ => bail!("unknown command {verb} — /help"),
    }
    Ok(Flow::Continue)
}

/// Dial a contact and hold a conversation.
async fn call(
    started: Instant,
    live: &Live<'_>,
    name: &str,
    address: &str,
    lines: &mut mpsc::Receiver<ui::Typed>,
    screen: &Screen,
) -> Result<Flow> {
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
    let dialling = tor::dial_retrying(live.client, hs_id, DIAL_TIMEOUT, |attempt, err| {
        stage(screen, started, &format!("attempt {attempt} failed: {err}"))
    });
    futures::pin_mut!(dialling);

    let stream = loop {
        tokio::select! {
            outcome = &mut dialling => break outcome.inspect_err(|_| screen.status("listening"))?,
            line = lines.recv() => match line.as_ref().map(|l| l.as_line().unwrap_or("").trim()) {
                // The interface is gone.
                None => return Ok(Flow::Quit),
                Some("/cancel") => {
                    screen.system(format!("gave up calling {name}"));
                    screen.status("listening");
                    return Ok(Flow::Continue);
                }
                // Giving up on a call that has not connected is the one place
                // where `/quit` needs no hang-up: there is nothing to hang up.
                Some("/quit") => {
                    screen.system(format!("gave up calling {name}"));
                    return Ok(Flow::Quit);
                }
                Some("") => {}
                Some(_) => screen.system(format!("still calling {name} — /cancel to give up")),
            },
        }
    };

    screen.system(format!("-- connected to {name} --"));
    screen.status(format!("in a call with {name}"));
    let (reader, writer) = stream.split();
    let flow = converse(reader, writer, name, live.incoming_dir, lines, screen).await;
    if let Flow::Continue = flow {
        screen.status("listening");
    }
    Ok(flow)
}

fn help(screen: &Screen) {
    for line in [
        "commands:",
        "  /add <name> <address> <key>   file a friend (address and key, both)",
        "  /call <name>                  call them",
        "  /contacts                     list the book",
        "  /forget <name>                drop a contact",
        "  /copy                         your address and key, to the clipboard",
        "  /quit                         leave",
        "during a call:",
        "  drop files on the window      they ride the message, where you put them",
        "  /send <path>                  offer one without a message",
        "  /send --direct <path>         offer it outside Tor: much faster, but it",
        "                                shows them your IP. They decide.",
        "  /accept  /refuse              answer an offer",
        "  /accept 2   /accept all       pick one, or take every file offered",
        "  /bye                          hang up",
        "keys:",
        "  up / down                     scroll one line",
        "  Ctrl-B / Ctrl-F               scroll one page",
        "  Ctrl-E                        jump back to the newest line",
        "  left / right / Home / End     move inside what you are typing",
        "                                a dropped file counts as one step",
        "  Ctrl-V                        paste (no Shift needed)",
        "  Ctrl-U                        clear the input   Ctrl-C  leave",
        "mouse:",
        "  click a file in a message     take it, same as /accept <its number>",
        "  drag over the history         select it; releasing copies it",
        "  wheel                         scroll",
        "  Shift-drag                    your terminal's own selection instead",
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

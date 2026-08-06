//! murmure — peer-to-peer terminal messaging over Tor onion services.
//!
//! Run it with no arguments. It publishes your address, keeps listening, and
//! takes commands typed in the input box:
//!
//! ```text
//! /add <name> <address> <key>   file a friend under a name
//! /call <name>                  call them
//! /answer   /decline            take, or turn down, a call coming in
//! /tell <name> <message>        leave a message; it waits until they are up
//! /presence <name>              ask to see when each other is online
//! /contacts                     list the book
//! /forget <name>                drop a contact
//! /quit                         leave
//! ```
//!
//! During a call, `/send <path>` offers a file, `/accept` and `/refuse` answer
//! one, and `/bye` hangs up. An accepted file lands in `<run dir>/incoming/`.
//!
//! `/call` needs both people online at the same moment. `/tell` does not: the
//! message is sealed on your own disk and goes out the next time that contact
//! appears. Nobody else ever holds it — no server, and never your other
//! contacts, who would learn when you write to somebody who is not them.
//!
//! A connection outlives the call held over it, so the second `/call` to
//! somebody costs nothing. A call coming in still has to be answered: the
//! connection being open is not consent to talk over it, so the caller's first
//! words are held unread until `/answer`.
//!
//! Two people who have agreed presence go further: a connection to each other
//! is held open from startup, which is both how each sees the other is up and
//! why calling them is instant. **Nothing is dialled, and no call is placed,
//! without somebody asking for it** — being reachable and being watched are
//! different permissions, and restricted discovery only settles the first.
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
mod link;
mod onion;
mod outbox;
mod pool;
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

use crate::contacts::{Contacts, Presence, Said};
use crate::identity::Identity;
use crate::link::Link;
use crate::outbox::Outbox;
use crate::pool::{Heard, Pool};
use crate::proto::Message;
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

/// How often we check that every contact we agreed presence with is still
/// connected, and dial the ones that are not.
///
/// A no-op for anyone already connected, so the cost is one map lookup per
/// contact per minute. What it buys is the only recovery path there is: a
/// contact whose machine slept comes back on the next sweep, and nothing else
/// would ever notice.
const PRESENCE_SWEEP: Duration = Duration::from_secs(60);

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
    // Shared rather than owned: a background dial runs in its own task and
    // needs the seed to prove who it is. One copy, not one per dial.
    let identity = Arc::new(Identity::load_or_create(&seed_path)?);
    identity.check_permissions()?;
    let expected = identity.onion_address();
    let mut book = Contacts::open(&run_dir.join("contacts.sealed"), &identity)?;
    let mut outbox = Outbox::open(&run_dir.join("outbox.sealed"), &identity)?;

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
        "identity {}, {} contact{}",
        if existed { "loaded" } else { "generated" },
        book.len(),
        if book.len() == 1 { "" } else { "s" }
    ));
    screen.system(format!("your address: {my_address}"));
    screen.system(format!("your key:     {}", identity.discovery_key()));
    screen.system("give a friend both lines, and compare the fingerprint out loud.");
    // The full list is forty lines. Worth it once, when there is nothing else
    // to go on; noise every morning after that.
    if existed {
        screen.system("/help lists the commands.");
    } else {
        help(&screen);
    }

    // ---- publish ---------------------------------------------------------
    //
    // From here on, every failure has to reach the screen rather than stdout:
    // stdout is the alternate screen now.
    if outbox.len() > 0 {
        screen.system(format!(
            "{} message{} still waiting to go out.",
            outbox.len(),
            if outbox.len() == 1 { "" } else { "s" }
        ));
    }

    let outcome = serve(
        started, run_dir, &seed_path, &identity, expected, &screen, &mut book, &mut outbox,
        &mut lines,
    )
    .await;
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
    identity: &Arc<Identity>,
    expected: tor_hscrypto::pk::HsId,
    screen: &Screen,
    book: &mut Contacts,
    outbox: &mut Outbox,
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
            &format!(
                "only your {} contact{} can see you are running",
                clients.len(),
                if clients.len() == 1 { "" } else { "s" }
            ),
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
    // Not on screen: the operator cannot act on it, and it only ever says the
    // same thing — the alternative is a hard failure a few lines above.
    tracing::info!(
        "[{:.1}s] published under our own key",
        started.elapsed().as_secs_f32()
    );

    screen.status("publishing to the directory");
    if tor::wait_until_reachable(&service, REACHABLE_TIMEOUT)
        .await
        .is_err()
    {
        // Under-reports; an incoming connection is the real test.
        stage(screen, started, "listening (Tor never confirmed it, which is normal)");
    }

    screen.status("listening");
    screen.system("ready — type a command.");
    screen.accepting(true);

    // ---- the idle loop ---------------------------------------------------
    let incoming = tor::incoming(requests);
    futures::pin_mut!(incoming);
    // Connections that outlived the call held over them, plus the ones presence
    // asked for. Starts empty; the first sweep below fills it.
    let mut pool = Pool::new();
    // Fires immediately, which is what connects to everyone at startup, and
    // then every minute to pick up whoever came back.
    let mut sweep = tokio::time::interval(PRESENCE_SWEEP);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Somebody calling, waiting to be answered. One at a time, like the calls
    // themselves.
    let mut ringing: Option<Ringing> = None;

    loop {
        // The select only *picks* the event. Handling it happens after, so that
        // no borrow held by a branch future is still alive while a conversation
        // runs — a conversation needs `lines`, and a call out of the pool needs
        // the pool.
        let event = tokio::select! {
            stream = incoming.next() => Event::Called(stream.map(Box::new)),
            line = lines.recv() => Event::Typed(line),
            heard = pool.ready() => Event::Spoke(heard),
            _ = sweep.tick() => Event::Sweep,
        };

        match event {
            // Somebody connected. That is not yet a call: it may be a contact
            // coming online, or a presence request, and neither should open a
            // conversation. The connection goes into the pool and the first
            // frame on it decides what it was — the same path a connection we
            // already held takes, so there is one answer and not two.
            //
            // An onion service is told nothing about its client, so the name
            // comes out of the handshake, one signature later, and not from the
            // connection.
            Event::Called(Some(stream)) => {
                let (reader, writer) = stream.split();
                match Link::open(reader, writer, identity).await {
                    Ok(link) => {
                        let peer = link.peer;
                        let name = name_for(book, &peer);
                        let agreed = book.presence_of(&name) == Presence::On;
                        // Somebody we agreed to watch arriving *is* the whole of
                        // "they are online" — there is nothing else to observe.
                        if pool.keep(link).await && agreed {
                            screen.system(format!("-- {name} is online --"));
                        }
                        deliver(&peer, outbox, &mut pool, screen).await;
                    }
                    Err(e) => screen.error(format!("-- a connection was dropped: {e:#} --")),
                }
            }
            Event::Called(None) => bail!("the incoming-stream channel closed"),
            // Agreeing to be seen is not something said during a call, so it is
            // settled out here and opens no conversation.
            Event::Spoke(Heard::Frame(peer, msg)) if said_about_presence(&msg).is_some() => {
                let said = said_about_presence(&msg).expect("guarded by the arm");
                // A stranger who got this far is someone we forgot. There is
                // nowhere to record an agreement with them, so nothing to say.
                match book.name_of(&peer.display_unredacted().to_string()) {
                    None => tracing::debug!("a presence frame from nobody in the book"),
                    Some(name) => {
                        let name = name.to_owned();
                        if let Err(e) = presence(&name, said, book, &mut pool, &live, screen).await {
                            screen.error(format!("{e:#}"));
                        }
                    }
                }
            }
            // Something written to us while we were out. Shown where it lands
            // rather than ringing: a message left last week is not a call, and
            // making it one would let `/decline` throw away something the
            // sender has every reason to believe arrived.
            Event::Spoke(Heard::Frame(peer, Message::Left { id, at, body })) => {
                match book.name_of(&peer.display_unredacted().to_string()) {
                    None => tracing::debug!("a message left by nobody in the book"),
                    Some(name) => {
                        let name = name.to_owned();
                        // Shown only the first time. Their outbox keeps it until
                        // we acknowledge, so a lost acknowledgement means it
                        // arrives again — which must cost a second frame, never
                        // a second copy on screen.
                        match book.accept_left(&name, id) {
                            Ok(true) => screen.say(
                                Kind::Theirs,
                                format!("{name} ({})> {body}", outbox::how_long_ago(at)),
                            ),
                            Ok(false) => tracing::debug!("a message we already had"),
                            Err(e) => screen.error(format!("{e:#}")),
                        }
                        // Acknowledged either way: the sender is holding it
                        // until we say we have it, and we do.
                        pool.send(peer, Message::Got(id)).await;
                    }
                }
            }
            // They have it. That, and only that, is what lets go of it.
            Event::Spoke(Heard::Frame(peer, Message::Got(id))) => {
                let address = peer.display_unredacted().to_string();
                match outbox.delivered(&address, id) {
                    Ok(true) => {
                        let left = outbox.waiting_for(&address);
                        let name = name_for(book, &peer);
                        if left == 0 {
                            screen.system(format!("-- everything you wrote to {name} arrived --"));
                        }
                    }
                    Ok(false) => tracing::debug!("an acknowledgement we had already acted on"),
                    Err(e) => screen.error(format!("{e:#}")),
                }
            }
            // Somebody we are already connected to has started talking. The
            // frame *is* the call arriving — there is no dial to notice and
            // nothing else to announce it.
            //
            // It is held, not acted on. The connection was open before anybody
            // wanted to talk, so entering the conversation here would be
            // answering the phone on the caller's behalf, and reading what they
            // said before deciding whether to take the call.
            Event::Spoke(Heard::Frame(peer, msg)) => {
                let name = name_for(book, &peer);
                if ringing.is_some() {
                    // Already being called by somebody else. Answer for them
                    // rather than leaving a second caller waiting on silence.
                    pool.send(peer, Message::CallDecline).await;
                    screen.system(format!("-- {name} called while you were busy --"));
                    continue;
                }
                screen.system(format!(
                    "-- {name} is calling — /answer to take it, /decline to refuse --"
                ));
                screen.status(format!("{name} is calling"));
                ringing = Some(Ringing {
                    peer,
                    name,
                    first: msg,
                });
            }
            // A background dial landed. This is the whole of "alice is online":
            // being connected to somebody is the same fact as seeing them.
            Event::Spoke(Heard::Reached(peer)) => {
                screen.system(format!("-- {} is online --", name_for(book, &peer)));
                deliver(&peer, outbox, &mut pool, screen).await;
            }
            // A connection ended with nobody talking over it. Only worth saying
            // for someone we were watching on purpose; otherwise the next
            // `/call` simply dials again and there is nothing to report.
            Event::Spoke(Heard::Lost(peer)) => {
                let name = name_for(book, &peer);
                if book.presence_of(&name) == Presence::On {
                    screen.system(format!("-- {name} went offline --"));
                }
                // A caller who left is not a caller to answer. Without this the
                // prompt sits there and `/answer` walks into a dead link.
                if ringing.as_ref().is_some_and(|r| r.peer == peer) {
                    ringing = None;
                    screen.system(format!("-- {name} stopped calling --"));
                    screen.status("listening");
                }
                tracing::debug!("a held connection ended");
            }
            Event::Sweep => hold_presence(&mut pool, book, &live),
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
                match command(
                    line, book, &live, &mut pool, outbox, &mut ringing, lines, started, screen,
                )
                    .await
                {
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
    identity: &'a Arc<Identity>,
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
    /// Something happened on the pool: a frame, a connection lost, or a
    /// background dial landing.
    Spoke(Heard),
    /// Time to make sure everyone we agreed presence with is still connected.
    Sweep,
}

/// What the idle loop does after a command.
enum Flow {
    Continue,
    Quit,
}

/// The name we know a proved identity by, or something honest if we do not.
///
/// The address is what the far side signed for, so a stranger who reaches this
/// point is a stranger by name only — someone we filed once and forgot, or who
/// kept a descriptor from before. Their fingerprint is shown so the operator
/// can recognise them if they ever knew them.
fn name_for(book: &Contacts, peer: &HsId) -> String {
    let address = peer.display_unredacted().to_string();
    match book.name_of(&address) {
        Some(name) => name.to_owned(),
        None => format!("someone not in your book ({})", onion::fingerprint(&address)),
    }
}

/// Open a connection to everyone who agreed presence, and keep it open.
///
/// Cheap to call often: a contact already connected, or already being dialled,
/// is skipped. Calling it on a timer is the only recovery there is — a peer
/// whose machine slept closes nothing and says nothing, so the sweep that finds
/// them missing is what brings them back.
fn hold_presence(pool: &mut Pool, book: &Contacts, live: &Live<'_>) {
    for (name, contact) in book.agreed() {
        match contact.address.parse::<HsId>() {
            Ok(peer) => pool.reach(live.client, peer, live.identity),
            // Refused by `/add`, so this cannot happen without a corrupt book.
            Err(e) => tracing::warn!("{name}'s address is unusable: {e}"),
        }
    }
}

/// Put everything waiting for this peer on the wire.
///
/// Nothing is removed here. A frame handed to a link is not a message received
/// — the link can die in between — so what leaves the queue is decided by their
/// [`Message::Got`] and by nothing else. Sending the same thing twice is the
/// price, and the recipient's delivery mark makes it cost nothing.
async fn deliver(peer: &HsId, outbox: &Outbox, pool: &mut Pool, screen: &Screen) {
    let address = peer.display_unredacted().to_string();
    let waiting = outbox.frames_for(&address);
    if waiting.is_empty() {
        return;
    }
    screen.system(format!(
        "-- sending {} message{} you left --",
        waiting.len(),
        if waiting.len() == 1 { "" } else { "s" }
    ));
    for frame in waiting {
        pool.send(*peer, frame).await;
    }
}

/// Somebody calling, waiting for an answer.
///
/// The connection was already open, so a call is announced by the caller's
/// first frame and by nothing else. That frame is held here — unread, unshown —
/// until somebody says whether to take the call. Answering it is what hands it
/// to the conversation, in its rightful place at the front.
struct Ringing {
    peer: HsId,
    /// What we know them by, worked out once when the call came in.
    name: String,
    first: Message,
}

/// Read a frame as a presence event, if that is what it is.
///
/// [`None`] for everything else, which is what tells the idle loop that a frame
/// is somebody starting to talk rather than somebody answering a question.
fn said_about_presence(msg: &Message) -> Option<Said> {
    match msg {
        Message::PresenceAsk => Some(Said::TheyAsk),
        Message::PresenceYes => Some(Said::TheyAgree),
        Message::PresenceNo => Some(Said::TheyRefuse),
        _ => None,
    }
}

/// Apply one presence event, and everything that follows from it.
///
/// One function for both directions — a request we type and a frame that
/// arrives — because they are the same state machine and splitting them is how
/// the two halves drift apart. The machine itself is in [`crate::contacts`] and
/// touches nothing; this is the part that stores, sends, and says.
async fn presence(
    name: &str,
    said: Said,
    book: &mut Contacts,
    pool: &mut Pool,
    live: &Live<'_>,
    screen: &Screen,
) -> Result<()> {
    let Some(address) = book.address_of(name).map(str::to_owned) else {
        bail!("no contact called {name} — /add them first");
    };
    let peer: HsId = address
        .parse()
        .map_err(|e| anyhow::anyhow!("{name}'s address is not a valid onion address: {e}"))?;

    let was = book.presence_of(name);
    let step = was.step(said, name);
    book.set_presence(name, step.to)?;
    if let Some(reply) = step.reply {
        // Queued if there is no connection yet, which is the normal case for a
        // request: presence is asked of somebody we are not yet connected to.
        pool.send(peer, reply).await;
    }
    if let Some(note) = step.note {
        screen.system(note);
    }

    match step.to {
        // Agreed. Connect now rather than waiting up to a minute for the sweep.
        Presence::On => pool.reach(live.client, peer, live.identity),
        // Not agreed, or no longer. Let go of the connection — `forget` closes
        // it rather than dropping it, so the refusal queued above still gets
        // out. Skipped when nothing changed, or a plain `/presence x off` typed
        // twice would hang up a connection a call had left open.
        Presence::Off if was != Presence::Off => pool.forget(&peer).await,
        _ => {}
    }
    Ok(())
}

/// Put a link back in the pool, or close it if the call ended because it died.
///
/// The whole point of the pool is that hanging up is not disconnecting — so
/// this is the one place that decides which of the two just happened, and there
/// is exactly one answer: the peer going away.
async fn shelve(pool: &mut Pool, link: Link, alive: bool) {
    if alive {
        // Back where it was; nothing to announce, since nobody arrived.
        let _ = pool.keep(link).await;
    } else if let Err(e) = link.close(true).await {
        tracing::debug!("closing a spent connection: {e:#}");
    }
}

/// Hold one conversation over an already-open link.
///
/// Returns whether the operator wants out of the program as well as out of the
/// call, and whether the connection is still worth keeping — a call ending is
/// not the connection ending, and only the peer going away makes it one.
///
/// Never propagates an error: a dropped call must not end the program, so a
/// failure is shown and treated as an ordinary hang-up.
async fn converse(
    link: &mut Link,
    peer: &str,
    first: Option<Message>,
    incoming_dir: &Path,
    lines: &mut mpsc::Receiver<ui::Typed>,
    screen: &Screen,
) -> (Flow, bool) {
    // The one place both an outgoing and an incoming call pass through, so the
    // input box learns who it is pointed at — and, whatever happens next,
    // learns that it is pointed at nobody again.
    screen.in_call(Some(peer));
    let ended = chat::run(link, peer, first, incoming_dir, lines, screen).await;
    screen.in_call(None);

    match ended {
        Ok(ended) => {
            screen.system(format!("-- {} --", ended.describe(peer)));
            let alive = ended != chat::Ended::PeerHungUp;
            if ended.leaves() {
                return (Flow::Quit, alive);
            }
            (Flow::Continue, alive)
        }
        // Whatever went wrong went wrong on this connection, so it is not one
        // to offer the next `/call`.
        Err(e) => {
            screen.error(format!("-- call dropped: {e:#} --"));
            (Flow::Continue, false)
        }
    }
}

/// Run one typed command.
#[allow(clippy::too_many_arguments)]
async fn command(
    line: &str,
    book: &mut Contacts,
    live: &Live<'_>,
    pool: &mut Pool,
    outbox: &mut Outbox,
    ringing: &mut Option<Ringing>,
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
            // Read before the removal, because after it there is no contact to
            // look the address up on.
            let address = book.address_of(name).and_then(|a| a.parse::<HsId>().ok());
            if book.remove(name)? {
                live.resync(book)?;
                // Somebody forgotten is somebody we stop holding a connection
                // to. Leaving one open would keep answering for a name that no
                // longer exists.
                if let Some(peer) = address {
                    // What was written to a name that no longer exists goes
                    // with it. Keeping it would deliver, months later, to
                    // somebody the operator decided to stop knowing.
                    let dropped = outbox.discard(&peer.display_unredacted().to_string())?;
                    if dropped > 0 {
                        screen.system(format!("dropped {dropped} message(s) waiting for {name}"));
                    }
                    pool.forget(&peer).await;
                }
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
                // Presence is shown when the list is asked for, and never on its
                // own. A permanent panel of who is online is a panel that says,
                // continuously and to anyone behind you, who you talk to.
                let standing = match contact.presence {
                    Presence::Off => String::new(),
                    Presence::WeAsked => "  (presence: asked, waiting)".to_owned(),
                    Presence::TheyAsked => format!("  (asks to see you — /presence {name})"),
                    Presence::On => match contact.address.parse::<HsId>() {
                        Ok(peer) if pool.holds(&peer) => "  (online)".to_owned(),
                        _ => "  (presence on, not connected)".to_owned(),
                    },
                };
                let waiting = match outbox.waiting_for(&contact.address) {
                    0 => String::new(),
                    n => format!("  ({n} waiting to go out)"),
                };
                screen.system(format!(
                    "  {name:<16} {}{standing}{waiting}",
                    onion::fingerprint(&contact.address)
                ));
            }
        }
        "/tell" => {
            let Some(name) = parts.next() else {
                bail!("usage: /tell <name> <message>");
            };
            // Everything after the name, spacing and all. `split_whitespace`
            // has eaten it, so take it from the original line.
            let body = line
                .split_once(name)
                .map(|(_, rest)| rest.trim())
                .unwrap_or_default();
            if body.is_empty() {
                bail!("usage: /tell {name} <message>");
            }
            let address = book
                .address_of(name)
                .ok_or_else(|| anyhow::anyhow!("no contact called {name} — /add them first"))?
                .to_owned();
            let peer: HsId = address
                .parse()
                .map_err(|e| anyhow::anyhow!("{name}'s address is unusable: {e}"))?;

            // Queued first, always, even when they are connected. One path, so
            // a message is on disk before anything is attempted with it and a
            // failure at any point after this cannot lose it.
            let dropped = outbox.queue(&address, body.to_owned())?;
            if dropped > 0 {
                screen.error(format!(
                    "{dropped} older message{} to {name} dropped — {} were already waiting",
                    if dropped == 1 { " was" } else { "s were" },
                    outbox.waiting_for(&address)
                ));
            }
            screen.say(Kind::Mine, format!("you (to {name})> {body}"));
            if pool.holds(&peer) {
                deliver(&peer, outbox, pool, screen).await;
            } else {
                screen.system(format!(
                    "{name} is not connected — kept, and it goes out when they next are ({} waiting)",
                    outbox.waiting_for(&address)
                ));
                // Not reached for a contact we hold no agreement with: they are
                // dialled by a call, and by nothing this can do for them.
                if book.presence_of(name) == Presence::On {
                    pool.reach(live.client, peer, live.identity);
                }
            }
        }
        "/answer" => {
            let Some(call) = ringing.take() else {
                bail!("nobody is calling");
            };
            let Some(mut link) = pool.take(&call.peer) else {
                // The connection went away between the ring and the answer.
                bail!("{} is no longer connected", call.name);
            };
            screen.system(format!("-- in a call with {} --", call.name));
            screen.status(format!("in a call with {}", call.name));
            let (flow, alive) = converse(
                &mut link,
                &call.name,
                Some(call.first),
                live.incoming_dir,
                lines,
                screen,
            )
            .await;
            shelve(pool, link, alive).await;
            if let Flow::Continue = flow {
                screen.status("listening");
            }
            return Ok(flow);
        }
        "/decline" => {
            let Some(call) = ringing.take() else {
                bail!("nobody is calling");
            };
            // Told, rather than left to wonder: the connection stays open
            // either way, so silence would look exactly like a slow reader.
            pool.send(call.peer, Message::CallDecline).await;
            // Whatever they said goes with it. Declining a call is not a way of
            // reading it.
            screen.system(format!("-- turned down the call from {} --", call.name));
            screen.status("listening");
        }
        "/presence" => {
            let Some(name) = parts.next() else {
                bail!("usage: /presence <name>   — or /presence <name> off");
            };
            let said = match parts.next() {
                Some("off") | Some("no") => Said::WeStop,
                None => Said::WeAsk,
                Some(other) => bail!("/presence {name} {other}? the only extra word is 'off'"),
            };
            presence(name, said, book, pool, live, screen).await?;
        }
        "/call" => {
            let Some(name) = parts.next() else {
                bail!("usage: /call <name>");
            };
            let address = book
                .address_of(name)
                .ok_or_else(|| anyhow::anyhow!("no contact called {name} — /add them first"))?
                .to_owned();
            return call(started, live, pool, name, &address, lines, screen).await;
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

/// Reach a contact — from the pool if we are already connected, by dialling if
/// not — and hold a conversation.
async fn call(
    started: Instant,
    live: &Live<'_>,
    pool: &mut Pool,
    name: &str,
    address: &str,
    lines: &mut mpsc::Receiver<ui::Typed>,
    screen: &Screen,
) -> Result<Flow> {
    let hs_id: tor_hscrypto::pk::HsId = address
        .parse()
        .map_err(|e| anyhow::anyhow!("{address} is not a valid onion address: {e}"))?;

    // The connection may already be there, in which case there is nothing to
    // compose. This is what the pool is for, and the only visible difference is
    // that the seven-to-fifty-second wait does not happen.
    if let Some(mut link) = pool.take(&hs_id) {
        screen.system(format!("-- still connected to {name} --"));
        screen.status(format!("in a call with {name}"));
        let (flow, alive) = converse(&mut link, name, None, live.incoming_dir, lines, screen).await;
        shelve(pool, link, alive).await;
        if let Flow::Continue = flow {
            screen.status("listening");
        }
        return Ok(flow);
    }

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
        {
            // arti's chain is four nested sentences that repeat themselves and
            // name a truncated address. All of it means one thing, and the log
            // keeps the original for the day it means something else.
            tracing::info!("dial attempt {attempt} failed: {err}");
            let why = if err.contains("descriptor") {
                "they are not published yet"
            } else if err.contains("timed out") || err.contains("Timeout") {
                "no answer yet"
            } else {
                "did not connect"
            };
            stage(screen, started, &format!("attempt {attempt}: {why}, retrying"));
        }
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

    let (reader, writer) = stream.split();
    let mut link = match Link::open(reader, writer, live.identity).await {
        Ok(link) => link,
        Err(e) => {
            screen.error(format!("-- call dropped: {e:#} --"));
            screen.status("listening");
            return Ok(Flow::Continue);
        }
    };

    // We dialled an address and the far side proved a key. If the two disagree,
    // something between us answered for them — so this is refused rather than
    // answered, and it is checked here rather than by name, because the key is
    // what was signed for.
    if link.peer != hs_id {
        screen.error(format!(
            "-- refused: you called {name}, but the far side proved a different key ({}) --",
            onion::fingerprint(&link.peer.display_unredacted().to_string())
        ));
        let _ = link.close(false).await;
        screen.status("listening");
        return Ok(Flow::Continue);
    }

    screen.system(format!("-- connected to {name} --"));
    screen.status(format!("in a call with {name}"));
    let (flow, alive) = converse(&mut link, name, None, live.incoming_dir, lines, screen).await;
    shelve(pool, link, alive).await;
    if let Flow::Continue = flow {
        screen.status("listening");
    }
    Ok(flow)
}

fn help(screen: &Screen) {
    for line in [
        "first time:  /copy, send both lines to them, /add theirs, then /call.",
        "             neither line is a secret. compare the fingerprint out loud.",
        "",
        "commands:",
        "  /add <name> <address> <key>   file a friend (address and key, both)",
        "  /tell <name> <message>        leave a message. it waits, sealed on your disk,",
        "                                until they are next online — no server holds it",
        "  /call <name>                  call them — 7-50 s the first time, then instant",
        "                                for as long as the connection holds. /cancel to give up",
        "  /answer                       take the call somebody is making",
        "  /decline                      turn it down; they are told, and hear nothing else",
        "  /presence <name>              ask to see when each other is online. they must agree,",
        "                                and either of you can stop it with /presence <name> off",
        "  /contacts                     list the book, and who is online",
        "  /forget <name>                drop a contact",
        "  /copy                         your address and key, to the clipboard",
        "  /help                         this",
        "  /quit                         leave, hanging up first if you are in a call",
        "during a call:",
        "  drop files on the window      they ride the message, where you put them",
        "  /send <path>                  offer one without a message",
        "  /direct <message>             send this message's files outside Tor:",
        "                                much faster, but it shows them your IP",
        "  /send --direct <path>         the same, for a file sent on its own",
        "  /accept  /refuse              answer the newest message that offered files",
        "  /accept 2   /accept all       pick one by its number, or take every one",
        "  /bye                          hang up",
        "keys:",
        "  up / down                     scroll one line",
        "  Ctrl-B / Ctrl-F               scroll one page",
        "  Ctrl-E                        jump back to the newest line",
        "  left / right / Home / End     move inside what you are typing",
        "                                a dropped file counts as one step",
        "  Ctrl-V                        paste (no Shift needed)",
        "  Ctrl-U                        clear the input",
        "  Ctrl-C                        leave, from anywhere",
        "mouse:",
        "  click an underlined file      take it, same as /accept <its number>",
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
/// Say a startup stage on screen, and keep the stopwatch for the log.
///
/// The timing is instrumentation: it is what tells *me* whether a bootstrap was
/// slow, and it tells the operator nothing they can act on. It goes to
/// `murmure.log`, where looking for it is a deliberate act.
fn stage(screen: &Screen, started: Instant, what: &str) {
    tracing::info!("[{:.1}s] {what}", started.elapsed().as_secs_f32());
    screen.system(what);
}

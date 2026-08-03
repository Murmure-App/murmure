//! The conversation loop.
//!
//! One open stream, frames in both directions, until either side hangs up.
//!
//! # Who owns the keyboard
//!
//! Not this module. `main` owns the one and only stdin reader and hands typed
//! lines here through a channel, because the idle loop and the conversation both
//! need them and two concurrent readers on stdin lose lines to each other.
//!
//! # Shape
//!
//! Two tasks and one loop. The **reader** task pulls frames off the wire and
//! forwards them, deciding nothing; the **writer** task is the only thing that
//! touches the write half. Everything in between — what to print, what to
//! answer, where a transfer is up to — happens in the loop, which is therefore
//! the single owner of every piece of state. No locks, and no state split
//! across a task boundary.
//!
//! That matters most for files. A transfer's state is read by the keyboard
//! branch (`/accept`), by the wire branch (a chunk arriving) and by the pump
//! that sends the next chunk. Any two of those in different tasks would need a
//! mutex; in one loop they need nothing.
//!
//! # Files, in one paragraph
//!
//! The sender offers, the recipient answers — never automatically, because a
//! file lands on their disk. An accept carries the offset already on disk, so a
//! transfer that died halfway resumes. Chunks then flow one way while the
//! conversation keeps working in the other. See [`crate::files`] for why the
//! integrity check is one hash of the whole file rather than a verified stream.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use futures::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::files::{self, Offer};
use crate::proto::{self, MAX_CHUNK, MAX_TEXT, Message};
use crate::ui::{Kind, Screen};

/// How many outbound frames may queue before the sender waits.
///
/// Small on purpose: a backlog here means the network is slower than the typing,
/// and making the typist wait is more honest than growing a buffer. It is also
/// what paces a file transfer — the chunk pump waits for room in this channel
/// rather than for a timer.
const OUTBOX: usize = 32;

/// How many inbound frames may queue before the reader task waits.
///
/// Backpressure onto the peer's circuit is the right answer to a loop that is
/// busy: the alternative is buffering a file in memory on the way to the disk.
const INBOX: usize = 32;


/// How often a running transfer refreshes the bar.
///
/// Time-based, not byte-based: on a direct link a byte threshold fires
/// hundreds of times a second and redraws the whole interface for nothing,
/// while over Tor the same threshold can take ten seconds to come round. What
/// the reader wants is a bar that moves at a steady, readable rate either way.
const REFRESH: std::time::Duration = std::time::Duration::from_millis(120);

/// Live progress, throttled.
///
/// Owns the last-drawn instant so callers do not each reinvent the throttle;
/// the direct tasks and the chunk pump all go through this.
struct Progress {
    name: String,
    total: u64,
    verb: &'static str,
    last: std::time::Instant,
}

impl Progress {
    fn new(verb: &'static str, name: impl Into<String>, total: u64) -> Self {
        Self {
            name: name.into(),
            total,
            verb,
            // Far enough back that the first call always draws.
            last: std::time::Instant::now() - REFRESH,
        }
    }

    /// Draw the bar if enough time has passed. `done` is bytes so far.
    fn show(&mut self, done: u64, screen: &Screen) {
        if self.last.elapsed() < REFRESH {
            return;
        }
        self.last = std::time::Instant::now();
        screen.status(format!("{} {} {}", self.verb, self.name, bar(done, self.total)));
    }
}

/// A bar, a percentage and the two sizes, in one line.
fn bar(done: u64, total: u64) -> String {
    /// Characters of bar. Narrow enough to leave the name and sizes visible on
    /// an 80-column terminal, which is the narrowest anyone actually uses.
    const WIDTH: u64 = 20;

    let done = done.min(total);
    // A zero total is "nothing to do", so it reads as finished rather than as
    // a division by zero.
    let filled = (done * WIDTH).checked_div(total).unwrap_or(WIDTH);
    let percent = (done * 100).checked_div(total).unwrap_or(100);
    format!(
        "[{}{}] {percent:>3}%  {} / {}",
        "\u{2588}".repeat(filled as usize),
        "\u{2591}".repeat((WIDTH - filled) as usize),
        files::human(done),
        files::human(total),
    )
}

/// How a conversation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// The peer closed the stream.
    PeerHungUp,
    /// We did, with `/bye`.
    WeHungUp,
    /// We did, with `/quit`: hang up *and* leave the program.
    Quit,
    /// stdin reached EOF: Ctrl-D, or a piped script running out.
    InputClosed,
}

impl Ended {
    /// What to tell the operator, using the name they know the peer by.
    pub fn describe(self, peer: &str) -> String {
        match self {
            Ended::PeerHungUp => format!("{peer} hung up"),
            Ended::WeHungUp | Ended::Quit => "you hung up".to_owned(),
            Ended::InputClosed => "input closed".to_owned(),
        }
    }

    /// Should the program stop, rather than go back to listening?
    pub fn leaves(self) -> bool {
        matches!(self, Ended::Quit | Ended::InputClosed)
    }
}

/// Which way a file should travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Through the conversation's onion circuit, like everything else. Slow,
    /// and reveals nothing.
    Tor,
    /// Straight to the peer, outside Tor. Fast, and tells them our address —
    /// so it is only ever reached by asking for it by name.
    Direct,
}

/// How a transfer that ran outside Tor ended.
///
/// Carried back from the task that owned it, because that task holds the file
/// and the socket and the loop holds everything else.
enum DirectDone {
    /// The bytes went out.
    Sent(String),
    /// The bytes came in and are on disk; the loop verifies and renames.
    Received(Box<Offer>),
    /// It did not work. The message says why, for the operator.
    Failed(String),
}

/// A file going out, and how far it has got.
struct Sending {
    file: std::fs::File,
    name: String,
    /// Whether the peer has answered the offer. Nothing is read from disk
    /// before they do.
    accepted: bool,
    /// Bytes written to the wire so far, counted from zero even on a resume so
    /// that the number on screen matches the recipient's.
    sent: u64,
    /// Total size, for the progress line.
    size: u64,
    /// The bar, and its own throttle.
    progress: Progress,
    /// Where this file lives, kept so a direct transfer can reopen it in its
    /// own task rather than moving the handle out from under the chunk pump.
    path: PathBuf,
    /// Whether the offer asked for a direct link. The recipient still decides.
    route: Route,
}

/// A file a peer put in a message, waiting for our answer.
#[derive(Debug)]
struct Offered {
    /// The number shown on screen. Assigned when the offer arrives and never
    /// reused, so `/accept 3` always means the thing that was drawn as `[3]`.
    ///
    /// Not a position in this list: taking one shifts every position after it,
    /// which made `/accept 3` say "there is no file 3" once `/accept 2` had
    /// been used — while `[3]` was still on screen.
    number: usize,
    /// Which message it arrived in. `/accept` with no number takes from the
    /// newest, because that is the one the operator has just read.
    batch: usize,
    offer: Offer,
    /// Whether the sender asked for it to travel outside Tor. A property of how
    /// this transfer was proposed, not of the file.
    direct: bool,
}

/// A file we put in a message, waiting for theirs.
///
/// The path is kept because a `FileAccept` names a hash, and the hash alone
/// does not say where the file is on our disk.
struct Outgoing {
    hash: [u8; 32],
    path: PathBuf,
    name: String,
    size: u64,
    route: Route,
}

/// Which offered file a verb is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    /// No argument: from the newest message that still has files waiting.
    ///
    /// "The one I just read", which is what somebody typing a bare `/accept`
    /// means. It used to be the oldest still unanswered, and that is wrong in
    /// the ordinary case: two messages arrive with files, you answer the second
    /// one, and a file from the first turns up instead.
    Newest,
    /// A number as shown on screen, counting from 1.
    Numbered(usize),
    /// Every one of them.
    ///
    /// Transfers still run one at a time — the wire carries one file at a time
    /// whatever the operator asked — so this is a standing instruction rather
    /// than a batch: finishing one starts the next.
    All,
}

impl Which {
    fn parse(rest: &str) -> Self {
        match rest.trim() {
            "all" | "tout" | "tous" => Which::All,
            other => match other.parse() {
                Ok(n) => Which::Numbered(n),
                Err(_) => Which::Newest,
            },
        }
    }
}

/// Take one offer out of the queue.
///
/// A bare `/accept` takes from the **newest** message, earliest file first.
/// Taking the globally oldest is what a queue does, and it surprised everyone:
/// you type `/accept` right after reading a message, and you mean the thing you
/// just read — not something you left unanswered ten minutes ago.
fn take_pending(pending: &mut Vec<Offered>, which: Which) -> Result<Offered> {
    if pending.is_empty() {
        bail!("nothing to answer");
    }
    let index = match which {
        Which::Newest | Which::All => {
            let newest = pending.iter().map(|o| o.batch).max().expect("not empty");
            pending
                .iter()
                .position(|o| o.batch == newest)
                .expect("the max came from this list")
        }
        Which::Numbered(n) => pending
            .iter()
            .position(|o| o.number == n)
            .ok_or_else(|| match pending.len() {
                1 => anyhow::anyhow!("there is no file {n}; only [{}] is waiting", pending[0].number),
                _ => anyhow::anyhow!(
                    "there is no file {n}; waiting: {}",
                    pending
                        .iter()
                        .map(|o| format!("[{}]", o.number))
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            })?,
    };
    Ok(pending.remove(index))
}

/// A file coming in, and how far it has got.
struct Receiving {
    file: std::fs::File,
    offer: Offer,
    written: u64,
    progress: Progress,
}

/// Run a conversation over an open stream.
///
/// `lines` is borrowed rather than consumed: when the conversation ends, the
/// caller goes back to reading commands from the same keyboard. `incoming_dir`
/// is where accepted files land.
pub async fn run<R, W>(
    reader: R,
    writer: W,
    peer: &str,
    incoming_dir: &Path,
    lines: &mut mpsc::Receiver<crate::ui::Typed>,
    screen: &Screen,
) -> Result<Ended>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // First, and while both halves are still here to be handed to it: agree on
    // a version. A peer running a different build would otherwise decode our
    // frames as whatever its own enum says that byte means, and the failure
    // would arrive later wearing the wrong name. See [`proto::handshake`].
    let mut reader = reader;
    let mut writer = writer;
    proto::handshake(&mut reader, &mut writer).await?;

    let (outbox, mut queued) = mpsc::channel::<Message>(OUTBOX);
    let (inbox_tx, mut inbox) = mpsc::channel::<Message>(INBOX);

    let writing = tokio::spawn(async move {
        while let Some(msg) = queued.recv().await {
            proto::write_frame(&mut writer, &msg).await?;
        }
        Ok::<(), anyhow::Error>(())
    });

    // Decides nothing: every frame goes to the loop, which owns the state that
    // says what a frame means.
    let reading = tokio::spawn(async move {
        while let Some(msg) = proto::read_frame(&mut reader).await? {
            if inbox_tx.send(msg).await.is_err() {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    });
    futures::pin_mut!(reading);

    // All conversation state, owned here and nowhere else.
    let mut sending: Option<Sending> = None;
    let mut receiving: Option<Receiving> = None;
    // Offers waiting for an answer, oldest first. A message can carry several
    // files, so this is a queue rather than a slot — and `/accept` with no
    // number takes the oldest, which is what "the one I just saw" means.
    let mut pending: Vec<Offered> = Vec::new();
    // Files we put in a message and have not been answered about yet. Keyed by
    // hash because that is what a `FileAccept` names.
    let mut offered: Vec<Outgoing> = Vec::new();
    // Set by `/accept all`. The wire carries one file at a time whatever the
    // operator asked, so taking them all is a standing instruction: each
    // transfer that finishes starts the next one still queued.
    let mut take_everything = false;
    // Numbers shown on screen, and which message a file arrived in. Both only
    // ever go up: a number that is reused is a number that means two things.
    let mut next_number = 0usize;
    let mut next_batch = 0usize;
    // Whether a transfer was running last time round, so the status line can be
    // handed back exactly once when it stops.
    let mut was_running = false;
    // Set once the operator has asked to leave but a transfer is still running.
    // Ending the call there would truncate a file mid-flight, and the recipient
    // would have no way to tell that from a network drop.
    let mut leaving: Option<Ended> = None;
    // False once the keyboard channel has closed for good.
    let mut keyboard_open = true;
    // True once the reader task has ended and we chose to stay for a direct
    // transfer. Guards the branch, since polling a finished handle panics.
    let mut peer_gone = false;
    // A transfer running outside Tor lives in its own task: it owns the file
    // and the socket, and reports back through the channel.
    let mut direct_task: Option<tokio::task::JoinHandle<()>> = None;
    let (direct_done_tx, mut direct_done) = mpsc::channel::<DirectDone>(1);

    let ended = loop {
        tokio::select! {
            // Ordered, not random, and the order is load-bearing twice over.
            //
            // The keyboard comes first so a `/bye` typed during a transfer is
            // seen at once rather than after the file.
            //
            // The inbox comes before the reader task's completion, because a
            // peer that hangs up immediately after the last frame makes both
            // ready at the same moment. Taking the hang-up first would drop
            // whatever is still queued — including the `FileDone` that turns a
            // pile of chunks into a file. Draining first is correct: `recv`
            // yields `None` once the queue is empty *and* the sender is gone, at
            // which point this arm switches off and the hang-up is taken.
            //
            // The pump is last: it runs on whatever is left over.
            biased;

            // Guarded so that a channel which has run dry — `recv` returning
            // `None` for ever — cannot spin the loop.
            typed = lines.recv(), if keyboard_open => {
                let Some(line) = typed else {
                    keyboard_open = false;
                    if !busy(&sending, &receiving, &direct_task) { break Ended::InputClosed }
                    leaving = Some(Ended::InputClosed);
                    continue;
                };
                // A message carrying files is not a command and never was one:
                // it goes out as a Post, with the files where they were put.
                let line = match line {
                    crate::ui::Typed::Post { parts, direct } => {
                        match post(parts, direct, &mut offered, &outbox, screen).await {
                            Ok(()) => {}
                            Err(e) => screen.error(format!("{e:#}")),
                        }
                        continue;
                    }
                    crate::ui::Typed::Line(s) => s,
                };
                match classify(&line) {
                    Typed::Nothing => continue,
                    // `/bye` goes back to listening, `/quit` leaves the program.
                    // Both wait for a file rather than truncating it, and both
                    // give up waiting if asked twice.
                    Typed::HangUp(how) => {
                        if !busy(&sending, &receiving, &direct_task) || leaving.is_some() {
                            break how;
                        }
                        screen.system(
                            "-- hanging up when the file is done; type it again to leave now --",
                        );
                        leaving = Some(how);
                    }
                    // Anything else starting with '/' stays here. Letting it
                    // through would send `/add alice <address>` — a contact's
                    // address — straight to whoever is on the other end.
                    Typed::UnknownCommand(verb) => screen.error(format!(
                        "{verb} is not available during a call — /bye first. \
                         (start a line with // to send a literal slash)"
                    )),
                    Typed::Send(path, route) => {
                        if let Err(e) =
                            start_sending(&path, route, &mut offered, &outbox, screen).await
                        {
                            screen.error(format!("{e:#}"));
                        }
                    }
                    Typed::Accept(which) => {
                        take_everything = which == Which::All;
                        if let Err(e) = accept(
                            incoming_dir,
                            &mut pending,
                            which,
                            &mut receiving,
                            &mut direct_task,
                            &direct_done_tx,
                            &outbox,
                            screen,
                        )
                        .await
                        {
                            screen.error(format!("{e:#}"));
                        }
                    }
                    Typed::Refuse(Which::All) => {
                        take_everything = false;
                        if pending.is_empty() {
                            screen.error("nothing to refuse");
                        }
                        for o in std::mem::take(&mut pending) {
                            screen.system(format!("refused {:?}", o.offer.name));
                            if outbox
                                .send(Message::FileReject { hash: o.offer.hash })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                    Typed::Refuse(which) => match take_pending(&mut pending, which) {
                        Ok(o) => {
                            screen.system(format!("refused {:?}", o.offer.name));
                            if outbox
                                .send(Message::FileReject { hash: o.offer.hash })
                                .await
                                .is_err()
                            {
                                break Ended::PeerHungUp;
                            }
                        }
                        Err(e) => screen.error(format!("{e:#}")),
                    },
                    Typed::Message(text) => {
                        if text.len() > MAX_TEXT {
                            screen.error(format!(
                                "line dropped: {} bytes, the limit is {MAX_TEXT}",
                                text.len()
                            ));
                            continue;
                        }
                        // Echo our own line: without it the conversation is
                        // one-sided on screen, and there is no way to tell a
                        // sent message from a swallowed one.
                        screen.say(Kind::Mine, format!("you> {text}"));
                        if outbox.send(Message::Text(text)).await.is_err() {
                            break Ended::PeerHungUp;
                        }
                    }
                }
            }

            // A transfer that ran outside Tor has finished, one way or another.
            // Before the inbox, so a peer hanging up straight after cannot take
            // the outcome down with it.
            Some(done) = direct_done.recv() => {
                direct_task = None;
                match done {
                    DirectDone::Sent(name) => screen.system(format!("-- sent {name} directly --")),
                    DirectDone::Received(offer) => {
                        match files::finish(incoming_dir, &offer) {
                            Ok(path) => screen.system(format!("-- received {} --", path.display())),
                            Err(e) => screen.error(format!("{e:#}")),
                        }
                    }
                    // The partial stays on disk, so offering the same file
                    // again over Tor picks up where this stopped.
                    DirectDone::Failed(why) => {
                        screen.error(format!("-- the direct link failed: {why} --"));
                        screen.system("   the part already received is kept; offer it again to resume over Tor");
                    }
                }
            }

            Some(msg) = inbox.recv() => {
                let outcome = handle(
                    msg, peer, incoming_dir,
                    &mut pending, &mut next_number, &mut next_batch,
                    &mut receiving, &mut sending, &mut offered,
                    &mut direct_task, &direct_done_tx,
                    &outbox, screen,
                ).await;
                match outcome {
                    // A protocol fault ends the conversation rather than being
                    // absorbed: past this point we no longer know what the peer
                    // thinks the stream contains.
                    Err(e) => {
                        screen.error(format!("{e:#}"));
                        break Ended::PeerHungUp;
                    }
                    Ok(false) => break Ended::PeerHungUp,
                    Ok(true) => {}
                }
            }

            // The peer's side of the conversation ended, cleanly or not. Only
            // reached once the inbox above has been drained.
            //
            // Guarded, because it can now be taken without leaving the loop: a
            // completed `JoinHandle` polled twice panics.
            outcome = &mut reading, if !peer_gone => {
                outcome.map_err(|e| anyhow::anyhow!("the reader task panicked: {e}"))??;
                // A direct transfer runs on its own socket, so the peer closing
                // the *Tor* stream says nothing about it — and the sending side
                // hangs up as soon as its own half is done, which is normal.
                // Leaving here would drop the file on the floor with every byte
                // already on disk.
                if direct_task.as_ref().is_some_and(|t| !t.is_finished()) {
                    peer_gone = true;
                    leaving.get_or_insert(Ended::PeerHungUp);
                } else {
                    break Ended::PeerHungUp;
                }
            }

            // Last, and only while a file is going out. `reserve` is ready when
            // the outbox has room, so the disk is read exactly as fast as the
            // circuit drains — no timer, no buffer growing behind our back.
            Ok(permit) = outbox.reserve(), if sending.is_some() => {
                match pump(&mut sending, screen) {
                    Ok(Some(msg)) => permit.send(msg),
                    Ok(None) => {}
                    Err(e) => {
                        screen.error(format!("{e:#}"));
                        sending = None;
                    }
                }
            }
        }

        // `/accept all` is a standing instruction, so a transfer that just
        // finished is what starts the next one. Done here rather than inside
        // the completion handlers, because there are three of them — a Tor
        // FileDone, a direct one, and a direct failure — and all three mean the
        // same thing to the queue.
        if take_everything
            && !busy(&sending, &receiving, &direct_task)
            && !pending.is_empty()
            && let Err(e) = accept(
                incoming_dir,
                &mut pending,
                Which::Newest,
                &mut receiving,
                &mut direct_task,
                &direct_done_tx,
                &outbox,
                screen,
            )
            .await
        {
            screen.error(format!("{e:#}"));
            take_everything = false;
        }
        if pending.is_empty() {
            take_everything = false;
        }

        // The bar is the status line, so something has to put the status back
        // when the transfer ends — otherwise it sits frozen at 100% for the
        // rest of the call. One place, because the four ways a transfer can
        // finish all mean the same thing here.
        let running = busy(&sending, &receiving, &direct_task);
        if was_running && !running {
            screen.status(format!("in a call with {peer}"));
        }
        was_running = running;

        // The transfer that was holding the call open has finished.
        if let Some(end) = leaving
            && !busy(&sending, &receiving, &direct_task)
        {
            break end;
        }
    };

    // Order matters. The reader task holds the inbox sender, and the writer
    // outlives its queue only while a sender exists. Stop the reader first, then
    // drop ours, or `writing.await` waits on a channel nothing will close.
    reading.abort();
    drop(outbox);
    match writing.await {
        Ok(Ok(())) => {}
        // A write failing as the peer hangs up is the normal race, not a fault.
        Ok(Err(e)) if ended == Ended::PeerHungUp => tracing::debug!("write at hang-up: {e:#}"),
        Ok(Err(e)) => bail!(e),
        Err(e) => bail!("the writer task panicked: {e}"),
    }

    if let Some(r) = receiving {
        screen.system(format!(
            "-- {:?} interrupted at {} of {}; offer it again to resume --",
            r.offer.name,
            files::human(r.written),
            files::human(r.offer.size)
        ));
    }
    Ok(ended)
}

/// Is there file business we should not walk out on?
///
/// An offer the peer has not answered yet counts, because the usual reason to
/// type `/send` then `/bye` is "here, take this, I'm off" — leaving instantly
/// would cancel the very thing that was just offered. A peer who never answers
/// would hold the call open, so a second `/bye` leaves regardless.
fn busy(
    sending: &Option<Sending>,
    receiving: &Option<Receiving>,
    direct_task: &Option<tokio::task::JoinHandle<()>>,
) -> bool {
    sending.is_some()
        || receiving.is_some()
        // A direct transfer holds no `Sending`/`Receiving` — the task owns the
        // file — so without this a `/bye` mid-transfer would cut it.
        || direct_task.as_ref().is_some_and(|t| !t.is_finished())
}

/// Act on one frame from the peer. `false` means the conversation is over.
#[allow(clippy::too_many_arguments)]
async fn handle(
    msg: Message,
    peer: &str,
    incoming_dir: &Path,
    pending: &mut Vec<Offered>,
    next_number: &mut usize,
    next_batch: &mut usize,
    receiving: &mut Option<Receiving>,
    sending: &mut Option<Sending>,
    offered: &mut Vec<Outgoing>,
    direct_task: &mut Option<tokio::task::JoinHandle<()>>,
    direct_done: &mpsc::Sender<DirectDone>,
    outbox: &mpsc::Sender<Message>,
    screen: &Screen,
) -> Result<bool> {
    match msg {
        Message::Text(body) => {
            // The peer's raw bytes must not reach the terminal: see
            // `files::sanitize_for_display` for why a chat line is exactly as
            // dangerous as a filename here.
            let body = files::sanitize_for_display(&body);
            screen.say(Kind::Theirs, format!("{peer}> {body}"));
        }
        Message::Ping => {
            if outbox.send(Message::Pong).await.is_err() {
                return Ok(false);
            }
        }
        Message::Pong => {}

        // The old one-file-per-conversation offer. Kept so a peer running the
        // previous version is still understood: it is the same thing as a Post
        // carrying exactly one file and no text.
        Message::FileOffer { name, size, hash, direct } => {
            screen.system(format!("-- {peer} offers a file --"));
            *next_batch += 1;
            *next_number += 1;
            take_offer(
                proto::FileRef { name, size, hash },
                direct, *next_number, *next_batch, peer, incoming_dir, pending, screen,
            )?;
        }

        Message::Post { pieces, direct } => {
            // Rebuilt into one line so the sentence and its files read as what
            // they are — one message — instead of arriving as unrelated events.
            let lead = format!("{peer}> ");
            let mut shown = lead.clone();
            let mut files = Vec::new();
            let mut chips = Vec::new();
            *next_batch += 1;
            for piece in pieces {
                match piece {
                    proto::Piece::Text(t) => {
                        // Straight from the network to a terminal: same trust
                        // boundary as a filename, same treatment.
                        shown.push_str(&files::sanitize_for_display(&t));
                    }
                    proto::Piece::File(f) => {
                        let name = files::safe_name(&f.name)?;
                        if !shown.ends_with(' ') && shown.len() > lead.len() {
                            shown.push(' ');
                        }
                        *next_number += 1;
                        // Char offsets, because that is what a mouse click
                        // resolves to — bytes would land mid-character on any
                        // accented name.
                        let start = shown.chars().count();
                        shown.push_str(&format!("[{name}]"));
                        chips.push((start, shown.chars().count(), *next_number));
                        files.push((*next_number, proto::FileRef { name, ..f }));
                    }
                }
            }
            screen.say_with_files(Kind::Theirs, shown.trim_end().to_owned(), chips);

            for (number, f) in files {
                take_offer(f, direct, number, *next_batch, peer, incoming_dir, pending, screen)?;
            }
            if !pending.is_empty() {
                screen.system(format!(
                    "   click a file to take it — or /accept to take {}, /refuse to decline{}",
                    if pending.len() == 1 { "it" } else { "them" },
                    if pending.len() == 1 { "" } else { ", /accept all for every one" },
                ));
            }
        }

        Message::FileAccept { hash, offset, direct } => {
            // Which file, of those we put in a message. The hash says so, so no
            // ordering has to be agreed between the two sides.
            let Some(i) = offered.iter().position(|o| o.hash == hash) else {
                bail!("{peer} accepted a file we never offered");
            };
            if sending.is_some() {
                // One transfer at a time on the wire, even when a message
                // carried several. They stay queued, not lost.
                bail!("{peer} accepted a second file while one is still going");
            }
            let out = offered.remove(i);
            if offset > out.size {
                bail!("{peer} asked to resume past the end of the file");
            }
            let file = std::fs::File::open(&out.path)
                .with_context(|| format!("reopening {}", out.path.display()))?;
            *sending = Some(Sending {
                file,
                name: out.name.clone(),
                accepted: false,
                sent: 0,
                size: out.size,
                progress: Progress::new("sending", out.name.clone(), out.size),
                path: out.path.clone(),
                route: out.route,
            });
            let s = sending.as_mut().expect("just set");
            if let Some(d) = direct {
                if s.route != Route::Direct {
                    bail!("{peer} answered with a direct link we never asked for");
                }
                screen.system(format!("-- {peer} agreed to a direct link; connecting --"));
                match crate::transport::direct::dial(&d.candidates, d.fingerprint).await {
                    Ok(stream) => {
                        // The task takes over the file from here. `sending` is
                        // cleared so the chunk pump stays out of it — two
                        // writers on one transfer would interleave.
                        let s = sending.take().expect("checked just above");
                        let done = direct_done.clone();
                        let sc = screen.clone();
                        *direct_task = Some(tokio::spawn(async move {
                            let outcome = match push_direct(
                                s.path, offset, stream,
                                Progress::new("sending", s.name.clone(), s.size),
                                sc,
                            )
                            .await
                            {
                                Ok(()) => DirectDone::Sent(s.name),
                                Err(e) => DirectDone::Failed(format!("{e:#}")),
                            };
                            let _ = done.send(outcome).await;
                        }));
                        return Ok(true);
                    }
                    Err(e) => {
                        // They are sitting on a listening socket waiting for a
                        // connection that is not coming, and cannot tell that
                        // from us being slow. Say so, then fall through to the
                        // ordinary chunk path below.
                        screen.system(format!("-- could not reach them directly ({e:#}); using Tor --"));
                        if outbox.send(Message::DirectFailed).await.is_err() {
                            return Ok(false);
                        }
                    }
                }
            }
            let Some(s) = sending.as_mut() else {
                bail!("the transfer went away while answering {peer}");
            };
            std::io::Seek::seek(&mut s.file, std::io::SeekFrom::Start(offset))
                .context("seeking to the resume point")?;
            s.accepted = true;
            s.sent = offset;
            screen.system(match offset {
                0 => format!("-- sending {:?} --", s.name),
                _ => format!("-- resuming {:?} from {} --", s.name, files::human(offset)),
            });
        }

        Message::FileReject { hash } => {
            match offered.iter().position(|o| o.hash == hash) {
                Some(i) => {
                    let out = offered.remove(i);
                    screen.system(format!("-- {peer} declined {:?} --", out.name));
                }
                // Declining what is already going out: stop it.
                None => match sending.take() {
                    Some(s) => screen.system(format!("-- {peer} declined {:?} --", s.name)),
                    None => screen.system(format!("-- {peer} declined a file --")),
                },
            }
        }

        Message::DirectFailed => {
            // We are sitting on a listening socket for a connection that is not
            // coming. Stop waiting, and reopen the partial for chunks — the
            // file the task would have written is exactly the one we resume.
            if let Some(task) = direct_task.take() {
                task.abort();
            }
            screen.system(format!("-- {peer} could not reach us directly; using Tor --"));
        }

        Message::FileChunk(data) => {
            let Some(r) = receiving.as_mut() else {
                bail!("{peer} sent file data we did not accept");
            };
            let room = r.offer.size - r.written;
            if data.len() as u64 > room {
                bail!(
                    "{peer} sent more data than the {} offered",
                    files::human(r.offer.size)
                );
            }
            std::io::Write::write_all(&mut r.file, &data).context("writing to the partial file")?;
            r.written += data.len() as u64;
            r.progress.show(r.written, screen);
        }

        Message::FileDone => {
            let Some(r) = receiving.take() else {
                bail!("{peer} ended a transfer that was not running");
            };
            // Flush before hashing: the bytes have to be on disk to be read back.
            std::io::Write::flush(&mut { r.file }).context("flushing the partial file")?;
            match files::finish(incoming_dir, &r.offer) {
                Ok(path) => screen.system(format!("-- received {} --", path.display())),
                Err(e) => screen.error(format!("{e:#}")),
            }
        }
    }
    Ok(true)
}


/// Queue one offered file, after checking it is one we would take.
#[allow(clippy::too_many_arguments)]
fn take_offer(
    f: proto::FileRef,
    direct: bool,
    number: usize,
    batch: usize,
    peer: &str,
    incoming_dir: &Path,
    pending: &mut Vec<Offered>,
    screen: &Screen,
) -> Result<()> {
    let name = files::safe_name(&f.name)?;
    if f.size == 0 || f.size > files::MAX_FILE {
        bail!("{peer} offered a file of {} bytes, which is not a size we take", f.size);
    }
    let offer = Offer { name, size: f.size, hash: f.hash };
    let resume = files::resume_offset(incoming_dir, &offer.hash, offer.size);

    screen.system(format!(
        "   [{number}] {:?} ({}){}",
        offer.name,
        files::human(offer.size),
        match resume {
            0 => String::new(),
            r => format!(" — {} already here, /accept resumes", files::human(r)),
        }
    ));
    if direct {
        // Said plainly, because agreeing is what exposes them: a direct link
        // hands the peer our IP and shows both ISPs these two are exchanging
        // data. The number above is what turns that into a per-file choice.
        screen.system("       asked to go outside Tor — faster, shows them your IP");
    }
    pending.push(Offered { number, batch, offer, direct });
    Ok(())
}

/// Send a message, with the files the operator put inside it.
///
/// Nothing moves yet: this is the offer. Each file becomes something the far
/// side answers one by one, because each one lands on their disk.
async fn post(
    parts: Vec<crate::ui::Part>,
    direct: bool,
    offered: &mut Vec<Outgoing>,
    outbox: &mpsc::Sender<Message>,
    screen: &Screen,
) -> Result<()> {
    let mut pieces = Vec::new();
    let mut shown = String::new();
    let mut fresh = Vec::new();

    for part in parts {
        match part {
            crate::ui::Part::Text(t) => {
                shown.push_str(&t);
                pieces.push(proto::Piece::Text(t));
            }
            crate::ui::Part::File(path) => {
                // Reading and hashing happens here rather than at accept time:
                // a file that cannot be read must fail before the message goes,
                // not after the other person has said yes to it.
                let offer = files::describe(&path)?;
                if !shown.is_empty() && !shown.ends_with(' ') {
                    shown.push(' ');
                }
                shown.push_str(&format!("[{}]", offer.name));
                pieces.push(proto::Piece::File(proto::FileRef {
                    name: offer.name.clone(),
                    size: offer.size,
                    hash: offer.hash,
                }));
                fresh.push(Outgoing {
                    hash: offer.hash,
                    path,
                    name: offer.name,
                    size: offer.size,
                    route: if direct { Route::Direct } else { Route::Tor },
                });
            }
        }
    }
    if pieces.is_empty() {
        return Ok(());
    }

    screen.say(Kind::Mine, format!("you> {}", shown.trim()));
    if !fresh.is_empty() {
        screen.system(format!(
            "-- offered {} file{}; waiting for them to accept --",
            fresh.len(),
            if fresh.len() == 1 { "" } else { "s" }
        ));
    }
    offered.extend(fresh);
    outbox
        .send(Message::Post { pieces, direct })
        .await
        .map_err(|_| anyhow::anyhow!("the conversation ended"))
}

/// Offer a file, after checking we can actually read it.
async fn start_sending(
    path: &Path,
    route: Route,
    offered: &mut Vec<Outgoing>,
    outbox: &mpsc::Sender<Message>,
    screen: &Screen,
) -> Result<()> {
    let offer = files::describe(path)?;
    // Registered exactly where a file put inside a message is registered.
    // Keeping two lists — one for `/send`, one for a message — is what made a
    // `FileAccept` land on "a file we never offered" depending on which verb
    // had been used.
    if offered.iter().any(|o| o.hash == offer.hash) {
        bail!("that file is already offered and waiting for an answer");
    }

    screen.system(format!(
        "-- offered {:?} ({}); waiting for them to accept --",
        offer.name,
        files::human(offer.size)
    ));
    if route == Route::Direct {
        // Said on our side too, not just theirs: asking for a direct link
        // exposes them, and the person doing the asking should see that
        // spelled out rather than only the person answering.
        screen.system("   asked for a direct link — they decide, and it shows them your IP");
    }
    offered.push(Outgoing {
        hash: offer.hash,
        path: path.to_path_buf(),
        name: offer.name.clone(),
        size: offer.size,
        route,
    });
    outbox
        .send(Message::FileOffer {
            name: offer.name,
            size: offer.size,
            hash: offer.hash,
            direct: route == Route::Direct,
        })
        .await
        .map_err(|_| anyhow::anyhow!("the conversation ended"))
}

/// Send a whole file over an open direct stream, from `offset`.
///
/// Runs in its own task: it owns the file and the socket for as long as the
/// transfer lasts, so the conversation loop keeps answering the keyboard at
/// full speed underneath.
async fn push_direct(
    path: PathBuf,
    offset: u64,
    mut stream: crate::transport::direct::Link<quinn::SendStream>,
    mut progress: Progress,
    screen: Screen,
) -> Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

    let mut file = tokio::fs::File::open(&path)
        .await
        .with_context(|| format!("reopening {}", path.display()))?;
    file.seek(std::io::SeekFrom::Start(offset))
        .await
        .context("seeking to the resume point")?;

    let mut buf = vec![0u8; MAX_CHUNK];
    let mut sent = offset;
    loop {
        let n = file.read(&mut buf).await.context("reading the file")?;
        if n == 0 {
            break;
        }
        stream
            .write_all(&buf[..n])
            .await
            .context("writing to the direct link")?;
        sent += n as u64;
        progress.show(sent, &screen);
    }
    // Closes the stream cleanly, which is what tells the far side it has it all.
    stream.finish().context("closing the direct link")?;
    // The peer needs the connection to stay up long enough to read what is
    // still in flight; dropping the endpoint here would reset it.
    stream.stopped().await.ok();
    Ok(())
}

/// Read a whole file off a direct stream into its partial, then hand it back
/// for verification.
async fn pull_direct(
    listener: crate::transport::direct::Listener,
    incoming_dir: PathBuf,
    offer: Offer,
    mut progress: Progress,
    screen: Screen,
) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let mut stream = listener.accept().await?;
    let partial = files::partial_path(&incoming_dir, &offer.hash);
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&partial)
        .await
        .with_context(|| format!("opening {}", partial.display()))?;

    let mut written = 0u64;
    let mut buf = vec![0u8; MAX_CHUNK];
    loop {
        let n = stream
            .read(&mut buf)
            .await
            .context("reading the direct link")?
            .unwrap_or(0);
        if n == 0 {
            break;
        }
        written += n as u64;
        progress.show(written, &screen);
        if written > offer.size {
            bail!("the peer sent more than the {} offered", files::human(offer.size));
        }
        file.write_all(&buf[..n])
            .await
            .context("writing to the partial file")?;
    }
    file.flush().await.context("flushing the partial file")?;
    Ok(())
}

/// Take the pending offer: open the partial, and tell the peer where to start.
///
/// `wanted_direct` is what the offer asked for. Agreeing means opening a port
/// and naming our addresses, so this is the one place where the recipient's
/// `/accept` turns into an exposure — and the only place it can, because the
/// sender has no way to reach us otherwise.
#[allow(clippy::too_many_arguments)]
async fn accept(
    incoming_dir: &Path,
    pending: &mut Vec<Offered>,
    which: Which,
    receiving: &mut Option<Receiving>,
    direct_task: &mut Option<tokio::task::JoinHandle<()>>,
    direct_done: &mpsc::Sender<DirectDone>,
    outbox: &mpsc::Sender<Message>,
    screen: &Screen,
) -> Result<()> {
    if receiving.is_some() || direct_task.as_ref().is_some_and(|t| !t.is_finished()) {
        bail!("one file at a time — this one waits until the current transfer ends");
    }
    let taken = take_pending(pending, which)?;
    let (offer, wanted_direct) = (taken.offer, taken.direct);
    std::fs::create_dir_all(incoming_dir)
        .with_context(|| format!("creating {}", incoming_dir.display()))?;

    let offset = files::resume_offset(incoming_dir, &offer.hash, offer.size);

    if wanted_direct {
        // A resumed direct transfer would have to tell the sender where to
        // start *and* stream from there; the stream carries no offsets, so the
        // two would have to agree out of band. Refusing the route rather than
        // the file keeps that out of the protocol: the partial is still there,
        // and Tor picks it up where it stopped.
        if offset > 0 {
            screen.system("-- resuming, so this one goes over Tor --");
        } else {
            match crate::transport::direct::listen() {
                Ok(listener) => {
                    let direct = proto::Direct {
                        candidates: listener.candidates.clone(),
                        fingerprint: listener.fingerprint,
                    };
                    screen.system(format!("-- taking {:?} over a direct link --", offer.name));
                    let done = direct_done.clone();
                    let dir = incoming_dir.to_path_buf();
                    let mine = offer.clone();
                    let sc = screen.clone();
                    let bar = Progress::new("receiving", mine.name.clone(), mine.size);
                    *direct_task = Some(tokio::spawn(async move {
                        let outcome = match pull_direct(listener, dir, mine.clone(), bar, sc).await {
                            Ok(()) => DirectDone::Received(Box::new(mine)),
                            Err(e) => DirectDone::Failed(format!("{e:#}")),
                        };
                        let _ = done.send(outcome).await;
                    }));
                    return outbox
                        .send(Message::FileAccept {
                            hash: offer.hash,
                            offset,
                            direct: Some(direct),
                        })
                        .await
                        .map_err(|_| anyhow::anyhow!("the conversation ended"));
                }
                // Not fatal: Tor is underneath, and saying why beats a silent
                // downgrade on the one path whose whole point is being chosen.
                Err(e) => screen.system(format!("-- no direct link ({e:#}); using Tor --")),
            }
        }
    }

    let partial = files::partial_path(incoming_dir, &offer.hash);
    // Append rather than truncate: `offset` is exactly what is already there,
    // so the peer's first chunk continues the file.
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&partial)
        .with_context(|| format!("opening {}", partial.display()))?;

    screen.system(format!("-- taking {:?} --", offer.name));
    let hash = offer.hash;
    let bar = Progress::new("receiving", offer.name.clone(), offer.size);
    *receiving = Some(Receiving {
        offer,
        file,
        written: offset,
        progress: bar,
    });
    outbox
        .send(Message::FileAccept { hash, offset, direct: None })
        .await
        .map_err(|_| anyhow::anyhow!("the conversation ended"))
}

/// The next chunk to put on the wire, if a transfer is running and not finished.
///
/// Returns `None` when there is nothing to send *right now* — either the peer
/// has not accepted yet, or the last chunk has gone out and the state has
/// already been cleared.
fn pump(sending: &mut Option<Sending>, screen: &Screen) -> Result<Option<Message>> {
    let Some(s) = sending.as_mut() else {
        return Ok(None);
    };
    if !s.accepted {
        return Ok(None);
    }
    if s.sent >= s.size {
        let name = s.name.clone();
        *sending = None;
        screen.system(format!("-- sent {name} --"));
        return Ok(Some(Message::FileDone));
    }

    let want = MAX_CHUNK.min((s.size - s.sent) as usize);
    let mut buf = vec![0u8; want];
    let mut filled = 0;
    while filled < want {
        let n = std::io::Read::read(&mut s.file, &mut buf[filled..])
            .context("reading the file being sent")?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    if filled == 0 {
        // The file shrank under us. Ending the transfer is honest; the hash on
        // the far side would fail anyway.
        bail!("{:?} ended sooner than its size said", s.name);
    }
    buf.truncate(filled);
    s.sent += filled as u64;
    s.progress.show(s.sent, screen);
    Ok(Some(Message::FileChunk(buf)))
}

/// What a line typed during a call turns out to be.
#[derive(Debug, PartialEq, Eq)]
enum Typed {
    /// Blank; ignore it.
    Nothing,
    /// `/bye` or `/quit`, carrying which one it was.
    HangUp(Ended),
    /// `/send <path>`, or `/send --direct <path>`.
    Send(PathBuf, Route),
    /// `/accept`, and which file: the oldest, a numbered one, or every one.
    Accept(Which),
    /// `/refuse`, likewise.
    Refuse(Which),
    /// Any other `/word`. Held back rather than sent.
    UnknownCommand(String),
    /// Something to say, with any `//` escape already unwrapped.
    Message(String),
}

/// Decide what a typed line is.
///
/// A leading `/` means "command" during a call, and the set is closed: hang up,
/// the three file verbs, or refuse. Nothing beginning with `/` is ever sent by
/// accident, because the accident sends secrets. `//` at the start escapes it,
/// for the rare line that genuinely opens with a slash.
fn classify(line: &str) -> Typed {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Typed::Nothing;
    }
    if let Some(rest) = trimmed.strip_prefix("//") {
        return Typed::Message(format!("/{rest}"));
    }
    if !trimmed.starts_with('/') {
        return Typed::Message(line.to_owned());
    }

    let (verb, rest) = match trimmed.split_once(char::is_whitespace) {
        Some((v, r)) => (v, r.trim()),
        None => (trimmed, ""),
    };
    match verb {
        "/bye" => Typed::HangUp(Ended::WeHungUp),
        // Typing `/quit` mid-call used to be refused, which meant `/bye` then
        // `/quit`: two commands for one intention nobody splits in their head.
        "/quit" => Typed::HangUp(Ended::Quit),
        // A message can carry several files, so the verbs take an argument.
        // See [`Which`] for what no argument means.
        "/accept" => Typed::Accept(Which::parse(rest)),
        "/refuse" => Typed::Refuse(Which::parse(rest)),
        // The whole remainder, not the first word: paths have spaces in them,
        // and quoting rules would be one more thing to explain.
        // The whole remainder is the path, so `--direct` is only a flag when it
        // is the first word — a file actually called `--direct` still sends.
        "/send" if !rest.is_empty() => match rest.strip_prefix("--direct") {
            Some(path) if path.starts_with(char::is_whitespace) => {
                Typed::Send(PathBuf::from(expand_home(path.trim())), Route::Direct)
            }
            _ => Typed::Send(PathBuf::from(expand_home(rest)), Route::Tor),
        },
        _ => Typed::UnknownCommand(verb.to_owned()),
    }
}

/// Expand a leading `~/`, which is the shell's job and there is no shell here.
///
/// ponytail: only the leading form, not `~user`. Nobody types the second one at
/// a chat prompt.
fn expand_home(path: &str) -> String {
    match path.strip_prefix("~/") {
        Some(rest) => match std::env::var_os("HOME") {
            Some(home) => Path::new(&home).join(rest).to_string_lossy().into_owned(),
            None => path.to_owned(),
        },
        None => path.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::compat::{TokioAsyncReadCompatExt as _, TokioAsyncWriteCompatExt as _};

    /// A plain typed line, which is what every command is.
    fn line(s: &str) -> crate::ui::Typed {
        crate::ui::Typed::Line(s.to_owned())
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("murmure-chat-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The one that matters: a command typed during a call must never travel.
    #[test]
    fn commands_typed_during_a_call_are_never_sent() {
        assert_eq!(classify("/bye"), Typed::HangUp(Ended::WeHungUp));
        // `/quit` hangs up *and* leaves, rather than being refused.
        assert_eq!(classify("/quit"), Typed::HangUp(Ended::Quit));
        assert_eq!(
            classify("/add alice haticv.onion"),
            Typed::UnknownCommand("/add".into())
        );
        assert_eq!(classify("/call bob"), Typed::UnknownCommand("/call".into()));
        assert_eq!(classify("  "), Typed::Nothing);
        // `/send` with nothing after it is a mistake, not a message.
        assert_eq!(classify("/send"), Typed::UnknownCommand("/send".into()));
    }

    #[test]
    fn the_file_verbs_are_recognised() {
        assert_eq!(classify("/accept"), Typed::Accept(Which::Newest));
        assert_eq!(classify("/accept 2"), Typed::Accept(Which::Numbered(2)));
        assert_eq!(classify("/accept all"), Typed::Accept(Which::All));
        assert_eq!(classify("/refuse all"), Typed::Refuse(Which::All));
        // Anything that is not a number and not "all" falls back to the oldest
        // rather than erroring: the operator meant `/accept`.
        assert_eq!(classify("/accept please"), Typed::Accept(Which::Newest));
        assert_eq!(classify("/refuse"), Typed::Refuse(Which::Newest));
        assert_eq!(
            classify("/send /tmp/rapport.pdf"),
            Typed::Send(PathBuf::from("/tmp/rapport.pdf"), Route::Tor)
        );
        // A path with spaces survives, without quoting rules to learn.
        assert_eq!(
            classify("/send /tmp/mes documents/le rapport.pdf"),
            Typed::Send(PathBuf::from("/tmp/mes documents/le rapport.pdf"), Route::Tor)
        );
    }

    /// Leaving Tor is never the default, so it takes a word to ask for.
    #[test]
    fn only_an_explicit_flag_leaves_tor() {
        assert_eq!(
            classify("/send --direct /tmp/gros.pdf"),
            Typed::Send(PathBuf::from("/tmp/gros.pdf"), Route::Direct)
        );
        // The flag is only a flag as the first word: everything after `/send`
        // is a path, so a file that happens to be named this still sends.
        assert_eq!(
            classify("/send /tmp/--direct"),
            Typed::Send(PathBuf::from("/tmp/--direct"), Route::Tor)
        );
        assert_eq!(
            classify("/send --directory/rapport.pdf"),
            Typed::Send(PathBuf::from("--directory/rapport.pdf"), Route::Tor)
        );
        // A flag with nothing after it is not a transfer.
        assert_eq!(
            classify("/send --direct"),
            Typed::Send(PathBuf::from("--direct"), Route::Tor)
        );
    }

    #[test]
    fn a_double_slash_sends_a_literal_slash() {
        assert_eq!(classify("//bye"), Typed::Message("/bye".into()));
        assert_eq!(
            classify("//usr/bin is where it lives"),
            Typed::Message("/usr/bin is where it lives".into())
        );
    }

    #[test]
    fn ordinary_lines_are_untouched() {
        assert_eq!(classify("bonjour"), Typed::Message("bonjour".into()));
        assert_eq!(
            classify("et voilà 3/4 du chemin"),
            Typed::Message("et voilà 3/4 du chemin".into())
        );
    }

    /// Both sides of a conversation, over an in-memory duplex: what one types
    /// is what the other reads.
    #[test]
    fn a_typed_line_reaches_the_other_side() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let dir = scratch("typed");
            let (alice, bob) = tokio::io::duplex(4096);
            let (alice_r, alice_w) = tokio::io::split(alice);
            let (bob_r, bob_w) = tokio::io::split(bob);

            let (tx, mut rx) = mpsc::channel::<crate::ui::Typed>(4);
            tx.send(line("bonjour")).await.unwrap();
            tx.send(line("/bye")).await.unwrap();
            let (screen, _updates) = crate::ui::channel();

            let talking = tokio::spawn(async move {
                run(
                    alice_r.compat(),
                    alice_w.compat_write(),
                    "them",
                    &dir,
                    &mut rx,
                    &screen,
                )
                .await
            });

            // Bob is hand-rolled here rather than another `run`, so he has to
            // answer the handshake himself — which also makes this the test
            // that two matching versions agree at all.
            let mut bob_r = bob_r.compat();
            let mut bob_w = bob_w.compat_write();
            proto::handshake(&mut bob_r, &mut bob_w).await.unwrap();

            let got = proto::read_frame(&mut bob_r).await.unwrap();
            assert_eq!(got, Some(Message::Text("bonjour".into())));

            assert_eq!(talking.await.unwrap().unwrap(), Ended::WeHungUp);
        });
    }

    /// Drive both ends of a real conversation over one duplex, so a transfer
    /// goes through the same loop, the same framing and the same disk paths it
    /// would over a circuit.
    ///
    /// The recipient types `answer` when the offer appears on screen, not
    /// before. That ordering is not a convenience: the loop answers the keyboard
    /// ahead of the wire, so a pre-typed `/accept` would be refused for an offer
    /// that had not arrived yet — which is also what would happen to a person
    /// typing ahead.
    ///
    /// `already_here` pre-places that many bytes of the payload as a partial,
    /// which is what an interrupted transfer leaves behind and what the resume
    /// path picks up.
    fn transfer(
        tag: &str,
        payload: &[u8],
        answer: &str,
        already_here: usize,
        route: Route,
    ) -> (PathBuf, PathBuf) {
        let dir = scratch(tag);
        let (from, to) = (dir.join("out"), dir.join("in"));
        std::fs::create_dir_all(&from).unwrap();
        let source = from.join("rapport.pdf");
        std::fs::write(&source, payload).unwrap();

        if already_here > 0 {
            std::fs::create_dir_all(&to).unwrap();
            let hash = files::describe(&source).unwrap().hash;
            std::fs::write(files::partial_path(&to, &hash), &payload[..already_here]).unwrap();
        }

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            // Big enough that a full chunk and its frame header fit while the
            // far side is busy writing to disk.
            let (a, b) = tokio::io::duplex(256 * 1024);
            let (ar, aw) = tokio::io::split(a);
            let (br, bw) = tokio::io::split(b);

            let (a_tx, mut a_rx) = mpsc::channel::<crate::ui::Typed>(8);
            let (b_tx, mut b_rx) = mpsc::channel::<crate::ui::Typed>(8);
            let (a_screen, a_updates) = crate::ui::channel();
            let (b_screen, b_updates) = crate::ui::channel();

            let flag = match route {
                Route::Direct => "--direct ",
                Route::Tor => "",
            };
            a_tx.send(line(&format!("/send {flag}{}", source.display())))
                .await
                .unwrap();

            // Alice leaves once her side reports the file gone, or the peer
            // declined it.
            let watch_alice = tokio::spawn(react(a_updates, a_tx, &["-- sent ", "declined"], "/bye".to_owned()));
            // Bob answers the moment the offer is on screen.
            let watch_bob = tokio::spawn(react(b_updates, b_tx, &["offers"], answer.to_owned()));

            let to_b = to.clone();
            let bob = tokio::spawn(async move {
                run(br.compat(), bw.compat_write(), "alice", &to_b, &mut b_rx, &b_screen).await
            });
            let unused = dir.join("unused");
            let alice = tokio::spawn(async move {
                run(ar.compat(), aw.compat_write(), "bob", &unused, &mut a_rx, &a_screen).await
            });

            alice.await.unwrap().unwrap();
            bob.await.unwrap().unwrap();
            watch_alice.abort();
            watch_bob.abort();
        });

        (dir, to.join("rapport.pdf"))
    }

    /// Watch a screen and type `reply` the first time a line matches.
    async fn react(
        mut updates: mpsc::UnboundedReceiver<crate::ui::Update>,
        keyboard: mpsc::Sender<crate::ui::Typed>,
        triggers: &'static [&'static str],
        reply: String,
    ) {
        while let Some(update) = updates.recv().await {
            let crate::ui::Update::Line(entry) = update else {
                continue;
            };
            if triggers.iter().any(|t| entry.text().contains(t)) {
                let _ = keyboard.send(line(&reply)).await;
                return;
            }
        }
    }

    /// A file offered, accepted and received, byte for byte.
    ///
    /// Deliberately larger than one chunk: a transfer that fits in a single
    /// frame would never exercise the pump.
    #[test]
    fn a_file_offered_and_accepted_arrives_intact() {
        let payload: Vec<u8> = (0..MAX_CHUNK * 2 + 777).map(|i| (i % 251) as u8).collect();
        let (dir, landed) = transfer("transfer", &payload, "/accept", 0, Route::Tor);

        assert!(landed.exists(), "the file must be in the incoming directory");
        assert_eq!(std::fs::read(&landed).unwrap(), payload);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The whole v2 path, on two real conversations: `--direct` is asked for,
    /// the recipient agrees and opens a port, the bytes cross a QUIC link that
    /// never touches the Tor stream, and the hash still has to match at the end.
    #[test]
    fn a_direct_transfer_arrives_intact() {
        // Larger than anything the chunk pump would send in one frame, so a
        // file that arrived over Tor by mistake would not look the same.
        let payload: Vec<u8> = (0..MAX_CHUNK * 3 + 1234).map(|i| (i % 251) as u8).collect();
        let (dir, landed) = transfer("direct", &payload, "/accept", 0, Route::Direct);

        assert!(landed.exists(), "the file must land after a direct transfer");
        assert_eq!(std::fs::read(&landed).unwrap(), payload);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Refusing works the same whichever route was asked for — declining the
    /// file must not be harder because the sender wanted to go fast.
    #[test]
    fn a_direct_offer_can_still_be_refused() {
        let (dir, landed) = transfer("direct-refuse", b"jamais envoye", "/refuse", 0, Route::Direct);
        assert!(!landed.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A resumed transfer falls back to Tor: the direct stream carries no
    /// offsets, so the two sides would have to agree on one out of band.
    #[test]
    fn a_direct_offer_with_a_partial_on_disk_uses_tor() {
        let payload: Vec<u8> = (0..MAX_CHUNK + 500).map(|i| (i % 251) as u8).collect();
        let cut = payload.len() / 2;
        let (dir, landed) = transfer("direct-resume", &payload, "/accept", cut, Route::Direct);

        assert!(landed.exists(), "the resumed file must still land");
        assert_eq!(std::fs::read(&landed).unwrap(), payload);
        let _ = std::fs::remove_dir_all(&dir);
    }


    /// The shape the whole rework exists for: one message, a sentence, and two
    /// files sitting inside it — answered one at a time, by number.
    #[test]
    fn a_message_can_carry_several_files() {
        let dir = scratch("post");
        let (from, to) = (dir.join("out"), dir.join("in"));
        std::fs::create_dir_all(&from).unwrap();
        let one = from.join("photo1.png");
        let two = from.join("photo2.png");
        std::fs::write(&one, vec![1u8; 5000]).unwrap();
        std::fs::write(&two, vec![2u8; 7000]).unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let (a, b) = tokio::io::duplex(256 * 1024);
            let (ar, aw) = tokio::io::split(a);
            let (br, bw) = tokio::io::split(b);
            let (a_tx, mut a_rx) = mpsc::channel::<crate::ui::Typed>(8);
            let (b_tx, mut b_rx) = mpsc::channel::<crate::ui::Typed>(8);
            let (a_screen, a_updates) = crate::ui::channel();
            let (b_screen, b_updates) = crate::ui::channel();

            // Exactly what the input box produces from "voici [1] et [2] !".
            a_tx.send(crate::ui::Typed::Post {
                parts: vec![
                    crate::ui::Part::Text("voici".into()),
                    crate::ui::Part::File(one.clone()),
                    crate::ui::Part::Text("et".into()),
                    crate::ui::Part::File(two.clone()),
                ],
                direct: false,
            })
            .await
            .unwrap();

            // Alice leaves once both have gone.
            let watch_a = tokio::spawn(react_n(a_updates, a_tx, "-- sent ", 2, "/bye".to_owned()));
            // Bob takes the second one first, on purpose: the number has to
            // pick, not the order they arrived in.
            let watch_b = tokio::spawn(react_seq(
                b_updates,
                b_tx,
                vec![("[2]".to_owned(), "/accept 2".to_owned()), ("-- received".to_owned(), "/accept 1".to_owned())],
            ));

            let to_b = to.clone();
            let bob = tokio::spawn(async move {
                run(br.compat(), bw.compat_write(), "alice", &to_b, &mut b_rx, &b_screen).await
            });
            let unused = dir.join("unused");
            let alice = tokio::spawn(async move {
                run(ar.compat(), aw.compat_write(), "bob", &unused, &mut a_rx, &a_screen).await
            });
            alice.await.unwrap().unwrap();
            bob.await.unwrap().unwrap();
            watch_a.abort();
            watch_b.abort();
        });

        assert_eq!(std::fs::read(to.join("photo1.png")).unwrap(), vec![1u8; 5000]);
        assert_eq!(std::fs::read(to.join("photo2.png")).unwrap(), vec![2u8; 7000]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Answer once per trigger, in order, then stop.
    async fn react_seq(
        mut updates: mpsc::UnboundedReceiver<crate::ui::Update>,
        keyboard: mpsc::Sender<crate::ui::Typed>,
        mut script: Vec<(String, String)>,
    ) {
        while let Some(update) = updates.recv().await {
            let crate::ui::Update::Line(entry) = update else { continue };
            let Some((needle, reply)) = script.first() else { return };
            if entry.text().contains(needle.as_str()) {
                let reply = reply.clone();
                script.remove(0);
                let _ = keyboard.send(line(&reply)).await;
            }
        }
    }

    /// Reply once `needle` has been seen `count` times.
    async fn react_n(
        mut updates: mpsc::UnboundedReceiver<crate::ui::Update>,
        keyboard: mpsc::Sender<crate::ui::Typed>,
        needle: &'static str,
        count: usize,
        reply: String,
    ) {
        let mut seen = 0;
        while let Some(update) = updates.recv().await {
            let crate::ui::Update::Line(entry) = update else { continue };
            if entry.text().contains(needle) {
                seen += 1;
                if seen == count {
                    let _ = keyboard.send(line(&reply)).await;
                    return;
                }
            }
        }
    }


    /// `/accept all` is a standing instruction, not a batch: the wire still
    /// carries one file at a time, so finishing one has to start the next.
    #[test]
    fn accept_all_takes_every_file_in_turn() {
        let dir = scratch("acceptall");
        let (from, to) = (dir.join("out"), dir.join("in"));
        std::fs::create_dir_all(&from).unwrap();
        let one = from.join("un.bin");
        let two = from.join("deux.bin");
        let three = from.join("trois.bin");
        std::fs::write(&one, vec![1u8; 4000]).unwrap();
        std::fs::write(&two, vec![2u8; 6000]).unwrap();
        std::fs::write(&three, vec![3u8; 8000]).unwrap();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let (a, b) = tokio::io::duplex(256 * 1024);
            let (ar, aw) = tokio::io::split(a);
            let (br, bw) = tokio::io::split(b);
            let (a_tx, mut a_rx) = mpsc::channel::<crate::ui::Typed>(8);
            let (b_tx, mut b_rx) = mpsc::channel::<crate::ui::Typed>(8);
            let (a_screen, a_updates) = crate::ui::channel();
            let (b_screen, b_updates) = crate::ui::channel();

            a_tx.send(crate::ui::Typed::Post {
                parts: vec![
                    crate::ui::Part::Text("tout d'un coup".into()),
                    crate::ui::Part::File(one),
                    crate::ui::Part::File(two),
                    crate::ui::Part::File(three),
                ],
                direct: false,
            })
            .await
            .unwrap();

            let watch_a = tokio::spawn(react_n(a_updates, a_tx, "-- sent ", 3, "/bye".to_owned()));
            // One command for three files.
            let watch_b = tokio::spawn(react(b_updates, b_tx, &["[3]"], "/accept all".to_owned()));

            let to_b = to.clone();
            let bob = tokio::spawn(async move {
                run(br.compat(), bw.compat_write(), "alice", &to_b, &mut b_rx, &b_screen).await
            });
            let unused = dir.join("unused");
            let alice = tokio::spawn(async move {
                run(ar.compat(), aw.compat_write(), "bob", &unused, &mut a_rx, &a_screen).await
            });
            alice.await.unwrap().unwrap();
            bob.await.unwrap().unwrap();
            watch_a.abort();
            watch_b.abort();
        });

        assert_eq!(std::fs::read(to.join("un.bin")).unwrap(), vec![1u8; 4000]);
        assert_eq!(std::fs::read(to.join("deux.bin")).unwrap(), vec![2u8; 6000]);
        assert_eq!(std::fs::read(to.join("trois.bin")).unwrap(), vec![3u8; 8000]);
        let _ = std::fs::remove_dir_all(&dir);
    }


    fn offered_file(number: usize, batch: usize, name: &str) -> Offered {
        Offered {
            number,
            batch,
            offer: Offer { name: name.into(), size: 10, hash: [number as u8; 32] },
            direct: false,
        }
    }

    /// A bare `/accept` means the message you just read, not the one you left
    /// unanswered ten minutes ago.
    #[test]
    fn a_bare_accept_takes_the_newest_message() {
        let mut pending = vec![
            offered_file(1, 1, "vieux.jpg"),
            offered_file(2, 2, "recent_a.jpg"),
            offered_file(3, 2, "recent_b.jpg"),
        ];

        // The newest message, and within it the first file.
        assert_eq!(take_pending(&mut pending, Which::Newest).unwrap().offer.name, "recent_a.jpg");
        assert_eq!(take_pending(&mut pending, Which::Newest).unwrap().offer.name, "recent_b.jpg");
        // Only then the one left over from before.
        assert_eq!(take_pending(&mut pending, Which::Newest).unwrap().offer.name, "vieux.jpg");
        assert!(take_pending(&mut pending, Which::Newest).is_err());
    }

    /// The bug behind the visible one: numbers were positions, so taking one
    /// renumbered the rest and `[3]` stopped meaning what was on screen.
    #[test]
    fn a_number_keeps_meaning_what_was_drawn() {
        let mut pending = vec![
            offered_file(1, 1, "a.jpg"),
            offered_file(2, 1, "b.jpg"),
            offered_file(3, 1, "c.jpg"),
        ];

        assert_eq!(take_pending(&mut pending, Which::Numbered(2)).unwrap().offer.name, "b.jpg");
        // [3] is still on screen, so it must still be [3].
        assert_eq!(take_pending(&mut pending, Which::Numbered(3)).unwrap().offer.name, "c.jpg");
        assert_eq!(take_pending(&mut pending, Which::Numbered(1)).unwrap().offer.name, "a.jpg");
    }

    /// A number nobody is waiting on says which ones are.
    #[test]
    fn an_unknown_number_lists_what_is_waiting() {
        let mut pending = vec![offered_file(4, 1, "a.jpg"), offered_file(7, 2, "b.jpg")];
        let err = take_pending(&mut pending, Which::Numbered(2)).unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("[4]") && text.contains("[7]"), "{text}");
        assert_eq!(pending.len(), 2, "a bad number takes nothing");
    }


    /// The bar has to stay honest at both ends and never overflow its width.
    #[test]
    fn the_bar_fills_from_empty_to_full() {
        let empty = bar(0, 1000);
        assert!(empty.contains("  0%"), "{empty}");
        assert!(empty.contains('\u{2591}') && !empty.contains('\u{2588}'), "{empty}");

        let half = bar(500, 1000);
        assert!(half.contains(" 50%"), "{half}");

        let full = bar(1000, 1000);
        assert!(full.contains("100%"), "{full}");
        assert!(!full.contains('\u{2591}'), "{full}");

        // Every bar is the same width, whatever it says.
        let width = |s: &str| s.chars().filter(|c| *c == '\u{2588}' || *c == '\u{2591}').count();
        assert_eq!(width(&empty), width(&half));
        assert_eq!(width(&half), width(&full));

        // A peer claiming more than it offered must not make it wrap round.
        let over = bar(2000, 1000);
        assert!(over.contains("100%"), "{over}");
        assert_eq!(width(&over), width(&full));
        // And a zero-sized total must not divide by zero.
        assert!(bar(0, 0).contains("100%"));
    }

    /// A refused offer leaves nothing behind.
    #[test]
    fn a_refused_file_is_never_written() {
        let (dir, landed) = transfer("refuse", b"bonjour tout le monde", "/refuse", 0, Route::Tor);
        assert!(!landed.exists());
        assert!(
            std::fs::read_dir(dir.join("in")).is_err(),
            "refusing must not even create the directory"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The resume path, exercised where it lives: a partial already on disk
    /// means the accept asks for the rest, and the two halves join up.
    #[test]
    fn a_half_received_file_resumes_from_disk() {
        let payload: Vec<u8> = (0..MAX_CHUNK + 500).map(|i| (i % 251) as u8).collect();
        let cut = payload.len() / 2;
        let (dir, landed) = transfer("resume", &payload, "/accept", cut, Route::Tor);

        assert!(landed.exists(), "the resumed file must land");
        assert_eq!(
            std::fs::read(&landed).unwrap(),
            payload,
            "the two halves must join with no gap and no overlap"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

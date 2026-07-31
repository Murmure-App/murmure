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

/// How often a running transfer reports progress, in bytes.
const PROGRESS_EVERY: u64 = 1024 * 1024;

/// How a conversation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// The peer closed the stream.
    PeerHungUp,
    /// We did, with `/bye`.
    WeHungUp,
    /// stdin reached EOF: Ctrl-D, or a piped script running out.
    InputClosed,
}

impl Ended {
    /// What to tell the operator, using the name they know the peer by.
    pub fn describe(self, peer: &str) -> String {
        match self {
            Ended::PeerHungUp => format!("{peer} hung up"),
            Ended::WeHungUp => "you hung up".to_owned(),
            Ended::InputClosed => "input closed".to_owned(),
        }
    }
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
    /// Next progress report, in bytes sent.
    next_report: u64,
}

/// A file coming in, and how far it has got.
struct Receiving {
    file: std::fs::File,
    offer: Offer,
    written: u64,
    next_report: u64,
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
    lines: &mut mpsc::Receiver<String>,
    screen: &Screen,
) -> Result<Ended>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (outbox, mut queued) = mpsc::channel::<Message>(OUTBOX);
    let (inbox_tx, mut inbox) = mpsc::channel::<Message>(INBOX);

    let mut writer = writer;
    let writing = tokio::spawn(async move {
        while let Some(msg) = queued.recv().await {
            proto::write_frame(&mut writer, &msg).await?;
        }
        Ok::<(), anyhow::Error>(())
    });

    // Decides nothing: every frame goes to the loop, which owns the state that
    // says what a frame means.
    let mut reader = reader;
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
    let mut pending: Option<Offer> = None;
    // Set once the operator has asked to leave but a transfer is still running.
    // Ending the call there would truncate a file mid-flight, and the recipient
    // would have no way to tell that from a network drop.
    let mut leaving: Option<Ended> = None;
    // False once the keyboard channel has closed for good.
    let mut keyboard_open = true;

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
                    if !busy(&sending, &receiving) { break Ended::InputClosed }
                    leaving = Some(Ended::InputClosed);
                    continue;
                };
                match classify(&line) {
                    Typed::Nothing => continue,
                    Typed::HangUp => {
                        if !busy(&sending, &receiving) || leaving.is_some() {
                            break Ended::WeHungUp;
                        }
                        screen.system(
                            "-- hanging up when the file is done; /bye again to leave now --",
                        );
                        leaving = Some(Ended::WeHungUp);
                    }
                    // Anything else starting with '/' stays here. Letting it
                    // through would send `/add alice <address>` — a contact's
                    // address — straight to whoever is on the other end.
                    Typed::UnknownCommand(verb) => screen.error(format!(
                        "{verb} is not available during a call — /bye first. \
                         (start a line with // to send a literal slash)"
                    )),
                    Typed::Send(path) => {
                        if let Err(e) = start_sending(&path, &mut sending, &outbox, screen).await {
                            screen.error(format!("{e:#}"));
                        }
                    }
                    Typed::Accept => {
                        if let Err(e) =
                            accept(incoming_dir, &mut pending, &mut receiving, &outbox, screen).await
                        {
                            screen.error(format!("{e:#}"));
                        }
                    }
                    Typed::Refuse => match pending.take() {
                        Some(offer) => {
                            screen.system(format!("refused {:?}", offer.name));
                            if outbox.send(Message::FileReject).await.is_err() {
                                break Ended::PeerHungUp;
                            }
                        }
                        None => screen.error("nothing to refuse"),
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

            Some(msg) = inbox.recv() => {
                let outcome = handle(
                    msg, peer, incoming_dir,
                    &mut pending, &mut receiving, &mut sending,
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
            outcome = &mut reading => {
                outcome.map_err(|e| anyhow::anyhow!("the reader task panicked: {e}"))??;
                break Ended::PeerHungUp;
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

        // The transfer that was holding the call open has finished.
        if let Some(end) = leaving
            && !busy(&sending, &receiving)
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
fn busy(sending: &Option<Sending>, receiving: &Option<Receiving>) -> bool {
    sending.is_some() || receiving.is_some()
}

/// Act on one frame from the peer. `false` means the conversation is over.
#[allow(clippy::too_many_arguments)]
async fn handle(
    msg: Message,
    peer: &str,
    incoming_dir: &Path,
    pending: &mut Option<Offer>,
    receiving: &mut Option<Receiving>,
    sending: &mut Option<Sending>,
    outbox: &mpsc::Sender<Message>,
    screen: &Screen,
) -> Result<bool> {
    match msg {
        Message::Text(body) => screen.say(Kind::Theirs, format!("{peer}> {body}")),
        Message::Ping => {
            if outbox.send(Message::Pong).await.is_err() {
                return Ok(false);
            }
        }
        Message::Pong => {}

        Message::FileOffer { name, size, hash } => {
            // The name is about to be shown to the operator, who decides on the
            // strength of it. Sanitise before it reaches the screen, not just
            // before it reaches the filesystem.
            let name = files::safe_name(&name)?;
            if size == 0 || size > files::MAX_FILE {
                bail!("{peer} offered a file of {size} bytes, which is not a size we take");
            }
            if receiving.is_some() || pending.is_some() {
                // One at a time, like one call at a time.
                let _ = outbox.send(Message::FileReject).await;
                screen.system(format!("{peer} offered another file; one at a time"));
                return Ok(true);
            }

            let offer = Offer { name, size, hash };
            let resume = files::resume_offset(incoming_dir, &offer.hash, offer.size);
            screen.system(format!(
                "-- {peer} offers {:?} ({}) --",
                offer.name,
                files::human(offer.size)
            ));
            if resume > 0 {
                screen.system(format!(
                    "   {} already here from an earlier attempt; /accept resumes",
                    files::human(resume)
                ));
            }
            screen.system("   /accept to take it, /refuse to decline");
            *pending = Some(offer);
        }

        Message::FileAccept { offset } => {
            let Some(s) = sending.as_mut() else {
                bail!("{peer} accepted a file we never offered");
            };
            if offset > s.size {
                bail!("{peer} asked to resume past the end of the file");
            }
            std::io::Seek::seek(&mut s.file, std::io::SeekFrom::Start(offset))
                .context("seeking to the resume point")?;
            s.accepted = true;
            s.sent = offset;
            s.next_report = offset + PROGRESS_EVERY;
            screen.system(match offset {
                0 => format!("-- sending {:?} --", s.name),
                _ => format!("-- resuming {:?} from {} --", s.name, files::human(offset)),
            });
        }

        Message::FileReject => {
            match sending.take() {
                Some(s) => screen.system(format!("-- {peer} declined {:?} --", s.name)),
                None => screen.system(format!("-- {peer} declined a file --")),
            }
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
            if r.written >= r.next_report {
                screen.system(format!(
                    "   {} of {}",
                    files::human(r.written),
                    files::human(r.offer.size)
                ));
                r.next_report = r.written + PROGRESS_EVERY;
            }
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

/// Offer a file, after checking we can actually read it.
async fn start_sending(
    path: &Path,
    sending: &mut Option<Sending>,
    outbox: &mpsc::Sender<Message>,
    screen: &Screen,
) -> Result<()> {
    if sending.is_some() {
        bail!("already sending a file; one at a time");
    }
    let offer = files::describe(path)?;
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening {}", path.display()))?;

    screen.system(format!(
        "-- offered {:?} ({}); waiting for them to accept --",
        offer.name,
        files::human(offer.size)
    ));
    // Held back until the peer accepts: `sent` stays at zero and the pump reads
    // nothing until a FileAccept sets the offset.
    *sending = Some(Sending {
        file,
        name: offer.name.clone(),
        accepted: false,
        sent: 0,
        size: offer.size,
        next_report: PROGRESS_EVERY,
    });
    outbox
        .send(Message::FileOffer {
            name: offer.name,
            size: offer.size,
            hash: offer.hash,
        })
        .await
        .map_err(|_| anyhow::anyhow!("the conversation ended"))
}

/// Take the pending offer: open the partial, and tell the peer where to start.
async fn accept(
    incoming_dir: &Path,
    pending: &mut Option<Offer>,
    receiving: &mut Option<Receiving>,
    outbox: &mpsc::Sender<Message>,
    screen: &Screen,
) -> Result<()> {
    let Some(offer) = pending.take() else {
        bail!("nothing to accept");
    };
    std::fs::create_dir_all(incoming_dir)
        .with_context(|| format!("creating {}", incoming_dir.display()))?;

    let offset = files::resume_offset(incoming_dir, &offer.hash, offer.size);
    let partial = files::partial_path(incoming_dir, &offer.hash);
    // Append rather than truncate: `offset` is exactly what is already there,
    // so the peer's first chunk continues the file.
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&partial)
        .with_context(|| format!("opening {}", partial.display()))?;

    screen.system(format!("-- taking {:?} --", offer.name));
    *receiving = Some(Receiving {
        offer,
        file,
        written: offset,
        next_report: offset + PROGRESS_EVERY,
    });
    outbox
        .send(Message::FileAccept { offset })
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
    if s.sent >= s.next_report {
        screen.system(format!(
            "   {} of {}",
            files::human(s.sent),
            files::human(s.size)
        ));
        s.next_report = s.sent + PROGRESS_EVERY;
    }
    Ok(Some(Message::FileChunk(buf)))
}

/// What a line typed during a call turns out to be.
#[derive(Debug, PartialEq, Eq)]
enum Typed {
    /// Blank; ignore it.
    Nothing,
    /// `/bye`.
    HangUp,
    /// `/send <path>`.
    Send(PathBuf),
    /// `/accept`.
    Accept,
    /// `/refuse`.
    Refuse,
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
        "/bye" => Typed::HangUp,
        "/accept" => Typed::Accept,
        "/refuse" => Typed::Refuse,
        // The whole remainder, not the first word: paths have spaces in them,
        // and quoting rules would be one more thing to explain.
        "/send" if !rest.is_empty() => Typed::Send(PathBuf::from(expand_home(rest))),
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

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("murmure-chat-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The one that matters: a command typed during a call must never travel.
    #[test]
    fn commands_typed_during_a_call_are_never_sent() {
        assert_eq!(classify("/bye"), Typed::HangUp);
        assert_eq!(
            classify("/add alice haticv.onion"),
            Typed::UnknownCommand("/add".into())
        );
        assert_eq!(classify("/call bob"), Typed::UnknownCommand("/call".into()));
        assert_eq!(classify("/quit"), Typed::UnknownCommand("/quit".into()));
        assert_eq!(classify("  "), Typed::Nothing);
        // `/send` with nothing after it is a mistake, not a message.
        assert_eq!(classify("/send"), Typed::UnknownCommand("/send".into()));
    }

    #[test]
    fn the_file_verbs_are_recognised() {
        assert_eq!(classify("/accept"), Typed::Accept);
        assert_eq!(classify("/refuse"), Typed::Refuse);
        assert_eq!(
            classify("/send /tmp/rapport.pdf"),
            Typed::Send(PathBuf::from("/tmp/rapport.pdf"))
        );
        // A path with spaces survives, without quoting rules to learn.
        assert_eq!(
            classify("/send /tmp/mes documents/le rapport.pdf"),
            Typed::Send(PathBuf::from("/tmp/mes documents/le rapport.pdf"))
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
            let (bob_r, _bob_w) = tokio::io::split(bob);

            let (tx, mut rx) = mpsc::channel::<String>(4);
            tx.send("bonjour".to_owned()).await.unwrap();
            tx.send("/bye".to_owned()).await.unwrap();
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

            let mut bob_r = bob_r.compat();
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
    fn transfer(tag: &str, payload: &[u8], answer: &str, already_here: usize) -> (PathBuf, PathBuf) {
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

            let (a_tx, mut a_rx) = mpsc::channel::<String>(8);
            let (b_tx, mut b_rx) = mpsc::channel::<String>(8);
            let (a_screen, a_updates) = crate::ui::channel();
            let (b_screen, b_updates) = crate::ui::channel();

            a_tx.send(format!("/send {}", source.display()))
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
        keyboard: mpsc::Sender<String>,
        triggers: &'static [&'static str],
        reply: String,
    ) {
        while let Some(update) = updates.recv().await {
            let crate::ui::Update::Line(entry) = update else {
                continue;
            };
            if triggers.iter().any(|t| entry.text().contains(t)) {
                let _ = keyboard.send(reply).await;
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
        let (dir, landed) = transfer("transfer", &payload, "/accept", 0);

        assert!(landed.exists(), "the file must be in the incoming directory");
        assert_eq!(std::fs::read(&landed).unwrap(), payload);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A refused offer leaves nothing behind.
    #[test]
    fn a_refused_file_is_never_written() {
        let (dir, landed) = transfer("refuse", b"bonjour tout le monde", "/refuse", 0);
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
        let (dir, landed) = transfer("resume", &payload, "/accept", cut);

        assert!(landed.exists(), "the resumed file must land");
        assert_eq!(
            std::fs::read(&landed).unwrap(),
            payload,
            "the two halves must join with no gap and no overlap"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

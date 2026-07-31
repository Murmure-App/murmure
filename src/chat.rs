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
//! Two concurrent jobs share the stream. The **reader** pulls frames off the
//! wire; the **writer** is the only thing that touches the write half. Typed
//! lines and automatic replies (a `Pong` for a `Ping`) both queue to the writer
//! through one channel, so there is one owner and no lock.

use anyhow::{Result, bail};
use futures::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::proto::{self, MAX_TEXT, Message};
use crate::ui::{Kind, Screen};

/// How many outbound frames may queue before the sender waits.
///
/// Small on purpose: a backlog here means the network is slower than the typing,
/// and making the typist wait is more honest than growing a buffer.
const OUTBOX: usize = 32;

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

/// Run a conversation over an open stream.
///
/// `lines` is borrowed rather than consumed: when the conversation ends, the
/// caller goes back to reading commands from the same keyboard.
pub async fn run<R, W>(
    reader: R,
    writer: W,
    peer: &str,
    lines: &mut mpsc::Receiver<String>,
    screen: &Screen,
) -> Result<Ended>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (outbox, mut queued) = mpsc::channel::<Message>(OUTBOX);

    let mut writer = writer;
    let writing = tokio::spawn(async move {
        while let Some(msg) = queued.recv().await {
            proto::write_frame(&mut writer, &msg).await?;
        }
        Ok::<(), anyhow::Error>(())
    });

    let peer_label = peer.to_owned();
    let replies = outbox.clone();
    let on_screen = screen.clone();
    let mut reader = reader;
    let reading = tokio::spawn(async move {
        while let Some(msg) = proto::read_frame(&mut reader).await? {
            if let Some(line) = render(&msg, &peer_label) {
                on_screen.say(Kind::Theirs, line);
            }
            if let Some(reply) = respond(&msg) {
                // A closed outbox means the writer is gone, i.e. the
                // conversation is over. Stop rather than error.
                if replies.send(reply).await.is_err() {
                    break;
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });
    futures::pin_mut!(reading);

    let ended = loop {
        tokio::select! {
            // The peer's side of the conversation ended, cleanly or not.
            outcome = &mut reading => {
                outcome.map_err(|e| anyhow::anyhow!("the reader task panicked: {e}"))??;
                break Ended::PeerHungUp;
            }
            typed = lines.recv() => {
                let Some(line) = typed else { break Ended::InputClosed };
                let line = match classify(&line) {
                    Typed::Nothing => continue,
                    Typed::HangUp => break Ended::WeHungUp,
                    // Anything else starting with '/' stays here. Letting it
                    // through would send `/add alice <address>` — a contact's
                    // address — straight to whoever is on the other end.
                    Typed::UnknownCommand(verb) => {
                        screen.error(format!(
                            "{verb} is not available during a call — /bye first. \
                             (start a line with // to send a literal slash)"
                        ));
                        continue;
                    }
                    Typed::Message(text) => text,
                };
                if line.len() > MAX_TEXT {
                    screen.error(format!(
                        "line dropped: {} bytes, the limit is {MAX_TEXT}",
                        line.len()
                    ));
                    continue;
                }
                // Echo our own line: without it the conversation is one-sided
                // on screen, and there is no way to tell a sent message from a
                // swallowed one.
                screen.say(Kind::Mine, format!("you> {line}"));
                if outbox.send(Message::Text(line)).await.is_err() {
                    break Ended::PeerHungUp;
                }
            }
        }
    };

    // Order matters. The reader task holds a clone of the outbox, so dropping
    // ours is not enough to end the writer: as long as the reader is parked on
    // `read_frame` — which it is whenever *we* hang up — that clone keeps the
    // channel open and `writing.await` never returns. Stop the reader first.
    reading.abort();
    drop(outbox);
    match writing.await {
        Ok(Ok(())) => {}
        // A write failing as the peer hangs up is the normal race, not a fault.
        Ok(Err(e)) if ended == Ended::PeerHungUp => tracing::debug!("write at hang-up: {e:#}"),
        Ok(Err(e)) => bail!(e),
        Err(e) => bail!("the writer task panicked: {e}"),
    }
    Ok(ended)
}

/// What a line typed during a call turns out to be.
#[derive(Debug, PartialEq, Eq)]
enum Typed {
    /// Blank; ignore it.
    Nothing,
    /// `/bye`.
    HangUp,
    /// Any other `/word`. Held back rather than sent.
    UnknownCommand(String),
    /// Something to say, with any `//` escape already unwrapped.
    Message(String),
}

/// Decide what a typed line is.
///
/// A leading `/` means "command" during a call, and there are exactly two
/// outcomes: hang up, or refuse. Nothing beginning with `/` is ever sent by
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
    if trimmed.starts_with('/') {
        let verb = trimmed.split_whitespace().next().unwrap_or(trimmed);
        return if verb == "/bye" {
            Typed::HangUp
        } else {
            Typed::UnknownCommand(verb.to_owned())
        };
    }
    Typed::Message(line.to_owned())
}

/// What a received message puts on screen, if anything.
fn render(msg: &Message, peer: &str) -> Option<String> {
    match msg {
        Message::Text(body) => Some(format!("{peer}> {body}")),
        // Liveness traffic is not conversation.
        Message::Ping | Message::Pong => None,
    }
}

/// What a received message is answered with, if anything.
fn respond(msg: &Message) -> Option<Message> {
    match msg {
        Message::Ping => Some(Message::Pong),
        Message::Text(_) | Message::Pong => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::compat::{TokioAsyncReadCompatExt as _, TokioAsyncWriteCompatExt as _};

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

    #[test]
    fn ping_is_answered_with_pong_and_nothing_else_is() {
        assert_eq!(respond(&Message::Ping), Some(Message::Pong));
        assert_eq!(respond(&Message::Pong), None);
        assert_eq!(respond(&Message::Text("bonjour".into())), None);
    }

    #[test]
    fn only_text_reaches_the_screen() {
        assert_eq!(
            render(&Message::Text("bonjour".into()), "alice"),
            Some("alice> bonjour".to_owned())
        );
        assert_eq!(render(&Message::Ping, "alice"), None);
        assert_eq!(render(&Message::Pong, "alice"), None);
    }

    /// Both sides of a conversation, over an in-memory duplex: what one types
    /// is what the other reads.
    #[test]
    fn a_typed_line_reaches_the_other_side() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
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
}

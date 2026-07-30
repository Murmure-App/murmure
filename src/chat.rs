//! The conversation loop.
//!
//! One open stream, frames in both directions, for as long as both sides stay
//! connected. Terminal in, terminal out — the TUI replaces the printing later,
//! not the loop.
//!
//! # Shape
//!
//! Three concurrent jobs share one stream:
//!
//! - the **reader** pulls frames off the wire and reacts to them;
//! - the **keyboard** turns typed lines into [`Message::Text`];
//! - the **writer** is the only thing that touches the write half.
//!
//! Reader and keyboard both need to send, so they queue through a channel
//! instead of sharing the writer behind a lock. One owner, no contention, and
//! the send order is whatever reached the queue first.

use anyhow::{Context as _, Result};
use futures::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::sync::mpsc;

use crate::proto::{self, MAX_TEXT, Message};

/// How many outbound frames may queue before the sender waits.
///
/// Small on purpose: a backlog here means the network is slower than the typing,
/// and blocking the keyboard is more honest than growing a buffer nobody reads.
const OUTBOX: usize = 32;

/// Run a conversation over an open stream until either side hangs up.
///
/// `peer` is what incoming lines get labelled with on screen.
pub async fn run<R, W>(reader: R, writer: W, peer: &str) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (outbox, mut queued) = mpsc::channel::<Message>(OUTBOX);

    // The single owner of the write half.
    let mut writer = writer;
    let writing = tokio::spawn(async move {
        while let Some(msg) = queued.recv().await {
            proto::write_frame(&mut writer, &msg).await?;
        }
        Ok::<(), anyhow::Error>(())
    });

    // Incoming frames.
    let peer = peer.to_owned();
    let replies = outbox.clone();
    let mut reader = reader;
    let reading = tokio::spawn(async move {
        while let Some(msg) = proto::read_frame(&mut reader).await? {
            if let Some(line) = render(&msg, &peer) {
                println!("{line}");
            }
            if let Some(reply) = respond(&msg) {
                // A closed outbox means the writer is gone, which means the
                // conversation is over; stop rather than error.
                if replies.send(reply).await.is_err() {
                    break;
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    // Typed lines. Ctrl-D ends the conversation.
    let typing = tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Some(line) = lines.next_line().await.context("reading stdin")? {
            if line.is_empty() {
                continue;
            }
            if line.len() > MAX_TEXT {
                eprintln!("(line dropped: {} bytes, limit is {MAX_TEXT})", line.len());
                continue;
            }
            if outbox.send(Message::Text(line)).await.is_err() {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    // Whichever ends first ends the conversation: the peer hung up, or we did.
    let outcome = tokio::select! {
        r = reading => r.context("the reader task panicked")?,
        r = typing  => r.context("the keyboard task panicked")?,
        r = writing => r.context("the writer task panicked")?,
    };
    outcome
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
}

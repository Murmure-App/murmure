//! Wire protocol for the control plane.
//!
//! One long-lived stream per conversation carries a sequence of length-prefixed
//! frames, each holding one [`Message`].
//!
//! # Why length prefixes and not stream close
//!
//! Closing a Tor stream is not a clean EOF. `poll_close` sends `End::new_misc()`
//! and the reader turns every reason other than `EndReceived(DONE)` into an
//! error — so a reader waiting for EOF fails *after* having received every byte.
//! The keystore milestone hit exactly that. Nothing in murmure may use stream
//! close to delimit anything; a frame's length says where it ends.
//!
//! # Why one stream per conversation
//!
//! A rendezvous costs 7-50 s (PETS 2025). A stream per message would pay that
//! per message. The stream is opened once and kept.

// Nothing calls this yet: the milestone binary still speaks raw bytes. The chat
// loop is what wires it in, and this attribute goes away with it.
#![allow(dead_code)]

use anyhow::{Context as _, Result, bail};
use futures::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use serde::{Deserialize, Serialize};

/// Largest frame accepted, in bytes.
///
/// The control plane carries text and small negotiation payloads — never file
/// data, which is what the direct plane (v2) is for. The cap exists because the
/// length prefix arrives from the network: without it, a hostile or corrupt
/// peer sizes our allocation for us.
pub const MAX_FRAME: usize = 64 * 1024;

/// Longest text body accepted, in bytes of UTF-8.
///
/// Well under [`MAX_FRAME`] so that framing overhead can never make a legal
/// message unsendable.
pub const MAX_TEXT: usize = 32 * 1024;

/// One unit of conversation.
///
/// Deliberately small. File offers, chunk requests and the candidate exchange of
/// the direct plane get added when those features exist, not before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    /// A chat line.
    Text(String),
    /// "Are you still there?" — answered with [`Message::Pong`].
    ///
    /// Only meaningful on an already-open stream, where it is free. Presence for
    /// contacts *without* an open stream costs a full rendezvous; see the
    /// presence section of `aidd_docs/INSTALL.md`.
    Ping,
    /// Answer to [`Message::Ping`].
    Pong,
}

impl Message {
    /// Reject a message that cannot legally be sent, before it reaches the wire.
    fn check(&self) -> Result<()> {
        if let Message::Text(body) = self
            && body.len() > MAX_TEXT
        {
            bail!(
                "text body is {} bytes, over the {MAX_TEXT}-byte limit",
                body.len()
            );
        }
        Ok(())
    }
}

/// Encode and send one frame.
pub async fn write_frame<W>(w: &mut W, msg: &Message) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    msg.check()?;
    let body = postcard::to_stdvec(msg).context("encoding a frame")?;
    // Unreachable while MAX_TEXT is the only variable-length payload and stays
    // well under MAX_FRAME, but the check is cheap and outlives that assumption.
    if body.len() > MAX_FRAME {
        bail!("encoded frame is {} bytes, over MAX_FRAME", body.len());
    }
    let len = u32::try_from(body.len()).expect("checked against MAX_FRAME above");

    w.write_all(&len.to_le_bytes())
        .await
        .context("writing a frame length")?;
    w.write_all(&body).await.context("writing a frame body")?;
    w.flush().await.context("flushing a frame")?;
    Ok(())
}

/// Read one frame.
///
/// A peer that hangs up between frames yields [`None`]; a peer that hangs up
/// *inside* a frame is an error, because a truncated frame is corruption rather
/// than a normal end of conversation.
pub async fn read_frame<R>(r: &mut R) -> Result<Option<Message>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    match read_exact_or_eof(r, &mut len_buf).await? {
        // Clean hang-up on a frame boundary.
        ReadEnd::Eof => return Ok(None),
        ReadEnd::Filled => {}
    }

    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 {
        bail!("peer announced a zero-length frame");
    }
    // Checked *before* allocating: the length came from the network.
    if len > MAX_FRAME {
        bail!("peer announced a {len}-byte frame, over the {MAX_FRAME}-byte limit");
    }

    let mut body = vec![0u8; len];
    match read_exact_or_eof(r, &mut body).await? {
        ReadEnd::Eof => bail!("stream ended inside a {len}-byte frame"),
        ReadEnd::Filled => {}
    }

    let msg: Message = postcard::from_bytes(&body).context("decoding a frame")?;
    msg.check()?;
    Ok(Some(msg))
}

/// Outcome of a fill-this-buffer read.
enum ReadEnd {
    /// The buffer was filled.
    Filled,
    /// The stream ended before a single byte arrived.
    Eof,
}

/// Fill `buf`, distinguishing "nothing left to read" from "ran out mid-buffer".
///
/// `AsyncReadExt::read_exact` collapses the two into one error kind, and the
/// difference is what separates a peer hanging up politely from a truncated
/// frame.
async fn read_exact_or_eof<R>(r: &mut R, buf: &mut [u8]) -> Result<ReadEnd>
where
    R: AsyncRead + Unpin,
{
    let mut filled = 0;
    while filled < buf.len() {
        let n = r
            .read(&mut buf[filled..])
            .await
            .context("reading from the stream")?;
        if n == 0 {
            if filled == 0 {
                return Ok(ReadEnd::Eof);
            }
            bail!(
                "stream ended after {filled} of {} expected bytes",
                buf.len()
            );
        }
        filled += n;
    }
    Ok(ReadEnd::Filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode messages back-to-back the way a conversation does, then read them
    /// back: order, content and frame boundaries all have to survive.
    #[test]
    fn frames_round_trip_in_sequence() {
        let sent = vec![
            Message::Text("bonjour".into()),
            Message::Ping,
            Message::Pong,
            Message::Text("un message plus long, avec des accents éàü".into()),
        ];

        let mut wire = Vec::new();
        futures::executor::block_on(async {
            for msg in &sent {
                write_frame(&mut wire, msg).await.unwrap();
            }
        });

        let mut read = wire.as_slice();
        let mut got = Vec::new();
        futures::executor::block_on(async {
            while let Some(msg) = read_frame(&mut read).await.unwrap() {
                got.push(msg);
            }
        });

        assert_eq!(sent, got);
    }

    /// A hang-up on a frame boundary is the normal end of a conversation.
    #[test]
    fn clean_end_of_stream_yields_none() {
        let mut empty: &[u8] = &[];
        let got = futures::executor::block_on(read_frame(&mut empty)).unwrap();
        assert!(got.is_none());
    }

    /// A hang-up inside a frame is corruption, not a polite goodbye.
    #[test]
    fn truncated_frame_is_an_error() {
        let mut wire = Vec::new();
        futures::executor::block_on(write_frame(&mut wire, &Message::Text("bonjour".into())))
            .unwrap();
        wire.truncate(wire.len() - 1);

        let mut read = wire.as_slice();
        let err = futures::executor::block_on(read_frame(&mut read)).unwrap_err();
        assert!(
            err.to_string().contains("stream ended after"),
            "expected a truncation error, got: {err}"
        );
    }

    /// The length prefix comes from the network, so it must not size our
    /// allocation. This is the frame that would otherwise ask for 4 GiB.
    #[test]
    fn oversized_length_prefix_is_refused_before_allocating() {
        let mut wire = u32::MAX.to_le_bytes().to_vec();
        wire.extend_from_slice(b"never read");

        let mut read = wire.as_slice();
        let err = futures::executor::block_on(read_frame(&mut read)).unwrap_err();
        assert!(
            err.to_string().contains("over the"),
            "expected a size-limit error, got: {err}"
        );
    }

    /// An over-long body is refused by the sender, not discovered by the peer.
    #[test]
    fn oversized_text_is_refused_by_the_sender() {
        let too_long = Message::Text("a".repeat(MAX_TEXT + 1));
        let mut wire = Vec::new();
        let err = futures::executor::block_on(write_frame(&mut wire, &too_long)).unwrap_err();
        assert!(
            err.to_string().contains("over the"),
            "expected a size-limit error, got: {err}"
        );
        assert!(wire.is_empty(), "nothing may reach the wire");
    }
}

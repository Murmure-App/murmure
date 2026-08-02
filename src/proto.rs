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

/// Bytes of file data in one [`Message::FileChunk`].
///
/// Half of [`MAX_FRAME`], which leaves the enum discriminant and postcard's
/// length varint far more room than they can ever use. Larger chunks would mean
/// fewer frames and a longer stall before a `/bye` typed mid-transfer is seen;
/// this size keeps the loop answering the keyboard several times a second even
/// on a slow circuit.
pub const MAX_CHUNK: usize = 32 * 1024;

/// Longest filename accepted from a peer, in bytes.
///
/// Enforced on both sides. Names arrive from the network and end up on a
/// filesystem, so [`crate::files::safe_name`] does the real work; this only
/// keeps an absurd one off the wire in the first place.
pub const MAX_NAME: usize = 255;

/// Most addresses a peer may offer for a direct link.
///
/// A machine has a handful of interfaces. The cap is here because the list
/// arrives from the network and every entry costs a dial attempt with a
/// timeout — without it, a peer could make us spend minutes failing to connect
/// to addresses of their choosing, which is a way of scanning our network from
/// the outside as much as it is a way of wasting our time.
pub const MAX_CANDIDATES: usize = 8;

/// How to reach a peer's direct link, and which certificate to trust there.
///
/// Sent only inside [`Message::FileAccept`], and only when the recipient has
/// agreed to a direct transfer: it names their addresses, which is exactly the
/// thing Tor was hiding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Direct {
    /// Addresses to try, in order.
    pub candidates: Vec<std::net::SocketAddr>,
    /// BLAKE3 of the certificate the listener will present. Travelling over the
    /// already-authenticated onion circuit is what makes it trustworthy, and
    /// what makes a certificate authority unnecessary.
    pub fingerprint: [u8; 32],
}

/// Most files one message may carry.
///
/// From the network, so it is not the peer's to choose: each one becomes a
/// pending offer the operator has to look at, and a message with a thousand
/// would be a way to bury the screen.
pub const MAX_FILES: usize = 16;

/// What a file looks like on the wire, before anyone agrees to take it.
///
/// The same three fields as [`crate::files::Offer`], kept separate because that
/// one is the local view and this one is what a peer sends us — the boundary
/// where the name still has to be sanitised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRef {
    pub name: String,
    pub size: u64,
    pub hash: [u8; 32],
}

/// One piece of a message: some text, or a file sitting where it was put.
///
/// A sequence rather than text with placeholder characters. A placeholder would
/// be a character a peer could also type, so the count in the text and the
/// count in the list could disagree — a desynchronisation to detect and reject.
/// With a sequence there is nothing to keep in step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Piece {
    Text(String),
    File(FileRef),
}

/// One unit of conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    /// A chat line.
    Text(String),
    /// A message, with any files the sender put inside it.
    ///
    /// This is what replaces "a file transfer is its own conversation": the
    /// files keep the position they were dropped at, several can ride one
    /// message, and the sentence around them arrives at the same time rather
    /// than before or after.
    ///
    /// Sending one still moves no data. Each file becomes an offer the
    /// recipient answers one by one — a file lands on their disk, so they are
    /// still the ones who say yes.
    Post {
        pieces: Vec<Piece>,
        /// The sender is asking for the files to travel outside Tor. Applies to
        /// every file in the message; the recipient still decides.
        direct: bool,
    },
    /// "Are you still there?" — answered with [`Message::Pong`].
    ///
    /// Only meaningful on an already-open stream, where it is free. Presence for
    /// contacts *without* an open stream costs a full rendezvous; see the
    /// presence section of `aidd_docs/INSTALL.md`.
    Ping,
    /// Answer to [`Message::Ping`].
    Pong,
    /// "I have a file for you." Answered with [`Message::FileAccept`] or
    /// [`Message::FileReject`], never automatically — a file lands on the
    /// recipient's disk, so the recipient says yes.
    ///
    /// `hash` is BLAKE3 of the whole file. It identifies the transfer across
    /// restarts, which is what makes resuming safe: the same hash is the same
    /// bytes, so appending to a partial cannot silently splice two files.
    FileOffer {
        name: String,
        size: u64,
        hash: [u8; 32],
        /// The sender is asking to send this one outside Tor. It is a request,
        /// not a decision: the recipient is the one who would expose an
        /// address, so the recipient answers.
        direct: bool,
    },
    /// "Send it, starting at this byte." Non-zero when resuming a partial.
    ///
    /// `direct` is the recipient's answer to a direct request: `Some` means
    /// they agreed and are listening at these addresses, `None` means the
    /// transfer goes over Tor as usual. A `None` against a direct offer is a
    /// refusal of the *route*, not of the file.
    FileAccept {
        /// Which file, of those the message carried. The hash identifies it
        /// with no bookkeeping on either side — it is already what the transfer
        /// is named after on disk.
        hash: [u8; 32],
        offset: u64,
        direct: Option<Direct>,
    },
    /// "No thanks." Also the answer to an offer that arrives mid-transfer.
    FileReject { hash: [u8; 32] },
    /// "I agreed to go direct, but I could not reach you — falling back."
    ///
    /// Needed because the recipient is sitting on a listening socket waiting
    /// for a connection that is never coming, and has no other way to tell that
    /// from a peer who is merely slow. After this, the file arrives as
    /// ordinary [`Message::FileChunk`]s.
    DirectFailed,
    /// File data, in order, starting from the accepted offset.
    FileChunk(Vec<u8>),
    /// No more data. The recipient verifies the hash before keeping anything.
    FileDone,
}

impl Message {
    /// Reject a message that cannot legally be sent, before it reaches the wire.
    ///
    /// Runs on both sides: the sender must not emit one, and the reader must not
    /// hand one up. The limits are what stops a peer from choosing our
    /// allocation sizes, so they are checked on the way in as well as out.
    fn check(&self) -> Result<()> {
        match self {
            Message::Text(body) if body.len() > MAX_TEXT => bail!(
                "text body is {} bytes, over the {MAX_TEXT}-byte limit",
                body.len()
            ),
            Message::FileOffer { name, .. } if name.len() > MAX_NAME => bail!(
                "filename is {} bytes, over the {MAX_NAME}-byte limit",
                name.len()
            ),
            Message::FileChunk(data) if data.len() > MAX_CHUNK => bail!(
                "file chunk is {} bytes, over the {MAX_CHUNK}-byte limit",
                data.len()
            ),
            Message::FileChunk(data) if data.is_empty() => {
                bail!("an empty file chunk says nothing; FileDone ends a transfer")
            }
            Message::Post { pieces, .. } => {
                let text: usize = pieces
                    .iter()
                    .map(|p| match p {
                        Piece::Text(t) => t.len(),
                        Piece::File(_) => 0,
                    })
                    .sum();
                if text > MAX_TEXT {
                    bail!("message text is {text} bytes, over the {MAX_TEXT}-byte limit");
                }
                let files = pieces.iter().filter(|p| matches!(p, Piece::File(_))).count();
                if files > MAX_FILES {
                    bail!("a message carrying {files} files is over the {MAX_FILES} limit");
                }
                for p in pieces {
                    if let Piece::File(f) = p
                        && f.name.len() > MAX_NAME
                    {
                        bail!(
                            "filename is {} bytes, over the {MAX_NAME}-byte limit",
                            f.name.len()
                        );
                    }
                }
                if pieces.is_empty() {
                    bail!("an empty message says nothing");
                }
                Ok(())
            }
            Message::FileAccept {
                direct: Some(d), ..
            } => {
                if d.candidates.is_empty() {
                    bail!("a direct link was agreed to but no address was given");
                }
                if d.candidates.len() > MAX_CANDIDATES {
                    bail!(
                        "the peer offered {} addresses for a direct link, over the \
                         {MAX_CANDIDATES} limit",
                        d.candidates.len()
                    );
                }
                Ok(())
            }
            _ => Ok(()),
        }
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
        let n = match r.read(&mut buf[filled..]).await {
            Ok(n) => n,
            // A peer that hung up is not a failure, even though the transport
            // reports one. See `is_hangup`.
            Err(e) if is_hangup(&e) => 0,
            Err(e) => return Err(e).context("reading from the stream"),
        };
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

/// Is this read error just the other side hanging up?
///
/// Closing a Tor stream is not a clean EOF. `DataWriter::poll_close` sends an
/// END cell with reason `MISC` (`tor-proto-0.44.0/src/stream.rs:82`), and the
/// reading side turns every reason other than `DONE` into an error
/// (`tor-proto-0.44.0/src/client/stream/data.rs:503`). So a peer typing `/bye`
/// arrives here as a failure rather than as end-of-stream.
///
/// Matching on the message is unpleasant, and it is what the transport offers:
/// the error is an `io::Error` whose kind is `Other`, so the kind carries
/// nothing. The same string-matching approach is already used, for the same
/// reason, in `transport::tor::is_key_already_exists`.
///
/// ponytail: if arti ever exposes a typed end-of-stream reason, replace this
/// with it — the whole knowledge lives in this one function.
fn is_hangup(err: &std::io::Error) -> bool {
    let text = err.to_string();
    text.contains("END cell") || text.contains("stream closed")
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

    /// A peer hanging up reaches us as a transport error, and must still read
    /// as the end of the conversation rather than as a fault.
    #[test]
    fn a_tor_hangup_reads_as_end_of_stream() {
        use std::io::Error;

        struct HangsUp;
        impl AsyncRead for HangsUp {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut [u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                std::task::Poll::Ready(Err(Error::other(
                    "Received an END cell with reason MISC",
                )))
            }
        }

        let got = futures::executor::block_on(read_frame(&mut HangsUp)).unwrap();
        assert!(got.is_none(), "a hang-up must be None, not an error");
    }

    /// A real read failure must still be a failure.
    #[test]
    fn a_genuine_read_error_is_not_swallowed() {
        use std::io::{Error, ErrorKind};

        struct Broken;
        impl AsyncRead for Broken {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut [u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                std::task::Poll::Ready(Err(Error::new(ErrorKind::BrokenPipe, "disk on fire")))
            }
        }

        assert!(futures::executor::block_on(read_frame(&mut Broken)).is_err());
    }

    /// A full-size chunk has to fit a frame, or the largest legal transfer
    /// message is one that can never be sent.
    #[test]
    fn a_full_chunk_still_fits_a_frame() {
        let full = Message::FileChunk(vec![0u8; MAX_CHUNK]);
        let mut wire = Vec::new();
        futures::executor::block_on(write_frame(&mut wire, &full)).unwrap();
        assert!(wire.len() < MAX_FRAME, "{} bytes", wire.len());

        let mut read = wire.as_slice();
        let got = futures::executor::block_on(read_frame(&mut read)).unwrap();
        assert_eq!(got, Some(full));
    }

    /// The whole file exchange, back to back on one stream.
    #[test]
    fn a_transfer_round_trips() {
        let sent = vec![
            Message::FileOffer {
                name: "rapport.pdf".into(),
                size: 5,
                hash: [7u8; 32],
                direct: false,
            },
            Message::FileAccept {
                hash: [7u8; 32],
                offset: 2,
                direct: None,
            },
            Message::FileChunk(b"llo".to_vec()),
            Message::FileDone,
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

    /// Every limit that exists to stop a peer choosing our allocation sizes.
    #[test]
    fn oversized_file_messages_are_refused_by_the_sender() {
        for bad in [
            Message::FileChunk(vec![0u8; MAX_CHUNK + 1]),
            Message::FileOffer {
                name: "n".repeat(MAX_NAME + 1),
                size: 0,
                hash: [0u8; 32],
                direct: false,
            },
            // Nothing to write and not an ending: a peer looping on these would
            // keep the transfer open forever.
            Message::FileChunk(Vec::new()),
        ] {
            let mut wire = Vec::new();
            assert!(
                futures::executor::block_on(write_frame(&mut wire, &bad)).is_err(),
                "{bad:?} must not reach the wire"
            );
            assert!(wire.is_empty());
        }
    }

    /// The direct-link negotiation, end to end on one stream.
    #[test]
    fn a_direct_negotiation_round_trips() {
        let sent = vec![
            Message::FileOffer {
                name: "gros.pdf".into(),
                size: 2_400_000,
                hash: [3u8; 32],
                direct: true,
            },
            Message::FileAccept {
                hash: [1u8; 32],
                offset: 0,
                direct: Some(Direct {
                    candidates: vec![
                        "192.168.1.42:51820".parse().unwrap(),
                        "[fe80::1]:51820".parse().unwrap(),
                    ],
                    fingerprint: [9u8; 32],
                }),
            },
            Message::DirectFailed,
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
        assert_eq!(sent, got, "IPv4 and IPv6 addresses must both survive");
    }

    /// The candidate list comes from the network and every entry costs a dial
    /// with a timeout, so its size is not the peer's to choose.
    #[test]
    fn a_direct_answer_must_offer_at_least_one_address_and_not_too_many() {
        let one: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();

        let empty = Message::FileAccept {
            hash: [0u8; 32],
            offset: 0,
            direct: Some(Direct {
                candidates: Vec::new(),
                fingerprint: [0u8; 32],
            }),
        };
        let flood = Message::FileAccept {
            hash: [0u8; 32],
            offset: 0,
            direct: Some(Direct {
                candidates: vec![one; MAX_CANDIDATES + 1],
                fingerprint: [0u8; 32],
            }),
        };
        for bad in [empty, flood] {
            let mut wire = Vec::new();
            assert!(
                futures::executor::block_on(write_frame(&mut wire, &bad)).is_err(),
                "{bad:?} must not reach the wire"
            );
            assert!(wire.is_empty());
        }

        // The plain Tor answer carries no addresses at all, and must stay legal.
        let mut wire = Vec::new();
        futures::executor::block_on(write_frame(
            &mut wire,
            &Message::FileAccept {
                hash: [0u8; 32],
                offset: 12,
                direct: None,
            },
        ))
        .expect("a Tor transfer names no address");
        assert!(!wire.is_empty());
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

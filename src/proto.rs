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

use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use futures::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use tor_hscrypto::pk::{HsId, HsIdKey};
use tor_llcrypto::pk::ed25519;

use crate::identity::Identity;

/// What this build speaks.
///
/// Bump it whenever [`Message`] changes shape in a way an older build would
/// misread — which postcard makes almost every change: the wire carries a
/// variant's *position* in the enum, not its name, so inserting one anywhere
/// but the end shifts everything after it.
///
/// There is no negotiation and no backward compatibility, on purpose. murmure
/// is young enough that maintaining two wire formats would cost more than
/// telling two people to run the same build, and a version that is refused
/// loudly is worth more than one that half-works.
pub const VERSION: u16 = 4;

/// Sent before anything else, so that a stream carrying something other than
/// murmure fails as itself rather than as a nonsensical version number.
const MAGIC: &[u8; 7] = b"murmure";

/// Longest a peer may take to say what it speaks.
///
/// The rendezvous is already paid for by the time this runs, so nine bytes are
/// one round trip away — this is generous by an order of magnitude. What
/// matters is that it is finite: a build with no handshake at all sends
/// nothing, and waiting forever for it is exactly the silent failure the
/// handshake exists to prevent.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Domain separator for the signed challenge. Frozen: changing it invalidates
/// every signature both sides would compute, which is a version bump.
const AUTH_CONTEXT: &[u8] = b"murmure-auth-v1";

/// The opening bytes: magic, version, who we claim to be, and a challenge.
const HELLO_LEN: usize = 7 + 2 + 32 + 32;

/// Agree on a version, then prove to each other who is on the line.
///
/// Returns the peer's `.onion` identity, **verified** — they signed our
/// challenge with the key that address is derived from, so it is theirs or
/// nobody's.
///
/// # Why identity has to be proved here
///
/// An onion service authenticates the server and not the client: a stream
/// arriving at our service comes from someone who could read our descriptor,
/// which restricted discovery narrows to our contacts, and no further. So
/// before this, an incoming call was from "they" — murmure could not name the
/// caller even among people it knows. Presence has nowhere to attach without a
/// name, and neither does anything else that treats one contact differently
/// from another.
///
/// The proof is cheap because the address already *is* an ed25519 public key.
/// There is no certificate, no third party and no new key: each side signs
/// `context || signer || verifier || the verifier's nonce` with the seed it
/// already owns, and the address it claims is the key that check runs against.
///
/// The nonce is what stops a recording of yesterday's handshake from being
/// replayed today. Naming both parties in a fixed order is what stops our own
/// challenge being reflected back at us: the bytes we would have to verify are
/// not the bytes we signed.
///
/// # Why the header is written by hand
///
/// The obvious design is a `Message::Hello` variant, and it does not work:
/// postcard would encode it, so the mis-decoding this guards against would
/// apply to the guard itself. A peer whose enum has a variant inserted above
/// `Hello` would read our version as some other message entirely. A fixed
/// header owes nothing to serde and cannot drift with the enum.
///
/// Both sides send before they read, in both rounds, so nobody blocks waiting
/// for the other to go first.
pub async fn handshake<R, W>(r: &mut R, w: &mut W, me: &Identity) -> Result<HsId>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let my_id = me.onion_address();
    let mut my_nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut my_nonce);

    let mut ours = [0u8; HELLO_LEN];
    ours[..7].copy_from_slice(MAGIC);
    ours[7..9].copy_from_slice(&VERSION.to_le_bytes());
    ours[9..41].copy_from_slice(&id_bytes(&my_id)?);
    ours[41..].copy_from_slice(&my_nonce);
    w.write_all(&ours).await.context("saying who we are")?;
    w.flush().await.context("saying who we are")?;

    // Read in two bites, and the split is deliberate. Whatever else connects to
    // this port — a scanner, a browser, an older murmure — nine bytes is enough
    // to say what it is. Waiting for all seventy-three first would report a
    // short HTTP probe as a truncated read instead of as something that does
    // not speak murmure.
    let mut head = [0u8; 9];
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, r.read_exact(&mut head)).await {
        Err(_) => bail!(
            "the other side never said which version of murmure it speaks — \
             it is probably an older build. Both sides must run the same one."
        ),
        Ok(read) => read.context("reading the other side's opening")?,
    }

    if &head[..7] != MAGIC {
        bail!("whatever answered on that address, it does not speak murmure");
    }
    let their_version = u16::from_le_bytes([head[7], head[8]]);
    if their_version != VERSION {
        bail!(
            "version mismatch: they speak murmure {their_version}, this is murmure {VERSION}. \
             Both sides must run the same build — there is no compatibility between \
             versions yet."
        );
    }

    let mut theirs = [0u8; HELLO_LEN - 9];
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, r.read_exact(&mut theirs)).await {
        Err(_) => bail!("the other side never said which address it claims"),
        Ok(read) => read.context("reading the address the other side claims")?,
    }
    let their_id_bytes: [u8; 32] = theirs[..32].try_into().expect("fixed slice");
    let their_key = ed25519::PublicKey::from_bytes(&their_id_bytes)
        .map_err(|_| anyhow::anyhow!("the address the other side claims is not a valid key"))?;
    let their_id = HsIdKey::from(their_key).id();
    let their_nonce: [u8; 32] = theirs[32..].try_into().expect("fixed slice");

    // We sign the challenge they sent; they sign the one we sent.
    let signed = me.sign(&challenge(&id_bytes(&my_id)?, &their_id_bytes, &their_nonce));
    w.write_all(&signed.to_bytes())
        .await
        .context("proving who we are")?;
    w.flush().await.context("proving who we are")?;

    let mut proof = [0u8; 64];
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, r.read_exact(&mut proof)).await {
        Err(_) => bail!("the other side never proved the address it claims"),
        Ok(read) => read.context("reading the other side's proof")?,
    }
    their_key
        .verify(
            &challenge(&their_id_bytes, &id_bytes(&my_id)?, &my_nonce),
            &ed25519::Signature::from_bytes(&proof),
        )
        .map_err(|_| {
            anyhow::anyhow!(
                "the other side claims an address it cannot prove it owns — \
                 refusing the connection"
            )
        })?;

    Ok(their_id)
}

/// The bytes a signer commits to: who they are, who they are talking to, and
/// the challenge that side chose.
///
/// Order is load-bearing. `signer` and `verifier` swap places between the two
/// sides, so a signature made in one direction cannot be verified in the other
/// — which is what a reflection attack would need.
fn challenge(signer: &[u8; 32], verifier: &[u8; 32], nonce: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(AUTH_CONTEXT.len() + 96);
    msg.extend_from_slice(AUTH_CONTEXT);
    msg.extend_from_slice(signer);
    msg.extend_from_slice(verifier);
    msg.extend_from_slice(nonce);
    msg
}

/// The 32 bytes of an `.onion` identity, which are its ed25519 public key.
fn id_bytes(id: &HsId) -> Result<[u8; 32]> {
    Ok(HsIdKey::try_from(*id)
        .map_err(|_| anyhow::anyhow!("this identity is not a valid ed25519 key"))?
        .to_bytes())
}

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
    /// "I am still here."
    ///
    /// Sent on a timer by both sides of an open connection and answered by
    /// nobody: any frame at all proves the far side is alive, so a reply would
    /// only be a second way to learn the same thing. Swallowed by
    /// [`crate::link`] before it can reach a conversation — a keepalive must
    /// never look like somebody starting to talk.
    ///
    /// Free on a stream that is already open, which is the only place it is
    /// sent. Presence for a contact with no open stream costs a full
    /// rendezvous, and that is what the connection pool exists to avoid.
    Ping,
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
    /// "May I keep a connection open to you, and see when you are up?"
    ///
    /// Being reachable and being watched are different permissions. Restricted
    /// discovery already settles the first — a stranger cannot even read our
    /// descriptor — and this settles the second, which is why it is asked out
    /// loud instead of being assumed from the contacts book.
    PresenceAsk,
    /// "Yes." From here on both sides hold a connection open to each other.
    PresenceYes,
    /// "No", or "not any more". Sent on refusal and on `/presence <name> off`,
    /// and in both cases the sender stops holding a connection open.
    PresenceNo,
    /// "I am not taking this call."
    ///
    /// A connection outlives the call held over it, so nothing about the
    /// *connection* says whether anybody picked up. Without this the caller
    /// types into a conversation the other side never entered, and has no way
    /// to tell that from someone reading slowly.
    CallDecline,
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
/// # The two ways a peer leaves
///
/// `/bye` closes the stream and the circuit stays up long enough to carry the
/// END cell, so the reader sees that. `/quit` ends the whole program: the Tor
/// client is dropped, the circuit goes with it, and what arrives instead is
/// **`NotConnected`** — the stream was pulled out from underneath. Both mean
/// the same thing to the person still sitting there, and only the first used to
/// be recognised, so quitting looked like a fault: "call dropped: reading from
/// the stream: Stream not connected".
///
/// What this deliberately gives up: a circuit that dies on its own — a network
/// drop — now reads as a hang-up too. That distinction is not worth keeping,
/// because nothing on this side can act on it. The peer is gone either way, and
/// calling it a fault when it is usually somebody typing `/quit` is the more
/// misleading of the two.
///
/// Matching on the message is unpleasant, and it is most of what the transport
/// offers: some of these arrive as `ErrorKind::Other` with the reason only in
/// the text. The kind is checked first anyway, because when it *is* set it is
/// the thing that cannot drift. The same string-matching approach is used, for
/// the same reason, in `transport::tor::is_key_already_exists`.
///
/// ponytail: if arti ever exposes a typed end-of-stream reason, replace this
/// with it — the whole knowledge lives in this one function.
fn is_hangup(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    if matches!(
        err.kind(),
        ErrorKind::NotConnected | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
    ) {
        return true;
    }
    let text = err.to_string();
    text.contains("END cell") || text.contains("stream closed") || text.contains("not connected")
}

#[cfg(test)]
mod tests {
    use tokio_util::compat::{TokioAsyncReadCompatExt as _, TokioAsyncWriteCompatExt as _};

    use super::*;

    /// Us, for tests that only need someone to be.
    fn me() -> Identity {
        Identity::for_test([1u8; 32])
    }

    /// The opening a peer on `version` with this identity would send. The
    /// challenge is left zero: a test that never gets as far as the signature
    /// does not care what it was.
    fn hello(version: u16, who: &Identity) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&id_bytes(&who.onion_address()).unwrap());
        out.extend_from_slice(&[0u8; 32]);
        out
    }

    /// Two builds that agree get past the version and on to the identities.
    #[tokio::test]
    async fn matching_versions_agree() {
        let them = Identity::for_test([2u8; 32]);
        let r = hello(VERSION, &them);
        let mut sent = Vec::new();
        // No proof follows, so this stops at the signature — which is far
        // enough to prove the version and the identity were both accepted.
        let _ = handshake(&mut r.as_slice(), &mut sent, &me()).await;
        assert_eq!(
            &sent[..hello(VERSION, &me()).len() - 32],
            &hello(VERSION, &me())[..hello(VERSION, &me()).len() - 32],
            "we announced our version and our address"
        );
    }

    /// The failure the version half exists for: two people who cloned the
    /// repository weeks apart. Without it, postcard decodes their frames
    /// against our enum and the error arrives later wearing the wrong name.
    #[tokio::test]
    async fn a_different_version_is_refused_by_name() {
        let r = hello(VERSION + 1, &Identity::for_test([2u8; 32]));
        let e = handshake(&mut r.as_slice(), &mut Vec::new(), &me())
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains(&(VERSION + 1).to_string()), "names theirs: {e}");
        assert!(e.contains(&VERSION.to_string()), "and ours: {e}");
        assert!(e.contains("same build"), "and says what to do: {e}");
    }

    /// Anything else that connects to the onion port fails as itself.
    #[tokio::test]
    async fn something_that_is_not_murmure_is_told_apart_from_a_version() {
        let r = b"GET / HTTP".to_vec();
        let e = handshake(&mut r.as_slice(), &mut Vec::new(), &me())
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("does not speak murmure"), "{e}");
    }

    /// A build with no handshake sends nothing at all. Waiting forever for it
    /// is the silent failure this replaces, so the wait has to end.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_never_answers_gives_up() {
        // Never ready, never closed: an older build sitting on an open stream
        // with nothing to say.
        let (mine, _theirs) = tokio::io::duplex(1024);
        let (r, w) = tokio::io::split(mine);
        let e = handshake(&mut r.compat(), &mut w.compat_write(), &me())
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("older build"), "{e}");
    }

    /// A peer that says who it is and then goes quiet has still proved
    /// nothing, and the wait for the proof must end too.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_never_proves_itself_gives_up() {
        let (mine, theirs) = tokio::io::duplex(1024);
        let (r, w) = tokio::io::split(mine);
        let (_their_r, their_w) = tokio::io::split(theirs);
        {
            use tokio::io::AsyncWriteExt as _;
            let mut their_w = their_w;
            their_w
                .write_all(&hello(VERSION, &Identity::for_test([2u8; 32])))
                .await
                .unwrap();
            their_w.flush().await.unwrap();
            std::mem::forget(their_w);
        }
        let e = handshake(&mut r.compat(), &mut w.compat_write(), &me())
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("never proved"), "{e}");
    }

    /// A peer that hangs up mid-header is a broken connection, not a version.
    #[tokio::test]
    async fn a_truncated_header_is_an_error() {
        let mut r = &MAGIC[..4];
        assert!(handshake(&mut r, &mut Vec::new(), &me()).await.is_err());
    }

    /// The challenge is what makes a recording useless. Two handshakes from the
    /// same identity commit to different bytes, so yesterday's signature proves
    /// nothing today.
    #[tokio::test]
    async fn every_handshake_asks_a_different_question() {
        let mut first = Vec::new();
        let mut second = Vec::new();
        let r = hello(VERSION, &Identity::for_test([2u8; 32]));
        let _ = handshake(&mut r.as_slice(), &mut first, &me()).await;
        let _ = handshake(&mut r.as_slice(), &mut second, &me()).await;
        assert_ne!(
            first[41..HELLO_LEN],
            second[41..HELLO_LEN],
            "a fixed challenge would make every proof replayable"
        );
    }

    /// Encode messages back-to-back the way a conversation does, then read them
    /// back: order, content and frame boundaries all have to survive.
    #[test]
    fn frames_round_trip_in_sequence() {
        let sent = vec![
            Message::Text("bonjour".into()),
            Message::Ping,
            Message::PresenceAsk,
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


    /// `/quit` on the far side drops the whole Tor client, so the stream is
    /// pulled away rather than closed. It has to read as a hang-up, not as a
    /// fault — this is what put "call dropped: … Stream not connected" on
    /// screen when somebody simply left.
    #[test]
    fn a_peer_quitting_reads_as_end_of_stream() {
        use std::io::{Error, ErrorKind};

        struct Gone(ErrorKind, &'static str);
        impl AsyncRead for Gone {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut [u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                std::task::Poll::Ready(Err(Error::new(self.0, self.1)))
            }
        }

        // The kind, when the transport bothers to set it.
        for kind in [
            ErrorKind::NotConnected,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
        ] {
            let got = futures::executor::block_on(read_frame(&mut Gone(kind, "gone")));
            assert!(got.unwrap().is_none(), "{kind:?} must be a hang-up");
        }

        // And the text, when it does not — which is the case actually observed.
        let mut opaque = Gone(ErrorKind::Other, "Stream not connected");
        assert!(
            futures::executor::block_on(read_frame(&mut opaque))
                .unwrap()
                .is_none()
        );
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

//! One open connection to one peer.
//!
//! A [`Link`] owns everything about a connection except what is said over it:
//! the version handshake, the two tasks that turn a byte stream into a queue of
//! frames, and the teardown. What it deliberately does not own is the
//! conversation — [`crate::chat::run`] borrows a link, and a link outlives the
//! call held over it.
//!
//! That is the whole point of this module. Dialling an onion service takes 7 to
//! 50 seconds (PETS 2025), which used to be the price of every `/call` because
//! the conversation loop owned its stream and closed it on hang-up. A link that
//! survives its call is a `/call` that costs nothing the second time — and it is
//! what presence needs, since knowing a contact is reachable and being able to
//! talk to them are then the same fact rather than two connections.
//!
//! # Errors arrive in order, on purpose
//!
//! The reader sends `Result<Message>` rather than `Message`, so a stream fault
//! is queued *behind* the frames that were already read. Without that ordering,
//! a peer who hangs up immediately after a final frame could have the hang-up
//! observed first, dropping a `FileDone` that turns a pile of chunks into a
//! file. Making the failure part of the same queue means the ordering is the
//! channel's, not something the call loop has to arrange.

use anyhow::{Context as _, Result, bail};
use futures::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tor_hscrypto::pk::HsId;

use crate::identity::Identity;

use crate::proto::{self, Message};

/// How many frames may queue on the way out before the producer waits.
///
/// Waiting is the point: a file is read from disk exactly as fast as the
/// circuit drains, with no buffer growing behind our back.
const OUTBOX: usize = 32;

/// How many frames may queue on the way in.
///
/// Same size as the outbox and for the same reason — a peer that floods us is
/// slowed at the socket rather than in memory, and 32 chunks is about 2 MB.
const INBOX: usize = 32;

/// A connection to a peer, framed and version-checked.
///
/// The two channels are public because a caller needs both at once — sending a
/// reply while waiting on the next frame — and borrowing them through methods
/// would ask the borrow checker to prove that two `&mut self` calls do not
/// overlap, which they do.
pub struct Link {
    /// Who is on the other end, proved rather than claimed.
    ///
    /// The one fact a caller cannot work out for itself: an onion service is
    /// told nothing about its client, so without the handshake's signature an
    /// incoming connection would be from nobody in particular.
    pub peer: HsId,
    /// Frames to send. Cloneable, so a transfer task can hold one.
    pub outbox: mpsc::Sender<Message>,
    /// Frames received, in order, ending with the reason the peer stopped.
    ///
    /// `None` from `recv` is a clean hang-up; `Some(Err(_))` is a fault.
    pub inbox: mpsc::Receiver<Result<Message>>,
    reading: JoinHandle<()>,
    writing: JoinHandle<Result<()>>,
}

impl Link {
    /// Agree on a version, find out who this is, then start framing.
    ///
    /// The handshake happens here rather than in the conversation loop because
    /// it belongs to the connection: it is asked once, when the connection is
    /// made, not once per call held over it.
    pub async fn open<R, W>(reader: R, writer: W, me: &Identity) -> Result<Self>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let mut reader = reader;
        let mut writer = writer;
        let peer = proto::handshake(&mut reader, &mut writer, me).await?;

        let (outbox, mut queued) = mpsc::channel::<Message>(OUTBOX);
        let (inbox_tx, inbox) = mpsc::channel::<Result<Message>>(INBOX);

        let writing = tokio::spawn(async move {
            while let Some(msg) = queued.recv().await {
                proto::write_frame(&mut writer, &msg).await?;
            }
            Ok(())
        });

        // Decides nothing: every frame goes to whoever holds the inbox, which
        // owns the state that says what a frame means.
        let reading = tokio::spawn(async move {
            loop {
                match proto::read_frame(&mut reader).await {
                    // A clean end. Dropping the sender is the signal; there is
                    // nothing to report.
                    Ok(None) => break,
                    Ok(Some(msg)) => {
                        if inbox_tx.send(Ok(msg)).await.is_err() {
                            break;
                        }
                    }
                    // Queued behind the frames already read, so the reason the
                    // peer stopped never overtakes what they said.
                    Err(e) => {
                        let _ = inbox_tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        });

        Ok(Self {
            peer,
            outbox,
            inbox,
            reading,
            writing,
        })
    }

    /// Close the connection and report whether everything we queued got out.
    ///
    /// Order matters. The reader holds the inbox sender, and the writer outlives
    /// its queue only while a sender exists: stop the reader first, then drop
    /// ours, or awaiting the writer waits on a channel nothing will close.
    ///
    /// `peer_hung_up` says whether a failed write is news. When the peer has
    /// already gone, a write failing on the way out is the normal race and not
    /// a fault worth showing anyone.
    pub async fn close(self, peer_hung_up: bool) -> Result<()> {
        self.reading.abort();
        drop(self.outbox);
        match self.writing.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) if peer_hung_up => {
                tracing::debug!("write at hang-up: {e:#}");
                Ok(())
            }
            Ok(Err(e)) => Err(e).context("sending the last of what was queued"),
            Err(e) => bail!("the writer task panicked: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::compat::{TokioAsyncReadCompatExt as _, TokioAsyncWriteCompatExt as _};

    /// Two links over one duplex, which is the arrangement every real
    /// conversation uses.
    async fn pair() -> (Link, Link) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        // Two seeds, so the two sides are genuinely different people and the
        // handshake has something to tell apart.
        let alice = Identity::for_test([1u8; 32]);
        let bob = Identity::for_test([2u8; 32]);
        // Both at once: the handshake writes before it reads, so opening them
        // one after the other would deadlock on a duplex with a small buffer.
        let (a, b) = tokio::join!(
            Link::open(ar.compat(), aw.compat_write(), &alice),
            Link::open(br.compat(), bw.compat_write(), &bob)
        );
        (a.unwrap(), b.unwrap())
    }

    /// Each side learns who the other is, and neither is told — both prove it.
    ///
    /// This is what an onion service cannot do on its own: the caller is
    /// anonymous by construction, so before the handshake signed anything, an
    /// incoming connection was from nobody in particular.
    #[tokio::test]
    async fn both_sides_come_away_knowing_who_they_are_talking_to() {
        let (a, b) = pair().await;
        assert_eq!(a.peer, Identity::for_test([2u8; 32]).onion_address());
        assert_eq!(b.peer, Identity::for_test([1u8; 32]).onion_address());
    }

    /// Claiming an address is not owning it. Here the claim is a real murmure
    /// identity's address, sent by someone who does not hold that seed — which
    /// is exactly the impersonation the signature exists to refuse.
    #[tokio::test]
    async fn an_address_that_cannot_be_proved_is_refused() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);

        let victim = Identity::for_test([1u8; 32]);
        let liar = Identity::for_test([9u8; 32]);
        let other = Identity::for_test([2u8; 32]);

        // The liar opens the connection with the victim's address in the
        // header and their own key underneath. The header is not the part that
        // has to be right.
        let forged = {
            use futures::io::AsyncWriteExt as _;
            let mut w = aw.compat_write();
            let mut hello = [0u8; 7 + 2 + 32 + 32];
            hello[..7].copy_from_slice(b"murmure");
            hello[7..9].copy_from_slice(&crate::proto::VERSION.to_le_bytes());
            hello[9..41].copy_from_slice(
                &tor_hscrypto::pk::HsIdKey::try_from(victim.onion_address())
                    .unwrap()
                    .to_bytes(),
            );
            tokio::spawn(async move {
                let _ = w.write_all(&hello).await;
                let _ = w.flush().await;
                // Whatever it signs next, it cannot sign with the victim's key.
                let _ = w.write_all(&liar.sign(b"anything at all").to_bytes()).await;
                let _ = w.flush().await;
                // Hold the write half open so the far side fails on the proof
                // rather than on a closed stream.
                std::future::pending::<()>().await;
            })
        };

        let opened = Link::open(br.compat(), bw.compat_write(), &other).await;
        forged.abort();
        let refused = opened.err().expect("a forged address must not open a link");
        assert!(
            refused.to_string().contains("cannot prove"),
            "the refusal has to name the reason: {refused:#}"
        );
        drop(ar);
    }

    #[tokio::test]
    async fn a_frame_sent_on_one_side_arrives_on_the_other() {
        let (a, mut b) = pair().await;
        a.outbox.send(Message::Text("bonjour".into())).await.unwrap();
        assert_eq!(
            b.inbox.recv().await.unwrap().unwrap(),
            Message::Text("bonjour".into())
        );
    }

    /// The property the whole module exists for: a call ending is not the
    /// connection ending. Nothing here closes the link between the two
    /// exchanges, and the second one still arrives.
    #[tokio::test]
    async fn a_link_outlives_what_is_said_over_it() {
        let (a, mut b) = pair().await;

        a.outbox.send(Message::Text("first call".into())).await.unwrap();
        assert_eq!(
            b.inbox.recv().await.unwrap().unwrap(),
            Message::Text("first call".into())
        );

        a.outbox.send(Message::Text("second call".into())).await.unwrap();
        assert_eq!(
            b.inbox.recv().await.unwrap().unwrap(),
            Message::Text("second call".into())
        );
    }

    /// Closing one side ends the other's inbox rather than leaving it waiting.
    #[tokio::test]
    async fn closing_one_side_ends_the_other_s_inbox() {
        let (a, mut b) = pair().await;
        a.close(false).await.unwrap();
        assert!(b.inbox.recv().await.is_none(), "a closed link must not hang");
    }

    /// The end of the stream never overtakes what was said before it.
    ///
    /// This is the ordering the conversation loop used to arrange by hand, with
    /// a biased select and a guard flag, because a peer hanging up right after
    /// a final frame made both events ready at once — and taking the hang-up
    /// first dropped the `FileDone` that turns a pile of chunks into a file.
    /// Here it is the channel's ordering and cannot be got wrong.
    #[tokio::test]
    async fn everything_said_arrives_before_the_end_of_the_stream() {
        let (alice, mut bob) = pair().await;

        alice.outbox.send(Message::Text("said first".into())).await.unwrap();
        alice.outbox.send(Message::Text("said last".into())).await.unwrap();
        // Hangs up immediately: both frames are still in flight.
        alice.close(false).await.unwrap();

        assert_eq!(
            bob.inbox.recv().await.unwrap().unwrap(),
            Message::Text("said first".into())
        );
        assert_eq!(
            bob.inbox.recv().await.unwrap().unwrap(),
            Message::Text("said last".into())
        );
        assert!(bob.inbox.recv().await.is_none(), "and only then, the end");
    }
}

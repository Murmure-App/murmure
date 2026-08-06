//! Connections kept open between calls.
//!
//! A [`Link`] used to exist for exactly as long as the conversation held over
//! it. Reaching an onion service costs 7 to 50 seconds (PETS 2025), so hanging
//! up threw away the expensive part and the next `/call` paid for it again.
//! The pool is the place a link goes when nobody is talking over it.
//!
//! Nothing here dials. A link enters the pool because a call already happened —
//! we placed one, or someone placed one to us — and stays until the peer goes
//! away. Deciding to open a connection *before* anyone wants to talk is
//! presence, it needs both sides to have agreed to it, and that agreement does
//! not exist yet.
//!
//! # Why an idle link still has to be watched
//!
//! Both ends keep the link, so the far side can start talking again with no
//! warning: their first frame is the whole announcement. Something must be
//! waiting on every idle inbox, or that frame sits unread and the call looks
//! like it was never placed.

use std::collections::HashMap;

use anyhow::Result;
use tor_hscrypto::pk::HsId;

use crate::link::Link;
use crate::proto::Message;

/// Every connection that is open but not in use.
///
/// Keyed by the peer's proved identity rather than by contact name: the name is
/// ours and can be changed with `/forget`, while the key is what the far side
/// signed with and is the only thing two links can be told apart by.
#[derive(Default)]
pub struct Pool {
    idle: HashMap<HsId, Link>,
}

impl Pool {
    /// Hand a link back when the call over it ends.
    ///
    /// Replaces any earlier link to the same peer, which is what should happen:
    /// a second connection to someone we are already connected to means the
    /// first one is stale.
    pub fn keep(&mut self, link: Link) {
        self.idle.insert(link.peer, link);
    }

    /// Take the open connection to `peer`, if there is one.
    pub fn take(&mut self, peer: &HsId) -> Option<Link> {
        self.idle.remove(peer)
    }

    /// Wait until one idle connection has something on it, and say which.
    ///
    /// [`None`] means that peer's stream ended while nobody was talking over
    /// it; the link is spent and the caller should drop it. `Some` is the first
    /// frame of a conversation the far side just started — already off the
    /// wire, so whoever runs that conversation has to be given it.
    ///
    /// Cancel-safe, which is what makes it usable as a `select!` arm:
    /// [`tokio::sync::mpsc::Receiver::recv`] takes nothing off a channel it is
    /// dropped while polling, so the losing branches lose nothing.
    pub async fn ready(&mut self) -> (HsId, Option<Result<Message>>) {
        if self.idle.is_empty() {
            // A branch that resolved instantly here would spin the idle loop
            // at whatever speed the CPU allows. Never resolving is correct:
            // with nothing open there is nothing this arm can ever report.
            return std::future::pending().await;
        }
        let waiting = self.idle.iter_mut().map(|(peer, link)| {
            let peer = *peer;
            Box::pin(async move { (peer, link.inbox.recv().await) })
        });
        futures::future::select_all(waiting).await.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use tokio_util::compat::{TokioAsyncReadCompatExt as _, TokioAsyncWriteCompatExt as _};

    /// Two ends of one connection, both already handshaken.
    async fn pair(a_seed: [u8; 32], b_seed: [u8; 32]) -> (Link, Link) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        let (one, two) = (Identity::for_test(a_seed), Identity::for_test(b_seed));
        let (a, b) = tokio::join!(
            Link::open(ar.compat(), aw.compat_write(), &one),
            Link::open(br.compat(), bw.compat_write(), &two)
        );
        (a.unwrap(), b.unwrap())
    }

    /// An empty pool waits rather than reporting nothing over and over, which
    /// is the difference between an idle program and one pinning a core.
    #[tokio::test(start_paused = true)]
    async fn an_empty_pool_never_reports() {
        let mut pool = Pool::default();
        let waited = tokio::time::timeout(std::time::Duration::from_secs(3600), pool.ready()).await;
        assert!(waited.is_err(), "an empty pool must have nothing to say");
    }

    /// The point of the module: a link outlives the call, and is there next
    /// time under the identity the far side proved.
    #[tokio::test]
    async fn a_kept_link_is_found_again_by_who_the_peer_proved_to_be() {
        let (alice_side, _bob_side) = pair([1u8; 32], [2u8; 32]).await;
        let bob = alice_side.peer;

        let mut pool = Pool::default();
        pool.keep(alice_side);
        assert!(pool.take(&bob).is_some(), "the link should still be open");
        assert!(pool.take(&bob).is_none(), "and only handed out once");
    }

    /// A peer who starts talking on a connection nobody is using is heard.
    #[tokio::test]
    async fn a_frame_on_an_idle_link_names_who_sent_it() {
        let (alice_side, bob_side) = pair([1u8; 32], [2u8; 32]).await;
        let bob = alice_side.peer;

        let mut pool = Pool::default();
        pool.keep(alice_side);
        bob_side.outbox.send(Message::Text("still there?".into())).await.unwrap();

        let (who, frame) = pool.ready().await;
        assert_eq!(who, bob);
        assert_eq!(frame.unwrap().unwrap(), Message::Text("still there?".into()));
    }

    /// Several open links, and the one that speaks is the one reported.
    #[tokio::test]
    async fn the_pool_watches_every_idle_link_at_once() {
        let (to_bob, bob) = pair([1u8; 32], [2u8; 32]).await;
        let (to_carol, carol) = pair([1u8; 32], [3u8; 32]).await;
        let carol_id = to_carol.peer;

        let mut pool = Pool::default();
        pool.keep(to_bob);
        pool.keep(to_carol);

        // Bob stays quiet; nothing about him should keep Carol from being heard.
        carol.outbox.send(Message::Text("it is me".into())).await.unwrap();
        let (who, frame) = pool.ready().await;
        assert_eq!(who, carol_id);
        assert_eq!(frame.unwrap().unwrap(), Message::Text("it is me".into()));
        drop(bob);
    }

    /// A peer going away while nobody is talking is reported as the end of that
    /// link, not left to be discovered by a `/call` that quietly does nothing.
    #[tokio::test]
    async fn a_peer_leaving_an_idle_link_is_noticed() {
        let (to_bob, bob) = pair([1u8; 32], [2u8; 32]).await;
        let bob_id = to_bob.peer;

        let mut pool = Pool::default();
        pool.keep(to_bob);
        bob.close(false).await.unwrap();

        let (who, frame) = pool.ready().await;
        assert_eq!(who, bob_id);
        assert!(frame.is_none(), "a closed stream ends the link");
    }
}

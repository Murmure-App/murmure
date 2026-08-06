//! Connections kept open between calls.
//!
//! A [`Link`] used to exist for exactly as long as the conversation held over
//! it. Reaching an onion service costs 7 to 50 seconds (PETS 2025), so hanging
//! up threw away the expensive part and the next `/call` paid for it again.
//! The pool is the place a link goes when nobody is talking over it.
//!
//! A link enters the pool one of two ways. Either a call already happened — we
//! placed one, or someone placed one to us — or presence was agreed with that
//! contact, in which case [`Pool::reach`] opens the connection before anybody
//! asks for it. The second one is the whole of presence: holding a connection
//! open *is* being visible, and losing it is going offline.
//!
//! Nothing is dialled without that agreement. A contact who has not said yes is
//! never connected to on their behalf, which is why this module takes an
//! explicit `reach` call rather than walking the contacts book itself.
//!
//! # Why an idle link still has to be watched
//!
//! Both ends keep the link, so the far side can start talking again with no
//! warning: their first frame is the whole announcement. Something must be
//! waiting on every idle inbox, or that frame sits unread and the call looks
//! like it was never placed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tor_hscrypto::pk::HsId;

use crate::identity::Identity;
use crate::link::Link;
use crate::proto::Message;
use crate::transport::tor;

/// How long one background dial may take before it is given up on.
///
/// Shorter than the four minutes `/call` allows, and for the opposite reason:
/// nobody is waiting. A dial that has not landed by now is better retried on
/// the next sweep than left holding a circuit.
const DIAL_AHEAD: Duration = Duration::from_secs(120);

/// How many frames may wait for a connection that does not exist yet.
///
/// This is not the offline outbox — that is its own thing, and it is sealed to
/// disk. This is a handful of presence frames waiting for a dial to land, and
/// the cap is here so that a contact who never answers cannot make it grow.
const WAITING: usize = 4;

/// What one turn of [`Pool::ready`] found.
pub enum Heard {
    /// A frame arrived on a connection nobody was talking over. There is no
    /// "incoming call" to answer: this frame *is* the call starting.
    Frame(HsId, Message),
    /// A connection ended. Already removed from the pool by the time this is
    /// returned — the caller cannot forget to.
    Lost(HsId),
    /// A background dial landed, and that contact is now reachable instantly.
    Reached(HsId),
}

/// Every connection that is open but not in use.
///
/// Keyed by the peer's proved identity rather than by contact name: the name is
/// ours and can be changed with `/forget`, while the key is what the far side
/// signed with and is the only thing two links can be told apart by.
pub struct Pool {
    idle: HashMap<HsId, Link>,
    /// Dials in flight, so one contact is never dialled twice at once and a
    /// withdrawn agreement can cancel one already running.
    dialling: HashMap<HsId, JoinHandle<()>>,
    /// Frames with nowhere to go yet, per peer. Drained the moment a
    /// connection to that peer exists.
    waiting: HashMap<HsId, Vec<Message>>,
    landed: mpsc::Receiver<(HsId, Result<Link>)>,
    lands: mpsc::Sender<(HsId, Result<Link>)>,
}

impl Pool {
    pub fn new() -> Self {
        // One slot per contact anyone would plausibly agree with, and dials are
        // taken off it immediately in any case.
        let (lands, landed) = mpsc::channel(16);
        Self {
            idle: HashMap::new(),
            dialling: HashMap::new(),
            waiting: HashMap::new(),
            landed,
            lands,
        }
    }

    /// Take a link into the pool, and hand it anything that was waiting for it.
    ///
    /// The one door in, whether the link came from a call that just ended or
    /// from a dial that just landed. Both have to drain [`Pool::send`]'s queue:
    /// a `/presence` typed during a call would otherwise sit there for ever,
    /// because the connection it was waiting for is the one the call was on.
    ///
    /// Replaces any earlier link to the same peer, which is what should happen:
    /// a second connection to someone we are already connected to means the
    /// first one is stale.
    ///
    /// Returns whether this peer went from unconnected to connected. Both sides
    /// of a presence agreement dial each other, so without this the two
    /// connections that result would each announce the same person arriving.
    pub async fn keep(&mut self, link: Link) -> bool {
        if let Some(queued) = self.waiting.remove(&link.peer) {
            for msg in queued {
                if link.outbox.send(msg).await.is_err() {
                    break;
                }
            }
        }
        self.idle.insert(link.peer, link).is_none()
    }

    /// Take the open connection to `peer`, if there is one.
    pub fn take(&mut self, peer: &HsId) -> Option<Link> {
        self.idle.remove(peer)
    }

    /// Is there an open connection to this peer right now?
    pub fn holds(&self, peer: &HsId) -> bool {
        self.idle.contains_key(peer)
    }

    /// Open a connection to `peer` in the background, unless one already exists
    /// or is on its way.
    ///
    /// Returns at once: the dial takes 7 to 50 seconds and the caller is the
    /// idle loop, which has a keyboard to answer. The result comes back through
    /// [`Pool::ready`].
    ///
    /// Only ever called for a contact who agreed to presence. That is not
    /// enforced here — the contacts book is the thing that knows — but it is
    /// the reason this is a method someone calls rather than something the pool
    /// does on its own.
    pub fn reach(&mut self, client: &tor::Client, peer: HsId, me: &Arc<Identity>) {
        if self.idle.contains_key(&peer) || self.dialling.contains_key(&peer) {
            return;
        }
        let (client, me, lands) = (client.clone(), me.clone(), self.lands.clone());
        let dial = tokio::spawn(async move {
            let opened = async {
                // Silent about its attempts: nobody asked for this connection,
                // so nobody should have to read about it failing.
                let stream = tor::dial_retrying(&client, peer, DIAL_AHEAD, |_, _| {}).await?;
                let (reader, writer) = stream.split();
                let link = Link::open(reader, writer, &me).await?;
                // We dialled an address and something proved a different key.
                // Refused for the same reason `/call` refuses it: the key is
                // what was signed for.
                if link.peer != peer {
                    anyhow::bail!("the far side proved a different key than the one dialled");
                }
                Ok(link)
            }
            .await;
            let _ = lands.send((peer, opened)).await;
        });
        self.dialling.insert(peer, dial);
    }

    /// Send a frame to `peer`, or hold it until there is a connection to send
    /// it on.
    ///
    /// A presence request is the thing this exists for: it is asked of somebody
    /// who is, by definition, not yet someone we hold a connection to.
    pub async fn send(&mut self, peer: HsId, msg: Message) {
        let msg = match self.idle.get(&peer) {
            Some(link) => match link.outbox.send(msg).await {
                Ok(()) => return,
                // The link is on its way out and the reader has not noticed
                // yet. Queue it for the connection that replaces this one.
                Err(returned) => returned.0,
            },
            None => msg,
        };
        let queue = self.waiting.entry(peer).or_default();
        if queue.len() < WAITING {
            queue.push(msg);
        }
    }

    /// Drop everything to do with this peer: the connection, any dial on its
    /// way, and anything queued for it.
    ///
    /// What `/forget` and the end of a presence agreement both mean. The link
    /// is closed rather than dropped so the last frame queued on it — the
    /// `PresenceNo` that says why — still gets out.
    pub async fn forget(&mut self, peer: &HsId) {
        if let Some(dial) = self.dialling.remove(peer) {
            dial.abort();
        }
        self.waiting.remove(peer);
        if let Some(link) = self.idle.remove(peer)
            && let Err(e) = link.close(false).await
        {
            tracing::debug!("closing a connection we no longer want: {e:#}");
        }
    }

    /// Wait until something happens on a connection we hold or are opening.
    ///
    /// Cancel-safe, which is what makes it usable as a `select!` arm:
    /// [`tokio::sync::mpsc::Receiver::recv`] takes nothing off a channel it is
    /// dropped while polling, so the losing branches lose nothing.
    pub async fn ready(&mut self) -> Heard {
        loop {
            let event = {
                // Destructured, because the two halves are polled at once and
                // borrowing them through `self` twice is not something the
                // borrow checker can be talked into.
                let Pool { idle, landed, .. } = self;
                if idle.is_empty() {
                    // A branch that resolved instantly would spin the idle loop
                    // at whatever speed the CPU allows. With nothing open there
                    // is only ever a dial to wait for.
                    Seen::Landed(landed.recv().await)
                } else {
                    let watching = idle.iter_mut().map(|(peer, link)| {
                        let peer = *peer;
                        Box::pin(async move { (peer, link.inbox.recv().await) })
                    });
                    tokio::select! {
                        landing = landed.recv() => Seen::Landed(landing),
                        (heard, ..) = futures::future::select_all(watching) => {
                            Seen::Frame(heard.0, heard.1)
                        }
                    }
                }
            };

            match event {
                Seen::Frame(peer, Some(Ok(msg))) => return Heard::Frame(peer, msg),
                Seen::Frame(peer, ended) => {
                    if let Some(Err(e)) = ended {
                        tracing::debug!("a held connection ended: {e:#}");
                    }
                    self.idle.remove(&peer);
                    return Heard::Lost(peer);
                }
                // We hold a sender for as long as the pool exists, so the
                // channel cannot be closed from under us.
                Seen::Landed(None) => unreachable!("the pool owns a sender for this channel"),
                Seen::Landed(Some((peer, outcome))) => {
                    self.dialling.remove(&peer);
                    match outcome {
                        Ok(link) => {
                            // Not fresh means their connection to us landed
                            // first and has already been announced.
                            if self.keep(link).await {
                                return Heard::Reached(peer);
                            }
                            continue;
                        }
                        // Not news: a contact who is out is the ordinary case,
                        // and the next sweep tries again. Saying so on screen
                        // would be a running commentary on who is offline.
                        Err(e) => {
                            tracing::debug!("dialling a contact ahead of time: {e:#}");
                            continue;
                        }
                    }
                }
            }
        }
    }
}

/// One turn of the wait, before the pool has done anything about it.
enum Seen {
    Frame(HsId, Option<Result<Message>>),
    Landed(Option<(HsId, Result<Link>)>),
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
        let mut pool = Pool::new();
        let waited = tokio::time::timeout(Duration::from_secs(3600), pool.ready()).await;
        assert!(waited.is_err(), "an empty pool must have nothing to say");
    }

    /// The point of the module: a link outlives the call, and is there next
    /// time under the identity the far side proved.
    #[tokio::test]
    async fn a_kept_link_is_found_again_by_who_the_peer_proved_to_be() {
        let (alice_side, _bob_side) = pair([1u8; 32], [2u8; 32]).await;
        let bob = alice_side.peer;

        let mut pool = Pool::new();
        pool.keep(alice_side).await;
        assert!(pool.take(&bob).is_some(), "the link should still be open");
        assert!(pool.take(&bob).is_none(), "and only handed out once");
    }

    /// A peer who starts talking on a connection nobody is using is heard.
    #[tokio::test]
    async fn a_frame_on_an_idle_link_names_who_sent_it() {
        let (alice_side, bob_side) = pair([1u8; 32], [2u8; 32]).await;
        let bob = alice_side.peer;

        let mut pool = Pool::new();
        pool.keep(alice_side).await;
        bob_side.outbox.send(Message::Text("still there?".into())).await.unwrap();

        let Heard::Frame(who, msg) = pool.ready().await else {
            panic!("a frame on an idle link is a call starting, nothing else");
        };
        assert_eq!(who, bob);
        assert_eq!(msg, Message::Text("still there?".into()));
    }

    /// Several open links, and the one that speaks is the one reported.
    #[tokio::test]
    async fn the_pool_watches_every_idle_link_at_once() {
        let (to_bob, bob) = pair([1u8; 32], [2u8; 32]).await;
        let (to_carol, carol) = pair([1u8; 32], [3u8; 32]).await;
        let carol_id = to_carol.peer;

        let mut pool = Pool::new();
        pool.keep(to_bob).await;
        pool.keep(to_carol).await;

        // Bob stays quiet; nothing about him should keep Carol from being heard.
        carol.outbox.send(Message::Text("it is me".into())).await.unwrap();
        let Heard::Frame(who, msg) = pool.ready().await else {
            panic!("Carol spoke; that is what should have been heard");
        };
        assert_eq!(who, carol_id);
        assert_eq!(msg, Message::Text("it is me".into()));
        drop(bob);
    }

    /// A presence request is asked of somebody we are not connected to yet —
    /// that is what makes it a request — so it has to survive the wait.
    #[tokio::test]
    async fn a_frame_with_nowhere_to_go_waits_for_a_connection() {
        let (to_bob, mut bob) = pair([1u8; 32], [2u8; 32]).await;
        let bob_id = to_bob.peer;

        let mut pool = Pool::new();
        // Nothing open to Bob: the pool is empty and the link is still ours.
        pool.send(bob_id, Message::PresenceAsk).await;

        // The connection arrives — here from a call ending, which is the case
        // that used to lose it: `/presence bob` typed during a call to bob is
        // waiting for the very connection the call was using.
        pool.keep(to_bob).await;

        assert_eq!(
            bob.inbox.recv().await.unwrap().unwrap(),
            Message::PresenceAsk,
            "the request must go out as soon as there is something to send it on"
        );
    }

    /// A contact who never answers must not be able to make us grow.
    #[tokio::test]
    async fn frames_waiting_on_a_peer_who_never_answers_are_capped() {
        let (to_bob, mut bob) = pair([1u8; 32], [2u8; 32]).await;
        let bob_id = to_bob.peer;

        let mut pool = Pool::new();
        for _ in 0..WAITING * 10 {
            pool.send(bob_id, Message::PresenceAsk).await;
        }
        pool.keep(to_bob).await;

        let mut arrived = 0;
        while tokio::time::timeout(Duration::from_millis(50), bob.inbox.recv())
            .await
            .is_ok_and(|f| f.is_some())
        {
            arrived += 1;
        }
        assert_eq!(arrived, WAITING, "the queue is bounded, and stays bounded");
    }

    /// A peer going away while nobody is talking is reported as the end of that
    /// link, not left to be discovered by a `/call` that quietly does nothing.
    #[tokio::test]
    async fn a_peer_leaving_an_idle_link_is_noticed() {
        let (to_bob, bob) = pair([1u8; 32], [2u8; 32]).await;
        let bob_id = to_bob.peer;

        let mut pool = Pool::new();
        pool.keep(to_bob).await;
        bob.close(false).await.unwrap();

        let Heard::Lost(who) = pool.ready().await else {
            panic!("a closed stream is a connection lost");
        };
        assert_eq!(who, bob_id);
        assert!(!pool.holds(&bob_id), "and the pool must not keep offering it");
    }
}

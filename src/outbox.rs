//! Messages written to somebody who was not there, kept until they are.
//!
//! This is the piece that makes murmure stop being a phone call. Before it, a
//! message could only exist while both people were connected at the same
//! moment; now one that cannot be delivered is sealed on the sender's disk and
//! goes out when the recipient next appears.
//!
//! # Why it stays with the sender
//!
//! The two obvious places to leave an undelivered message are both worse than
//! not having the feature:
//!
//! - **A server** ends "no server anyone operates", and whoever runs it learns
//!   who writes to whom — the one thing murmure exists to hide.
//! - **At your contacts**, relayed, is worse still: it tells your friends when
//!   you are writing to somebody who is not them.
//!
//! Keeping it with the sender costs one thing and buys the rest: the message
//! only moves when both people are online at *some* point, not the same one.
//! Nobody else ever holds it.
//!
//! # Delivery is confirmed, not assumed
//!
//! A message is removed here only when the recipient says they have it. Putting
//! a frame on a link is not delivery — the link can die between the write and
//! the far end — and a message dropped silently is the failure nobody forgives.
//!
//! The recipient's side of that is a per-sender high-water mark in the contacts
//! book, so a lost acknowledgement costs a redelivery and never a duplicate.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::proto::Message;
use crate::store;

/// Key-derivation context for the outbox file. Frozen: changing it makes every
/// existing outbox unreadable.
const KEY_CONTEXT: &str = "murmure 2026 outbox";

/// How many undelivered messages may pile up for one contact.
///
/// A queue with no ceiling is a disk-filling bug waiting for somebody who never
/// comes back. When the ceiling is hit the *oldest* is dropped and the sender is
/// told, because a message that vanishes without a word is the one failure this
/// whole module exists to avoid.
const MAX_WAITING: usize = 64;

/// One message waiting for its recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Waiting {
    /// Ours, and increasing for ever. It is what the recipient acknowledges,
    /// and what lets them tell a redelivery from something new.
    pub id: u64,
    /// When it was written, in seconds since the epoch. Travels with the
    /// message: one delivered a week late must not read as one just said.
    pub at: u64,
    pub body: String,
}

/// Everything written and not yet delivered, sealed on disk.
///
/// Keyed by `.onion` address rather than by contact name, so renaming somebody
/// — or forgetting and re-adding them — does not strand what was written to
/// them.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Outbox {
    queued: BTreeMap<String, Vec<Waiting>>,
    /// The next id to hand out. Persisted, and only ever increases: the
    /// recipient uses it to reject what they have already seen, so an id that
    /// went backwards would make new messages look old.
    next: u64,
    #[serde(skip)]
    path: PathBuf,
    #[serde(skip)]
    key: Zeroizing<[u8; 32]>,
}

impl Outbox {
    /// Open the outbox at `path`, or start an empty one.
    pub fn open(path: &Path, identity: &crate::identity::Identity) -> Result<Self> {
        let key = identity.derive_key(KEY_CONTEXT);
        let mut outbox = match store::read_sealed(path, &key)? {
            Some(plaintext) => postcard::from_bytes::<Outbox>(&plaintext).map_err(|e| {
                anyhow::anyhow!(
                    "the outbox at {} is unreadable: {e}\n\
                     It was written by an older murmure. Delete the file to start a \
                     new one — anything still waiting in it is lost.",
                    path.display()
                )
            })?,
            None => Outbox::default(),
        };
        outbox.path = path.to_path_buf();
        outbox.key = key;
        Ok(outbox)
    }

    fn save(&self) -> Result<()> {
        // What people wrote, in the clear, for exactly as long as sealing takes.
        let plaintext = Zeroizing::new(
            postcard::to_stdvec(self).map_err(|e| anyhow::anyhow!("encoding the outbox: {e}"))?,
        );
        store::write_sealed(&self.path, &self.key, &plaintext)
    }

    /// Put a message by for `address`. Returns the number dropped to make room.
    ///
    /// Refused here if it is too long to ever travel. [`Message::check`] would
    /// refuse it at the wire instead, which is far worse than it sounds: the
    /// write fails, so no acknowledgement comes back, so it stays at the head
    /// of the queue and kills the writer on every future connection to that
    /// contact — taking everything queued behind it with it.
    pub fn queue(&mut self, address: &str, body: String) -> Result<usize> {
        if body.len() > crate::proto::MAX_TEXT {
            bail!(
                "that message is {} bytes, over the {}-byte limit. \
                 Shorten it, or send it as a file during a call.",
                body.len(),
                crate::proto::MAX_TEXT
            );
        }
        let id = self.next;
        self.next += 1;
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();

        let queue = self.queued.entry(address.trim().to_owned()).or_default();
        queue.push(Waiting { id, at, body });
        // Oldest first: what somebody wrote ten minutes ago is likelier to still
        // matter than what they wrote last month.
        let dropped = queue.len().saturating_sub(MAX_WAITING);
        queue.drain(..dropped);
        self.save()?;
        Ok(dropped)
    }

    /// Everything waiting for `address`, oldest first, as frames.
    pub fn frames_for(&self, address: &str) -> Vec<Message> {
        self.queued
            .get(address.trim())
            .into_iter()
            .flatten()
            .map(|w| Message::Left {
                id: w.id,
                at: w.at,
                body: w.body.clone(),
            })
            .collect()
    }

    /// The recipient has it. Drop it, and say whether there was one to drop.
    ///
    /// An unknown id is not an error: an acknowledgement can arrive twice, and
    /// the second one means the same thing as the first.
    pub fn delivered(&mut self, address: &str, id: u64) -> Result<bool> {
        let Some(queue) = self.queued.get_mut(address.trim()) else {
            return Ok(false);
        };
        let Some(at) = queue.iter().position(|w| w.id == id) else {
            return Ok(false);
        };
        queue.remove(at);
        if queue.is_empty() {
            self.queued.remove(address.trim());
        }
        self.save()?;
        Ok(true)
    }

    /// Forget everything written to `address`, for `/forget`.
    pub fn discard(&mut self, address: &str) -> Result<usize> {
        let gone = self.queued.remove(address.trim()).map_or(0, |q| q.len());
        if gone > 0 {
            self.save()?;
        }
        Ok(gone)
    }

    /// How many messages are waiting for one contact.
    pub fn waiting_for(&self, address: &str) -> usize {
        self.queued.get(address.trim()).map_or(0, Vec::len)
    }

    /// How many are waiting in total.
    pub fn len(&self) -> usize {
        self.queued.values().map(Vec::len).sum()
    }
}

/// "3 days ago", roughly, for a message that waited.
///
/// Deliberately coarse. The point is to stop a week-old message reading as
/// something just said, not to timestamp it — and a precise clock on every line
/// is a precise record of when you were at the machine.
pub fn how_long_ago(at: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let seconds = now.saturating_sub(at);
    match seconds {
        0..=90 => "just now".to_owned(),
        91..=5400 => format!("{} minutes ago", seconds / 60),
        5401..=172_800 => format!("{} hours ago", seconds / 3600),
        _ => format!("{} days ago", seconds / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    const ALICE: &str = "haticvmas7sfodcos2yhp7sf43cxifwl5aafgeathnyad4culhdj7ryd.onion";
    const BOB: &str = "bbticvmas7sfodcos2yhp7sf43cxifwl5aafgeathnyad4culhdj7ryd.onion";

    fn scratch(tag: &str) -> (PathBuf, Identity) {
        let dir = std::env::temp_dir().join(format!("murmure-outbox-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let identity = Identity::load_or_create(&dir.join("identity.seed")).unwrap();
        (dir.join("outbox.sealed"), identity)
    }

    /// The whole point: what you wrote to someone who was out survives you
    /// closing the program, and comes back in the order you wrote it.
    #[test]
    fn what_was_written_survives_a_restart_in_order() {
        let (path, identity) = scratch("restart");

        let mut out = Outbox::open(&path, &identity).unwrap();
        out.queue(ALICE, "first".into()).unwrap();
        out.queue(BOB, "not for alice".into()).unwrap();
        out.queue(ALICE, "second".into()).unwrap();

        let reopened = Outbox::open(&path, &identity).unwrap();
        let frames = reopened.frames_for(ALICE);
        assert_eq!(frames.len(), 2);
        assert!(
            matches!(&frames[0], Message::Left { body, .. } if body == "first"),
            "oldest first, or a conversation arrives backwards"
        );
        assert!(matches!(&frames[1], Message::Left { body, .. } if body == "second"));
        assert_eq!(reopened.waiting_for(BOB), 1);
        assert_eq!(reopened.len(), 3);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// Nothing waiting is readable by whoever picks up the laptop.
    #[test]
    fn the_outbox_is_not_readable_on_disk() {
        let (path, identity) = scratch("sealed");
        let mut out = Outbox::open(&path, &identity).unwrap();
        out.queue(ALICE, "meet me at six".into()).unwrap();

        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"meet m"));
        assert!(!raw.windows(16).any(|w| w == &ALICE.as_bytes()[..16]));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// A message is only forgotten once the recipient says they have it.
    #[test]
    fn a_message_leaves_the_queue_only_when_it_is_acknowledged() {
        let (path, identity) = scratch("ack");
        let mut out = Outbox::open(&path, &identity).unwrap();
        out.queue(ALICE, "one".into()).unwrap();
        out.queue(ALICE, "two".into()).unwrap();

        let Message::Left { id: first, .. } = out.frames_for(ALICE)[0].clone() else {
            panic!("frames_for produces Left frames");
        };
        assert!(out.delivered(ALICE, first).unwrap());
        assert_eq!(out.waiting_for(ALICE), 1);

        // Acknowledged twice means the same thing as once. A lost ack costs a
        // redelivery; a second one must not cost the next message.
        assert!(!out.delivered(ALICE, first).unwrap());
        assert!(!out.delivered(ALICE, 9999).unwrap());
        assert_eq!(out.waiting_for(ALICE), 1);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// Ids never repeat, so the recipient can tell a redelivery from a new
    /// message however many times a queue is emptied and refilled.
    #[test]
    fn ids_only_ever_go_up() {
        let (path, identity) = scratch("ids");
        let mut out = Outbox::open(&path, &identity).unwrap();
        out.queue(ALICE, "one".into()).unwrap();
        let Message::Left { id: first, .. } = out.frames_for(ALICE)[0].clone() else {
            unreachable!()
        };
        out.delivered(ALICE, first).unwrap();

        // Emptied, reopened, refilled — and still ahead of what was delivered.
        let mut out = Outbox::open(&path, &identity).unwrap();
        out.queue(ALICE, "two".into()).unwrap();
        let Message::Left { id: second, .. } = out.frames_for(ALICE)[0].clone() else {
            unreachable!()
        };
        assert!(second > first, "an id that went backwards would look old");

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// Someone who never comes back must not fill the disk — and must not do it
    /// quietly either.
    #[test]
    fn the_queue_is_capped_and_says_when_it_drops_something() {
        let (path, identity) = scratch("cap");
        let mut out = Outbox::open(&path, &identity).unwrap();

        for i in 0..MAX_WAITING {
            assert_eq!(out.queue(ALICE, format!("{i}")).unwrap(), 0);
        }
        assert_eq!(out.waiting_for(ALICE), MAX_WAITING);

        // One over, and the oldest goes — reported, not silently.
        assert_eq!(out.queue(ALICE, "the newest".into()).unwrap(), 1);
        assert_eq!(out.waiting_for(ALICE), MAX_WAITING);
        let frames = out.frames_for(ALICE);
        assert!(matches!(&frames[0], Message::Left { body, .. } if body == "1"));
        assert!(matches!(frames.last().unwrap(), Message::Left { body, .. } if body == "the newest"));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// A message too long to ever travel is refused here, not at the wire.
    ///
    /// Refused later, it would fail inside the writer task, never be
    /// acknowledged, stay at the head of the queue, and kill the writer again
    /// on every future connection — with everything behind it never delivered.
    #[tokio::test]
    async fn a_message_too_long_to_send_is_refused_before_it_is_kept() {
        let (path, identity) = scratch("toolong");
        let mut out = Outbox::open(&path, &identity).unwrap();

        let too_long = "x".repeat(crate::proto::MAX_TEXT + 1);
        assert!(out.queue(ALICE, too_long).is_err());
        assert_eq!(out.waiting_for(ALICE), 0, "and it must not reach the disk");

        // Exactly at the limit still travels.
        let at_limit = "x".repeat(crate::proto::MAX_TEXT);
        assert!(out.queue(ALICE, at_limit).is_ok());
        for frame in out.frames_for(ALICE) {
            assert!(
                crate::proto::write_frame(&mut Vec::new(), &frame)
                    .await
                    .is_ok(),
                "anything the outbox keeps has to be something the wire accepts"
            );
        }

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn forgetting_a_contact_forgets_what_was_written_to_them() {
        let (path, identity) = scratch("discard");
        let mut out = Outbox::open(&path, &identity).unwrap();
        out.queue(ALICE, "one".into()).unwrap();
        out.queue(ALICE, "two".into()).unwrap();
        out.queue(BOB, "yours".into()).unwrap();

        assert_eq!(out.discard(ALICE).unwrap(), 2);
        assert_eq!(out.waiting_for(ALICE), 0);
        assert_eq!(out.waiting_for(BOB), 1, "and nobody else's");
        assert_eq!(out.discard(ALICE).unwrap(), 0);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn how_long_ago_stays_coarse() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(how_long_ago(now), "just now");
        assert_eq!(how_long_ago(now - 600), "10 minutes ago");
        assert_eq!(how_long_ago(now - 7200), "2 hours ago");
        assert_eq!(how_long_ago(now - 3 * 86_400), "3 days ago");
        // A clock that went backwards must not produce a message from the
        // future, which would sort and read as nonsense.
        assert_eq!(how_long_ago(now + 5000), "just now");
    }
}

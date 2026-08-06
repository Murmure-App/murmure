//! What was said, kept — if and only if somebody asked for it.
//!
//! This is the one feature in murmure that is not obviously an improvement, and
//! it is built so that saying no costs nothing.
//!
//! Without it, closing murmure ends the conversation. That was never designed;
//! it fell out of holding everything in memory. But it is a real property: a
//! machine seized, stolen, or borrowed reveals nothing about what was said.
//! Writing history to disk gives that up on purpose.
//!
//! So it is off, it stays off until `/history on`, and the other person is told
//! when it goes on. A conversation on disk that nobody asked for is not
//! recoverable by apologising afterwards.
//!
//! # Not JSON, not SQLite
//!
//! Both were considered and neither earns its place. JSON would be the
//! conversation in plaintext on the disk — the contacts-book problem again — and
//! sealing it leaves the JSON doing nothing. SQLite buys incremental append and
//! range queries, and murmure needs neither: a scrollback is read from the end,
//! all at once, at startup. It would cost a dependency and, to be encrypted at
//! all, either a C library arti does not ship or per-row encryption that leaves
//! message count, sizes and timing readable.
//!
//! [`crate::store`] again, then, with a cap: one sealed blob, rewritten whole.
//! At a megabyte that is a millisecond, and there is nothing new to review.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::store;

/// Key-derivation context for the history file. Frozen.
const KEY_CONTEXT: &str = "murmure 2026 history";

/// Most bytes of message text kept, across all conversations.
///
/// A cap in bytes rather than in messages, because one message may be 32 KB and
/// a few thousand of those is not "about a megabyte", it is a gigabyte. The
/// oldest go first.
const MAX_BYTES: usize = 1024 * 1024;

/// How many lines `/history` shows when asked with no number.
pub const SHOWN: usize = 20;

/// One line of a conversation, as it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Line {
    /// Seconds since the epoch.
    pub at: u64,
    /// Whose conversation this belongs to, by `.onion` address.
    ///
    /// The address and not the name: a name is ours, and `/forget` then re-`/add`
    /// under a different one would silently split one conversation in two.
    pub with: String,
    /// True if we wrote it.
    pub mine: bool,
    pub body: String,
}

/// The record, sealed on disk.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct History {
    /// Whether anything is being written down at all. Persisted, so it survives
    /// a restart — turning it on is a decision, not a session setting.
    on: bool,
    lines: VecDeque<Line>,
    #[serde(skip)]
    path: PathBuf,
    #[serde(skip)]
    key: Zeroizing<[u8; 32]>,
}

impl History {
    pub fn open(path: &Path, identity: &crate::identity::Identity) -> Result<Self> {
        let key = identity.derive_key(KEY_CONTEXT);
        let mut history = match store::read_sealed(path, &key)? {
            Some(plaintext) => postcard::from_bytes::<History>(&plaintext).map_err(|e| {
                anyhow::anyhow!(
                    "the history at {} is unreadable: {e}\n\
                     It was written by an older murmure. Delete the file to start a \
                     new one — what is in it is lost, which is the same thing \
                     /history off would have done.",
                    path.display()
                )
            })?,
            None => History::default(),
        };
        history.path = path.to_path_buf();
        history.key = key;
        Ok(history)
    }

    fn save(&self) -> Result<()> {
        let plaintext = Zeroizing::new(
            postcard::to_stdvec(self).map_err(|e| anyhow::anyhow!("encoding the history: {e}"))?,
        );
        store::write_sealed(&self.path, &self.key, &plaintext)
    }

    /// Is anything being written down?
    pub fn on(&self) -> bool {
        self.on
    }

    /// Start or stop keeping a record.
    ///
    /// Turning it off **erases what is there**. Anything else would leave the
    /// operator believing they had stopped keeping a record while the record
    /// they already have sits on the disk.
    pub fn set(&mut self, on: bool) -> Result<usize> {
        self.on = on;
        let forgotten = if on { 0 } else { self.lines.len() };
        if !on {
            self.lines.clear();
        }
        self.save()?;
        Ok(forgotten)
    }

    /// Write one line down. Does nothing while history is off.
    pub fn note(&mut self, with: &str, mine: bool, body: &str) -> Result<()> {
        if !self.on {
            return Ok(());
        }
        self.lines.push_back(Line {
            at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default(),
            with: with.trim().to_owned(),
            mine,
            body: body.to_owned(),
        });
        self.trim();
        self.save()
    }

    /// Drop the oldest lines until what is kept fits the cap.
    fn trim(&mut self) {
        let mut total: usize = self.lines.iter().map(|l| l.body.len()).sum();
        while total > MAX_BYTES {
            match self.lines.pop_front() {
                Some(gone) => total -= gone.body.len(),
                None => break,
            }
        }
    }

    /// The last `count` lines, oldest first — optionally only with one peer.
    pub fn tail(&self, with: Option<&str>, count: usize) -> Vec<&Line> {
        let matching = self
            .lines
            .iter()
            .filter(|l| with.is_none_or(|w| l.with == w.trim()));
        let kept: Vec<&Line> = matching.collect();
        kept[kept.len().saturating_sub(count)..].to_vec()
    }

    /// Erase everything kept about one peer, for `/forget`.
    pub fn forget(&mut self, with: &str) -> Result<usize> {
        let before = self.lines.len();
        self.lines.retain(|l| l.with != with.trim());
        let gone = before - self.lines.len();
        if gone > 0 {
            self.save()?;
        }
        Ok(gone)
    }

    /// How many lines are kept.
    pub fn len(&self) -> usize {
        self.lines.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    const ALICE: &str = "haticvmas7sfodcos2yhp7sf43cxifwl5aafgeathnyad4culhdj7ryd.onion";
    const BOB: &str = "bbticvmas7sfodcos2yhp7sf43cxifwl5aafgeathnyad4culhdj7ryd.onion";

    fn scratch(tag: &str) -> (PathBuf, Identity) {
        let dir = std::env::temp_dir().join(format!("murmure-history-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let identity = Identity::load_or_create(&dir.join("identity.seed")).unwrap();
        (dir.join("history.sealed"), identity)
    }

    /// The default has to be the one that keeps the least, and it has to hold
    /// even when something tries to write.
    #[test]
    fn nothing_is_written_down_until_it_is_asked_for() {
        let (path, identity) = scratch("default");
        let mut history = History::open(&path, &identity).unwrap();

        assert!(!history.on(), "history must be off until somebody says so");
        history.note(ALICE, true, "something said before it was on").unwrap();
        assert_eq!(history.len(), 0, "a note while off is not a note");

        // And it stays off across a restart — being on is a decision, so being
        // off must not be something a restart quietly undoes either way.
        history.set(true).unwrap();
        let reopened = History::open(&path, &identity).unwrap();
        assert!(reopened.on());
        assert_eq!(reopened.len(), 0, "and nothing from before it was on");

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// What is kept survives a restart, in order, and separated by peer.
    #[test]
    fn a_conversation_comes_back_in_order() {
        let (path, identity) = scratch("order");
        let mut history = History::open(&path, &identity).unwrap();
        history.set(true).unwrap();

        history.note(ALICE, true, "on se voit à six heures ?").unwrap();
        history.note(ALICE, false, "oui").unwrap();
        history.note(BOB, false, "nothing to do with alice").unwrap();

        let reopened = History::open(&path, &identity).unwrap();
        let with_alice = reopened.tail(Some(ALICE), SHOWN);
        assert_eq!(with_alice.len(), 2);
        assert_eq!(with_alice[0].body, "on se voit à six heures ?");
        assert!(with_alice[0].mine);
        assert!(!with_alice[1].mine);
        assert_eq!(reopened.tail(None, SHOWN).len(), 3, "and everything, together");

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// Turning it off erases. Anything else leaves the operator believing they
    /// stopped keeping a record while the one they have sits on the disk.
    #[test]
    fn turning_it_off_erases_what_was_kept() {
        let (path, identity) = scratch("off");
        let mut history = History::open(&path, &identity).unwrap();
        history.set(true).unwrap();
        history.note(ALICE, true, "a secret").unwrap();

        assert_eq!(history.set(false).unwrap(), 1, "and says how much it erased");
        assert_eq!(history.len(), 0);

        let reopened = History::open(&path, &identity).unwrap();
        assert_eq!(reopened.len(), 0);
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(8).any(|w| w == b"a secret"));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn what_is_kept_is_not_readable_on_disk() {
        let (path, identity) = scratch("sealed");
        let mut history = History::open(&path, &identity).unwrap();
        history.set(true).unwrap();
        history.note(ALICE, true, "rendez-vous à la gare").unwrap();

        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(10).any(|w| w == b"rendez-vou"));
        assert!(!raw.windows(16).any(|w| w == &ALICE.as_bytes()[..16]));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// A long conversation must not become a disk-filling bug.
    #[test]
    fn the_record_is_bounded_by_bytes_not_by_optimism() {
        let (path, identity) = scratch("cap");
        let mut history = History::open(&path, &identity).unwrap();
        history.set(true).unwrap();

        // Deliberately large lines: a cap counted in messages would let a few
        // thousand of these become a gigabyte.
        let big = "x".repeat(64 * 1024);
        for _ in 0..24 {
            history.note(ALICE, true, &big).unwrap();
        }
        let kept: usize = history.tail(None, usize::MAX).iter().map(|l| l.body.len()).sum();
        assert!(kept <= MAX_BYTES, "kept {kept} bytes, over the cap");
        assert!(history.len() > 0, "and it keeps what it can, not nothing");

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn forgetting_a_contact_forgets_what_they_said() {
        let (path, identity) = scratch("forget");
        let mut history = History::open(&path, &identity).unwrap();
        history.set(true).unwrap();
        history.note(ALICE, true, "one").unwrap();
        history.note(ALICE, false, "two").unwrap();
        history.note(BOB, false, "mine").unwrap();

        assert_eq!(history.forget(ALICE).unwrap(), 2);
        assert_eq!(history.tail(Some(ALICE), SHOWN).len(), 0);
        assert_eq!(history.tail(Some(BOB), SHOWN).len(), 1, "and nobody else's");
        assert_eq!(history.forget(ALICE).unwrap(), 0);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}

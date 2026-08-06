//! The contacts book: a name you chose, and what is behind it — the `.onion`
//! address to dial, and the discovery key that lets that peer find *us*.
//!
//! Sealed on disk under a key derived from the identity seed — see
//! [`crate::store`] for why that is not optional. That seal is why the
//! authorised-client list is assembled here in memory and handed to arti
//! directly, instead of using arti's `key_dirs`, which would write one
//! plaintext file per contact and undo the whole point of sealing the book.
//!
//! Names are local and private. Your friend does not know, and does not need to
//! know, what you called them; nothing here travels on the wire.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::proto::Message;
use crate::store;

/// Key-derivation context for the contacts file. Changing this string makes
/// every existing contacts book unreadable, so it is frozen.
const KEY_CONTEXT: &str = "murmure 2026 contacts book";

/// Longest accepted contact name, in bytes.
const MAX_NAME: usize = 64;

/// Whether this contact and we have agreed to see each other online.
///
/// Two permissions, not one. Restricted discovery already settles *reachable* —
/// a stranger cannot read our descriptor at all. This settles *watched*, which
/// is a different thing: a friend who can call us does not thereby get to know
/// when we are at the machine. So it is asked, and it is refusable.
///
/// Both halves have to be [`Presence::On`] before either side holds a
/// connection open, which is what makes it mutual rather than something one
/// person switches on for the other.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Presence {
    /// Nobody has asked, or somebody said no. The starting state, and the one
    /// `/forget` and a refusal both return to.
    #[default]
    Off,
    /// We asked. Nothing happens until they answer.
    WeAsked,
    /// They asked. Nothing happens until we answer — deliberately: an unanswered
    /// request is not consent, and time passing must not turn it into consent.
    TheyAsked,
    /// Agreed, both ways. Connections are held open from here.
    On,
}

/// Something that happened to a presence agreement.
///
/// Four events and no fifth: presence is asked, answered, or withdrawn. Keeping
/// them in one type is what lets the whole agreement be one function with no
/// I/O in it, and therefore be tested without a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Said {
    /// We typed `/presence <name>`.
    WeAsk,
    /// We typed `/presence <name> off`.
    WeStop,
    /// A [`Message::PresenceAsk`] arrived.
    TheyAsk,
    /// A [`Message::PresenceYes`] arrived.
    TheyAgree,
    /// A [`Message::PresenceNo`] arrived.
    TheyRefuse,
}

/// Where a presence event leaves things.
pub struct Step {
    /// The state to store.
    pub to: Presence,
    /// What to send them, if anything.
    pub reply: Option<Message>,
    /// What to tell the operator, if there is anything worth saying.
    pub note: Option<String>,
}

impl Presence {
    /// Apply one event, and say what follows from it.
    ///
    /// Pure: it stores nothing and sends nothing. The two rules underneath it
    /// are that consent is mutual — [`Presence::On`] is only ever reached by
    /// both sides saying yes — and that silence is never consent, so
    /// [`Presence::TheyAsked`] sits there until somebody answers it.
    pub fn step(self, said: Said, name: &str) -> Step {
        use Presence::*;
        let (to, reply, note) = match (self, said) {
            // We ask. If they were already asking, that is both sides saying
            // yes and there is nothing left to wait for.
            (TheyAsked, Said::WeAsk) => (On, Some(Message::PresenceYes), Some(format!(
                "you and {name} will see each other online from now on"
            ))),
            (On, Said::WeAsk) => (On, None, Some(format!("{name} already sees you online"))),
            (_, Said::WeAsk) => (WeAsked, Some(Message::PresenceAsk), Some(format!(
                "asked {name} — they will see it the next time you are both connected"
            ))),

            // We withdraw. Told either way, because a request we made and no
            // longer want is as much theirs to hear as an agreement we end.
            (Off, Said::WeStop) => (Off, None, Some(format!("{name} was not seeing you anyway"))),
            (WeAsked, Said::WeStop) => (Off, Some(Message::PresenceNo), Some(format!(
                "withdrew the request to {name}"
            ))),
            (_, Said::WeStop) => (Off, Some(Message::PresenceNo), Some(format!(
                "{name} no longer sees when you are online, and you no longer see them"
            ))),

            // They ask. Crossing requests are not a conflict — they are two
            // people agreeing, which is exactly the thing being asked for.
            (WeAsked, Said::TheyAsk) => (On, Some(Message::PresenceYes), Some(format!(
                "you and {name} will see each other online from now on"
            ))),
            // Asked again by someone we already agreed with: their build
            // restarted and lost nothing but the last confirmation. Answer it,
            // and do not narrate it.
            (On, Said::TheyAsk) => (On, Some(Message::PresenceYes), None),
            (_, Said::TheyAsk) => (TheyAsked, None, Some(format!(
                "{name} asks to see when you are online — /presence {name} to agree, \
                 /presence {name} off to decline"
            ))),

            (WeAsked | On, Said::TheyAgree) => (On, None, Some(format!(
                "you and {name} will see each other online from now on"
            ))),
            // A yes to a question we did not ask. Nothing to record: consent we
            // never sought is not consent we can act on.
            (other, Said::TheyAgree) => (other, None, None),

            (Off, Said::TheyRefuse) => (Off, None, None),
            (WeAsked, Said::TheyRefuse) => (Off, None, Some(format!(
                "{name} would rather not be seen online"
            ))),
            (_, Said::TheyRefuse) => (Off, None, Some(format!(
                "{name} stopped sharing when they are online"
            ))),
        };
        Step { to, reply, note }
    }
}

/// One filed friend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    /// Their `.onion`, which is what we dial.
    pub address: String,
    /// Their service discovery key, in `descriptor:x25519:<base32>` form.
    ///
    /// This is *their* public key, and it goes into *our* service's authorised
    /// clients — it is what lets them read our descriptor. It is not used to
    /// reach them; for that we present our own key, derived from our own seed.
    pub discovery: String,
    /// Where this contact stands on seeing, and being seen by, us.
    pub presence: Presence,
    /// The lowest [`Message::Left`] id from this contact we have not accepted.
    ///
    /// Their outbox keeps a message until we acknowledge it, so an
    /// acknowledgement lost to a dropped link costs a redelivery. This is what
    /// makes that redelivery free: anything below this mark is something we
    /// already have, acknowledged again and shown to nobody.
    pub seen: u64,
    /// This contact asked not to be written down.
    ///
    /// Their side of `/history`. Honoured whatever our own setting is, so
    /// turning history on does not quietly override somebody who already said
    /// no.
    pub objects_to_history: bool,
    /// We asked *them* not to write us down.
    ///
    /// Kept so the request can be repeated on every connection. It is a
    /// standing objection, not an event: one that only travelled once would be
    /// silently forgotten by the far side after any restart.
    pub we_object: bool,
}

/// A name-to-contact book.
///
/// `BTreeMap` rather than `HashMap`: listing contacts should come out in the
/// same order every time, and at this size the difference costs nothing.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Contacts {
    entries: BTreeMap<String, Contact>,
    #[serde(skip)]
    path: PathBuf,
    /// The key this book is sealed under, derived from the identity seed.
    ///
    /// Wiped on drop: it opens the file that *is* the social graph, so it is
    /// worth exactly as much as the graph itself.
    #[serde(skip)]
    key: Zeroizing<[u8; 32]>,
}

impl Contacts {
    /// Open the book at `path`, or start an empty one.
    pub fn open(path: &Path, identity: &crate::identity::Identity) -> Result<Self> {
        let key = identity.derive_key(KEY_CONTEXT);
        let mut book = match store::read_sealed(path, &key)? {
            // postcard is not self-describing, so a book written before a
            // contact grew a field fails here rather than decoding into
            // nonsense. Say what to do about it.
            Some(plaintext) => postcard::from_bytes::<Contacts>(&plaintext).map_err(|e| {
                anyhow::anyhow!(
                    "the contacts book at {} is unreadable: {e}\n\
                     It was written by an older murmure — a contact now carries a \
                     service discovery key, a presence setting, a delivery mark \
                     and a history objection. Delete the file and /add your contacts again; nothing \
                     else is lost, and the addresses and keys are not secrets.",
                    path.display()
                )
            })?,
            None => Contacts::default(),
        };
        book.path = path.to_path_buf();
        book.key = key;
        Ok(book)
    }

    /// Seal the book back to disk.
    fn save(&self) -> Result<()> {
        // The encoded book is the social graph in the clear. It exists in memory
        // for as long as it takes to seal it, and not a moment longer.
        let plaintext = Zeroizing::new(
            postcard::to_stdvec(self)
                .map_err(|e| anyhow::anyhow!("encoding the contacts book: {e}"))?,
        );
        store::write_sealed(&self.path, &self.key, &plaintext)
    }

    /// Add or replace a contact, then persist.
    ///
    /// Both halves are validated here rather than at dial time: a typo caught
    /// while typing beats a failed 50-second rendezvous — and, for the
    /// discovery key, beats a failure that cannot be diagnosed at all, because
    /// a restricted service looks identical to an offline one.
    pub fn add(&mut self, name: &str, address: &str, discovery: &str) -> Result<()> {
        let name = name.trim();
        let entry = Contact {
            address: address.trim().to_owned(),
            discovery: discovery.trim().to_owned(),
            presence: Presence::Off,
            seen: 0,
            objects_to_history: false,
            we_object: false,
        };
        check_name(name)?;
        crate::onion::check_address(&entry.address)?;
        crate::onion::check_discovery_key(&entry.discovery)?;

        // Compared on the two halves that identify the contact, not on the
        // whole entry: re-filing someone under the details they already have is
        // idempotent, and must stay so even once presence has moved off its
        // default.
        if let Some(existing) = self.entries.get(name)
            && (existing.address != entry.address || existing.discovery != entry.discovery)
        {
            bail!(
                "{name} is already someone else's name in this book.\n\
                 Remove it first if you really mean to point it at a new address:\n  \
                 /forget {name}"
            );
        }
        self.entries.insert(name.to_owned(), entry);
        self.save()
    }

    /// Drop a contact, then persist. Returns whether anything was there.
    pub fn remove(&mut self, name: &str) -> Result<bool> {
        let existed = self.entries.remove(name.trim()).is_some();
        if existed {
            self.save()?;
        }
        Ok(existed)
    }

    /// The address filed under `name`.
    pub fn address_of(&self, name: &str) -> Option<&str> {
        self.entries.get(name.trim()).map(|c| c.address.as_str())
    }

    /// The name filed for this address, if any.
    ///
    /// This used to be impossible, and the reason is worth keeping: restricted
    /// discovery decides *whether* a client may read our descriptor, and never
    /// tells the service which one did. The rendezvous is anonymous, so an
    /// incoming call was "they" and could not be anything else.
    ///
    /// What changed is not the transport. The caller now proves an address in
    /// [`crate::proto::handshake`] by signing a challenge with the key that
    /// address is derived from, so there is finally something to look up here.
    ///
    /// A linear scan: a book that would notice the difference is a book far
    /// past what this program is for.
    pub fn name_of(&self, address: &str) -> Option<&str> {
        let address = address.trim();
        self.entries
            .iter()
            .find(|(_, c)| c.address == address)
            .map(|(name, _)| name.as_str())
    }

    /// Where this contact stands on presence. Unknown names are [`Presence::Off`],
    /// which is the right answer: somebody we do not have cannot have agreed.
    pub fn presence_of(&self, name: &str) -> Presence {
        self.entries
            .get(name.trim())
            .map(|c| c.presence)
            .unwrap_or_default()
    }

    /// Move a contact to a new presence state, then persist. Returns whether
    /// there was a contact to move.
    pub fn set_presence(&mut self, name: &str, presence: Presence) -> Result<bool> {
        let Some(entry) = self.entries.get_mut(name.trim()) else {
            return Ok(false);
        };
        if entry.presence == presence {
            return Ok(true);
        }
        entry.presence = presence;
        self.save()?;
        Ok(true)
    }

    /// Record whether *we* object to this contact writing us down.
    pub fn set_our_objection(&mut self, name: &str, objects: bool) -> Result<bool> {
        let Some(entry) = self.entries.get_mut(name.trim()) else {
            return Ok(false);
        };
        if entry.we_object == objects {
            return Ok(true);
        }
        entry.we_object = objects;
        self.save()?;
        Ok(true)
    }

    /// Record whether this contact objects to being written down.
    pub fn set_objection(&mut self, name: &str, objects: bool) -> Result<bool> {
        let Some(entry) = self.entries.get_mut(name.trim()) else {
            return Ok(false);
        };
        if entry.objects_to_history == objects {
            return Ok(true);
        }
        entry.objects_to_history = objects;
        self.save()?;
        Ok(true)
    }

    /// Does this contact object to being written down? Unknown names object,
    /// which is the safe answer for somebody we cannot ask.
    pub fn objects_to_history(&self, name: &str) -> bool {
        self.entries
            .get(name.trim())
            .is_none_or(|c| c.objects_to_history)
    }

    /// Accept a message id from this contact, or say we have it already.
    ///
    /// Raises the high-water mark on the way through, so a message is shown
    /// exactly once however many times the sender redelivers it.
    pub fn accept_left(&mut self, name: &str, id: u64) -> Result<bool> {
        let Some(entry) = self.entries.get_mut(name.trim()) else {
            return Ok(false);
        };
        if id < entry.seen {
            return Ok(false);
        }
        entry.seen = id + 1;
        self.save()?;
        Ok(true)
    }

    /// The contacts we hold a connection open to, by name.
    ///
    /// Only [`Presence::On`]: an unanswered request is not consent, and dialling
    /// on the strength of one would be helping ourselves to the answer.
    pub fn agreed(&self) -> impl Iterator<Item = (&str, &Contact)> {
        self.iter().filter(|(_, c)| c.presence == Presence::On)
    }

    /// Every contact, name first, in a stable order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Contact)> {
        self.entries.iter().map(|(n, c)| (n.as_str(), c))
    }

    /// How many contacts are filed.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Reject names that would be confusing or unusable.
fn check_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("a contact needs a name");
    }
    if name.len() > MAX_NAME {
        bail!("{name:?} is {} bytes, the limit is {MAX_NAME}", name.len());
    }
    // Commands start with '/', and whitespace would make `/call alice bob`
    // ambiguous.
    if name.starts_with('/') {
        bail!("a contact name cannot start with '/'");
    }
    if name.chars().any(char::is_whitespace) {
        bail!("a contact name cannot contain spaces");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    const ADDR_A: &str = "haticvmas7sfodcos2yhp7sf43cxifwl5aafgeathnyad4culhdj7ryd.onion";
    const ADDR_B: &str = "bbticvmas7sfodcos2yhp7sf43cxifwl5aafgeathnyad4culhdj7ryd.onion";
    const KEY_A: &str = "descriptor:x25519:ZPRRMIV6DV6SJFL7SFBSVLJ5VUNPGCDFEVZ7M23LTLVTCCXJQBKA";
    const KEY_B: &str = "descriptor:x25519:YPRRMIV6DV6SJFL7SFBSVLJ5VUNPGCDFEVZ7M23LTLVTCCXJQBKA";

    fn scratch(tag: &str) -> (PathBuf, Identity) {
        let dir = std::env::temp_dir().join(format!("murmure-contacts-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let identity = Identity::load_or_create(&dir.join("identity.seed")).unwrap();
        (dir.join("contacts.sealed"), identity)
    }

    #[test]
    fn contacts_survive_a_reopen() {
        let (path, identity) = scratch("reopen");

        let mut book = Contacts::open(&path, &identity).unwrap();
        book.add("alice", ADDR_A, KEY_A).unwrap();
        assert_eq!(book.len(), 1);

        let reopened = Contacts::open(&path, &identity).unwrap();
        assert_eq!(reopened.address_of("alice"), Some(ADDR_A));
        let (_, alice) = reopened.iter().next().unwrap();
        assert_eq!(alice.discovery, KEY_A);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn the_book_is_not_readable_on_disk() {
        let (path, identity) = scratch("sealed");
        let mut book = Contacts::open(&path, &identity).unwrap();
        book.add("alice", ADDR_A, KEY_A).unwrap();

        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(5).any(|w| w == b"alice"));
        assert!(!raw.windows(16).any(|w| w == &ADDR_A.as_bytes()[..16]));
        // The discovery key is not a secret, but it identifies a contact just
        // as well as their address does, so it must not sit in the clear either.
        assert!(!raw.windows(16).any(|w| w == &KEY_A.as_bytes()[..16]));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn renaming_a_contact_onto_a_new_address_needs_an_explicit_forget() {
        let (path, identity) = scratch("clash");
        let mut book = Contacts::open(&path, &identity).unwrap();
        book.add("alice", ADDR_A, KEY_A).unwrap();

        // Same name, same entry: idempotent, not an error.
        assert!(book.add("alice", ADDR_A, KEY_A).is_ok());
        // Same name, different address: refused.
        assert!(book.add("alice", ADDR_B, KEY_A).is_err());
        // Same name and address, rotated key: also refused. A contact whose key
        // changed has to be forgotten first, so nobody swaps a key in quietly.
        assert!(book.add("alice", ADDR_A, KEY_B).is_err());

        assert!(book.remove("alice").unwrap());
        assert!(book.add("alice", ADDR_B, KEY_B).is_ok());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn bad_names_addresses_and_keys_are_refused() {
        let (path, identity) = scratch("validate");
        let mut book = Contacts::open(&path, &identity).unwrap();

        assert!(book.add("", ADDR_A, KEY_A).is_err());
        assert!(book.add("/call", ADDR_A, KEY_A).is_err());
        assert!(book.add("two words", ADDR_A, KEY_A).is_err());
        assert!(book.add("alice", "not-an-address", KEY_A).is_err());
        assert!(book.add("alice", ADDR_A, "not-a-key").is_err());
        // The two halves swapped, which is the mistake a copy-paste makes.
        assert!(book.add("alice", KEY_A, ADDR_A).is_err());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// Presence is only ever reached by both sides saying yes.
    ///
    /// The two crossing paths are the ones worth pinning down: one side asking
    /// after the other already did is not a conflict to resolve, it is the
    /// agreement completing.
    #[test]
    fn presence_needs_both_sides_and_gets_there_either_way() {
        // We ask, they agree.
        let asked = Presence::Off.step(Said::WeAsk, "alice");
        assert_eq!(asked.to, Presence::WeAsked);
        assert_eq!(asked.reply, Some(Message::PresenceAsk));
        assert_eq!(asked.to.step(Said::TheyAgree, "alice").to, Presence::On);

        // They ask, we agree.
        let told = Presence::Off.step(Said::TheyAsk, "alice");
        assert_eq!(told.to, Presence::TheyAsked);
        assert_eq!(told.reply, None, "being asked must not answer itself");
        let agreed = told.to.step(Said::WeAsk, "alice");
        assert_eq!(agreed.to, Presence::On);
        assert_eq!(agreed.reply, Some(Message::PresenceYes));

        // Both ask at once, from either side. Same destination.
        assert_eq!(Presence::WeAsked.step(Said::TheyAsk, "a").to, Presence::On);
        assert_eq!(Presence::TheyAsked.step(Said::WeAsk, "a").to, Presence::On);
    }

    /// Silence is not consent, and neither is a yes to a question nobody asked.
    #[test]
    fn presence_is_never_reached_by_one_side_alone() {
        // An unanswered request stays unanswered however it is prodded.
        assert_eq!(
            Presence::TheyAsked.step(Said::TheyAsk, "a").to,
            Presence::TheyAsked
        );
        // A `yes` we never sought changes nothing — otherwise anyone in the
        // book could switch themselves on by sending one frame.
        assert_eq!(Presence::Off.step(Said::TheyAgree, "a").to, Presence::Off);
        assert_eq!(
            Presence::TheyAsked.step(Said::TheyAgree, "a").to,
            Presence::TheyAsked
        );
    }

    /// Either side can end it, and the other is told.
    #[test]
    fn presence_can_be_withdrawn_from_either_end() {
        let stopped = Presence::On.step(Said::WeStop, "alice");
        assert_eq!(stopped.to, Presence::Off);
        assert_eq!(stopped.reply, Some(Message::PresenceNo));
        assert_eq!(Presence::On.step(Said::TheyRefuse, "alice").to, Presence::Off);
        // A refusal we already acted on is not worth repeating on screen.
        assert!(Presence::Off.step(Said::TheyRefuse, "alice").note.is_none());
    }

    /// Only an agreement puts a contact in the list we hold connections to.
    #[test]
    fn only_agreed_contacts_are_dialled_ahead() {
        let (path, identity) = scratch("agreed");
        let mut book = Contacts::open(&path, &identity).unwrap();
        book.add("alice", ADDR_A, KEY_A).unwrap();
        book.add("bob", ADDR_B, KEY_B).unwrap();

        assert_eq!(book.presence_of("alice"), Presence::Off);
        assert_eq!(book.agreed().count(), 0);

        // Asked, not agreed: still nobody to dial.
        assert!(book.set_presence("alice", Presence::WeAsked).unwrap());
        assert_eq!(book.agreed().count(), 0);

        assert!(book.set_presence("alice", Presence::On).unwrap());
        assert_eq!(book.agreed().map(|(n, _)| n).collect::<Vec<_>>(), ["alice"]);

        // And it survives the file, like everything else in the book.
        let reopened = Contacts::open(&path, &identity).unwrap();
        assert_eq!(reopened.presence_of("alice"), Presence::On);
        assert_eq!(reopened.presence_of("bob"), Presence::Off);
        assert_eq!(reopened.presence_of("nobody"), Presence::Off);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn removing_something_absent_is_not_an_error() {
        let (path, identity) = scratch("absent");
        let mut book = Contacts::open(&path, &identity).unwrap();
        assert!(!book.remove("nobody").unwrap());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}

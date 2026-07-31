//! The contacts book: a name you chose, and the `.onion` address behind it.
//!
//! Sealed on disk under a key derived from the identity seed — see
//! [`crate::store`] for why that is not optional.
//!
//! Names are local and private. Your friend does not know, and does not need to
//! know, what you called them; nothing here travels on the wire.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::store;

/// Key-derivation context for the contacts file. Changing this string makes
/// every existing contacts book unreadable, so it is frozen.
const KEY_CONTEXT: &str = "murmure 2026 contacts book";

/// Longest accepted contact name, in bytes.
const MAX_NAME: usize = 64;

/// A name-to-address book.
///
/// `BTreeMap` rather than `HashMap`: listing contacts should come out in the
/// same order every time, and at this size the difference costs nothing.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Contacts {
    entries: BTreeMap<String, String>,
    #[serde(skip)]
    path: PathBuf,
    #[serde(skip)]
    key: [u8; 32],
}

impl Contacts {
    /// Open the book at `path`, or start an empty one.
    pub fn open(path: &Path, identity: &crate::identity::Identity) -> Result<Self> {
        let key = identity.derive_key(KEY_CONTEXT);
        let mut book = match store::read_sealed(path, &key)? {
            Some(plaintext) => postcard::from_bytes::<Contacts>(&plaintext)
                .map_err(|e| anyhow::anyhow!("the contacts book is unreadable: {e}"))?,
            None => Contacts::default(),
        };
        book.path = path.to_path_buf();
        book.key = key;
        Ok(book)
    }

    /// Seal the book back to disk.
    fn save(&self) -> Result<()> {
        let plaintext = postcard::to_stdvec(self)
            .map_err(|e| anyhow::anyhow!("encoding the contacts book: {e}"))?;
        store::write_sealed(&self.path, &self.key, &plaintext)
    }

    /// Add or replace a contact, then persist.
    ///
    /// The address is validated here rather than at dial time: a typo caught
    /// while typing beats a failed 50-second rendezvous.
    pub fn add(&mut self, name: &str, address: &str) -> Result<()> {
        let name = name.trim();
        let address = address.trim();
        check_name(name)?;
        crate::onion::check_address(address)?;

        if let Some(existing) = self.entries.get(name)
            && existing != address
        {
            bail!(
                "{name} is already someone else's name in this book.\n\
                 Remove it first if you really mean to point it at a new address:\n  \
                 /forget {name}"
            );
        }
        self.entries.insert(name.to_owned(), address.to_owned());
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
        self.entries.get(name.trim()).map(String::as_str)
    }

    // No reverse lookup here on purpose: an onion service learns nothing about
    // who is dialling it, so there is no address to look a caller up by. That
    // arrives with restricted discovery (see INSTALL.md), and so does the
    // function.

    /// Every contact, name first, in a stable order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(n, a)| (n.as_str(), a.as_str()))
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
        book.add("alice", ADDR_A).unwrap();
        assert_eq!(book.len(), 1);

        let reopened = Contacts::open(&path, &identity).unwrap();
        assert_eq!(reopened.address_of("alice"), Some(ADDR_A));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn the_book_is_not_readable_on_disk() {
        let (path, identity) = scratch("sealed");
        let mut book = Contacts::open(&path, &identity).unwrap();
        book.add("alice", ADDR_A).unwrap();

        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(5).any(|w| w == b"alice"));
        assert!(!raw.windows(16).any(|w| w == &ADDR_A.as_bytes()[..16]));

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn renaming_a_contact_onto_a_new_address_needs_an_explicit_forget() {
        let (path, identity) = scratch("clash");
        let mut book = Contacts::open(&path, &identity).unwrap();
        book.add("alice", ADDR_A).unwrap();

        // Same name, same address: idempotent, not an error.
        assert!(book.add("alice", ADDR_A).is_ok());
        // Same name, different address: refused.
        assert!(book.add("alice", ADDR_B).is_err());

        assert!(book.remove("alice").unwrap());
        assert!(book.add("alice", ADDR_B).is_ok());

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn bad_names_and_addresses_are_refused() {
        let (path, identity) = scratch("validate");
        let mut book = Contacts::open(&path, &identity).unwrap();

        assert!(book.add("", ADDR_A).is_err());
        assert!(book.add("/call", ADDR_A).is_err());
        assert!(book.add("two words", ADDR_A).is_err());
        assert!(book.add("alice", "not-an-address").is_err());

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

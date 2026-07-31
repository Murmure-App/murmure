//! murmure's own identity.
//!
//! murmure owns a 32-byte ed25519 seed on disk and derives everything else from
//! it: the `HsIdKeypair` handed to arti, and the `.onion` address that
//! identifies the peer publicly. arti is a *consumer* of this key, never its
//! producer — that is what makes `identity` the root of the architecture drawn
//! in `aidd_docs/INSTALL.md`.
//!
//! Derivation chain, all of it inside `tor-llcrypto` / `tor-hscrypto`:
//!
//! ```text
//! [u8; 32] seed
//!   -> ed25519::Keypair            (Keypair::from_bytes)
//!   -> ed25519::ExpandedKeypair    (From<&Keypair>)
//!   -> HsIdKeypair                 (newtype, derive_more::From)
//!   -> HsIdKey -> HsId             (the .onion address)
//! ```

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use rand::RngCore as _;
use tor_hscrypto::pk::{HsId, HsIdKey, HsIdKeypair};
use tor_llcrypto::pk::ed25519;

/// Length of the ed25519 secret seed murmure persists.
pub const SEED_LEN: usize = 32;

/// A murmure identity: one 32-byte ed25519 seed, and everything derived from it.
pub struct Identity {
    /// The secret seed. Never printed, never logged.
    seed: [u8; SEED_LEN],
    /// Where the seed lives on disk. Only `check_permissions` reads it, and that
    /// has nothing to check off Unix — hence the allow rather than a cfg on the
    /// field, which would make the two constructors platform-specific too.
    #[cfg_attr(not(unix), allow(dead_code))]
    path: PathBuf,
}

impl Identity {
    /// Load the seed at `path`, or generate one and persist it 0600 on first run.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            Self::create(path)
        }
    }

    /// Load an existing seed file.
    fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("reading the identity seed at {}", path.display()))?;
        let seed: [u8; SEED_LEN] = bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "{} is {} bytes, expected exactly {SEED_LEN}; \
                 delete it to generate a fresh identity",
                path.display(),
                bytes.len()
            )
        })?;
        Ok(Self {
            seed,
            path: path.to_path_buf(),
        })
    }

    /// Generate a seed from the OS CSPRNG and write it with 0600 permissions.
    fn create(path: &Path) -> Result<Self> {
        let mut seed = [0u8; SEED_LEN];
        rand::rngs::OsRng.fill_bytes(&mut seed);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }

        // The file must never be readable by anyone else, and it must not exist
        // already — create_new turns a concurrent creation into an error rather
        // than a silently overwritten identity.
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(path)
            .with_context(|| format!("creating the identity seed at {}", path.display()))?;
        file.write_all(&seed)
            .with_context(|| format!("writing the identity seed at {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("flushing the identity seed at {}", path.display()))?;

        // Off Unix there is nothing to tighten here. std exposes only the
        // read-only flag, which is not a permission — setting it would restrict
        // nobody while looking like it did. On Windows the file inherits the
        // profile directory's ACL: the owner, SYSTEM and Administrators.
        //
        // ponytail: an ACL narrowed to the owner alone needs the win32 API and a
        // Windows-only dependency. Worth it the day murmure runs on a shared
        // Windows machine; the profile ACL covers a personal one.

        let this = Self {
            seed,
            path: path.to_path_buf(),
        };
        this.check_permissions()?;
        Ok(this)
    }

    /// Refuse to run on a seed file that anyone but the owner can read.
    pub fn check_permissions(&self) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&self.path)
                .with_context(|| format!("stat {}", self.path.display()))?
                .permissions()
                .mode()
                & 0o777;
            if mode & 0o077 != 0 {
                // Qualified: the import would be unused off Unix.
                anyhow::bail!(
                    "{} is mode {mode:o}; the identity seed must be 0600. \
                     Run: chmod 600 {}",
                    self.path.display(),
                    self.path.display()
                );
            }
        }
        Ok(())
    }

    /// The ed25519 keypair, in the expanded form arti's keystore speaks.
    ///
    /// Returns a fresh value on every call: `HsIdKeypair` is not `Clone`, and
    /// `TorClient::launch_onion_service_with_hsid` consumes it.
    pub fn hs_id_keypair(&self) -> HsIdKeypair {
        let keypair = ed25519::Keypair::from_bytes(&self.seed);
        let expanded = ed25519::ExpandedKeypair::from(&keypair);
        HsIdKeypair::from(expanded)
    }

    /// Derive a 32-byte secret from the seed, for a named purpose.
    ///
    /// `context` separates purposes: the key sealing the contacts book and the
    /// key sealing the history must never be the same key, or a flaw in one
    /// use compromises the other. BLAKE3's `derive_key` is a KDF designed for
    /// exactly this, so there is no home-made construction here.
    ///
    /// Consequence, deliberate and already recorded in the brainstorm: losing
    /// the seed loses everything it sealed. There is no recovery.
    pub fn derive_key(&self, context: &str) -> [u8; 32] {
        blake3::derive_key(context, &self.seed)
    }

    /// The `.onion` identity derived from the seed, computed locally.
    ///
    /// This is the value phase 3 compares arti's published address against. It
    /// never touches the keystore, so a match proves arti used *our* key.
    pub fn onion_address(&self) -> HsId {
        HsIdKey::from(&self.hs_id_keypair()).id()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use safelog::DisplayRedacted as _;

    /// The all-zero seed is a known-answer vector: same seed, same address.
    #[test]
    fn address_is_a_pure_function_of_the_seed() {
        let a = Identity {
            seed: [7u8; SEED_LEN],
            path: PathBuf::from("/nonexistent"),
        };
        let b = Identity {
            seed: [7u8; SEED_LEN],
            path: PathBuf::from("/nonexistent"),
        };
        let c = Identity {
            seed: [8u8; SEED_LEN],
            path: PathBuf::from("/nonexistent"),
        };
        assert_eq!(a.onion_address(), b.onion_address());
        assert_ne!(a.onion_address(), c.onion_address());
    }

    #[test]
    fn address_is_a_well_formed_v3_onion() {
        let id = Identity {
            seed: [1u8; SEED_LEN],
            path: PathBuf::from("/nonexistent"),
        };
        let addr = id.onion_address().display_unredacted().to_string();
        assert!(addr.ends_with(".onion"), "{addr}");
        assert_eq!(addr.len(), 56 + ".onion".len(), "{addr}");
    }

    #[test]
    fn seed_roundtrips_through_disk_at_0600() {
        let dir = std::env::temp_dir().join(format!("murmure-idtest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("identity.seed");

        let first = Identity::load_or_create(&path).expect("create");
        assert_eq!(fs::metadata(&path).expect("stat").len(), SEED_LEN as u64);
        first.check_permissions().expect("0600");

        let second = Identity::load_or_create(&path).expect("load");
        assert_eq!(first.onion_address(), second.onion_address());

        fs::remove_file(&path).expect("rm");
        let third = Identity::load_or_create(&path).expect("recreate");
        assert_ne!(first.onion_address(), third.onion_address());

        let _ = fs::remove_dir_all(&dir);
    }
}

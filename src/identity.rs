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

use anyhow::{Context as _, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use bip39::Mnemonic;
use rand::RngCore as _;
use tor_hscrypto::pk::{
    HsClientDescEncKey, HsClientDescEncSecretKey, HsId, HsIdKey, HsIdKeypair,
};
use tor_llcrypto::pk::{curve25519, ed25519};
use zeroize::Zeroizing;

use crate::store;

/// Length of the ed25519 secret seed murmure persists.
pub const SEED_LEN: usize = 32;

/// Marks a seed file as passphrase-encrypted rather than raw bytes. Chosen so
/// the two formats are told apart by content, not just length — an encrypted
/// file could coincidentally be some other length in a future format.
///
/// The second format writes its Argon2 cost after the magic, so the cost can
/// rise later without a third. The first used Argon2's defaults and wrote
/// nothing; it is still read, and rewritten in the second on the next load.
const MAGIC: [u8; 6] = *b"MURM2E";
const MAGIC_V1: [u8; 6] = *b"MURM1E";

/// Argon2id cost for new files: 64 MiB, three passes, one lane. About a
/// third of a second once per start, against Argon2's default of 19 MiB and
/// two passes, which is sized for a server answering many logins.
const COST: Cost = Cost { m_kib: 64 * 1024, t: 3, p: 1 };

/// What the first format used, never written down.
const COST_V1: Cost = Cost {
    m_kib: Params::DEFAULT_M_COST,
    t: Params::DEFAULT_T_COST,
    p: Params::DEFAULT_P_COST,
};

/// Argon2's three knobs, as the file stores them: little-endian `u32`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cost {
    m_kib: u32,
    t: u32,
    p: u32,
}

impl Cost {
    const LEN: usize = 12;

    fn to_bytes(self) -> [u8; Self::LEN] {
        let mut out = [0; Self::LEN];
        for (at, v) in [self.m_kib, self.t, self.p].into_iter().enumerate() {
            out[at * 4..at * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        out
    }

    /// Read back, refusing a cost this program would never write: the file is
    /// ours, but a tampered one must not make a start take an hour or 4 GiB.
    fn from_bytes(bytes: &[u8; Self::LEN]) -> Result<Self> {
        let n = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"));
        let cost = Cost { m_kib: n(0), t: n(4), p: n(8) };
        if cost.m_kib > 1024 * 1024 || cost.t > 16 || cost.p > 8 {
            bail!("the seed file asks for an Argon2 cost out of range: {cost:?}");
        }
        Ok(cost)
    }
}

/// Length of the random salt stored alongside an encrypted seed.
const SALT_LEN: usize = 16;

/// Derive a 32-byte key from a passphrase and salt via Argon2id.
///
/// This is the one place a human-chosen secret enters the picture, so it goes
/// through Argon2id rather than BLAKE3 — a KDF built to be slow against
/// brute force, unlike `Identity::derive_key`, which derives from a seed that
/// is already high entropy.
fn derive_key_from_passphrase(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    cost: Cost,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(cost.m_kib, cost.t, cost.p, Some(32))
        .map_err(|e| anyhow::anyhow!("Argon2 parameters {cost:?}: {e}"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
        .map_err(|e| anyhow::anyhow!("deriving a key from the passphrase: {e}"))?;
    Ok(out)
}

/// Whether `bytes` is a passphrase-encrypted seed file rather than a raw seed.
fn is_encrypted(bytes: &[u8]) -> bool {
    bytes.len() > MAGIC.len() && (bytes[..MAGIC.len()] == MAGIC || bytes[..MAGIC.len()] == MAGIC_V1)
}

/// Written in the first format, whose cost is too low to keep.
fn is_v1(bytes: &[u8]) -> bool {
    bytes.starts_with(&MAGIC_V1)
}

/// Seal `seed` under `passphrase`. Pure: no file I/O, no prompting — so tests
/// can drive it directly instead of through the terminal or an env var.
fn encrypt_seed_bytes(seed: &[u8; SEED_LEN], passphrase: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let key = derive_key_from_passphrase(passphrase, &salt, COST)?;
    let sealed = store::seal(&key, seed)?;

    let mut out = Vec::with_capacity(MAGIC.len() + Cost::LEN + SALT_LEN + sealed.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&COST.to_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Open what [`encrypt_seed_bytes`] produced.
fn decrypt_seed_bytes(bytes: &[u8], passphrase: &str) -> Result<Zeroizing<[u8; SEED_LEN]>> {
    let rest = &bytes[MAGIC.len()..];
    let (cost, rest) = if is_v1(bytes) {
        (COST_V1, rest)
    } else {
        let (cost, rest) = rest
            .split_first_chunk::<{ Cost::LEN }>()
            .context("encrypted seed file is truncated")?;
        (Cost::from_bytes(cost)?, rest)
    };
    if rest.len() < SALT_LEN {
        bail!("encrypted seed file is truncated");
    }
    let (salt, sealed) = rest.split_at(SALT_LEN);
    let salt: [u8; SALT_LEN] = salt.try_into().expect("split_at guarantees the length");

    let key = derive_key_from_passphrase(passphrase, &salt, cost)?;
    let plaintext =
        store::open(&key, sealed).context("wrong passphrase, or the seed file was tampered with")?;
    plaintext
        .as_slice()
        .try_into()
        .map(Zeroizing::new)
        .map_err(|_| anyhow::anyhow!("decrypted seed is not {SEED_LEN} bytes"))
}

/// Read a passphrase for an existing encrypted seed: from the env var if set
/// (scripting/tests — the value then lives in the process environment, which
/// is less safe than a prompt nobody else can read), a terminal prompt
/// otherwise.
fn read_passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var("MURMURE_SEED_PASSPHRASE") {
        return Ok(Zeroizing::new(p));
    }
    Ok(Zeroizing::new(
        rpassword::prompt_password(prompt).context("reading the passphrase")?,
    ))
}

/// Read a *new* passphrase, confirmed by asking twice, unless the env var
/// escape hatch is set.
fn read_new_passphrase() -> Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var("MURMURE_SEED_PASSPHRASE") {
        return Ok(Zeroizing::new(p));
    }
    let first = rpassword::prompt_password("new identity passphrase: ")
        .context("reading the passphrase")?;
    let second = rpassword::prompt_password("confirm passphrase: ").context("reading the passphrase")?;
    if first != second {
        bail!("passphrases did not match");
    }
    if first.is_empty() {
        bail!("passphrase must not be empty");
    }
    Ok(Zeroizing::new(first))
}

/// Atomically overwrite `path` with `bytes` at 0600. Shared by
/// [`Identity::encrypt_at_rest`] and [`Identity::decrypt_at_rest`], both of
/// which replace an existing seed file rather than refusing to clobber one
/// the way [`Identity::create`] does.
fn write_seed_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("flushing {}", tmp.display()))?;
    drop(file);
    fs::rename(&tmp, path).with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
    store::sync_parent(path);
    Ok(())
}

/// Key-derivation context for the service-discovery key. Frozen: changing it
/// changes the key every contact has already authorised.
const DISCOVERY_CONTEXT: &str = "murmure 2026 service discovery";

/// A murmure identity: one 32-byte ed25519 seed, and everything derived from it.
pub struct Identity {
    /// The secret seed. Never printed, never logged, and wiped on drop.
    ///
    /// `Zeroizing` rather than a bare array: this is the one value the whole
    /// threat model rests on, and an array is `Copy`, so leaving it bare means
    /// every move leaves a readable copy behind on the stack. The wrapper is
    /// not `Copy`, which makes those accidental copies a compile error.
    seed: Zeroizing<[u8; SEED_LEN]>,
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
        // The read buffer holds the seed too, so it is wiped on the way out
        // rather than left in a freed allocation.
        let bytes = Zeroizing::new(
            fs::read(path)
                .with_context(|| format!("reading the identity seed at {}", path.display()))?,
        );
        let seed: Zeroizing<[u8; SEED_LEN]> = if is_encrypted(&bytes) {
            let passphrase = read_passphrase("identity passphrase: ")?;
            let seed = decrypt_seed_bytes(&bytes, &passphrase)?;
            // The passphrase is only ever in hand here, so this is where the
            // first format moves to the second. Failing to is not failing to
            // start: the old file still opens next time.
            if is_v1(&bytes)
                && let Err(e) = encrypt_seed_bytes(&seed, &passphrase).and_then(|out| write_seed_bytes(path, &out))
            {
                tracing::warn!("could not upgrade the seed file's passphrase hashing: {e:#}");
            }
            seed
        } else {
            bytes.as_slice().try_into().map(Zeroizing::new).map_err(|_| {
                anyhow::anyhow!(
                    "{} is {} bytes, expected exactly {SEED_LEN}; \
                     delete it to generate a fresh identity",
                    path.display(),
                    bytes.len()
                )
            })?
        };
        Ok(Self {
            seed,
            path: path.to_path_buf(),
        })
    }

    /// Encrypt an existing plaintext seed file at rest, under a passphrase.
    ///
    /// Prompts for the new passphrase (or reads `MURMURE_SEED_PASSPHRASE`)
    /// before touching the file, so a mistyped passphrase never destroys the
    /// original.
    pub fn encrypt_at_rest(path: &Path) -> Result<()> {
        // A plaintext seed file: the buffer is the seed, so it is wiped too.
        let bytes = Zeroizing::new(
            fs::read(path).with_context(|| format!("reading the identity seed at {}", path.display()))?,
        );
        if is_encrypted(&bytes) {
            bail!(
                "{} is already passphrase-encrypted; run with MURMURE_DECRYPT_IDENTITY=1 first \
                 to change or remove the passphrase",
                path.display()
            );
        }
        let seed: Zeroizing<[u8; SEED_LEN]> = bytes.as_slice().try_into().map(Zeroizing::new).map_err(|_| {
            anyhow::anyhow!("{} is {} bytes, expected exactly {SEED_LEN}", path.display(), bytes.len())
        })?;
        let passphrase = read_new_passphrase()?;
        let out = encrypt_seed_bytes(&seed, &passphrase)?;
        write_seed_bytes(path, &out)
    }

    /// Decrypt an encrypted seed file back to raw bytes on disk.
    pub fn decrypt_at_rest(path: &Path) -> Result<()> {
        let bytes = fs::read(path)
            .with_context(|| format!("reading the identity seed at {}", path.display()))?;
        if !is_encrypted(&bytes) {
            bail!("{} is not passphrase-encrypted", path.display());
        }
        let passphrase = read_passphrase("identity passphrase: ")?;
        let seed = decrypt_seed_bytes(&bytes, &passphrase)?;
        write_seed_bytes(path, seed.as_slice())
    }

    /// This identity's seed as a 24-word BIP-39 recovery phrase.
    ///
    /// Losing the seed still loses everything it sealed — [`derive_key`]'s doc
    /// comment already says so, and a paper backup does not change that. What
    /// it changes is the seed's own durability: 32 raw bytes do not survive a
    /// dead disk, twenty-four words on paper do.
    ///
    /// [`derive_key`]: Identity::derive_key
    pub fn mnemonic_phrase(&self) -> Result<Zeroizing<String>> {
        let mnemonic = Mnemonic::from_entropy(self.seed.as_ref())
            .context("encoding the seed as a recovery phrase")?;
        Ok(Zeroizing::new(mnemonic.to_string()))
    }

    /// The seed a 24-word BIP-39 phrase encodes.
    ///
    /// Checked, not trusted: `Mnemonic`'s parser verifies the checksum word,
    /// so a single mistyped word is a parse error here rather than a
    /// different, silently wrong identity.
    fn seed_from_mnemonic(phrase: &str) -> Result<Zeroizing<[u8; SEED_LEN]>> {
        let mnemonic: Mnemonic = phrase
            .trim()
            .parse()
            .context("not a valid BIP-39 recovery phrase")?;
        let entropy = mnemonic.to_entropy();
        entropy.as_slice().try_into().map(Zeroizing::new).map_err(|_| {
            anyhow::anyhow!(
                "recovery phrase encodes {} bytes, expected {SEED_LEN} (24 words)",
                entropy.len()
            )
        })
    }

    /// Print the recovery phrase for the seed at `path`.
    pub fn export_mnemonic(path: &Path) -> Result<Zeroizing<String>> {
        if !path.exists() {
            bail!("no identity seed at {}; nothing to export", path.display());
        }
        let identity = Self::load(path)?;
        identity.check_permissions()?;
        identity.mnemonic_phrase()
    }

    /// Write a fresh seed file at `path` from a recovery phrase.
    ///
    /// Refuses to touch a path that already holds an identity — restoring is
    /// for a *lost* seed, and silently overwriting a live one would trade one
    /// lost identity for another.
    pub fn restore_from_mnemonic(path: &Path, phrase: &str) -> Result<()> {
        if path.exists() {
            bail!(
                "{} already holds an identity; move it aside first if you mean to replace it",
                path.display()
            );
        }
        let seed = Self::seed_from_mnemonic(phrase)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        write_seed_bytes(path, seed.as_slice())
    }

    /// Generate a seed from the OS CSPRNG and write it with 0600 permissions.
    fn create(path: &Path) -> Result<Self> {
        // Wrapped before it is filled, not after: a bare array would be filled,
        // copied into the wrapper, and the original left behind untouched.
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        rand::rngs::OsRng.fill_bytes(seed.as_mut());

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
        file.write_all(seed.as_slice())
            .with_context(|| format!("writing the identity seed at {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("flushing the identity seed at {}", path.display()))?;
        store::sync_parent(path);

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

    /// Sign a message with the key the `.onion` address is derived from.
    ///
    /// This is what lets a peer be *named*. An onion service authenticates the
    /// server, never the client, so an incoming stream carries no identity at
    /// all — the caller has to assert one and prove it. Proving it costs
    /// nothing extra here: the address already is this public key, so the
    /// signature checks against the address itself rather than against a
    /// certificate somebody has to trust.
    ///
    /// Only [`crate::proto::handshake`] should call this, and only over the
    /// challenge it builds. A signing oracle over arbitrary attacker-chosen
    /// bytes is how signature schemes get turned against their owner; the
    /// domain separator in that challenge is what keeps this key's signatures
    /// from meaning anything anywhere else.
    pub fn sign(&self, message: &[u8]) -> ed25519::Signature {
        let keypair = ed25519::Keypair::from_bytes(&self.seed);
        ed25519::ExpandedKeypair::from(&keypair).sign(message)
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
    pub fn derive_key(&self, context: &str) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(blake3::derive_key(context, self.seed.as_ref()))
    }

    /// The x25519 secret murmure proves itself with to a restricted service.
    ///
    /// # One key for every peer, on purpose
    ///
    /// The Tor spec files a discovery keypair per *service* you want to reach,
    /// and arti's keystore indexes it by the service's `HsId`. Generating a
    /// fresh one per contact would mean three messages to add a friend: their
    /// address, then a key derived from it, then theirs back. Deriving one key
    /// from the seed instead makes the exchange symmetric and one-shot — each
    /// side hands over `<address> <key>` once — and murmure inserts that same
    /// secret under every contact's `HsId`.
    ///
    /// The cost is that two contacts who compare notes see the same public key
    /// and learn they are talking to the same person. They already both hold
    /// your `.onion`, which says that far more directly, so nothing leaks that
    /// was not already out. Third parties see nothing either way: the
    /// descriptor carries per-client encrypted cookies, never the raw key.
    ///
    /// ponytail: revisit if murmure ever grows separable personas, which is the
    /// one case where linking two contacts would actually cost something.
    pub fn discovery_secret(&self) -> HsClientDescEncSecretKey {
        // `*` copies the bytes out so `StaticSecret` can own them; the wrapper
        // wipes its own copy at the end of the statement, and `StaticSecret`
        // zeroizes on drop in turn.
        curve25519::StaticSecret::from(*self.derive_key(DISCOVERY_CONTEXT)).into()
    }

    /// The public half, in the `descriptor:x25519:<base32>` form C Tor and arti
    /// both read. This is what a friend authorises.
    pub fn discovery_key(&self) -> HsClientDescEncKey {
        HsClientDescEncKey::from(&self.discovery_secret())
    }

    /// An identity with no file behind it, for tests in other modules.
    ///
    /// Test-only because nothing in the program should hold a seed it did not
    /// load from a checked file: `check_permissions` is the reason
    /// `load_or_create` is the only public constructor.
    #[cfg(test)]
    pub fn for_test(seed: [u8; SEED_LEN]) -> Self {
        Self {
            seed: Zeroizing::new(seed),
            path: PathBuf::from("/nonexistent"),
        }
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
            seed: Zeroizing::new([7u8; SEED_LEN]),
            path: PathBuf::from("/nonexistent"),
        };
        let b = Identity {
            seed: Zeroizing::new([7u8; SEED_LEN]),
            path: PathBuf::from("/nonexistent"),
        };
        let c = Identity {
            seed: Zeroizing::new([8u8; SEED_LEN]),
            path: PathBuf::from("/nonexistent"),
        };
        assert_eq!(a.onion_address(), b.onion_address());
        assert_ne!(a.onion_address(), c.onion_address());
    }

    #[test]
    fn discovery_key_is_a_pure_function_of_the_seed() {
        let a = Identity {
            seed: Zeroizing::new([7u8; SEED_LEN]),
            path: PathBuf::from("/nonexistent"),
        };
        let b = Identity {
            seed: Zeroizing::new([8u8; SEED_LEN]),
            path: PathBuf::from("/nonexistent"),
        };
        assert_eq!(a.discovery_key(), a.discovery_key());
        assert_ne!(a.discovery_key(), b.discovery_key());
        // The wire form is what a friend pastes into /add, so it has to parse
        // back to the same key.
        let text = a.discovery_key().to_string();
        assert!(text.starts_with("descriptor:x25519:"), "{text}");
        assert_eq!(text.parse::<HsClientDescEncKey>().unwrap(), a.discovery_key());
    }

    #[test]
    fn address_is_a_well_formed_v3_onion() {
        let id = Identity {
            seed: Zeroizing::new([1u8; SEED_LEN]),
            path: PathBuf::from("/nonexistent"),
        };
        let addr = id.onion_address().display_unredacted().to_string();
        assert!(addr.ends_with(".onion"), "{addr}");
        assert_eq!(addr.len(), 56 + ".onion".len(), "{addr}");
    }

    #[test]
    fn encrypted_seed_bytes_round_trip_under_the_right_passphrase() {
        let seed = [5u8; SEED_LEN];
        let encrypted = encrypt_seed_bytes(&seed, "correct horse battery staple").unwrap();
        assert!(is_encrypted(&encrypted));
        let decrypted = decrypt_seed_bytes(&encrypted, "correct horse battery staple").unwrap();
        assert_eq!(*decrypted, seed);
    }

    /// A seed file as the first format wrote it: magic, salt, sealed seed.
    fn first_format(seed: &[u8; SEED_LEN], passphrase: &str) -> Vec<u8> {
        let salt = [3u8; SALT_LEN];
        let key = derive_key_from_passphrase(passphrase, &salt, COST_V1).unwrap();
        [&MAGIC_V1[..], &salt, &store::seal(&key, seed).unwrap()].concat()
    }

    #[test]
    fn the_first_format_still_opens() {
        let seed = [9u8; SEED_LEN];
        let old = first_format(&seed, "pass");
        assert!(is_encrypted(&old) && is_v1(&old));
        assert_eq!(*decrypt_seed_bytes(&old, "pass").unwrap(), seed);
        assert!(decrypt_seed_bytes(&old, "wrong").is_err());
    }

    #[test]
    fn an_absurd_cost_is_refused_before_it_runs() {
        let mut file = encrypt_seed_bytes(&[1u8; SEED_LEN], "p").unwrap();
        file[MAGIC.len()..][..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decrypt_seed_bytes(&file, "p").is_err());
    }

    #[test]
    fn a_wrong_passphrase_cannot_open_an_encrypted_seed() {
        let seed = [5u8; SEED_LEN];
        let encrypted = encrypt_seed_bytes(&seed, "right").unwrap();
        assert!(decrypt_seed_bytes(&encrypted, "wrong").is_err());
    }

    #[test]
    fn a_plain_seed_file_is_not_mistaken_for_an_encrypted_one() {
        assert!(!is_encrypted(&[7u8; SEED_LEN]));
    }

    #[test]
    fn encrypt_then_decrypt_at_rest_round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!("murmure-idcrypt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("identity.seed");

        // SAFETY: this test does not run concurrently with another test that
        // reads or writes MURMURE_SEED_PASSPHRASE — it is the only one, and
        // the whole binary's tests run single-process but not necessarily
        // single-threaded, so this is scoped as tightly as std::env allows.
        unsafe { std::env::set_var("MURMURE_SEED_PASSPHRASE", "test passphrase") };

        let before = Identity::load_or_create(&path).expect("create");
        let address_before = before.onion_address();
        drop(before);

        Identity::encrypt_at_rest(&path).expect("encrypt");
        assert!(is_encrypted(&fs::read(&path).unwrap()));

        let after_encrypt = Identity::load_or_create(&path).expect("load encrypted");
        assert_eq!(after_encrypt.onion_address(), address_before);
        drop(after_encrypt);

        Identity::decrypt_at_rest(&path).expect("decrypt");
        assert!(!is_encrypted(&fs::read(&path).unwrap()));

        let after_decrypt = Identity::load_or_create(&path).expect("load decrypted");
        assert_eq!(after_decrypt.onion_address(), address_before);

        // A file in the first format opens, and is written back in the second.
        fs::write(&path, first_format(&after_decrypt.seed, "test passphrase")).unwrap();
        let upgraded = Identity::load_or_create(&path).expect("load the first format");
        assert_eq!(upgraded.onion_address(), address_before);
        let now = fs::read(&path).unwrap();
        assert!(now.starts_with(&MAGIC) && !is_v1(&now));
        assert_eq!(Cost::from_bytes(now[MAGIC.len()..][..Cost::LEN].try_into().unwrap()).unwrap(), COST);

        unsafe { std::env::remove_var("MURMURE_SEED_PASSPHRASE") };
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_mnemonic_phrase_round_trips_back_to_the_same_seed() {
        let seed = [5u8; SEED_LEN];
        let id = Identity::for_test(seed);
        let phrase = id.mnemonic_phrase().unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24, "{}", *phrase);
        assert_eq!(*Identity::seed_from_mnemonic(&phrase).unwrap(), seed);
    }

    /// "abandon" x24 is the canonical BIP-39 all-zero-entropy phrase, but the
    /// last word has to be the checksum for *that* entropy — twenty-four
    /// repeats of the same word is not it.
    #[test]
    fn a_phrase_with_a_bad_checksum_is_rejected() {
        let phrase = vec!["abandon"; 24].join(" ");
        assert!(Identity::seed_from_mnemonic(&phrase).is_err());
    }

    #[test]
    fn restore_from_mnemonic_writes_a_seed_matching_the_original() {
        let dir = std::env::temp_dir().join(format!("murmure-idmnem-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("identity.seed");

        let original = Identity::load_or_create(&path).expect("create");
        let address = original.onion_address();
        let phrase = original.mnemonic_phrase().unwrap();
        drop(original);
        fs::remove_file(&path).unwrap();

        Identity::restore_from_mnemonic(&path, &phrase).expect("restore");
        let restored = Identity::load_or_create(&path).expect("load restored");
        assert_eq!(restored.onion_address(), address);
        restored.check_permissions().expect("0600");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_from_mnemonic_refuses_to_clobber_an_existing_seed() {
        let dir = std::env::temp_dir().join(format!("murmure-idmnem-clobber-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("identity.seed");

        let original = Identity::load_or_create(&path).expect("create");
        let phrase = original.mnemonic_phrase().unwrap();
        drop(original);

        assert!(Identity::restore_from_mnemonic(&path, &phrase).is_err());

        let _ = fs::remove_dir_all(&dir);
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

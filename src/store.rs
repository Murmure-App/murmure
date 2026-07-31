//! Sealed files on disk.
//!
//! Everything murmure persists beyond the seed itself goes through here, and
//! nothing it persists is ever readable without the seed. The contacts book is
//! the first user; the history is the next.
//!
//! # Why the contacts book has to be sealed
//!
//! The whole project exists so that nobody can tell who talks to whom. A plain
//! `contacts.json` on the disk is that exact graph, written down, for anyone who
//! picks up the laptop. Sealing it is not extra caution — it is the same
//! requirement as the one on the wire.
//!
//! # Construction
//!
//! XChaCha20-Poly1305 with a random 24-byte nonce prepended to the ciphertext.
//! The extended nonce is what makes "fresh random nonce per write" safe without
//! tracking a counter across runs. The key comes from
//! [`crate::identity::Identity::derive_key`], which is BLAKE3's KDF — no
//! home-made construction anywhere in this path.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use chacha20poly1305::aead::{Aead as _, KeyInit as _};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore as _;

/// Length of the XChaCha20-Poly1305 nonce, in bytes.
const NONCE_LEN: usize = 24;

/// Seal `plaintext` under `key`. The result is `nonce || ciphertext`.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(&XNonce::from(nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("sealing failed"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open what [`seal`] produced.
///
/// Fails on a wrong key and on any tampering — Poly1305 authenticates, so a
/// flipped bit is an error rather than corrupted plaintext.
pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN {
        bail!("sealed data is {} bytes, too short to hold a nonce", sealed.len());
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split_at guarantees the length");

    XChaCha20Poly1305::new(key.into())
        .decrypt(&XNonce::from(nonce), ciphertext)
        .map_err(|_| {
            anyhow::anyhow!(
                "could not open the sealed file: wrong identity seed, or the file was tampered with"
            )
        })
}

/// Seal `plaintext` and write it to `path`, 0600, atomically.
///
/// Atomically because a half-written contacts book is a lost contacts book:
/// the seal covers the whole file, so a truncated write is unrecoverable rather
/// than partially readable. Write beside, then rename.
pub fn write_sealed(path: &Path, key: &[u8; 32], plaintext: &[u8]) -> Result<()> {
    let sealed = seal(key, plaintext)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
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
    file.write_all(&sealed)
        .with_context(|| format!("writing {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("flushing {}", tmp.display()))?;
    drop(file);

    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Read and open a sealed file, or [`None`] if it does not exist yet.
pub fn read_sealed(path: &Path, key: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(sealed) => Ok(Some(open(key, &sealed).with_context(|| {
            format!("opening {}", path.display())
        })?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_data_round_trips() {
        let key = [3u8; 32];
        let sealed = seal(&key, b"alice = haticv...onion").unwrap();
        assert_eq!(open(&key, &sealed).unwrap(), b"alice = haticv...onion");
    }

    #[test]
    fn the_plaintext_never_appears_in_the_sealed_bytes() {
        let key = [3u8; 32];
        let sealed = seal(&key, b"alice").unwrap();
        assert!(
            !sealed.windows(5).any(|w| w == b"alice"),
            "the contacts book must not be readable on disk"
        );
    }

    #[test]
    fn a_different_seed_cannot_open_it() {
        let sealed = seal(&[3u8; 32], b"alice").unwrap();
        assert!(open(&[4u8; 32], &sealed).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let key = [3u8; 32];
        let mut sealed = seal(&key, b"alice").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open(&key, &sealed).is_err());
    }

    /// Two seals of the same plaintext must differ, or the file leaks whether
    /// anything changed between two writes.
    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let key = [3u8; 32];
        assert_ne!(seal(&key, b"alice").unwrap(), seal(&key, b"alice").unwrap());
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let path = std::env::temp_dir().join("murmure-store-absent");
        let _ = fs::remove_file(&path);
        assert!(read_sealed(&path, &[3u8; 32]).unwrap().is_none());
    }

    #[test]
    fn files_round_trip_through_disk() {
        let dir = std::env::temp_dir().join(format!("murmure-store-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("contacts.sealed");
        let key = [9u8; 32];

        write_sealed(&path, &key, b"alice").unwrap();
        assert_eq!(read_sealed(&path, &key).unwrap().unwrap(), b"alice");

        // A rewrite replaces rather than appends.
        write_sealed(&path, &key, b"bob").unwrap();
        assert_eq!(read_sealed(&path, &key).unwrap().unwrap(), b"bob");

        let _ = fs::remove_dir_all(&dir);
    }
}

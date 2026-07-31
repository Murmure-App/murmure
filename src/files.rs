//! Sending a file over an open conversation, and receiving one safely.
//!
//! # Why BLAKE3 of the whole file, and not a verified-streaming tree
//!
//! The obvious reach here is `bao-tree`: BLAKE3's tree structure lets a
//! recipient verify each chunk as it arrives, so a lying sender is caught at the
//! first bad byte instead of after the last one.
//!
//! murmure does not need that. The stream is a Tor rendezvous circuit, so it is
//! already authenticated and encrypted end to end, and the peer is authenticated
//! by the `.onion` address the operator typed and read out loud. A sender who
//! wanted to give you the wrong bytes would simply offer a different file.
//! Verified streaming defends against a source you did not choose; this is a
//! source you called by name.
//!
//! What is actually needed is integrity against corruption, and an identity for
//! a transfer so that resuming appends to the right thing. One hash of the whole
//! file gives both, out of a dependency already in the tree.
//!
//! ponytail: bao-tree becomes worth it the day a file can arrive from somewhere
//! other than the peer at the end of the stream — a relay, a cache, a third
//! party. The hash in [`crate::proto::Message::FileOffer`] would become a bao
//! root, and this module is where that change lands.
//!
//! # Why the partial file is named after the hash
//!
//! A resumed transfer must append to bytes from the *same* file, or it splices
//! two files into one that no hash will ever match. Naming the partial after the
//! hash makes that structural: a partial that exists under a given hash can only
//! ever be a prefix of the file with that hash. No sidecar, no index, nothing to
//! keep in sync.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};

/// Largest file murmure will offer or accept, in bytes.
///
/// A conversation is one stream and one file at a time, so a huge transfer holds
/// the conversation hostage for as long as it runs. 2 GiB over a Tor circuit is
/// already many hours; anything larger wants the direct plane, not this one.
pub const MAX_FILE: u64 = 2 * 1024 * 1024 * 1024;

/// How many bytes to hash at a time when reading a file from disk.
const HASH_BUF: usize = 64 * 1024;

/// What a peer needs to know about a file before deciding to take it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// The name as it will be shown, already stripped of any path.
    pub name: String,
    pub size: u64,
    /// BLAKE3 of the whole file.
    pub hash: [u8; 32],
}

/// Read a file from disk and describe it, ready to offer.
pub fn describe(path: &Path) -> Result<Offer> {
    let meta = fs::metadata(path)
        .with_context(|| format!("{} cannot be read", path.display()))?;
    if meta.is_dir() {
        bail!("{} is a directory; send one file at a time", path.display());
    }
    if meta.len() == 0 {
        bail!("{} is empty", path.display());
    }
    if meta.len() > MAX_FILE {
        bail!(
            "{} is {}, over the {} limit",
            path.display(),
            human(meta.len()),
            human(MAX_FILE)
        );
    }

    // Our own filename, so it needs no sanitising to be *used* — but it is about
    // to become the peer's untrusted input, and sending a path would leak the
    // directory layout of this machine along with it.
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("{} has no usable filename", path.display()))?
        .to_owned();
    if name.len() > crate::proto::MAX_NAME {
        bail!("{name:?} is longer than {} bytes", crate::proto::MAX_NAME);
    }

    Ok(Offer {
        name,
        size: meta.len(),
        hash: hash_file(path)?,
    })
}

/// BLAKE3 of a file, read in chunks rather than loaded whole.
pub fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let mut file =
        fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; HASH_BUF];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("reading {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Turn a peer-supplied filename into one that is safe to create.
///
/// This is a trust boundary and it is treated as one. The name arrives from the
/// network and is about to become a path, which is how `../../.ssh/authorized_keys`
/// happens. Rather than blocklisting the dangerous shapes, the whole path is
/// discarded and only a final component is kept — and that component is then
/// checked to be an ordinary name.
///
/// Both separators are stripped, not just the platform's: a Windows-shaped name
/// arriving on Unix must not become a single file called `..\..\secrets`, which
/// is legal there and would be a path again the moment it is copied back.
pub fn safe_name(raw: &str) -> Result<String> {
    let last = raw
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(raw)
        .trim()
        .to_owned();

    if last.is_empty() || last == "." || last == ".." {
        bail!("the peer sent {raw:?} as a filename, which is not a name");
    }
    if last.len() > crate::proto::MAX_NAME {
        bail!("the peer sent a {}-byte filename", last.len());
    }
    // The operator decides whether to accept by reading this name, so anything
    // that makes it display differently from what it is gets refused.
    //
    // `is_control` covers C0 and C1 but *not* the bidirectional overrides, which
    // Unicode files as format characters: U+202E turns `innocent<RLO>gnp.exe`
    // into `innocentexe.png` on screen while remaining an executable. They are
    // listed rather than derived because std exposes no character categories,
    // and a named list of exactly what reorders text is clearer than a
    // dependency that would answer the same question.
    const BIDI: [char; 12] = [
        '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}',
        '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
    ];
    if last.chars().any(|c| c.is_control() || BIDI.contains(&c)) {
        bail!("the peer sent a filename containing invisible or reordering characters");
    }
    // Reserved on Windows, harmless on Unix, refused everywhere so that a file
    // received on one machine can be moved to another.
    if last.contains(':') {
        bail!("the peer sent {last:?}, which is not a portable filename");
    }
    Ok(last)
}

/// Where an incoming file is written while it is still incomplete.
///
/// Named after the hash, not the filename: see the module docs.
pub fn partial_path(dir: &Path, hash: &[u8; 32]) -> PathBuf {
    let mut name = String::with_capacity(32);
    for byte in &hash[..16] {
        name.push_str(&format!("{byte:02x}"));
    }
    dir.join(format!("{name}.part"))
}

/// How many bytes of this transfer are already on disk.
///
/// Zero when there is nothing to resume, which is also what a missing directory
/// means. A partial longer than the offer is a mismatch rather than a resume
/// point, so it starts again from nothing.
pub fn resume_offset(dir: &Path, hash: &[u8; 32], size: u64) -> u64 {
    match fs::metadata(partial_path(dir, hash)) {
        Ok(meta) if meta.len() < size => meta.len(),
        _ => 0,
    }
}

/// Verify a completed partial and move it into place under its real name.
///
/// Returns where it landed. The hash is checked *before* the file is given its
/// name, so a corrupted transfer never appears as a finished download.
pub fn finish(dir: &Path, offer: &Offer) -> Result<PathBuf> {
    let partial = partial_path(dir, &offer.hash);
    let got = hash_file(&partial)?;
    if got != offer.hash {
        // Keep the bytes: the operator may want to look. Rename so a retry
        // starts clean rather than resuming onto known-bad data.
        let quarantine = partial.with_extension("corrupt");
        let _ = fs::rename(&partial, &quarantine);
        bail!(
            "the received file does not match the hash it was offered under; \
             kept as {} rather than trusted",
            quarantine.display()
        );
    }

    let name = safe_name(&offer.name)?;
    let final_path = free_path(dir, &name);
    fs::rename(&partial, &final_path).with_context(|| {
        format!("moving {} to {}", partial.display(), final_path.display())
    })?;
    Ok(final_path)
}

/// `dir/name`, or `dir/name (2)` and so on if that is taken.
///
/// Overwriting silently would let a second transfer of a different file with the
/// same name destroy the first.
fn free_path(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    // Split on the last dot so `report.pdf` becomes `report (2).pdf` rather than
    // `report.pdf (2)`.
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s, format!(".{e}")),
        _ => (name, String::new()),
    };
    for n in 2..1000 {
        let candidate = dir.join(format!("{stem} ({n}){ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    // A thousand collisions is not a case worth more code; the rename fails
    // with a clear error and the operator clears the directory.
    dir.join(name)
}

/// Bytes, in a form a person reads without counting digits.
pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "kB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("murmure-files-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The one that matters: a name from the network must never become a path.
    #[test]
    fn a_hostile_filename_cannot_escape_the_directory() {
        assert_eq!(safe_name("../../.ssh/authorized_keys").unwrap(), "authorized_keys");
        assert_eq!(safe_name("/etc/passwd").unwrap(), "passwd");
        assert_eq!(safe_name(r"..\..\Windows\System32\x.dll").unwrap(), "x.dll");
        assert_eq!(safe_name("rapport.pdf").unwrap(), "rapport.pdf");

        // Nothing left once the path is gone.
        assert!(safe_name("../..").is_err());
        assert!(safe_name("/").is_err());
        assert!(safe_name("   ").is_err());
        assert!(safe_name(".").is_err());
        // A right-to-left override hiding the real extension from the operator:
        // this displays as `innocentexe.png` and runs as an executable.
        assert!(safe_name("innocent\u{202e}gnp.exe").is_err());
        // The isolates do the same job.
        assert!(safe_name("photo\u{2066}exe.\u{2069}png").is_err());
        assert!(safe_name("notes\u{0000}.txt").is_err());
        // An NTFS alternate data stream, and a drive letter.
        assert!(safe_name("notes.txt:hidden").is_err());
    }

    #[test]
    fn describing_a_file_gives_its_name_size_and_hash() {
        let dir = scratch("describe");
        let path = dir.join("rapport.pdf");
        fs::write(&path, b"bonjour").unwrap();

        let offer = describe(&path).unwrap();
        assert_eq!(offer.name, "rapport.pdf");
        assert_eq!(offer.size, 7);
        assert_eq!(offer.hash, *blake3::hash(b"bonjour").as_bytes());

        assert!(describe(&dir).is_err(), "a directory is not a file");
        fs::write(dir.join("empty"), b"").unwrap();
        assert!(describe(&dir.join("empty")).is_err(), "nothing to send");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_partial_is_resumed_only_when_it_belongs_to_this_transfer() {
        let dir = scratch("resume");
        let hash = *blake3::hash(b"bonjour tout le monde").as_bytes();
        let other = *blake3::hash(b"un autre fichier").as_bytes();

        assert_eq!(resume_offset(&dir, &hash, 21), 0, "nothing on disk yet");

        fs::write(partial_path(&dir, &hash), b"bonjour ").unwrap();
        assert_eq!(resume_offset(&dir, &hash, 21), 8);
        // A different file's partial is invisible to this one.
        assert_eq!(resume_offset(&dir, &other, 16), 0);
        // Longer than the offer: not a prefix, so not a resume point.
        assert_eq!(resume_offset(&dir, &hash, 4), 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_completed_transfer_is_verified_before_it_gets_its_name() {
        let dir = scratch("finish");
        let body = b"bonjour tout le monde";
        let offer = Offer {
            name: "rapport.pdf".into(),
            size: body.len() as u64,
            hash: *blake3::hash(body).as_bytes(),
        };

        fs::write(partial_path(&dir, &offer.hash), body).unwrap();
        let landed = finish(&dir, &offer).unwrap();
        assert_eq!(landed, dir.join("rapport.pdf"));
        assert_eq!(fs::read(&landed).unwrap(), body);

        // Same name again: the first file must survive.
        fs::write(partial_path(&dir, &offer.hash), body).unwrap();
        let second = finish(&dir, &offer).unwrap();
        assert_eq!(second, dir.join("rapport (2).pdf"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupted_bytes_never_appear_as_a_finished_download() {
        let dir = scratch("corrupt");
        let offer = Offer {
            name: "rapport.pdf".into(),
            size: 7,
            hash: *blake3::hash(b"bonjour").as_bytes(),
        };
        fs::write(partial_path(&dir, &offer.hash), b"bonsoir").unwrap();

        assert!(finish(&dir, &offer).is_err());
        assert!(
            !dir.join("rapport.pdf").exists(),
            "a file that failed its hash must not be given its name"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sizes_are_readable() {
        assert_eq!(human(0), "0 B");
        assert_eq!(human(999), "999 B");
        assert_eq!(human(1_500), "1.5 kB");
        assert_eq!(human(2_400_000), "2.4 MB");
    }
}

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

/// Cap on the total size of `incoming/`, used unless `MURMURE_INCOMING_QUOTA`
/// overrides it.
///
/// A peer choosing what to send you chooses how much of your disk it costs;
/// without a ceiling that is an unbounded write. 10 GiB is five transfers at
/// [`MAX_FILE`], generous for a one-conversation-at-a-time tool without being
/// no limit at all.
pub const DEFAULT_INCOMING_QUOTA: u64 = 10 * 1024 * 1024 * 1024;

/// The configured quota, in bytes: `MURMURE_INCOMING_QUOTA` if set and valid,
/// else [`DEFAULT_INCOMING_QUOTA`]. There is no "unlimited" value — an
/// operator writing `0` gets a quota of zero, which refuses every transfer,
/// not the no-limit some tools use `0` for elsewhere.
pub fn incoming_quota() -> u64 {
    parse_quota(std::env::var("MURMURE_INCOMING_QUOTA").ok().as_deref())
}

/// The pure half of [`incoming_quota`], split out so a test can cover the
/// parse/default logic without mutating the process environment — which every
/// test in the binary shares, and would race.
fn parse_quota(raw: Option<&str>) -> u64 {
    raw.and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_INCOMING_QUOTA)
}

/// Bytes already on disk in `dir` — partials and finished downloads alike.
///
/// A missing directory (nothing received yet) counts as empty rather than an
/// error, since that is the common case for a fresh contact.
///
/// ponytail: sums file sizes rather than asking the OS for free space on the
/// volume, so `MURMURE_INCOMING_QUOTA` bounds *this directory*, not the disk.
/// Upgrade to a `statvfs`/`GetDiskFreeSpaceEx` check (a new dependency; not in
/// std) if operators need it to react to a disk that is full for other
/// reasons too.
pub fn dir_size(dir: &Path) -> u64 {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.metadata().ok())
        .filter(|meta| meta.is_file())
        .map(|meta| meta.len())
        .sum()
}

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
    // Refused here rather than by the peer, whose only answer to a name it
    // will not save is to drop the offer.
    if safe_name(&name).is_err() {
        bail!(
            "{name:?} would be refused on the other side (hidden file, reserved or \
             non-portable name, or invisible characters); rename it first"
        );
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
    if last.starts_with('.') {
        bail!("the peer sent {raw:?} as a filename, which is a hidden file");
    }
    if last.len() > crate::proto::MAX_NAME {
        bail!("the peer sent a {}-byte filename", last.len());
    }
    // The operator decides whether to accept by reading this name, so anything
    // that makes it display differently from what it is gets refused outright
    // rather than cleaned — a cleaned name would still save under a different
    // string than the one shown. See [`has_display_spoofing_chars`] for what
    // that covers and why.
    if last.chars().any(has_display_spoofing_chars) {
        bail!("the peer sent a filename containing invisible or reordering characters");
    }
    // Reserved on Windows, harmless on Unix, refused everywhere so that a file
    // received on one machine can be moved to another. Windows also drops a
    // trailing dot, so `a.exe.` would be saved as `a.exe`.
    if last.contains([':', '<', '>', '"', '|', '?', '*']) || last.ends_with('.') {
        bail!("the peer sent {last:?}, which is not a portable filename");
    }
    let stem = last.split('.').next().unwrap_or(&last);
    let is_reserved = matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6"
            | "COM7" | "COM8" | "COM9" | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6"
            | "LPT7" | "LPT8" | "LPT9"
    );
    if is_reserved {
        bail!("the peer sent {last:?}, which is a reserved device name");
    }
    Ok(last)
}

/// Would this character make text display as something other than what it is?
///
/// `is_control` covers C0 and C1 — including ESC, which is how a terminal is
/// told to do anything at all, from moving the cursor to overwriting the
/// system clipboard via OSC 52 (the same mechanism [`crate::ui::copy_to_clipboard`]
/// uses on purpose). It does *not* cover the Unicode bidirectional overrides,
/// which Unicode files as format characters rather than control characters:
/// U+202E turns `innocent<RLO>gnp.exe` into `innocentexe.png` on screen while
/// remaining an executable. They are listed rather than derived because std
/// exposes no character categories, and a named list of exactly what reorders
/// text is clearer than a dependency that would answer the same question.
///
/// The invisible ones go too: zero-width spaces and joiners, word joiners,
/// the BOM, the soft hyphen, the line and paragraph separators, and the tag
/// characters. Each lets two names that look identical differ, or hides text
/// inside a line. A joiner-built emoji loses its joins and shows as its parts.
fn has_display_spoofing_chars(c: char) -> bool {
    const BIDI: [char; 12] = [
        '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}',
        '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
    ];
    const INVISIBLE: [char; 13] = [
        '\u{00ad}', '\u{180e}', '\u{200b}', '\u{200c}', '\u{200d}', '\u{2028}', '\u{2029}',
        '\u{2060}', '\u{2061}', '\u{2062}', '\u{2063}', '\u{2064}', '\u{feff}',
    ];
    c.is_control()
        || BIDI.contains(&c)
        || INVISIBLE.contains(&c)
        || ('\u{e0000}'..='\u{e007f}').contains(&c)
}

/// Strip whatever would let a peer's chat text control our terminal instead of
/// merely appearing on it.
///
/// A `Message::Text` body reaches the screen the same way a `FileOffer` name
/// does — printed straight into the operator's terminal — and needs the same
/// defence `safe_name` gives a filename. Unlike a filename, refusing the whole
/// message is not an option (there is nothing else to fall back to and no
/// sender to ask again), so the offending characters are dropped rather than
/// the message rejected.
pub fn sanitize_for_display(raw: &str) -> String {
    raw.chars().filter(|c| !has_display_spoofing_chars(*c)).collect()
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
        let _ = fs::remove_file(&partial);
        bail!(
            "the received file does not match the hash it was offered under; discarded corrupted download"
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
pub fn free_path(dir: &Path, name: &str) -> PathBuf {
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
        assert_eq!(safe_name("../../keys/authorized_keys").unwrap(), "authorized_keys");
        assert_eq!(safe_name("/etc/passwd").unwrap(), "passwd");
        assert_eq!(safe_name(r"..\..\Windows\System32\x.dll").unwrap(), "x.dll");
        assert_eq!(safe_name("rapport.pdf").unwrap(), "rapport.pdf");

        // Hidden files
        assert!(safe_name(".bashrc").is_err());
        assert!(safe_name("../../.ssh/.id_rsa").is_err());
        assert_eq!(safe_name("../../.ssh/authorized_keys").unwrap(), "authorized_keys");
        // Windows reserved devices
        assert!(safe_name("con").is_err());
        assert!(safe_name("CON.txt").is_err());
        assert!(safe_name("nul").is_err());
        assert!(safe_name("aux.pdf").is_err());
        assert!(safe_name("com1.dat").is_err());

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
        // What Windows refuses to create, or silently renames.
        for bad in ["a<b.txt", "a>b", "say \"hi\".txt", "a|b", "why?.txt", "*.txt", "a.exe."] {
            assert!(safe_name(bad).is_err(), "{bad:?} must be refused");
        }
        // Looks like `report.pdf`, is not: zero-width space, BOM, word joiner.
        for twin in ["re\u{200b}port.pdf", "\u{feff}report.pdf", "report\u{2060}.pdf"] {
            assert!(safe_name(twin).is_err(), "{twin:?} must be refused");
        }
    }

    /// A chat line has no filesystem to escape, but the same characters would
    /// still hand a peer our terminal — an ESC byte can drive OSC 52 (write the
    /// clipboard), move the cursor, or hide/overwrite what came before it.
    #[test]
    fn a_hostile_chat_line_is_cleaned_not_rejected() {
        assert_eq!(sanitize_for_display("bonjour"), "bonjour");
        // A raw ESC starting an OSC 52 clipboard write, terminated by BEL.
        assert_eq!(
            sanitize_for_display("hi\u{1b}]52;c;cG93bmVk\u{07}there"),
            "hi]52;c;cG93bmVkthere"
        );
        // The same bidi override that spoofs a filename spoofs a chat line too.
        assert_eq!(
            sanitize_for_display("innocent\u{202e}gnp.exe"),
            "innocentgnp.exe"
        );
        // Invisible characters and tag characters hide text inside a line.
        assert_eq!(
            sanitize_for_display("pay\u{200b}pal \u{e0041}\u{2028}ok"),
            "paypal ok"
        );
        // Never panics or rejects — there is no sender to ask again.
        assert_eq!(sanitize_for_display(""), "");
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

        // Legal here, refused by the receiver: caught before it is offered.
        #[cfg(unix)]
        for name in ["why?.txt", ".hidden"] {
            fs::write(dir.join(name), b"x").unwrap();
            assert!(describe(&dir.join(name)).is_err(), "{name:?} must not be offered");
        }

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
        assert!(
            !partial_path(&dir, &offer.hash).exists(),
            "corrupted partial must be cleaned up"
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

    #[test]
    fn dir_size_counts_files_and_ignores_a_missing_directory() {
        let dir = scratch("dir-size");
        assert_eq!(dir_size(&dir), 0, "nothing written yet");

        fs::write(dir.join("a.part"), vec![0u8; 100]).unwrap();
        fs::write(dir.join("b.part"), vec![0u8; 50]).unwrap();
        assert_eq!(dir_size(&dir), 150);

        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(dir_size(&dir), 0, "a missing directory is not an error");
    }

    #[test]
    fn quota_falls_back_to_the_default_on_garbage_or_absence() {
        assert_eq!(parse_quota(None), DEFAULT_INCOMING_QUOTA);
        assert_eq!(parse_quota(Some("not a number")), DEFAULT_INCOMING_QUOTA);
        assert_eq!(parse_quota(Some("-5")), DEFAULT_INCOMING_QUOTA);
        assert_eq!(parse_quota(Some("12345")), 12345);
    }
}

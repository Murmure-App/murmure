//! Inline image display in terminals that support it.
//!
//! Two protocols, both of which take the raw image file bytes and let the
//! terminal decode them — so nothing here decodes a pixel. That is what keeps
//! this module free of an `image` crate: the alternative, Sixel, is a
//! bitmap format the *sender* has to produce (decode, quantise, re-encode),
//! which is a materially bigger dependency for a terminal minority. Not done
//! here; see the `ponytail:` note on [`Protocol`].
//!
//! # Why this is not just another line in the transcript
//!
//! murmure's TUI (`src/ui.rs`) is a ratatui application: every visible cell
//! is redrawn from a `Buffer` each frame. An escape sequence embedded in a
//! line of transcript text would be treated as literal glyphs, not
//! interpreted by the terminal — ratatui does not pass bytes through, it
//! draws characters into cells. Showing an image for real means leaving the
//! alternate screen, writing raw bytes directly to the terminal, and coming
//! back — which is why this is a deliberate `/view` rather than something
//! that happens automatically the moment a file arrives.

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

/// Terminals speak one of two inline-image protocols, or neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Kitty, and terminals that copy its graphics protocol (WezTerm, Ghostty).
    Kitty,
    /// iTerm2's own inline image escape sequence.
    ITerm2,
}

/// Detect which protocol, if any, the terminal murmure is running in speaks.
///
/// Environment-variable sniffing rather than a capability query: both
/// protocols are opt-in escape sequences with no portable "do you support
/// this" probe, and every terminal that implements either one also sets an
/// identifying variable. A terminal this misses just falls back to plain
/// text, the same as it already does for every image today.
pub fn supported() -> Option<Protocol> {
    if std::env::var("TERM_PROGRAM").as_deref() == Ok("iTerm.app") {
        return Some(Protocol::ITerm2);
    }
    if std::env::var_os("KITTY_WINDOW_ID").is_some()
        || std::env::var("TERM").is_ok_and(|t| t.contains("kitty"))
        || std::env::var("TERM_PROGRAM").as_deref() == Ok("WezTerm")
        || std::env::var("TERM_PROGRAM").as_deref() == Ok("ghostty")
    {
        return Some(Protocol::Kitty);
    }
    None
}

/// Whether `path`'s extension is one murmure will try to display inline.
pub fn is_image(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()).map(str::to_lowercase).as_deref(),
        Some("png" | "jpg" | "jpeg" | "gif" | "bmp")
    )
}

/// The bytes murmure would write to the terminal to show `bytes` inline, or
/// an error explaining why it cannot.
///
/// ponytail: Kitty's protocol accepts raw pixel data (any format) or a PNG
/// file verbatim (`f=100`) — not a JPEG or GIF file, which would need
/// decoding to pixels first. iTerm2's protocol accepts any of PNG/JPEG/GIF
/// verbatim and sniffs the format itself, so it has no such restriction.
/// Upgrade path if this ever bites: transcode through the `image` crate
/// before handing Kitty anything that is not already a PNG.
pub fn encode(protocol: Protocol, bytes: &[u8]) -> Result<Vec<u8>, String> {
    match protocol {
        Protocol::Kitty => {
            const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
            if !bytes.starts_with(&PNG_MAGIC) {
                return Err("this terminal's inline images only support PNG here".to_owned());
            }
            Ok(kitty_escape(bytes))
        }
        Protocol::ITerm2 => Ok(iterm2_escape(bytes)),
    }
}

/// One Kitty graphics protocol transmission, chunked to 4096 base64 bytes per
/// escape the way the spec requires for anything past a trivial size.
fn kitty_escape(png_bytes: &[u8]) -> Vec<u8> {
    let encoded = BASE64.encode(png_bytes);
    let chunks: Vec<&[u8]> = encoded.as_bytes().chunks(4096).collect();
    let last = chunks.len().saturating_sub(1);

    let mut out = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        let more = u8::from(i != last);
        if i == 0 {
            out.extend_from_slice(format!("\x1b_Ga=T,f=100,m={more};").as_bytes());
        } else {
            out.extend_from_slice(format!("\x1b_Gm={more};").as_bytes());
        }
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\x1b\\");
    }
    out
}

/// iTerm2's inline image escape: no chunking required, the whole payload is
/// one OSC 1337 sequence.
fn iterm2_escape(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("\x1b]1337;File=inline=1;size={}:", bytes.len()).as_bytes());
    out.extend_from_slice(BASE64.encode(bytes).as_bytes());
    out.push(0x07);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3];

    #[test]
    fn image_extensions_are_recognised_case_insensitively() {
        assert!(is_image(Path::new("photo.png")));
        assert!(is_image(Path::new("photo.PNG")));
        assert!(is_image(Path::new("photo.jpeg")));
        assert!(!is_image(Path::new("archive.zip")));
        assert!(!is_image(Path::new("no_extension")));
    }

    #[test]
    fn kitty_encodes_a_png_and_terminates_the_escape() {
        let out = encode(Protocol::Kitty, PNG).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("\x1b_Ga=T,f=100,m=0;"), "{text:?}");
        assert!(text.ends_with("\x1b\\"), "{text:?}");
    }

    #[test]
    fn kitty_refuses_a_non_png() {
        assert!(encode(Protocol::Kitty, b"not a png").is_err());
    }

    #[test]
    fn kitty_chunks_a_large_payload() {
        let big = vec![7u8; 10_000];
        let mut data = PNG.to_vec();
        data.extend(big);
        let text = String::from_utf8(encode(Protocol::Kitty, &data).unwrap()).unwrap();
        // More than one escape means more than one chunk went out.
        assert!(text.matches("\x1b_G").count() > 1, "{}", text.matches("\x1b_G").count());
        // Every chunk but the last announces more data is coming.
        assert!(text.contains("m=1;"));
        assert!(text.contains("m=0;"));
    }

    #[test]
    fn iterm2_accepts_any_format_and_reports_the_true_size() {
        let out = encode(Protocol::ITerm2, b"not a png either").unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("\x1b]1337;File=inline=1;size=16:"), "{text:?}");
        assert_eq!(*text.as_bytes().last().unwrap(), 0x07);
    }
}

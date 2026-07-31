//! Onion address checks and their human-facing form.

use anyhow::{Result, bail};

/// Number of base32 characters in a v3 onion address, before `.onion`.
const V3_LEN: usize = 56;

/// Reject anything that is not a well-formed v3 onion address.
///
/// Checked before use, not at dial time: a typo caught while typing beats a
/// failed 50-second rendezvous.
pub fn check_address(address: &str) -> Result<()> {
    let Some(base32) = address.strip_suffix(".onion") else {
        bail!("{address} does not end in .onion");
    };
    if base32.len() != V3_LEN {
        bail!(
            "{address} has {} characters before .onion, expected {V3_LEN} (v3)",
            base32.len()
        );
    }
    if !base32
        .bytes()
        .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    {
        bail!("{address} is not lowercase base32");
    }
    Ok(())
}

/// A short, speakable digest of an address, for comparing out loud.
///
/// The address is 56 characters — nobody reads that over the phone correctly.
/// These are the first and last four, which is what the human check in the
/// brainstorm needs: an attacker who substituted the address has to match both
/// ends, and the ends are what a person actually verifies.
///
/// ponytail: 8 characters of base32 is 40 bits. Enough against a friend
/// mistyping and against an opportunistic swap, not against someone grinding
/// vanity addresses for weeks. Widen it if that threat ever becomes real.
pub fn fingerprint(address: &str) -> String {
    let base32 = address.strip_suffix(".onion").unwrap_or(address);
    let head: String = base32.chars().take(4).collect();
    let tail: String = base32
        .chars()
        .skip(base32.chars().count().saturating_sub(4))
        .collect();
    format!("{head} … {tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "haticvmas7sfodcos2yhp7sf43cxifwl5aafgeathnyad4culhdj7ryd.onion";

    #[test]
    fn fingerprint_takes_both_ends() {
        assert_eq!(fingerprint(GOOD), "hati … 7ryd");
    }

    #[test]
    fn well_formed_rejects_the_wrong_shapes() {
        assert!(check_address(GOOD).is_ok());
        // v2 length
        assert!(check_address("abcdefghij234567.onion").is_err());
        // no suffix
        assert!(check_address(GOOD.trim_end_matches(".onion")).is_err());
        // '1' and '8' are not in base32
        assert!(
            check_address("1aticvmas7sfodcos2yhp7sf43cxifwl5aafgeathnyad4culhdj7ry8.onion")
                .is_err()
        );
        // uppercase
        assert!(check_address(&GOOD.to_uppercase()).is_err());
    }
}

//! Onion address checks and their human-facing form.

use anyhow::{Context as _, Result, bail};
use tor_hscrypto::pk::HsClientDescEncKey;

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

/// Reject anything that is not a `descriptor:x25519:<base32>` discovery key.
///
/// Same reason as [`check_address`]: a key that only fails at dial time fails
/// silently, because a restricted service is *supposed* to be unreachable to a
/// client it does not recognise. There is no error to tell the two apart.
pub fn check_discovery_key(key: &str) -> Result<()> {
    key.parse::<HsClientDescEncKey>()
        .with_context(|| format!("{key} is not a service discovery key"))?;
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

/// Key-derivation context for the safety number. Frozen: changing it changes
/// every number two people have already compared.
const SAFETY_CONTEXT: &str = "murmure 2026 safety number";

/// Sixty digits two people compute alike from their two addresses, to read
/// out to each other.
///
/// Where [`fingerprint`] is 40 bits of one address, this covers every bit of
/// both, so no address ground to look alike gets past it. The pair is sorted
/// first: each side reads out the same number. Twelve groups of five digits,
/// each from five bytes of BLAKE3 output, as Signal does it.
pub fn safety_number(a: &str, b: &str) -> String {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    let mut hasher = blake3::Hasher::new_derive_key(SAFETY_CONTEXT);
    hasher.update(first.as_bytes());
    hasher.update(b"\n");
    hasher.update(second.as_bytes());
    let mut bytes = [0u8; 60];
    hasher.finalize_xof().fill(&mut bytes);
    bytes
        .chunks(5)
        .map(|five| {
            let n = five.iter().fold(0u64, |n, b| n << 8 | u64::from(*b));
            format!("{:05}", n % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_safety_number_is_the_same_from_both_sides_and_differs_per_pair() {
        const OTHER: &str = "rg4vaxch2neyqkejzdcvfjdkqdmuyj3fjktyjopjvc3xfvypvt55t3qd.onion";
        const THIRD: &str = "trsgbyk6vbbyvnyz5wmpw4n3d6m6ivzqgqm4qzhnfqxqeufqbnmwx5yd.onion";
        let number = safety_number(GOOD, OTHER);
        assert_eq!(number, safety_number(OTHER, GOOD));
        assert_ne!(number, safety_number(GOOD, THIRD));
        let groups: Vec<&str> = number.split(' ').collect();
        assert_eq!(groups.len(), 12);
        assert!(groups.iter().all(|g| g.len() == 5 && g.bytes().all(|b| b.is_ascii_digit())));
    }

    const GOOD: &str = "haticvmas7sfodcos2yhp7sf43cxifwl5aafgeathnyad4culhdj7ryd.onion";
    const GOOD_KEY: &str = "descriptor:x25519:ZPRRMIV6DV6SJFL7SFBSVLJ5VUNPGCDFEVZ7M23LTLVTCCXJQBKA";

    #[test]
    fn discovery_keys_need_the_full_prefix() {
        assert!(check_discovery_key(GOOD_KEY).is_ok());
        // lowercase base32 is equally valid
        assert!(check_discovery_key(&GOOD_KEY.to_lowercase()).is_ok());
        // the bare key material, without the two labels
        assert!(check_discovery_key(GOOD_KEY.rsplit(':').next().unwrap()).is_err());
        // an onion address pasted into the key slot
        assert!(check_discovery_key(GOOD).is_err());
        assert!(check_discovery_key("descriptor:ed25519:AAAA").is_err());
    }

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

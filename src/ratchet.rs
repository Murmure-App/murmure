//! The message ratchet: a fresh key for every frame, and a fresh Diffie-Hellman
//! agreement every time the conversation changes direction.
//!
//! This is the Double Ratchet from Signal's specification, with the parts that
//! only exist for an unreliable transport taken out.
//!
//! # What it adds on top of Tor
//!
//! A Tor circuit is already encrypted end to end, and its keys already die
//! with it. What it cannot give is recovery *during* a connection: a link
//! opened at breakfast can carry a conversation until the evening, and whoever
//! reads this process's memory at noon reads everything after noon too. Here,
//! every change of direction mixes in a new DH secret that was never in memory
//! at noon — so a compromise heals at the next reply (post-compromise
//! security), and every message key is erased once used (forward secrecy).
//!
//! # Why there is no skipped-key table
//!
//! Signal keeps keys for messages that have not arrived yet, because its
//! transport loses and reorders messages. Ours does neither: one ratchet lives
//! on one Tor stream, which is ordered and reliable, and a stream that breaks
//! takes the ratchet with it — the next connection starts a new one from a new
//! handshake. So a message is either the next one expected, or the connection
//! is broken. Accepting only the next one is less code, and it leaves no store
//! of keys for a hostile peer to fill.
//!
//! ponytail: in-order only. The day frames can arrive over two paths at once,
//! this needs Signal's bounded `MKSKIPPED` table.
//!
//! # How the two sides start
//!
//! The handshake leaves both with a root key and each other's ephemeral public
//! key. The caller plays Signal's Alice and ratchets straight away, so its
//! first frame already carries a new DH key. The answerer may speak first,
//! too — both sides send as soon as a link is up — so it starts with a sending
//! chain derived from the root key, under its handshake key, which the caller
//! expects as the first thing it will hear.

use anyhow::{Result, bail};
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore as _;
use tor_llcrypto::pk::curve25519;
use zeroize::Zeroizing;

/// KDF contexts. Frozen: changing one changes every key both sides compute,
/// which is a protocol version bump.
const ROOT_CONTEXT: &str = "murmure 2026 ratchet root step";
const FIRST_CHAIN_CONTEXT: &str = "murmure 2026 ratchet answerer first chain";

/// `sender's DH public key || previous chain length || message number`.
pub const HEADER_LEN: usize = 32 + 4 + 4;

/// What encryption adds to a frame: the header, and the Poly1305 tag.
pub const OVERHEAD: usize = HEADER_LEN + 16;

type Key = Zeroizing<[u8; 32]>;

/// One side of one connection's ratchet.
pub struct Ratchet {
    /// Our current DH key pair.
    dhs: curve25519::StaticSecret,
    /// The peer's current DH public key.
    dhr: curve25519::PublicKey,
    root: Key,
    /// `None` only on the caller, before it has heard anything.
    receiving: Option<Key>,
    sending: Key,
    /// Frames sent on the current sending chain.
    ns: u32,
    /// Frames received on the current receiving chain.
    nr: u32,
    /// Length of our previous sending chain, announced so the peer can tell
    /// that nothing was lost across the switch.
    pn: u32,
}

/// Written by hand so that no key can ever reach a log through `{:?}`.
impl std::fmt::Debug for Ratchet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ratchet").field("ns", &self.ns).field("nr", &self.nr).finish_non_exhaustive()
    }
}

impl Ratchet {
    /// The side that dialled: steps once immediately, so its first frame
    /// already rides a fresh DH agreement.
    pub fn caller(root: Key, handshake_secret: curve25519::StaticSecret, theirs: curve25519::PublicKey) -> Self {
        let first = first_chain(&root);
        let dhs = fresh_secret();
        let (root, sending) = root_step(&root, &dhs.diffie_hellman(&theirs));
        drop(handshake_secret);
        Self {
            dhs,
            dhr: theirs,
            root,
            receiving: Some(first),
            sending,
            ns: 0,
            nr: 0,
            pn: 0,
        }
    }

    /// The side that answered: keeps its handshake key until the caller's
    /// first frame moves it on, and may send on the first chain meanwhile.
    pub fn answerer(root: Key, handshake_secret: curve25519::StaticSecret, theirs: curve25519::PublicKey) -> Self {
        let sending = first_chain(&root);
        Self {
            dhs: handshake_secret,
            dhr: theirs,
            root,
            receiving: None,
            sending,
            ns: 0,
            nr: 0,
            pn: 0,
        }
    }

    /// Seal one frame body. The result is `header || ciphertext`.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let header = header(&curve25519::PublicKey::from(&self.dhs), self.pn, self.ns);
        let key = chain_step(&mut self.sending);
        self.ns = self.ns.checked_add(1).ok_or_else(|| anyhow::anyhow!("sending chain exhausted"))?;
        let sealed = ChaCha20Poly1305::new((&*key).into())
            .encrypt(&Nonce::default(), Payload { msg: plaintext, aad: &header })
            .map_err(|_| anyhow::anyhow!("sealing a frame failed"))?;
        let mut out = Vec::with_capacity(HEADER_LEN + sealed.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Open the next frame, or fail. Any failure means the connection is
    /// broken and must be dropped: the state is not rolled back.
    pub fn open(&mut self, frame: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if frame.len() < OVERHEAD {
            bail!("an encrypted frame of {} bytes is too short", frame.len());
        }
        let (header, sealed) = frame.split_at(HEADER_LEN);
        let their_dh: [u8; 32] = header[..32].try_into().expect("fixed slice");
        let pn = u32::from_le_bytes(header[32..36].try_into().expect("fixed slice"));
        let n = u32::from_le_bytes(header[36..40].try_into().expect("fixed slice"));

        if their_dh != *self.dhr.as_bytes() {
            // They turned the ratchet. Everything on their previous chain must
            // have arrived already: the stream is ordered and lossless.
            if pn != self.nr && self.receiving.is_some() {
                bail!("the peer's previous chain ended at {pn}, but {} frames arrived", self.nr);
            }
            self.dh_step(curve25519::PublicKey::from(their_dh));
        }
        if n != self.nr {
            bail!("expected frame {} of this chain, got {n}", self.nr);
        }
        let Some(receiving) = self.receiving.as_mut() else {
            bail!("the peer's first frame did not turn the ratchet");
        };
        let key = chain_step(receiving);
        self.nr += 1;
        ChaCha20Poly1305::new((&*key).into())
            .decrypt(&Nonce::default(), Payload { msg: sealed, aad: header })
            .map(Zeroizing::new)
            .map_err(|_| anyhow::anyhow!("a frame failed authentication"))
    }

    /// Signal's DHRatchet: a receiving chain from their new key, then a new
    /// key pair of ours and a sending chain from it.
    fn dh_step(&mut self, theirs: curve25519::PublicKey) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = theirs;
        let (root, receiving) = root_step(&self.root, &self.dhs.diffie_hellman(&self.dhr));
        self.dhs = fresh_secret();
        let (root, sending) = root_step(&root, &self.dhs.diffie_hellman(&self.dhr));
        self.root = root;
        self.receiving = Some(receiving);
        self.sending = sending;
    }
}

fn fresh_secret() -> curve25519::StaticSecret {
    // Filled by hand for the same reason as the handshake's ephemeral key:
    // `EphemeralSecret::random_from_rng` wants rand_core 0.10, this tree is on 0.8.
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(bytes.as_mut());
    curve25519::StaticSecret::from(*bytes)
}

fn header(dh: &curve25519::PublicKey, pn: u32, n: u32) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..32].copy_from_slice(dh.as_bytes());
    h[32..36].copy_from_slice(&pn.to_le_bytes());
    h[36..].copy_from_slice(&n.to_le_bytes());
    h
}

/// KDF_RK: a new root key and a new chain key from the old root and a DH output.
fn root_step(root: &Key, dh: &curve25519::SharedSecret) -> (Key, Key) {
    let mut hasher = blake3::Hasher::new_derive_key(ROOT_CONTEXT);
    hasher.update(root.as_ref());
    hasher.update(dh.as_bytes());
    let mut out = Zeroizing::new([0u8; 64]);
    hasher.finalize_xof().fill(out.as_mut());
    let mut root = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);
    root.copy_from_slice(&out[..32]);
    chain.copy_from_slice(&out[32..]);
    (root, chain)
}

/// KDF_CK: this message's key, and the chain moved one step on. The old chain
/// key is overwritten, so a used message key cannot be derived again.
fn chain_step(chain: &mut Key) -> Key {
    let message = Zeroizing::new(*blake3::keyed_hash(chain, &[1]).as_bytes());
    *chain = Zeroizing::new(*blake3::keyed_hash(chain, &[2]).as_bytes());
    message
}

/// The answerer's sending chain before the first DH step.
fn first_chain(root: &Key) -> Key {
    Zeroizing::new(blake3::derive_key(FIRST_CHAIN_CONTEXT, root.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pair as the handshake would leave it.
    fn pair() -> (Ratchet, Ratchet) {
        let (a, b) = (fresh_secret(), fresh_secret());
        let (a_pub, b_pub) = (curve25519::PublicKey::from(&a), curve25519::PublicKey::from(&b));
        let root = Zeroizing::new(blake3::derive_key("test", a.diffie_hellman(&b_pub).as_bytes()));
        (
            Ratchet::caller(root.clone(), a, b_pub),
            Ratchet::answerer(root, b, a_pub),
        )
    }

    fn say(from: &mut Ratchet, to: &mut Ratchet, text: &[u8]) {
        let frame = from.seal(text).unwrap();
        assert_eq!(&**to.open(&frame).unwrap(), text);
    }

    #[test]
    fn a_conversation_round_trips_whoever_speaks_first() {
        let (mut alice, mut bob) = pair();
        // The answerer first, before the caller has turned anything.
        say(&mut bob, &mut alice, b"allo ?");
        say(&mut bob, &mut alice, b"tu m'entends ?");
        say(&mut alice, &mut bob, b"oui");
        say(&mut alice, &mut bob, b"tres bien");
        for i in 0..20u8 {
            say(&mut bob, &mut alice, &[i]);
            say(&mut alice, &mut bob, &[i, i]);
        }
    }

    #[test]
    fn frames_crossing_on_the_wire_still_open() {
        let (mut alice, mut bob) = pair();
        // Both send before either reads, as the link does.
        let a = alice.seal(b"a").unwrap();
        let b = bob.seal(b"b").unwrap();
        assert_eq!(&**bob.open(&a).unwrap(), b"a");
        assert_eq!(&**alice.open(&b).unwrap(), b"b");
        say(&mut bob, &mut alice, b"c");
        say(&mut alice, &mut bob, b"d");
    }

    #[test]
    fn every_frame_uses_a_different_key() {
        let (mut alice, _) = pair();
        assert_ne!(alice.seal(b"same").unwrap()[HEADER_LEN..], alice.seal(b"same").unwrap()[HEADER_LEN..]);
    }

    #[test]
    fn a_reply_turns_the_dh_ratchet() {
        let (mut alice, mut bob) = pair();
        let first = alice.seal(b"1").unwrap();
        bob.open(&first).unwrap();
        let reply = bob.seal(b"2").unwrap();
        alice.open(&reply).unwrap();
        let again = alice.seal(b"3").unwrap();
        assert_ne!(first[..32], again[..32], "the caller must move to a new DH key after a reply");
        assert_ne!(reply[..32], first[..32]);
    }

    #[test]
    fn replayed_dropped_reordered_or_tampered_frames_are_refused() {
        let (mut alice, mut bob) = pair();
        let one = alice.seal(b"1").unwrap();
        let two = alice.seal(b"2").unwrap();
        bob.open(&one).unwrap();
        assert!(bob.open(&one).is_err(), "replay");

        let (mut alice, mut bob) = pair();
        let _lost = alice.seal(b"1").unwrap();
        let two_b = alice.seal(b"2").unwrap();
        assert!(bob.open(&two_b).is_err(), "gap");
        let _ = two;

        let (mut alice, mut bob) = pair();
        let mut bad = alice.seal(b"1").unwrap();
        *bad.last_mut().unwrap() ^= 1;
        assert!(bob.open(&bad).is_err(), "tampered body");

        let (mut alice, mut bob) = pair();
        let mut bad = alice.seal(b"1").unwrap();
        bad[35] ^= 1;
        assert!(bob.open(&bad).is_err(), "tampered header");

        assert!(bob.open(&[0u8; 10]).is_err(), "short");
    }

    #[test]
    fn a_stranger_with_another_root_cannot_read() {
        let (mut alice, _) = pair();
        let (_, mut eve) = pair();
        assert!(eve.open(&alice.seal(b"secret").unwrap()).is_err());
    }
}

//! Rooms: one conversation with several people, and no server.
//!
//! A room is kept by the person who opened it — the host — and lives in memory
//! only: it ends when the host leaves, and nothing about it is written down.
//! There is no group key. Every frame travels over the pairwise links that
//! already exist, each under its own ratchet, so somebody leaving leaves
//! nothing to re-key.
//!
//! # Who talks to whom
//!
//! One mechanism, two shapes. Every line is signed by its author and numbered,
//! and whoever receives a line they had not seen passes it once to the other
//! members they are linked to. Who is linked to whom decides the rest:
//!
//! - **Star.** Members who are not each other's contacts cannot reach each
//!   other at all — restricted discovery hides a service from anyone not in
//!   its book. Only the host is linked to everyone, so the host relays. It can
//!   hold a line back, but not change one or write one in somebody's name.
//! - **Mesh.** Members who *are* each other's contacts link up directly and
//!   hear each other first-hand; relaying becomes a fallback.
//!
//! Nobody chooses between them. A room is a star with a mesh growing inside it
//! wherever friends happen to share it.
//!
//! # What a member learns about the others
//!
//! Never their address. Each member signs with a key made for this room alone,
//! and the roster lists those keys next to a [`tag`] of each member's address
//! under the room's id. A tag can only be checked against an address one
//! already has, so a member learns which of *their own* contacts are in the
//! room, and about everybody else only that somebody is.
//!
//! A name is put to a key only on proof: the host is named by the roster it
//! sends over its own link, and a contact by the [`Message::RoomHello`] they
//! send over theirs. A roster that gives a contact a key other than the one
//! that contact proved is the host lying, and is reported as such. A key
//! nobody could prove proves only that the same person keeps talking — the
//! host vouches for who they are, and nothing here pretends otherwise.

use std::collections::{HashMap, HashSet};

use rand::RngCore as _;
use safelog::DisplayRedacted as _;
use tor_hscrypto::pk::HsId;
use tor_llcrypto::pk::ed25519;

use crate::proto::{MAX_MEMBERS, MAX_NAME, MAX_TEXT, Message, RoomId};

/// Is this a frame for [`Rooms::receive`]?
pub fn is_room(msg: &Message) -> bool {
    matches!(
        msg,
        Message::RoomInvite { .. }
            | Message::RoomJoin { .. }
            | Message::RoomDecline { .. }
            | Message::RoomLeave { .. }
            | Message::RoomRoster { .. }
            | Message::RoomHello { .. }
            | Message::RoomSay { .. }
    )
}

/// A room key: the ed25519 public key a member signs their lines with.
pub type Key = [u8; 32];

/// Prefixed to everything a room key signs, so that no signature made here
/// can be passed off as one made anywhere else.
const SIGNED: &[u8] = b"murmure-room-v1";

const TAG_CONTEXT: &str = "murmure 2026 room member tag";

/// What a roster says about a member's address: enough to recognise an
/// address one already knows, and nothing to learn one from.
pub fn tag(room: &RoomId, address: &HsId) -> [u8; 32] {
    let mut material = room.to_vec();
    material.extend_from_slice(address.display_unredacted().to_string().as_bytes());
    blake3::derive_key(TAG_CONTEXT, &material)
}

/// A short, readable form of a room key, for somebody we cannot name.
pub fn fingerprint(key: &Key) -> String {
    key[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Who said or did something, as far as it can be proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Who {
    Me,
    /// Somebody whose key was proved to be this peer's.
    Known(HsId),
    /// A key in the roster that nobody put a proved name to.
    Stranger(Key),
}

/// Something to put on screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A contact asked us in.
    Invited { from: HsId, name: String },
    /// An invitation turned away on our behalf: we are already in a room.
    Busy { from: HsId, name: String },
    Said { who: Who, body: String },
    Joined(Who),
    Left(Who),
    Declined(HsId),
    /// A key in the roster was proved to be this contact's.
    Recognised { key: Key, peer: HsId },
    /// The host's roster gives this contact a key other than the one they
    /// proved. Either the host is lying about who is in the room, or it is
    /// badly out of date — and there is no telling which from here.
    Mismatch(HsId),
    /// The room is over: the host left, or we lost them.
    Ended,
}

/// What handling a frame or a command came to.
#[derive(Debug, Default)]
pub struct Outcome {
    pub events: Vec<Event>,
    /// Frames to send, each over the link to that peer.
    pub send: Vec<(HsId, Message)>,
    /// Contacts in the room worth opening a connection to: the mesh.
    pub reach: Vec<HsId>,
}

impl Outcome {
    fn event(event: Event) -> Self {
        Outcome {
            events: vec![event],
            ..Outcome::default()
        }
    }
}

/// An invitation not yet answered.
struct Invite {
    from: HsId,
    room: RoomId,
    name: String,
}

/// The room we are in.
pub struct Room {
    pub id: RoomId,
    pub name: String,
    /// `None` when we are the host.
    host: Option<HsId>,
    /// Our key for this room and nothing else.
    signer: ed25519::Keypair,
    next_seq: u64,
    /// Every member's key and tag, as the host last said.
    roster: Vec<(Key, [u8; 32])>,
    /// The keys we can put a proved peer to. These are also the only peers a
    /// line is ever sent to: the room goes to people shown to be in it.
    bound: HashMap<Key, HsId>,
    /// Keys contacts said were theirs, kept until the roster agrees — the
    /// hello can arrive before the roster that lists them.
    claimed: HashMap<HsId, Key>,
    /// Contacts we already told our key to.
    greeted: HashSet<HsId>,
    /// The last line number seen from each key.
    last: HashMap<Key, u64>,
    /// Host only: who was asked and has not answered.
    invited: HashSet<HsId>,
}

impl Room {
    fn new(id: RoomId, name: String, host: Option<HsId>) -> Self {
        let mut secret = zeroize::Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(secret.as_mut());
        Room {
            id,
            name,
            host,
            signer: ed25519::Keypair::from_bytes(&secret),
            next_seq: 0,
            roster: Vec::new(),
            bound: HashMap::new(),
            claimed: HashMap::new(),
            greeted: HashSet::new(),
            last: HashMap::new(),
            invited: HashSet::new(),
        }
    }

    pub fn hosting(&self) -> bool {
        self.host.is_none()
    }

    fn key(&self) -> Key {
        self.signer.verifying_key().to_bytes()
    }

    fn who(&self, key: &Key) -> Who {
        if *key == self.key() {
            Who::Me
        } else if let Some(peer) = self.bound.get(key) {
            Who::Known(*peer)
        } else {
            Who::Stranger(*key)
        }
    }

    /// Everyone in the room, as far as we can name them.
    pub fn members(&self) -> Vec<Who> {
        self.roster.iter().map(|(key, _)| self.who(key)).collect()
    }

    /// The peers a line goes to: everybody proved to be in the room.
    fn targets(&self) -> Vec<HsId> {
        let mut peers: Vec<HsId> = Vec::new();
        for peer in self.bound.values() {
            if !peers.contains(peer) {
                peers.push(*peer);
            }
        }
        peers
    }

    /// Host only: the roster, to everyone in the room.
    fn broadcast_roster(&self) -> Vec<(HsId, Message)> {
        self.targets()
            .into_iter()
            .map(|peer| {
                (
                    peer,
                    Message::RoomRoster {
                        room: self.id,
                        members: self.roster.clone(),
                    },
                )
            })
            .collect()
    }

    /// Put names to the keys contacts claimed, now that the roster may list
    /// them.
    fn settle_claims(&mut self, out: &mut Outcome) {
        let claims: Vec<(HsId, Key)> = self.claimed.iter().map(|(p, k)| (*p, *k)).collect();
        for (peer, key) in claims {
            let their_tag = tag(&self.id, &peer);
            match self.roster.iter().find(|(_, t)| *t == their_tag) {
                // Not listed yet: the roster is on its way.
                None => {}
                Some((listed, _)) if *listed == key => {
                    self.claimed.remove(&peer);
                    if self.bound.insert(key, peer).is_none() {
                        out.events.push(Event::Recognised { key, peer });
                    }
                }
                Some(_) => {
                    self.claimed.remove(&peer);
                    out.events.push(Event::Mismatch(peer));
                }
            }
        }
    }
}

/// The room we are in, if any, and the invitation waiting, if any.
///
/// One room at a time, like one call at a time: a line typed without a command
/// has to go somewhere, and "the room you are in" is only an answer while
/// there is exactly one.
pub struct Rooms {
    me: HsId,
    pub room: Option<Room>,
    invite: Option<Invite>,
}

impl Rooms {
    pub fn new(me: HsId) -> Self {
        Rooms {
            me,
            room: None,
            invite: None,
        }
    }

    /// Open a room, with us as its host and only member.
    pub fn create(&mut self, name: &str) -> anyhow::Result<()> {
        if let Some(room) = &self.room {
            anyhow::bail!("you are already in #{} — /room leave first", room.name);
        }
        if name.is_empty() || name.len() > MAX_NAME {
            anyhow::bail!("a room name is 1 to {MAX_NAME} bytes");
        }
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        let mut room = Room::new(id, name.to_owned(), None);
        room.roster.push((room.key(), tag(&id, &self.me)));
        self.room = Some(room);
        Ok(())
    }

    /// Ask a contact in. Host only.
    pub fn invite(&mut self, peer: HsId) -> anyhow::Result<Message> {
        let Some(room) = self.room.as_mut() else {
            anyhow::bail!("you are not in a room — /room new <name> first");
        };
        if !room.hosting() {
            anyhow::bail!("only the host of #{} can invite", room.name);
        }
        if room.roster.len() + room.invited.len() >= MAX_MEMBERS {
            anyhow::bail!("a room holds at most {MAX_MEMBERS} people");
        }
        if room.bound.values().any(|p| *p == peer) {
            anyhow::bail!("they are already in #{}", room.name);
        }
        room.invited.insert(peer);
        Ok(Message::RoomInvite {
            room: room.id,
            name: room.name.clone(),
        })
    }

    /// Who invited us, and to what, if an invitation is waiting.
    pub fn pending(&self) -> Option<(HsId, &str)> {
        self.invite.as_ref().map(|i| (i.from, i.name.as_str()))
    }

    /// Say yes to the invitation waiting.
    pub fn join(&mut self) -> anyhow::Result<Outcome> {
        if let Some(room) = &self.room {
            anyhow::bail!("you are already in #{} — /room leave first", room.name);
        }
        let Some(invite) = self.invite.take() else {
            anyhow::bail!("nobody has invited you to a room");
        };
        let room = Room::new(invite.room, invite.name, Some(invite.from));
        let join = Message::RoomJoin {
            room: room.id,
            key: room.key(),
        };
        self.room = Some(room);
        Ok(Outcome {
            send: vec![(invite.from, join)],
            ..Outcome::default()
        })
    }

    /// Say no to the invitation waiting.
    pub fn decline(&mut self) -> anyhow::Result<Outcome> {
        let Some(invite) = self.invite.take() else {
            anyhow::bail!("nobody has invited you to a room");
        };
        Ok(Outcome {
            send: vec![(invite.from, Message::RoomDecline { room: invite.room })],
            ..Outcome::default()
        })
    }

    /// Leave the room. For the host, that ends it for everyone.
    pub fn leave(&mut self) -> anyhow::Result<Outcome> {
        let Some(room) = self.room.take() else {
            anyhow::bail!("you are not in a room");
        };
        let leave = Message::RoomLeave { room: room.id };
        let send = match room.host {
            None => room.targets().into_iter().map(|p| (p, leave.clone())).collect(),
            Some(host) => vec![(host, leave)],
        };
        Ok(Outcome {
            send,
            ..Outcome::default()
        })
    }

    /// Say something to the room.
    pub fn say(&mut self, body: &str) -> anyhow::Result<Outcome> {
        let Some(room) = self.room.as_mut() else {
            anyhow::bail!("you are not in a room");
        };
        if body.len() > MAX_TEXT {
            anyhow::bail!("that is {} bytes; a line is at most {MAX_TEXT}", body.len());
        }
        room.next_seq += 1;
        let key = room.key();
        let seq = room.next_seq;
        let sig = room
            .signer
            .sign(&signed(&room.id, &key, seq, body))
            .to_bytes()
            .to_vec();
        let say = Message::RoomSay {
            room: room.id,
            key,
            seq,
            body: body.to_owned(),
            sig,
        };
        Ok(Outcome {
            events: vec![Event::Said {
                who: Who::Me,
                body: body.to_owned(),
            }],
            send: room.targets().into_iter().map(|p| (p, say.clone())).collect(),
            reach: Vec::new(),
        })
    }

    /// A connection went away.
    pub fn lost(&mut self, peer: &HsId) -> Outcome {
        let Some(room) = self.room.as_mut() else {
            return Outcome::default();
        };
        if room.host == Some(*peer) {
            self.room = None;
            return Outcome::event(Event::Ended);
        }
        // A member keeps the names it proved: the line from somebody whose
        // direct link dropped still comes through the host, and a connection
        // that comes back is the same person.
        if !room.hosting() {
            return Outcome::default();
        }
        let keys: Vec<Key> = room
            .bound
            .iter()
            .filter(|(_, p)| *p == peer)
            .map(|(k, _)| *k)
            .collect();
        let mut out = Outcome::default();
        for key in keys {
            // Gone from the room, not only from our sight: the host is the
            // only way anybody else could still reach them.
            room.bound.remove(&key);
            room.roster.retain(|(k, _)| *k != key);
            out.events.push(Event::Left(Who::Known(*peer)));
        }
        if !out.events.is_empty() {
            out.send = room.broadcast_roster();
        }
        out
    }

    /// Handle a room frame from `from`. `contacts` are the addresses in our
    /// book, which is what a roster's tags are checked against.
    ///
    /// Anything that does not fit — a frame for another room, from somebody not
    /// shown to be in it, badly signed or already seen — is dropped without a
    /// word: a room frame from outside the room is noise or an attempt, and
    /// neither deserves a line on screen.
    pub fn receive(&mut self, from: HsId, msg: Message, contacts: &[HsId]) -> Outcome {
        match msg {
            Message::RoomInvite { room, name } => self.invited(from, room, name),
            Message::RoomJoin { room, key } => self.joined(from, room, key),
            Message::RoomDecline { room } => match self.room.as_mut() {
                Some(r) if r.id == room && r.hosting() => match r.invited.remove(&from) {
                    true => Outcome::event(Event::Declined(from)),
                    false => Outcome::default(),
                },
                _ => Outcome::default(),
            },
            Message::RoomLeave { room } => self.left(from, room),
            Message::RoomRoster { room, members } => self.roster(from, room, members, contacts),
            Message::RoomHello { room, key } => match self.room.as_mut() {
                // Only from a contact: a hello is worth exactly the proof of
                // who sent it, and the link only proves that for somebody in
                // our book.
                Some(r) if r.id == room && contacts.contains(&from) => {
                    r.claimed.insert(from, key);
                    let mut out = Outcome::default();
                    r.settle_claims(&mut out);
                    out
                }
                _ => Outcome::default(),
            },
            Message::RoomSay {
                room,
                key,
                seq,
                body,
                sig,
            } => self.heard(from, room, key, seq, body, sig),
            _ => Outcome::default(),
        }
    }

    fn invited(&mut self, from: HsId, room: RoomId, name: String) -> Outcome {
        // From the network, and bound for the screen and the window title.
        let name = crate::files::sanitize_for_display(&name);
        if self.room.is_some() {
            return Outcome {
                events: vec![Event::Busy { from, name }],
                send: vec![(from, Message::RoomDecline { room })],
                reach: Vec::new(),
            };
        }
        self.invite = Some(Invite {
            from,
            room,
            name: name.clone(),
        });
        Outcome::event(Event::Invited { from, name })
    }

    fn joined(&mut self, from: HsId, room: RoomId, key: Key) -> Outcome {
        let Some(r) = self.room.as_mut() else {
            return Outcome::default();
        };
        // Only somebody asked in, and only once per asking.
        if r.id != room || !r.hosting() || !r.invited.remove(&from) {
            return Outcome::default();
        }
        // A key already in the roster would make two members one author.
        if r.roster.iter().any(|(k, _)| *k == key) || r.roster.len() >= MAX_MEMBERS {
            return Outcome {
                send: vec![(from, Message::RoomLeave { room })],
                ..Outcome::default()
            };
        }
        r.roster.push((key, tag(&room, &from)));
        r.bound.insert(key, from);
        Outcome {
            events: vec![Event::Joined(Who::Known(from))],
            send: r.broadcast_roster(),
            reach: Vec::new(),
        }
    }

    fn left(&mut self, from: HsId, room: RoomId) -> Outcome {
        let Some(r) = self.room.as_ref() else {
            return Outcome::default();
        };
        if r.id != room {
            return Outcome::default();
        }
        if r.host == Some(from) {
            self.room = None;
            return Outcome::event(Event::Ended);
        }
        if r.hosting() {
            // Leaving and losing the connection are the same thing to a host.
            return self.lost(&from);
        }
        Outcome::default()
    }

    fn roster(
        &mut self,
        from: HsId,
        room: RoomId,
        members: Vec<(Key, [u8; 32])>,
        contacts: &[HsId],
    ) -> Outcome {
        let me = self.me;
        let Some(r) = self.room.as_mut() else {
            return Outcome::default();
        };
        if r.id != room || r.host != Some(from) {
            return Outcome::default();
        }
        let mut out = Outcome::default();
        let before: Vec<Key> = r.roster.iter().map(|(k, _)| *k).collect();
        r.roster = members;
        let now: Vec<Key> = r.roster.iter().map(|(k, _)| *k).collect();

        // A key no longer listed names nobody in the room any more.
        let gone: Vec<Key> = before.iter().filter(|k| !now.contains(k)).copied().collect();
        for key in &gone {
            out.events.push(Event::Left(r.who(key)));
            r.bound.remove(key);
            r.last.remove(key);
        }

        // The host is named by the roster itself: it came over the host's own
        // link, and the host is the one member whose word on their own key is
        // the proof.
        let host_tag = tag(&room, &from);
        if let Some((key, _)) = r.roster.iter().find(|(_, t)| *t == host_tag) {
            r.bound.insert(*key, from);
        }

        // Contacts in the room: tell them our key, and go and meet them.
        for peer in contacts {
            if *peer == from || *peer == me || r.greeted.contains(peer) {
                continue;
            }
            let theirs = tag(&room, peer);
            if r.roster.iter().any(|(_, t)| *t == theirs) {
                r.greeted.insert(*peer);
                out.send.push((
                    *peer,
                    Message::RoomHello {
                        room,
                        key: r.key(),
                    },
                ));
                out.reach.push(*peer);
            }
        }
        r.settle_claims(&mut out);

        for key in now.iter().filter(|k| !before.contains(k)) {
            if *key != r.key() {
                out.events.push(Event::Joined(r.who(key)));
            }
        }
        out
    }

    fn heard(
        &mut self,
        from: HsId,
        room: RoomId,
        key: Key,
        seq: u64,
        body: String,
        sig: Vec<u8>,
    ) -> Outcome {
        let Some(r) = self.room.as_mut() else {
            return Outcome::default();
        };
        if r.id != room || key == r.key() || !r.targets().contains(&from) {
            return Outcome::default();
        }
        if !r.roster.iter().any(|(k, _)| *k == key) {
            return Outcome::default();
        }
        if seq <= r.last.get(&key).copied().unwrap_or(0) {
            return Outcome::default();
        }
        let Ok(sig) = <[u8; 64]>::try_from(sig.as_slice()) else {
            return Outcome::default();
        };
        let Ok(author) = ed25519::PublicKey::from_bytes(&key) else {
            return Outcome::default();
        };
        if author
            .verify(
                &signed(&room, &key, seq, &body),
                &ed25519::Signature::from_bytes(&sig),
            )
            .is_err()
        {
            return Outcome::default();
        }
        r.last.insert(key, seq);
        let forward = Message::RoomSay {
            room,
            key,
            seq,
            body: body.clone(),
            sig: sig.to_vec(),
        };
        // Passed on once, to everyone but whoever it came from and whoever
        // wrote it. A duplicate stops here, on the sequence check above.
        let author_peer = r.bound.get(&key).copied();
        let send = r
            .targets()
            .into_iter()
            .filter(|p| *p != from && Some(*p) != author_peer)
            .map(|p| (p, forward.clone()))
            .collect();
        Outcome {
            events: vec![Event::Said {
                who: r.who(&key),
                body,
            }],
            send,
            reach: Vec::new(),
        }
    }
}

/// The bytes a room key signs for one line.
fn signed(room: &RoomId, key: &Key, seq: u64, body: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SIGNED.len() + 16 + 32 + 8 + body.len());
    bytes.extend_from_slice(SIGNED);
    bytes.extend_from_slice(room);
    bytes.extend_from_slice(key);
    bytes.extend_from_slice(&seq.to_le_bytes());
    bytes.extend_from_slice(body.as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn id(n: u8) -> HsId {
        Identity::for_test([n; 32]).onion_address()
    }

    /// A tiny network: every frame in `out.send` is handed to its recipient,
    /// and whatever that produces is handed on in turn, until nothing moves.
    /// Returns every event, by who saw it.
    fn run(
        nodes: &mut HashMap<HsId, Rooms>,
        contacts: &HashMap<HsId, Vec<HsId>>,
        from: HsId,
        out: Outcome,
    ) -> Vec<(HsId, Event)> {
        let mut seen: Vec<(HsId, Event)> = out.events.into_iter().map(|e| (from, e)).collect();
        let mut queue: Vec<(HsId, HsId, Message)> =
            out.send.into_iter().map(|(to, m)| (from, to, m)).collect();
        while let Some((sender, to, msg)) = queue.pop() {
            let Some(node) = nodes.get_mut(&to) else { continue };
            let theirs = contacts.get(&to).cloned().unwrap_or_default();
            let out = node.receive(sender, msg, &theirs);
            seen.extend(out.events.into_iter().map(|e| (to, e)));
            queue.extend(out.send.into_iter().map(|(t, m)| (to, t, m)));
        }
        seen
    }

    fn said(seen: &[(HsId, Event)], who: HsId) -> Vec<String> {
        seen.iter()
            .filter(|(at, _)| *at == who)
            .filter_map(|(_, e)| match e {
                Event::Said { body, .. } => Some(body.clone()),
                _ => None,
            })
            .collect()
    }

    /// Everyone's rooms, and everyone's book.
    type Net = (HashMap<HsId, Rooms>, HashMap<HsId, Vec<HsId>>);

    /// Host `a`, members `b` and `c`. `mutual` makes `b` and `c` contacts.
    fn room(mutual: bool) -> (Net, [HsId; 3]) {
        let (a, b, c) = (id(1), id(2), id(3));
        let mut contacts = HashMap::from([(a, vec![b, c]), (b, vec![a]), (c, vec![a])]);
        if mutual {
            contacts.get_mut(&b).unwrap().push(c);
            contacts.get_mut(&c).unwrap().push(b);
        }
        let mut nodes = HashMap::from([(a, Rooms::new(a)), (b, Rooms::new(b)), (c, Rooms::new(c))]);
        nodes.get_mut(&a).unwrap().create("table").unwrap();
        for peer in [b, c] {
            let invite = nodes.get_mut(&a).unwrap().invite(peer).unwrap();
            let seen = run(
                &mut nodes,
                &contacts,
                a,
                Outcome {
                    send: vec![(peer, invite)],
                    ..Outcome::default()
                },
            );
            assert!(seen.contains(&(peer, Event::Invited { from: a, name: "table".into() })));
            let out = nodes.get_mut(&peer).unwrap().join().unwrap();
            run(&mut nodes, &contacts, peer, out);
        }
        ((nodes, contacts), [a, b, c])
    }

    #[test]
    fn a_star_room_carries_a_line_through_the_host() {
        let ((mut nodes, contacts), [a, b, c]) = room(false);
        let out = nodes.get_mut(&b).unwrap().say("salut").unwrap();
        let seen = run(&mut nodes, &contacts, b, out);
        assert_eq!(said(&seen, a), ["salut"]);
        assert_eq!(said(&seen, c), ["salut"]);
        // c cannot name b: they are not contacts, and the host's word is not proof.
        assert!(seen.iter().any(|(at, e)| *at == c
            && matches!(e, Event::Said { who: Who::Stranger(_), .. })));
        // and a knows b by the link b joined over.
        assert!(seen.iter().any(|(at, e)| *at == a
            && *e == Event::Said { who: Who::Known(b), body: "salut".into() }));
    }

    #[test]
    fn a_mesh_room_names_contacts_and_shows_each_line_once() {
        let ((mut nodes, contacts), [a, b, c]) = room(true);
        // Mesh: b and c are bound to each other, not through the host.
        let r = nodes[&c].room.as_ref().unwrap();
        assert!(r.targets().contains(&b));
        let out = nodes.get_mut(&b).unwrap().say("coucou").unwrap();
        let seen = run(&mut nodes, &contacts, b, out);
        assert_eq!(said(&seen, a), ["coucou"]);
        assert_eq!(said(&seen, c), ["coucou"], "twice would mean a duplicate got through");
        assert!(seen.contains(&(c, Event::Said { who: Who::Known(b), body: "coucou".into() })));
    }

    #[test]
    fn a_relay_cannot_change_a_line() {
        let ((mut nodes, _), [a, b, c]) = room(false);
        let out = nodes.get_mut(&b).unwrap().say("vrai").unwrap();
        let Message::RoomSay { room, key, seq, sig, .. } = out.send[0].1.clone() else {
            panic!("a line is a RoomSay");
        };
        // The host, relaying to c, swaps the body.
        let forged = Message::RoomSay { room, key, seq, body: "faux".into(), sig };
        let out = nodes.get_mut(&c).unwrap().receive(a, forged, &[a]);
        assert!(out.events.is_empty());
    }

    #[test]
    fn a_replayed_line_is_ignored() {
        let ((mut nodes, _), [a, b, c]) = room(false);
        let out = nodes.get_mut(&b).unwrap().say("une fois").unwrap();
        let line = out.send[0].1.clone();
        let first = nodes.get_mut(&a).unwrap().receive(b, line.clone(), &[b, c]);
        assert_eq!(first.events.len(), 1);
        let again = nodes.get_mut(&a).unwrap().receive(b, line, &[b, c]);
        assert!(again.events.is_empty());
    }

    #[test]
    fn nobody_outside_the_room_is_heard_or_sent_to() {
        let ((mut nodes, _), [a, b, _]) = room(false);
        let out = nodes.get_mut(&b).unwrap().say("entre nous").unwrap();
        let line = out.send[0].1.clone();
        // A contact of the host, never invited, passing a real line along.
        let outsider = id(9);
        let heard = nodes.get_mut(&a).unwrap().receive(outsider, line, &[outsider]);
        assert!(heard.events.is_empty());
        let out = nodes.get_mut(&a).unwrap().say("x").unwrap();
        assert!(out.send.iter().all(|(to, _)| *to != outsider));
    }

    #[test]
    fn a_tag_is_only_recognisable_by_whoever_has_the_room_and_the_address() {
        let (b, room) = (id(2), [7u8; 16]);
        assert_eq!(tag(&room, &b), tag(&room, &b));
        assert_ne!(tag(&room, &b), tag(&[8u8; 16], &b), "the same person, unlinkable across rooms");
        assert_ne!(tag(&room, &b), tag(&room, &id(3)));
    }

    #[test]
    fn a_host_lying_about_a_contact_is_caught() {
        let ((mut nodes, contacts), [a, b, c]) = room(false);
        // b and c are friends, but the host lists b's tag with a key of its own.
        let fake = [42u8; 32];
        let room_id = nodes[&c].room.as_ref().unwrap().id;
        let mut members = nodes[&a].room.as_ref().unwrap().roster.clone();
        for (key, t) in members.iter_mut() {
            if *t == tag(&room_id, &b) {
                *key = fake;
            }
        }
        let mut theirs = contacts[&c].clone();
        theirs.push(b);
        nodes
            .get_mut(&c)
            .unwrap()
            .receive(a, Message::RoomRoster { room: room_id, members }, &theirs);
        let real = nodes[&b].room.as_ref().unwrap().key();
        let out = nodes
            .get_mut(&c)
            .unwrap()
            .receive(b, Message::RoomHello { room: room_id, key: real }, &theirs);
        assert_eq!(out.events, [Event::Mismatch(b)]);
    }

    #[test]
    fn the_host_leaving_ends_the_room_for_everyone() {
        let ((mut nodes, contacts), [a, b, c]) = room(false);
        let out = nodes.get_mut(&a).unwrap().leave().unwrap();
        let seen = run(&mut nodes, &contacts, a, out);
        assert!(seen.contains(&(b, Event::Ended)));
        assert!(seen.contains(&(c, Event::Ended)));
        assert!(nodes[&b].room.is_none() && nodes[&c].room.is_none());
    }

    #[test]
    fn a_member_leaving_is_seen_by_the_others() {
        let ((mut nodes, contacts), [a, b, c]) = room(false);
        let out = nodes.get_mut(&b).unwrap().leave().unwrap();
        let seen = run(&mut nodes, &contacts, b, out);
        assert!(seen.contains(&(a, Event::Left(Who::Known(b)))));
        assert!(seen.iter().any(|(at, e)| *at == c && matches!(e, Event::Left(_))));
        assert_eq!(nodes[&c].room.as_ref().unwrap().members().len(), 2);
    }

    #[test]
    fn only_someone_invited_can_join() {
        let ((mut nodes, _), [a, _, _]) = room(false);
        let stranger = id(9);
        let room_id = nodes[&a].room.as_ref().unwrap().id;
        let out = nodes
            .get_mut(&a)
            .unwrap()
            .receive(stranger, Message::RoomJoin { room: room_id, key: [5; 32] }, &[]);
        assert!(out.events.is_empty() && out.send.is_empty());
    }
}

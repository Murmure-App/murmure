//! Files in a room: who has what, and moving the bytes.
//!
//! A file put in a room is announced, signed, like a line ([`crate::room`]),
//! and nothing moves until somebody asks. They ask whoever told them about it
//! — the one link they know leads towards it — with [`Message::RoomFetch`], and
//! that peer either streams it from disk or, not having it, fetches it first
//! and then streams it. The second case is the host relaying between two
//! members who cannot reach each other.
//!
//! # Why the relay stores the whole file first
//!
//! Passing chunks through as they arrive would be faster, but it ties the
//! relay's reading from one link to its writing to another: a slow member
//! would stall the whole idle loop, room and keyboard with it. Storing first
//! makes each side its own transfer, and lets the second member to ask be
//! served from the copy the first one caused. The price is the file sitting on
//! the host's disk, under the run directory, until the room ends.
//!
//! # Why a relay cannot swap the bytes
//!
//! The hash every copy is checked against is the one the author signed with
//! their room key. A relay can refuse to pass a file on; it cannot pass on a
//! different one, because the recipient throws away anything that does not
//! hash to what the author said.

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use tokio::io::AsyncReadExt as _;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tor_hscrypto::pk::HsId;

use crate::chat::Progress;
use crate::files::{self, Offer};
use crate::proto::{FileRef, MAX_CHUNK, Message, RoomId};
use crate::ui::Screen;

/// A file we know is in the room.
pub struct Known {
    pub file: FileRef,
    /// Who put it there, as shown when it was announced.
    pub who: String,
    /// Who to ask for it. `None` for our own.
    from: Option<HsId>,
    /// A complete, checked copy on this machine, if there is one: ours, one we
    /// saved, or one we relayed.
    path: Option<PathBuf>,
}

/// A file on its way to us.
struct Down {
    from: HsId,
    dir: PathBuf,
    file: fs::File,
    written: u64,
    /// The operator asked for it. Otherwise we are only relaying it.
    mine: bool,
    /// Members waiting for us to have it, and where each wants it from.
    waiters: Vec<(HsId, u64)>,
    progress: Progress,
    /// When the last byte came, so a transfer that stopped without a word can
    /// be told from one that is only slow.
    heard: std::time::Instant,
}

/// How long a download may go without a byte before asking again replaces it.
///
/// Frames can vanish without anything saying so: a call holds the connection
/// away from the room, and whatever the room sent over it is dropped. Without
/// this the file would be "on its way" for ever.
const STALLED: std::time::Duration = std::time::Duration::from_secs(60);

/// Every file in the room we are in, and every transfer running for it.
pub struct Transfers {
    incoming: PathBuf,
    /// Copies kept only to pass on. Emptied when the room ends.
    relay: PathBuf,
    room: Option<RoomId>,
    known: Vec<Known>,
    down: HashMap<[u8; 32], Down>,
    uploads: Vec<JoinHandle<()>>,
}

/// Something only the caller can do: it holds the connections.
pub enum Action {
    Send(HsId, Message),
    /// Stream this file to this peer, from this byte.
    Upload {
        to: HsId,
        path: PathBuf,
        offset: u64,
        hash: [u8; 32],
    },
}

impl Transfers {
    pub fn new(incoming: PathBuf, relay: PathBuf) -> Self {
        Transfers {
            incoming,
            relay,
            room: None,
            known: Vec::new(),
            down: HashMap::new(),
            uploads: Vec::new(),
        }
    }

    /// Forget everything about the room we were in, and stop every transfer.
    ///
    /// Partial downloads the operator asked for stay in `incoming/`, where a
    /// later transfer of the same file picks them up; relayed copies go.
    pub fn reset(&mut self, room: Option<RoomId>) {
        for upload in self.uploads.drain(..) {
            upload.abort();
        }
        self.down.clear();
        self.known.clear();
        self.room = room;
        if self.relay.exists()
            && let Err(e) = fs::remove_dir_all(&self.relay)
        {
            tracing::debug!("emptying the relay directory: {e}");
        }
    }

    /// Which room these files belong to.
    pub fn room(&self) -> Option<RoomId> {
        self.room
    }

    /// The files announced so far, numbered from 1 as `/room get` takes them.
    pub fn list(&self) -> impl Iterator<Item = (usize, &Known)> {
        self.known.iter().enumerate().map(|(i, k)| (i + 1, k))
    }

    /// Get a file of ours ready to announce.
    pub fn share(&mut self, path: &Path) -> Result<FileRef> {
        let offer = files::describe(path)?;
        let file = FileRef {
            name: offer.name,
            size: offer.size,
            hash: offer.hash,
        };
        if self.known.iter().any(|k| k.file.hash == file.hash) {
            bail!("that file is already in the room");
        }
        self.known.push(Known {
            file: file.clone(),
            who: "you".to_owned(),
            from: None,
            path: Some(path.to_path_buf()),
        });
        Ok(file)
    }

    /// Somebody put a file in the room. Returns its number.
    pub fn announced(&mut self, file: FileRef, who: String, from: HsId) -> usize {
        if let Some(i) = self.known.iter().position(|k| k.file.hash == file.hash) {
            return i + 1;
        }
        self.known.push(Known {
            file,
            who,
            from: Some(from),
            path: None,
        });
        self.known.len()
    }

    /// The operator wants file `n`.
    pub fn get(&mut self, n: usize, screen: &Screen) -> Result<Vec<Action>> {
        let known = self
            .known
            .get(n.wrapping_sub(1))
            .ok_or_else(|| anyhow::anyhow!("no file {n} in this room — /room files"))?;
        let (hash, name) = (known.file.hash, known.file.name.clone());
        if known.from.is_none() {
            bail!("{name:?} is yours");
        }
        if let Some(down) = self.down.get_mut(&hash) {
            if !down.mine {
                // Already coming, to relay: keep it too when it lands.
                down.mine = true;
                return Ok(Vec::new());
            }
            if down.heard.elapsed() < STALLED {
                bail!("{name:?} is already on its way");
            }
            // Stalled. Asked again from where the partial stops, which is
            // safe because a stream that was going to resume would have.
            let waiters = std::mem::take(&mut down.waiters);
            self.down.remove(&hash);
            let ask = self.start(hash, true, None)?;
            if let Some(down) = self.down.get_mut(&hash) {
                down.waiters = waiters;
            }
            return Ok(vec![ask]);
        }
        if let Some(path) = known.path.clone() {
            // Relayed, so already here and already checked: a copy is all
            // that is left to do.
            let saved = save_copy(&self.incoming, &path, &name)?;
            screen.system(format!("-- saved {name:?} to {} --", saved.display()));
            return Ok(Vec::new());
        }
        Ok(vec![self.start(hash, true, None)?])
    }

    /// Open the partial and ask for the rest.
    fn start(&mut self, hash: [u8; 32], mine: bool, waiter: Option<(HsId, u64)>) -> Result<Action> {
        let room = self.room.context("not in a room")?;
        let known = self
            .known
            .iter()
            .find(|k| k.file.hash == hash)
            .context("a file nobody announced")?;
        let from = known.from.context("our own file")?;
        let size = known.file.size;
        // What the operator asked for goes where every received file goes; a
        // copy only held to pass on stays out of their way.
        let dir = if mine { self.incoming.clone() } else { self.relay.clone() };
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let offset = files::resume_offset(&dir, &hash, size);

        // One quota for both: the relay's copies are bytes on this disk that a
        // peer chose, exactly like the files this machine keeps.
        let used = files::dir_size(&self.incoming).saturating_add(files::dir_size(&self.relay));
        let remaining = size.saturating_sub(offset);
        let quota = files::incoming_quota();
        if used.saturating_add(remaining) > quota {
            bail!(
                "taking {:?} would put {} on disk, over the {} quota \
                 (raise it with MURMURE_INCOMING_QUOTA=<bytes>)",
                known.file.name,
                files::human(used + remaining),
                files::human(quota)
            );
        }
        let partial = files::partial_path(&dir, &hash);
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&partial)
            .with_context(|| format!("opening {}", partial.display()))?;
        let progress = Progress::new(
            if mine { "receiving" } else { "relaying" },
            files::sanitize_for_display(&known.file.name),
            size,
        );
        self.down.insert(
            hash,
            Down {
                from,
                dir,
                file,
                written: offset,
                mine,
                waiters: waiter.into_iter().collect(),
                progress,
                heard: std::time::Instant::now(),
            },
        );
        Ok(Action::Send(from, Message::RoomFetch { room, hash, offset }))
    }

    /// A member asked us for a file. `member` is whether they are in the room,
    /// as far as the room can show.
    pub fn fetch(&mut self, peer: HsId, hash: [u8; 32], offset: u64, member: bool, screen: &Screen) -> Vec<Action> {
        let Some(room) = self.room else {
            return Vec::new();
        };
        // Nobody outside the room is sent a byte of it, whatever they know.
        if !member {
            return Vec::new();
        }
        let no = || vec![Action::Send(peer, Message::RoomNoFile { room, hash })];
        let Some(known) = self.known.iter().find(|k| k.file.hash == hash) else {
            return no();
        };
        if offset >= known.file.size {
            return no();
        }
        if let Some(path) = known.path.clone() {
            return vec![Action::Upload {
                to: peer,
                path,
                offset,
                hash,
            }];
        }
        let name = files::sanitize_for_display(&known.file.name);
        if let Some(down) = self.down.get_mut(&hash) {
            down.waiters.push((peer, offset));
            return Vec::new();
        }
        match self.start(hash, false, Some((peer, offset))) {
            Ok(ask) => {
                screen.system(format!("-- relaying {name:?}: fetching it first --"));
                vec![ask]
            }
            Err(e) => {
                screen.error(format!("-- could not relay {name:?}: {e:#} --"));
                no()
            }
        }
    }

    /// Data for a file on its way. Only from the peer we asked.
    pub fn chunk(&mut self, peer: HsId, hash: [u8; 32], data: &[u8], screen: &Screen) -> Vec<Action> {
        let Some(down) = self.down.get_mut(&hash) else {
            return Vec::new();
        };
        if down.from != peer {
            return Vec::new();
        }
        let size = self.known.iter().find(|k| k.file.hash == hash).map_or(0, |k| k.file.size);
        let written = down.written.saturating_add(data.len() as u64);
        let result = if written > size {
            Err(anyhow::anyhow!("more data than the file holds"))
        } else {
            down.file.write_all(data).context("writing the partial file")
        };
        match result {
            Ok(()) => {
                down.written = written;
                down.heard = std::time::Instant::now();
                down.progress.show(written, screen);
                Vec::new()
            }
            Err(e) => self.fail(hash, &format!("{e:#}"), true, screen),
        }
    }

    /// The last of a file arrived: check it, and hand it on.
    pub fn done(&mut self, peer: HsId, hash: [u8; 32], screen: &Screen) -> Vec<Action> {
        if !self.down.get(&hash).is_some_and(|d| d.from == peer) {
            return Vec::new();
        }
        let mut down = self.down.remove(&hash).expect("checked above");
        let _ = down.file.flush();
        let Some(i) = self.known.iter().position(|k| k.file.hash == hash) else {
            return Vec::new();
        };
        let file = self.known[i].file.clone();
        let offer = Offer {
            name: file.name.clone(),
            size: file.size,
            hash,
        };
        let shown = files::sanitize_for_display(&file.name);
        let landed = if down.written != file.size {
            Err(anyhow::anyhow!("it ended at {} of {} bytes", down.written, file.size))
        } else if down.dir == self.incoming {
            // Checked, then named: a corrupted file never appears finished.
            files::finish(&self.incoming, &offer)
        } else {
            keep_relayed(&down.dir, &hash)
        };
        let path = match landed {
            Ok(path) => path,
            Err(e) => {
                // Put back only to be failed: `fail` tells the waiters.
                self.down.insert(hash, down);
                return self.fail(hash, &format!("{e:#}"), true, screen);
            }
        };
        if down.mine {
            let saved = if down.dir == self.incoming {
                Ok(path.clone())
            } else {
                save_copy(&self.incoming, &path, &file.name)
            };
            match saved {
                Ok(saved) => screen.system(format!("-- saved {shown:?} to {} --", saved.display())),
                Err(e) => screen.error(format!("-- {shown:?} arrived but could not be saved: {e:#} --")),
            }
        }
        screen.status("listening");
        self.known[i].path = Some(path.clone());
        down.waiters
            .into_iter()
            .map(|(to, offset)| Action::Upload {
                to,
                path: path.clone(),
                offset,
                hash,
            })
            .collect()
    }

    /// The peer we asked cannot give it to us.
    pub fn refused(&mut self, peer: HsId, hash: [u8; 32], screen: &Screen) -> Vec<Action> {
        if !self.down.get(&hash).is_some_and(|d| d.from == peer) {
            return Vec::new();
        }
        self.fail(hash, "whoever we asked could not give it", false, screen)
    }

    /// A connection went away: whatever was coming over it is not coming.
    ///
    /// The partial of a file the operator asked for stays, so asking again
    /// resumes it.
    pub fn lost(&mut self, peer: &HsId, screen: &Screen) -> Vec<Action> {
        let gone: Vec<[u8; 32]> = self
            .down
            .iter()
            .filter(|(_, d)| d.from == *peer)
            .map(|(h, _)| *h)
            .collect();
        gone.into_iter()
            .flat_map(|hash| self.fail(hash, "the connection it was coming over closed", false, screen))
            .collect()
    }

    /// Give up on a download, and tell whoever was waiting on it.
    fn fail(&mut self, hash: [u8; 32], why: &str, corrupt: bool, screen: &Screen) -> Vec<Action> {
        let Some(down) = self.down.remove(&hash) else {
            return Vec::new();
        };
        let name = self
            .known
            .iter()
            .find(|k| k.file.hash == hash)
            .map(|k| files::sanitize_for_display(&k.file.name))
            .unwrap_or_default();
        // A partial that went wrong is no prefix of anything worth resuming;
        // one only cut short is.
        if corrupt || !down.mine {
            let _ = fs::remove_file(files::partial_path(&down.dir, &hash));
        }
        screen.status("listening");
        screen.error(format!("-- {name:?} did not arrive: {why} --"));
        let Some(room) = self.room else {
            return Vec::new();
        };
        down.waiters
            .into_iter()
            .map(|(to, _)| Action::Send(to, Message::RoomNoFile { room, hash }))
            .collect()
    }

    /// Stream a file to a member, in the background.
    ///
    /// `outbox` is the member's connection. The task holds a clone of it and
    /// nothing else, so it ends by itself when the connection does.
    pub fn upload(&mut self, outbox: mpsc::Sender<Message>, path: PathBuf, offset: u64, hash: [u8; 32]) {
        let Some(room) = self.room else { return };
        self.uploads.retain(|u| !u.is_finished());
        self.uploads.push(tokio::spawn(async move {
            if let Err(e) = send_file(&outbox, room, &path, offset, hash).await {
                tracing::debug!("a room upload stopped: {e:#}");
                let _ = outbox.send(Message::RoomNoFile { room, hash }).await;
            }
        }));
    }
}

async fn send_file(
    outbox: &mpsc::Sender<Message>,
    room: RoomId,
    path: &Path,
    offset: u64,
    hash: [u8; 32],
) -> Result<()> {
    use tokio::io::AsyncSeekExt as _;
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("opening {}", path.display()))?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut buf = vec![0u8; MAX_CHUNK];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        outbox
            .send(Message::RoomChunk {
                room,
                hash,
                data: buf[..n].to_vec(),
            })
            .await
            .map_err(|_| anyhow::anyhow!("the connection closed"))?;
    }
    outbox
        .send(Message::RoomDone { room, hash })
        .await
        .map_err(|_| anyhow::anyhow!("the connection closed"))
}

/// Check a relayed partial and keep it under its hash, ready to pass on.
fn keep_relayed(dir: &Path, hash: &[u8; 32]) -> Result<PathBuf> {
    let partial = files::partial_path(dir, hash);
    if files::hash_file(&partial)? != *hash {
        let _ = fs::remove_file(&partial);
        bail!("it does not match the hash its author signed; discarded");
    }
    let kept = partial.with_extension("file");
    fs::rename(&partial, &kept).with_context(|| format!("keeping {}", kept.display()))?;
    Ok(kept)
}

/// Copy a checked file into `incoming/` under its (made safe) name.
fn save_copy(incoming: &Path, from: &Path, name: &str) -> Result<PathBuf> {
    fs::create_dir_all(incoming).with_context(|| format!("creating {}", incoming.display()))?;
    let to = files::free_path(incoming, &files::safe_name(name)?);
    fs::copy(from, &to).with_context(|| format!("copying to {}", to.display()))?;
    Ok(to)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn id(n: u8) -> HsId {
        Identity::for_test([n; 32]).onion_address()
    }

    fn dirs(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("murmure-roomfiles-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        (base.join("incoming"), base.join("relay"), base)
    }

    /// Run uploads the way the idle loop would, and hand every frame to `to`.
    async fn drain(rx: &mut mpsc::Receiver<Message>, to: &mut Transfers, from: HsId, screen: &Screen) -> Vec<Action> {
        let mut out = Vec::new();
        while let Some(msg) = rx.recv().await {
            match msg {
                Message::RoomChunk { hash, data, .. } => out.extend(to.chunk(from, hash, &data, screen)),
                Message::RoomDone { hash, .. } => {
                    out.extend(to.done(from, hash, screen));
                    break;
                }
                Message::RoomNoFile { hash, .. } => {
                    out.extend(to.refused(from, hash, screen));
                    break;
                }
                _ => {}
            }
        }
        out
    }

    fn upload(t: &mut Transfers, actions: Vec<Action>) -> (HsId, mpsc::Receiver<Message>) {
        let mut ups = actions.into_iter().filter_map(|a| match a {
            Action::Upload { to, path, offset, hash } => Some((to, path, offset, hash)),
            Action::Send(..) => None,
        });
        let (to, path, offset, hash) = ups.next().expect("an upload");
        let (tx, rx) = mpsc::channel(8);
        t.upload(tx, path, offset, hash);
        (to, rx)
    }

    /// Author `a`, relay `h`, member `c`: c asks h, h fetches from a, then
    /// serves c — and c ends with the author's bytes.
    #[tokio::test]
    async fn a_file_crosses_a_relay_and_arrives_intact() {
        let (screen, _ui) = crate::ui::channel();
        let (a, h, c) = (id(1), id(2), id(3));
        let room = [9u8; 16];
        let (ai, ar, base) = dirs("relay");
        let src = base.join("rapport.pdf");
        let bytes: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        fs::write(&src, &bytes).unwrap();

        let mut author = Transfers::new(ai, ar);
        author.reset(Some(room));
        let file = author.share(&src).unwrap();

        let mut relay = Transfers::new(base.join("h-in"), base.join("h-relay"));
        relay.reset(Some(room));
        relay.announced(file.clone(), "alice".into(), a);

        let mut member = Transfers::new(base.join("c-in"), base.join("c-relay"));
        member.reset(Some(room));
        member.announced(file.clone(), "alice".into(), h);

        // c asks h.
        let ask = member.get(1, &screen).unwrap();
        let [Action::Send(to, Message::RoomFetch { hash, offset, .. })] = &ask[..] else {
            panic!("c asks for it")
        };
        assert_eq!(*to, h);
        // h does not have it, so asks a.
        let relay_ask = relay.fetch(c, *hash, *offset, true, &screen);
        let [Action::Send(to, Message::RoomFetch { hash, offset, .. })] = &relay_ask[..] else {
            panic!("h fetches it first")
        };
        assert_eq!(*to, a);
        // a streams it to h; once h has it, h owes c an upload.
        let served = author.fetch(h, *hash, *offset, true, &screen);
        let (_, mut rx) = upload(&mut author, served);
        let owed = drain(&mut rx, &mut relay, a, &screen).await;
        let (to, mut rx) = upload(&mut relay, owed);
        assert_eq!(to, c);
        drain(&mut rx, &mut member, h, &screen).await;

        let got = fs::read(base.join("c-in").join("rapport.pdf")).unwrap();
        assert_eq!(got, bytes);
        // The relay kept only a copy to pass on, and nothing in its incoming/.
        assert!(!base.join("h-in").exists());
        relay.reset(None);
        assert!(!base.join("h-relay").exists(), "the room ending empties the relay");
        let _ = fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn a_relay_that_swaps_the_bytes_is_caught() {
        let (screen, _ui) = crate::ui::channel();
        let a = id(1);
        let room = [9u8; 16];
        let (ci, cr, base) = dirs("swap");
        let file = FileRef {
            name: "vrai.txt".into(),
            size: 5,
            hash: *blake3::hash(b"vrai!").as_bytes(),
        };
        let mut member = Transfers::new(ci.clone(), cr);
        member.reset(Some(room));
        member.announced(file.clone(), "alice".into(), a);
        member.get(1, &screen).unwrap();
        member.chunk(a, file.hash, b"faux!", &screen);
        member.done(a, file.hash, &screen);
        assert!(!ci.join("vrai.txt").exists());
        assert!(!files::partial_path(&ci, &file.hash).exists(), "the bad bytes are gone");
        let _ = fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn only_the_peer_asked_can_send_the_bytes() {
        let (screen, _ui) = crate::ui::channel();
        let (a, stranger) = (id(1), id(9));
        let (ci, cr, base) = dirs("stranger");
        let file = FileRef {
            name: "x.txt".into(),
            size: 3,
            hash: *blake3::hash(b"abc").as_bytes(),
        };
        let mut member = Transfers::new(ci.clone(), cr);
        member.reset(Some([1; 16]));
        member.announced(file.clone(), "alice".into(), a);
        member.get(1, &screen).unwrap();
        member.chunk(stranger, file.hash, b"abc", &screen);
        member.done(stranger, file.hash, &screen);
        assert!(!ci.join("x.txt").exists());
        member.chunk(a, file.hash, b"abc", &screen);
        member.done(a, file.hash, &screen);
        assert_eq!(fs::read(ci.join("x.txt")).unwrap(), b"abc");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn a_stalled_download_can_be_asked_for_again_and_resumes() {
        let (screen, _ui) = crate::ui::channel();
        let a = id(1);
        let (ci, cr, base) = dirs("stalled");
        let file = FileRef {
            name: "long.txt".into(),
            size: 6,
            hash: *blake3::hash(b"abcdef").as_bytes(),
        };
        let mut member = Transfers::new(ci.clone(), cr);
        member.reset(Some([1; 16]));
        member.announced(file.clone(), "alice".into(), a);
        member.get(1, &screen).unwrap();
        member.chunk(a, file.hash, b"abc", &screen);
        // Still moving: asking again is refused.
        assert!(member.get(1, &screen).is_err());
        // Nothing for a long while: asking again starts over from the partial.
        let d = member.down.get_mut(&file.hash).unwrap();
        d.heard = std::time::Instant::now().checked_sub(STALLED * 2).unwrap();
        let again = member.get(1, &screen).unwrap();
        assert!(matches!(&again[..], [Action::Send(to, Message::RoomFetch { offset: 3, .. })] if *to == a));
        member.chunk(a, file.hash, b"def", &screen);
        member.done(a, file.hash, &screen);
        assert_eq!(fs::read(ci.join("long.txt")).unwrap(), b"abcdef");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn nobody_outside_the_room_is_served() {
        let (screen, _ui) = crate::ui::channel();
        let (ai, ar, base) = dirs("outsider");
        let src = base.join("secret.txt");
        fs::write(&src, b"entre nous").unwrap();
        let mut author = Transfers::new(ai, ar);
        author.reset(Some([1; 16]));
        let file = author.share(&src).unwrap();
        assert!(author.fetch(id(9), file.hash, 0, false, &screen).is_empty());
        let _ = fs::remove_dir_all(&base);
    }
}

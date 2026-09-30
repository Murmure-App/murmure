# murmure

Peer-to-peer terminal messaging over Tor onion services.

The point is not that nobody can read your messages — every messenger does that
now. The point is that **nobody can tell who you talk to**: no account, no
directory, no server anyone operates. A call needs both of you online at the
same moment; a message left with `/tell` does not — it waits, sealed on your own
disk, until the other person appears.

> ## Read this before trusting it
>
> **murmure has never been audited, by anyone.** It is one person's project,
> a few weeks old. It has tests and its security decisions are argued for in
> the code, and that is not the same thing as review.
>
> The properties below are what it *aims* for and what its design supports.
> Whether the implementation actually delivers them is exactly the question an
> audit would answer, and nobody has asked it.
>
> Use it because a P2P terminal messenger is a nice thing to have. **Do not use
> it in a situation where being wrong about it would hurt you.** For that, use
> something that has been examined — Briar, or Signal, depending on what you
> need.
>
> Known limits are stated where they apply rather than collected here: search
> the page for "limit". Windows support is the newest and the least tried.

## Install

Three archives per release, on the [releases
page](https://github.com/Murmure-App/murmure/releases):

| archive | runs on |
|---|---|
| `linux-x86_64` | glibc 2.35 or newer, so Ubuntu 22.04 and up |
| `linux-aarch64` | the same, on ARM — a 64-bit Raspberry Pi, an ARM server |
| `macos-universal` | any Mac, Apple Silicon or Intel |
| `windows-x86_64` (zip) | 64-bit Windows 10 and 11 |

The Windows binary is new. Until September 2026 arti hung on Windows while
reading its first consensus (a dependency looped forever on Windows' 100 ns
clock; see `aidd_docs/arti-windows-hang.md`); murmure now carries the fix.
Run `murmure.exe` from Windows Terminal. It is not signed, so SmartScreen
warns before the first run. WSL 2 remains an option.

### On Windows, through WSL 2

murmure runs unchanged in WSL 2: it is the Linux binary, talking to Tor from
the Linux side. In PowerShell, once:

```powershell
wsl --install -d Ubuntu
```

Then open **Ubuntu** from Windows Terminal and follow the Linux instructions:
the `linux-x86_64` archive, or [Build](#build) after
`sudo apt install build-essential` (SQLite is compiled from source and needs a
C compiler).

Five things differ from a plain Linux machine:

- **Run it from your Linux home, not from `/mnt/c`.** murmure refuses to start
  if `identity.seed` is readable by anyone else, and files on the Windows drive
  cannot hold Unix permissions, so the check fails there — by design.
- **Received files** land in `~/.local/share/murmure/incoming/` inside Linux.
  From Windows, open `\\wsl$\Ubuntu\home\<you>\.local\share\murmure\` in
  Explorer.
- **Copying your address** works: Windows Terminal honours the clipboard escape
  murmure uses.
- **`/view` does not**: Windows Terminal speaks Sixel, and `/view` only speaks
  the Kitty and iTerm2 protocols.
- **`/send --direct`** needs to be reached from outside, and WSL 2 sits behind
  its own NAT by default. On Windows 11 22H2 or later, add this to
  `%UserProfile%\.wslconfig`, then run `wsl --shutdown`:

  ```ini
  [wsl2]
  networkingMode=mirrored
  ```

  Without it, a direct transfer simply falls back to Tor.

A binary from an anonymous account is worth exactly the trust you place in that
account, which should be none. `SHA256SUMS` only says the download arrived
intact; what ties an archive to the source that produced it is its provenance
attestation:

```sh
gh attestation verify murmure-*.tar.gz --repo Murmure-App/murmure   # or the .zip
```

On macOS the binary is neither signed nor notarized, so Gatekeeper quarantines
it. Clearing that is a decision, not a formality:

```sh
xattr -d com.apple.quarantine murmure
```

## Build

Building it yourself is the recommended path, and the only one that asks you to
trust nobody. Needs Rust ≥ 1.91.

```sh
rustup toolchain install stable && rustup default stable
cargo build --release
```

The first build compiles arti and takes several minutes. Later ones are quick.

**Both sides must run the same build.** The wire format carries no field names,
so a version that does not match cannot be interpreted — it can only be
detected. It is, at the start of every call, and murmure says which two versions
disagreed rather than failing later as something else. There is no
compatibility between versions yet; when you update, tell the person you talk
to.

## Run

```sh
./target/release/murmure
```

No arguments, no configuration. It prints your `.onion` address, publishes it,
and listens.

Startup is a few seconds to a minute — Tor has to fetch its directory. The input
box stays greyed out until it is ready and its title counts the progress up, so
a slow bootstrap never looks like a frozen one. `Ctrl-C` always works.

If the count sits at the same percentage for several minutes, it is not slow, it
is stuck. To see arti on its own, with no interface in the way:

```sh
cargo test --release -- --ignored --nocapture reaches_the_tor_network
```

## Calling someone

Each side runs murmure and reads **two lines** off the top of the screen: their
address, and their discovery key.

```text
your address: xxxxxxxx…xxxx.onion
your key:     descriptor:x25519:XXXX…XXXX
```

`/copy` puts both on your clipboard, in the order `/add` wants them. Send them
to the other person however you like. Neither is a secret — the address is a
public key, and the discovery key is the public half of one.

**Ctrl+V pastes**, without Shift. It reads the clipboard through `pbpaste`,
`wl-paste`, `xclip` or `xsel`, whichever the machine has — so there is no
clipboard library to install and no X11 headers to build against. Paste a file's
path and it becomes an attachment, same as dropping it.

**Drag over the history to select it, and it is copied when you let go** — no
Ctrl+C, which stays "get me out of here". The wheel scrolls.

murmure captures the mouse to do this, which means it replaces your terminal's
own selection rather than sitting alongside it. **Shift-drag** is the escape
hatch: every common terminal reads a Shift-drag as its own, so that is how you
select across the input box, or grab something murmure will not give you.

Selecting is aware of what it is selecting: an address that wrapped across three
rows comes back as one unbroken string, not three pieces with the wrap points
baked in.

> Both copy paths ask the terminal to do the copying (OSC 52), which works over
> SSH. Some terminals disable it; if nothing lands on the clipboard, Shift-drag
> and use your terminal's own copy.

```text
/add alice xxxx….onion descriptor:x25519:XXXX…    file them under a name
/call alice                                       dial (7–50 s, /cancel to stop)
/verify alice                                     a safety number to read out together
/notify off                                       no bell (on by default)
/answer   /decline                                take, or turn down, a call
/tell alice on rentre à 19h                       leave a message for later
/history                                          what is kept (nothing, by default)
/presence alice                                   ask to see each other online
/room new table   /room invite alice              open a room, ask people in
/room send ~/plan.pdf   /room get 1               put a file in the room, take one
/send ~/rapport.pdf                               offer a file (during a call)
/accept   /refuse                                 answer an offer of theirs
/cancel                                           stop a file coming in
/bye                                              hang up
/quit                                             leave
```

Then **compare the fingerprint out loud** — the short `hati … 7ryd` form shown
next to the name. It is the address itself, so if it matches you are talking to
the key you meant to. Nothing else authenticates the other side.

The fingerprint is 8 characters, 40 bits: enough against a typo or a quick
swap, not against somebody who spent weeks grinding an address that looks the
same at both ends. `/verify alice` shows a **safety number**: 60 digits
computed from both your whole addresses, the same on both sides. Read it out to
each other once, on a call or face to face; if every digit matches, nobody
stands between the two addresses you filed.

The 7–50 seconds is the price of the *first* call. The connection outlives the
call held over it, so calling the same person again costs nothing until one of
you leaves.

Anything you type while the call is still connecting is held and goes out as
soon as it connects; it is also what rings at the other end. Commands are not
held: they are commands, and only `/cancel` and `/quit` mean something before
there is a call.

**A call still has to be answered.** The connection being open is not consent to
talk over it, so a call coming in shows `-- alice is calling --` and waits for
`/answer`. What she said first is held unread until then; `/decline` tells her
you are not taking it, and you never see it.

**Several lines in one message:** Alt-Enter starts a new line inside it
(shown `↵` in the input), and a pasted paragraph keeps its lines. A peer on
0.1.0-beta.3 or older sees the lines run together.

When a message, a call or a room invitation arrives while the terminal is not
the window in front, murmure rings the terminal bell — a sound, a flash or a
taskbar mark, as your terminal sees fit. `/notify off` stops it for the session,
`MURMURE_NOTIFY=off` from the start. It relies on the terminal reporting focus:
most do; inside tmux, `set -g focus-events on`.

`/help` lists the rest, including the scroll keys.

## Friends-only discovery

The second half of `/add` is what makes the address stop being a bearer token.

With no contacts filed, murmure publishes an ordinary onion descriptor: anyone
who has ever seen your address can look it up and learn you are online. File one
contact and the service switches to **restricted discovery** — the descriptor's
introduction points are encrypted for the keys you listed, so to everybody else
your service is indistinguishable from one that does not exist.

Two honest limits, both upstream's:

- **`/forget` is not revocation.** The introduction points are not rotated, so
  someone you just removed can still reach them until they rotate on their own.
- **It is filed as DoS resistance.** It hides the descriptor; it is not an
  access-control layer, and murmure does not treat it as one.

Adding a contact takes effect without a restart, but the new descriptor has to
reach the directory first — give it a minute.

## Presence

`/presence alice` asks alice whether the two of you should see when each other
is online. She agrees by typing `/presence` back at you. From then on, both
murmures hold a connection open to each other whenever they run, and:

- you each see `-- alice is online --` when the other starts up, and
  `-- alice went offline --` when they stop;
- `/call alice` is instant, because there is nothing left to dial — she still
  has to `/answer`;
- `/contacts` shows who is up.

Either of you ends it with `/presence alice off`, and the other is told.

**It is asked rather than assumed, and that is the whole design.** Restricted
discovery already decides who can *reach* you. Being watched is a second
permission: a friend who can call you does not thereby get to know when you are
at your machine. So nothing is dialled on anyone's behalf until both sides have
said yes, an unanswered request stays unanswered for ever, and a `yes` to a
question you never asked changes nothing.

There is no panel of coloured dots. Presence is shown when you ask for
`/contacts` and when someone's state changes, and not otherwise — a permanent
list of who is online is a list, readable by anyone behind you, of who you talk
to.

What it costs: while presence is on with someone, you are holding a Tor circuit
to them and sending a two-byte keepalive each minute. That is visible to your
guard node as *traffic*, exactly as any open circuit is. It says nothing about
who is on the other end.

## Leaving a message

`/tell alice on rentre à 19h` when alice is out. The message is sealed on **your**
disk and goes out the next time she appears. She sees it where it lands, with
how long it waited; you see `-- everything you wrote to alice arrived --` when
her side confirms.

The two obvious places to leave an undelivered message are both worse than not
having the feature. A **server** ends "no server anyone operates" and whoever
runs it learns who writes to whom. **Relaying through your contacts** is worse
still: it tells your friends when you are writing to somebody who is not them.
Keeping it with the sender costs one thing — the message only moves when you are
both online at *some* point — and buys everything else.

**Delivery is confirmed, not assumed.** A message leaves your queue when the
recipient says they have it, never when it is handed to a connection. A lost
acknowledgement therefore costs a redelivery, and their side keeps a per-sender
mark so a redelivery is never a duplicate on screen.

Bounded, and bounded out loud: 64 messages per contact. Past that the oldest is
dropped and you are told which. A message that vanishes without a word is the
one failure this is built to avoid.

## Rooms

`/room new table` opens a room, `/room invite alice` asks a contact in, and she
answers with `/room join` or `/room decline`. Once in, anything you type that is
not a command goes to the room. `/room` lists who is there, `/room leave` goes.

A room lives in memory only. Nothing about it is written down, and it ends when
its host — whoever opened it — leaves.

**There is no server, and no group key.** Every line travels over the same
connections a call uses, each under its own ratchet, so somebody leaving leaves
nothing to re-key. Every line is signed by its author with a key made for that
room alone, and whoever passes a line on can hold it back but cannot change it
or write one in somebody else's name.

**Who is connected to whom decides the shape.** Two members who are not each
other's contacts cannot reach each other at all — friends-only discovery hides
you from anyone not in your book — so the host relays between them. Members who
*are* contacts connect directly and hear each other first-hand. Nobody picks:
a room is a star with the host in the middle, and a mesh wherever friends share
it.

**Nobody learns an address they did not already have.** The member list carries
room keys and a tag per member that can only be checked against an address one
already knows. So you see which of *your* contacts are in the room, by name;
everyone else shows as `~a1b2c3d4`. A contact's name is shown only once they
have proved that key over their own connection to you — if the host's list says
otherwise, you are told the host is lying about them.

What the host can do, and you should know: see every line (it is in the room),
hold lines back, and vouch for people you do not know — `~a1b2c3d4` is whoever
the host let in, and nothing more is proved about them.

**Files.** `/room send ~/plan.pdf`, or drop it on the window, puts a file in the
room: everyone sees `bob shared "plan.pdf" (3.0 MB) — /room get 1`, and nothing
moves until somebody asks. Whoever asks gets it from whoever told them about
it: straight from the author when they are contacts, through the host when they
are not. The host then takes the whole file first and passes it on, so it
arrives in roughly twice the time — and sits on the host's disk, outside
`incoming/`, until the room ends. Every copy is checked against the hash its
author signed, so the host can refuse to pass a file on but cannot pass on a
different one. It all goes over Tor, and it all counts against the same
`MURMURE_INCOMING_QUOTA`.

Limits, for now: 16 people, one room at a time. During a call the room waits,
and what it says over the connection to the person you are calling is lost —
a file coming over that connection included; ask for it again after the call.

## Sending a file

During a call, **drop files into your message**, wherever you want them:

```text
the holiday photos: [beach.jpg] [sunset.jpg] — the second one is better
```

Enter sends the sentence and the files as one thing. The other side sees your
message with the chips in place and **clicks the one they want**. By keyboard: `/accept` takes from the **message you just
read** rather than the oldest one left unanswered, `/accept 2` picks one by the
number shown, **`/accept all` takes every one**, `/refuse`
declines. `all` is a standing instruction rather than a batch — the wire carries
one file at a time regardless, so each one that finishes starts the next. `/send <path>` still offers a
file on its own if there is nothing to say around it.

A chip lands where the cursor is and behaves like a single character from there
on: the arrows step over it in one press, Backspace removes it whole, and you
can type on either side of it.

Nothing moves until the other person types `/accept` — a file lands on their disk, so they decide, not you. `/refuse`
declines it. One file at a time, and one call at a time. `/cancel` stops a
file already coming in; what arrived is kept, so the same file offered again
resumes from there. A chip from an earlier call is no longer clickable: each
call numbers its files from 1.

A running transfer draws a **progress bar in the title line** — name, percent
and both sizes — for either direction and either route.

An accepted file is written to `incoming/` in the data directory (see
[Files on disk](#files-on-disk)). It only gets its real name
once its BLAKE3 hash matches what was offered; until then it sits under a name
derived from that hash, with a `.part` extension.

That naming is what makes resuming work. If a call drops mid-transfer, offering
the same file again picks up exactly where it stopped — the partial can only
belong to the file whose hash it is named after, so there is no way to splice two
different files together. Nothing to configure and nothing to remember: offer it
again, accept again.

`/bye` during a transfer waits for the file to finish rather than truncating it.
A second `/bye` leaves immediately.

### Going faster, on purpose

Over Tor a file crosses six relays, which measures at 0.1–0.25 MB/s: a 2 MB PDF
takes about half a minute. Starting a line with **`/direct`** asks to send that
message's files outside Tor instead — on a local network that is roughly a thousand times faster.

**It is never automatic, and never silent.** A direct link tells the other peer
your IP address, and shows both ISPs that these two addresses are exchanging
data at this moment — the metadata this whole program exists to hide. So:

- the sender asks for it by name, per message — `/direct here they are: [a.jpg]`
  — and never through a mode that stays on and gets forgotten;
- the recipient sees that the offer is direct, and what agreeing exposes;
- agreeing is what opens the port — `/accept` over a direct offer is the only
  place murmure ever reveals an address.

A recipient who wants the file but not the exposure can still take it over Tor.
If the link cannot be established, both sides are told and it falls back to Tor
rather than failing.

**Whether it connects depends on IPv6.** Nothing has to be opened on your router
for two machines on the same network. Between two *different* networks, it comes
down to which address the other side can be reached at:

- **With IPv6 on both sides, it can.** There is no NAT, and a machine knows its
  own global IPv6 address because it is simply assigned to the interface. The
  reason IPv4 needs a STUN server is that a machine behind a NAT cannot learn its
  public address without asking someone; in IPv6 there is nothing to ask.
  What is left is your router's inbound firewall, and that is the part nobody can
  promise you. On the one router this was tried on — an Orange Livebox 7 — the
  IPv6 pinhole page is read-only: one fixed TCP entry, no way to add a UDP one,
  so QUIC never gets in. Assume it will not work across networks until you have
  seen it work.
- **With IPv4 only, it does not.** murmure advertises no public IPv4 address,
  because discovering one needs a third party and this program has none.

Either way a link that cannot be established falls back to Tor and says so, so
`--direct` never costs you a transfer.

One more limit: a resumed transfer always uses Tor — the direct stream carries no
offsets, so the two sides would have to agree on one out of band.

## History, if you ask for it

**Off.** Close murmure and the conversation is gone. That was never designed —
it fell out of holding everything in memory — but it is a real property: a
machine seized, stolen, or borrowed reveals nothing about what was said.

`/history on` gives that up on purpose. What you say and what you are told is
kept, sealed with the same construction as the contacts book, capped at a
megabyte with the oldest dropped. `/history` reads the last lines back.
`/history off` **erases** what is there — anything less would leave you believing
you had stopped keeping a record while the record you already have sits on the
disk.

Two things happen the moment you turn it on:

- **Everyone you are connected to is told**, and told again on every future
  connection. Being recorded and knowing you are recorded are different things,
  and the second is the only part that can honestly be offered.
- **They can refuse.** `/history no alice` asks alice not to write down what you
  say; her murmure honours it, stops at once mid-call, and erases what it
  already had of yours. Nothing here can stop a build that lies, and nothing
  pretends to — it is worth what any request not to repeat something is worth.

Not JSON, not SQLite. JSON would be the conversation in plaintext on the disk,
and sealing it leaves the JSON doing nothing. SQLite buys incremental append and
range queries, which a scrollback read from the end at startup does not need, and
costs either a C library arti does not ship or per-row encryption that leaves
message count, sizes and timing readable.

## Files on disk

Everything lives in one directory: the identity seed, the sealed contacts book,
received files, Tor's state, and `murmure.log`. It is the platform's data
directory — `~/.local/share/murmure` on Linux, `~/Library/Application
Support/murmure` on macOS, `%LOCALAPPDATA%\murmure\data` on Windows — so
starting murmure from anywhere finds the same identity.

Versions up to 0.1.0-beta.2 used `.murmure/` in the directory murmure was
started from. That one is still used when it is there, and murmure says so at
start; move it to the directory above to stop depending on where you start.

`identity.seed` **is** your identity — 32 bytes, mode 0600, never leaves the
machine. Lose it and you lose your address and your contacts book, which is
sealed under a key derived from it.

Two optional protections, each a one-shot run that exits before anything
starts:

- **A recovery phrase.** `MURMURE_EXPORT_MNEMONIC=1 ./murmure` prints your
  seed as 24 words; write them on paper. On a new machine, with no
  `identity.seed` yet, they bring back the same address:

  ```sh
  read -rs MURMURE_RESTORE_MNEMONIC && export MURMURE_RESTORE_MNEMONIC
  ./murmure
  unset MURMURE_RESTORE_MNEMONIC
  ```

  (`read -rs` keeps the words out of your shell history.) The phrase restores
  the identity only: the contacts book and history are files, and come back
  only if you copied the data directory too. Anyone holding the words *is* you.
- **A passphrase.** `MURMURE_ENCRYPT_IDENTITY=1 ./murmure` encrypts the seed
  with a passphrase (Argon2id), asked at every start from then on;
  `MURMURE_DECRYPT_IDENTITY=1` undoes it.

Set `MURMURE_DIR` to run a second instance on the same machine:

```sh
MURMURE_DIR=.murmure-b ./target/release/murmure
```

## Status

**Beta — `0.1.0-beta.3`.** Not a first stable release, and the version will not
lose its `-beta` because the code settles down. It loses it when someone other
than the author has read the parts that matter, which has not happened. Until
then the label is the honest one: usable, unverified.

Concretely, beta means two things you can plan around. The wire format can
change between releases and there is no compatibility across them, so both sides
update together. And the command names are not promises yet.

Text, rooms, presence, friends-only discovery and file transfer work, on macOS,
Linux and Windows. Windows needed a patched copy of one arti dependency — see
`aidd_docs/arti-windows-hang.md`.

## Licence

GPL-3.0-or-later — see `LICENSE`.

Chosen over a permissive licence on purpose: a program whose whole point is that
nobody watches you should not be something a third party can take, add
telemetry to, and ship closed.

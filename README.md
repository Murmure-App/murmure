# murmure

Peer-to-peer terminal messaging over Tor onion services.

The point is not that nobody can read your messages — every messenger does that
now. The point is that **nobody can tell who you talk to**: no account, no
directory, no server anyone operates. Both sides must be online at the same
time. It is a phone call, not a text message.

## Build

Needs Rust ≥ 1.91.

```sh
rustup toolchain install stable && rustup default stable
cargo build --release
```

The first build compiles arti and takes several minutes. Later ones are quick.

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
/send ~/rapport.pdf                               offer a file (during a call)
/accept   /refuse                                 answer an offer of theirs
/bye                                              hang up
/quit                                             leave
```

Then **compare the fingerprint out loud** — the short `hati … 7ryd` form shown
next to the name. It is the address itself, so if it matches you are talking to
the key you meant to. Nothing else authenticates the other side.

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

## Sending a file

During a call, **drop files into your message**, wherever you want them:

```text
the holiday photos: [beach.jpg] [sunset.jpg] — the second one is better
```

Enter sends the sentence and the files as one thing. The other side sees your
message with the chips in place and **clicks the one they want**. By keyboard: `/accept` takes the
first, `/accept 2` picks one, **`/accept all` takes every one**, `/refuse`
declines. `all` is a standing instruction rather than a batch — the wire carries
one file at a time regardless, so each one that finishes starts the next. `/send <path>` still offers a
file on its own if there is nothing to say around it.

A chip lands where the cursor is and behaves like a single character from there
on: the arrows step over it in one press, Backspace removes it whole, and you
can type on either side of it.

Nothing moves until the other person types `/accept` — a file lands on their disk, so they decide, not you. `/refuse`
declines it. One file at a time, and one call at a time.

An accepted file is written to `.murmure/incoming/`. It only gets its real name
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

- **With IPv6 on both sides, it works.** There is no NAT, and a machine knows its
  own global IPv6 address because it is simply assigned to the interface. The
  reason IPv4 needs a STUN server is that a machine behind a NAT cannot learn its
  public address without asking someone; in IPv6 there is nothing to ask. What is
  left is your router's inbound firewall, which is usually one setting.
- **With IPv4 only, it does not.** murmure advertises no public IPv4 address,
  because discovering one needs a third party and this program has none.

Either way a link that cannot be established falls back to Tor and says so, so
`--direct` never costs you a transfer.

One more limit: a resumed transfer always uses Tor — the direct stream carries no
offsets, so the two sides would have to agree on one out of band.

## Files on disk

Everything lives in `.murmure/` next to where you ran it: the identity seed, the
sealed contacts book, received files, Tor's state, and `murmure.log`.

`identity.seed` **is** your identity — 32 bytes, mode 0600, never leaves the
machine. Lose it and you lose your address and your contacts book, which is
sealed under a key derived from it. There is no recovery, by design.

Set `MURMURE_DIR` to run a second instance on the same machine:

```sh
MURMURE_DIR=.murmure-b ./target/release/murmure
```

## Status

Text, friends-only discovery and file transfer work, on macOS and Linux. Windows
does not: arti hangs fetching its first consensus, on two independent machines
and two networks — see `aidd_docs/arti-windows-hang.md`. Presence does not exist
yet; see `aidd_docs/INSTALL.md` for the design and what is still open.

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

Send both to the other person however you like. Neither is a secret — the
address is a public key, and the discovery key is the public half of one.

```text
/add alice xxxx….onion descriptor:x25519:XXXX…    file them under a name
/call alice                                       dial (7–50 s, /cancel to stop)
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

## Files

Everything lives in `.murmure/` next to where you ran it: the identity seed, the
sealed contacts book, Tor's state, and `murmure.log`.

`identity.seed` **is** your identity — 32 bytes, mode 0600, never leaves the
machine. Lose it and you lose your address and your contacts book, which is
sealed under a key derived from it. There is no recovery, by design.

Set `MURMURE_DIR` to run a second instance on the same machine:

```sh
MURMURE_DIR=.murmure-b ./target/release/murmure
```

## Status

Text and friends-only discovery work, on macOS and Linux. Windows does not: arti
hangs fetching its first consensus, on two independent machines and two networks
— see `aidd_docs/arti-windows-hang.md`. Files and presence do not exist yet; see
`aidd_docs/INSTALL.md` for the design and what is still open.

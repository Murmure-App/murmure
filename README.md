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

Startup takes **several minutes the first time** — Tor downloads the whole
directory cold. Later runs, off the cache, are tens of seconds. The input box
stays greyed out until it is ready and its title counts the progress up, so a
slow bootstrap never looks like a frozen one. `Ctrl-C` always works.

## Calling someone

Each side runs murmure and reads their own address off the top of the screen.
Send it to the other person however you like — it is a public key, not a secret.

```text
/add alice xxxxxxxx…xxxx.onion    file them under a name
/call alice                       dial (7–50 s is normal, /cancel to give up)
/bye                              hang up
/quit                             leave
```

Then **compare the fingerprint out loud** — the short `hati … 7ryd` form shown
next to the name. It is the address itself, so if it matches you are talking to
the key you meant to. Nothing else authenticates the other side.

`/help` lists the rest, including the scroll keys.

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

Text works. Files, presence, and friends-only transport do not exist yet — see
`aidd_docs/INSTALL.md` for the design and what is still open.

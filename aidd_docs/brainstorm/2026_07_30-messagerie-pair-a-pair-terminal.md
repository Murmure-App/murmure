# murmure — peer-to-peer terminal messaging

**Date**: 2026-07-30
**Status**: idea clarified, ready for the next step

---

## The idea

Terminal messaging between people who already know each other. Messages go from
one machine to the other with no intermediary able to read them, or to know who
talks to whom. Nothing to pay, nothing to host, no account.

## The need behind it

To depend on nobody, and to spend nothing. What motivates the project is not
confidentiality of content — end-to-end encryption already gives that, Signal
and WhatsApp included. What those products do not give, and what this project
aims at:

- Nobody knows **who talks to whom**, or when.
- No company can shut it down, bill for it, or change its terms.
- No central directory to trust for a correspondent's public key.

## What is decided

### Identity

Every user generates a key pair on their machine. Their public identifier is
**derived** from it — it never changes, and it is not their IP address. Deriving
it from the key means that claiming that identity requires holding the private
key: an impostor cannot place themselves under somebody else's identifier.

### First contact

The two people exchange their identifiers over any channel, **even an insecure
one** (SMS, WhatsApp, email). The channel does not need to be safe: a public
identifier is made to be seen. The only risk is that it gets **replaced** in
transit, and comparing a short fingerprint out loud is what rules that out — the
person's voice is the authentication.

Between friends only. **The case of two strangers is explicitly out of scope**,
and has no solution: with nothing in common to start from, no technique
distinguishes a correspondent from an impostor.

### Connection — three paths

The program tries them **in order**, automatically. By default the user chooses
nothing.

1. **Direct** — machine to machine, a port opened on the router.
2. **Assisted** — NAT traversal with the help of free public infrastructure.
3. **Relayed** — the Tor network.

Two installation modes:

- **Simple**: asks nothing, tries all three in order.
- **Custom**: allows forcing a specific path. Technically a switch on top of the
  ladder, not a second program.

### Messages

No intermediate storage. Both correspondents have to be connected **at the same
time** — it is a phone call, not a text message. A message that fails comes back
to the sender after several attempts, like a registered letter.

### Content

Text, images and files. **Nothing lands on disk without the recipient's explicit
confirmation.** Images are not displayed in the terminal in v1 (some modern
terminals can do it — to revisit later, not now).

An interrupted transfer **resumes where it stopped**.

### Usage

A contacts book, several conversations, and a **presence indicator** (who is
reachable) from v1.

### History

Two modes, at the user's choice:

- **Nothing is kept** — quit, and it all disappears.
- **Kept encrypted** on disk.

**Never in the clear**, in either mode.

### Form

A rich text-mode interface in the terminal: colours, frames, areas that refresh,
keyboard shortcuts. No graphical window, no web application.

---

## Success criterion

> Two machines, two different networks, two cities. Each person runs the
> command. They compare a fingerprint out loud, and it matches. One types a
> sentence, the other sees it appear. One sends a file, the other gets a
> confirmation prompt, accepts, and the file arrives intact.

---

## What remains open

### To settle at design time

| Topic | The question |
| --- | --- |
| **The identifier → address directory** | For paths 1 and 2, something has to translate an identifier into today's address. A server (refused), a table distributed among users (empty as long as there is no crowd — this project starts with two people), or leaning on Tor's already-populated directory. The project's last real technical unknown. |
| **The cost of presence** | With no server, knowing who is reachable means polling every contact in a loop. A permanent network cost, and it continuously signals one's own presence to every contact. The trade-off is still to be settled. |
| **Transfer resume across sessions** | Where the state of a partial transfer lives if both sides disconnect, and how integrity is checked at the end. |

### Assumptions made, to be confirmed

- Encryption relies on an **established and audited protocol**, never on a
  home-made construction. Home-made cryptography fails silently.
- **One identity per machine.** Using the same account on two computers is not
  planned for.
- **Losing the machine means losing the identity.** No key backup, no recovery.

### Accepted risks

- On paths 1 and 2, **the correspondent sees the IP address**, so roughly the
  city. Acceptable between friends, validated. Only path 3 (relayed) hides it.
- **The direct path will not work for everyone.** On 4G and at some ISPs, the
  machine has no reachable address at all, whatever the user does.

---

## Order of magnitude

| Scope | Estimate |
| --- | --- |
| Encrypted core, one conversation, a single network path | a few evenings |
| + contacts book, presence, several conversations | +2 to 3 weeks |
| + file transfer resume | +1 week |
| + the other two network paths | +2 to 4 weeks |

Complete project: several months of evenings for one person alone.

---

## Next step

Choose the technical architecture and the stack before writing code. The
language conditions the encryption, terminal and network libraries — that choice
may as well be made once and for all.

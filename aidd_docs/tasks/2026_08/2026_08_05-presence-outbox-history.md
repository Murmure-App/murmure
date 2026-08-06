---
name: design
description: Presence, a sender-side outbox, and persistent history — what each one is, what it costs, and what must be decided before any of it is written.
argument-hint: N/A
objective: "murmure stops requiring both people to be online at the same moment, without introducing a server, a third party, or a new place where metadata leaks."
status: accepted
---

# Design: presence, outbox, history

## Why these three, together

They look like three features. They are one, and the order matters.

murmure's stated limit is that both sides must be online at the same time — "it
is a phone call, not a text message". That limit is what stops it from being
used, and every obvious fix costs the thing the program exists to protect:

| fix | what it costs |
|---|---|
| publish presence openly | publishes when you are online — the metadata murmure hides |
| store offline messages on a server | a server. Ends 0 €/month and "no server anyone operates" |
| store them at your contacts | your contacts learn when you write to someone else. Worse than a server |

The way out is the third feature paying for the first two. **An undelivered
message stays with its sender, sealed.** Presence is what tells the sender it
can now be delivered. No third party holds anything, ever.

What changes is the condition on a conversation: from *both online at the same
moment, both typing* to *both online at some point, not necessarily the same
one*. That is the whole prize.

## 1. Presence

### Consent

Presence is per-contact and mutual. `/presence alice` asks; alice accepts; from
then on each side's murmure tries to hold a connection to the other whenever it
runs.

Restricted discovery already does most of this work — someone who is not in your
contacts book cannot decrypt your descriptor, so they cannot learn you are up.
Explicit consent adds one thing on top: a contact who can reach you does not
automatically get to watch you. Being reachable and being observed are different
permissions.

### It is a held-open connection, not a poll

**There is no "send a request every X seconds".** Dialing an onion service takes
7 to 50 seconds — a periodic poll cannot exist at that latency, and each attempt
would build a fresh circuit, which is both slow and more visible than one that
stays up.

Instead: connect once, keep the connection open, and send a few bytes of
keepalive on it periodically. The mutual handshake falls out of this for free —
the connection being established *is* both sides agreeing they are present.

Going down:

- **Deliberate exit.** Send one goodbye frame and leave. If it does not arrive,
  it does not arrive; the timeout below covers that. Do not wait for an
  acknowledgement — a program that hangs on exit is worse than a stale presence
  indicator.
- **Crash, network loss, closed lid.** The other side sees keepalives stop and
  declares the peer gone after a timeout. The timeout has to be several times the
  keepalive interval, because Tor latency is spiky and a peer that flickers
  between present and absent is worse than no indicator at all.

### The decision that has to be made first

Does the presence connection also carry the conversation?

- **A. Presence only.** The held connection carries keepalives and nothing else.
  `/call` still dials a fresh circuit, still takes 7-50 seconds. Small change:
  presence is a new module beside the existing call path, and `chat::run` is
  untouched.
- **B. The presence connection *is* the call.** Once a connection to a consenting
  contact is already open, there is nothing left to dial. `/call alice` becomes
  instant, and messages flow on a stream that already exists. This is the larger
  prize by a wide margin — the 7-50 second dial is the single most visible
  friction in murmure, and for anyone you have agreed to see, it disappears.

B costs a real refactor. Today `chat::run` owns one stream for the duration of
one call, and `Update::InCall(Option<String>)` encodes "at most one conversation
at a time". B means N idle connections plus one active conversation, so the call
loop stops owning the stream and starts borrowing one from a pool.

**Recommendation: B, and accept the refactor.** A leaves the thing that actually
makes murmure tiring to use exactly as it is. If B is too much for one pass,
build A first *with B's shape* — a connection pool that happens to carry only
keepalives — rather than a design that has to be thrown away.

> ✅ **B chosen, 2026-08-05.** The refactor is in scope.
>
> An earlier version of the order of work below started with "a pool carrying
> keepalives only" and moved the conversation onto it four steps later. That was
> A wearing B's name. It would have shipped an intermediate state that is
> strictly worse than today — N held circuits *and* a fresh 7-to-50-second dial
> every time somebody speaks — and it would have written the call path twice.
> The keepalive is a detail inside the first step, not a step.

### What it costs

- **N circuits held open**, one per consenting contact who is also running. Fine
  for a handful of contacts. It is not a design for hundreds.
- **A longer-lived circuit is more distinguishable to your guard relay** than
  sporadic ones. This is a real if modest change to the traffic you present.
- **Consent is revocable in the book, not on the network** — the same honest
  limit `/forget` already has. Someone you remove keeps what they already learned.

## 2. The outbox

A message typed to a contact who is not present is sealed and queued on the
sender's disk. When presence says they are back, the queue drains in order.

Storage is the mechanism already in `store.rs`: XChaCha20-Poly1305, random
24-byte nonce, key from `identity::derive_key`, `write_sealed`'s atomic
write-beside-and-rename, `postcard` for the body. **No new dependency, no second
encrypted format to audit.** The contacts book is the same code with different
contents.

Bounded, and bounded loudly: a queue that grows forever is a disk-filling bug
waiting for someone who does not come back. Cap it, and tell the sender when a
message is dropped rather than dropping it quietly.

## 3. Persistent history

This is the one that is *not* obviously an improvement, and it should not be
built on autopilot.

Today murmure keeps nothing. Close it and the conversation is gone — not as a
feature anyone designed, but it is a real property: a machine that is seized,
stolen, or borrowed reveals nothing about what was said. Writing history to disk
deliberately gives that up.

That does not make it wrong. It makes it a decision that belongs to the person
running the program, stated plainly, rather than a default that arrives with an
update.

### Not JSON, not SQLite

Both were on the table. Neither earns its place:

- **JSON** would be plaintext on disk, which is the contacts-book problem again:
  the conversation graph, written down, for whoever picks up the laptop. Sealing
  it puts us back at `store.rs`, and then the JSON is doing nothing.
- **SQLite** buys incremental append and range queries. murmure needs neither —
  a scrollback buffer is read from the end, all at once, at startup. It costs a
  new dependency and, to be encrypted at all, either SQLCipher (a C library that
  is not what arti's `static-sqlite` provides) or per-row encryption, which
  leaves message count, sizes and timing readable in the file.

**The answer is `store.rs` again**, with a cap. A capped log — the last few
thousand messages — sealed as one blob and rewritten on each message is around a
megabyte and a millisecond. `write_sealed` already does it, atomically, and there
is nothing new to review. SQLite becomes the right answer the day someone wants
search or unbounded history, and not before.

### Off by default

Recommended, for the same reason the beta label exists: the honest default for a
program nobody has audited is the one that keeps the least. `/history on` is a
sentence in the interface. A conversation on disk that the user did not ask for
is not recoverable by apology.

## Protocol

`proto::VERSION` goes to 2. Presence frames, a goodbye frame, and the outbox's
delivery ordering all change the shape of `Message`, and postcard encodes a
variant's *position*, not its name — so this is exactly the bump the version
handshake exists to catch. New variants go at the end of the enum.

## Order of work

1. **The pool, carrying the conversation.** ✅ A connection outlives the call
   held over it, and `chat::run` stops owning a stream — it borrows one from the
   pool. This is B.

   Two things were found by building it rather than by planning it:

   - **Nothing could be pooled, because nothing had a name.** An onion service
     is told nothing about its client, so an incoming connection came from
     "they" and could not be filed under a contact. The handshake now makes each
     side sign a challenge with the key its `.onion` address is derived from,
     and `proto::VERSION` went to 2 for it. That was the prerequisite, and it is
     the whole reason step 1 took two commits before the pool itself.
   - **The pool does not dial.** A link enters it because a call already
     happened. That sidesteps the policy problem noted under step 2 entirely —
     there is never a moment where murmure opens a connection nobody consented
     to — and it costs nothing, because the expensive part of a call is the
     first one either way.

   Still open, and moved to step 2 where the consent to spend it exists:
   keepalives and a liveness timeout. Without them a pooled link can go stale
   silently, and `/call alice` is instant into a socket nobody is listening on.

2. **Consent, keepalives, and dialling ahead.** ✅ `/presence <name>` and
   `/presence <name> off`, a four-state agreement stored in the book, a
   `Ping` every 60 s, a peer declared gone after 240 s of silence, and a sweep
   every 60 s that opens a connection to everyone who agreed and reopens the
   ones that dropped.

   Three things settled while building it:

   - **`Pong` is gone.** Both sides ping on their own timer and *any* frame
     proves the far side is alive, so a reply was a second way to learn the same
     thing. `proto::VERSION` went to 3.
   - **A keepalive must never reach a conversation.** The pool starts a call on
     the first frame of an idle link, so a forwarded `Ping` would open a phantom
     call every minute. `link` drops them where they arrive.
   - **The goodbye frame the design asked for was not built.** Closing the
     stream already says it — the reader reports the end, and the far side's
     liveness timer covers the case where the close never arrives. A frame whose
     only job is to be redundant with a close is a frame that can disagree with
     one.

   The state machine is a pure function with no I/O, in `contacts.rs`, so
   "silence is not consent" and "a yes to a question nobody asked changes
   nothing" are tests rather than intentions.

   **One thing the pool got wrong, caught by the person it was built for.** With
   a connection already open, the first frame on it was taken as a call *and
   answered* — no ring, no choice, and the caller's opening line displayed
   before anyone decided to take the call. A held connection is not consent to
   talk over it. So the frame is now held unread until `/answer`, `/decline`
   sends `Message::CallDecline` (`VERSION` 4) so the caller is not left
   guessing, and a second caller during a ring is turned down rather than left
   on silence. `Ended::Declined` exists because "they did not pick up" and "they
   hung up" are different things to be told.
3. **The outbox**, and draining it on a presence transition. ✅ `/tell <name>
   <message>` seals a message under `store.rs` in `outbox.sealed`, and it goes
   out the next time a connection to that contact appears — from a dial
   landing, from them connecting to us, or from a call.

   Three decisions that were not in the design:

   - **A message left is not a call.** It arrives as `Message::Left` and is
     shown where it lands. Making it ring would mean something written last week
     rings the phone, and would let `/decline` throw away what the sender has
     every reason to believe arrived.
   - **Delivery is acknowledged, not assumed.** `Message::Got` is what empties
     the queue; a frame handed to a link is not a message received, and the link
     can die in between. `VERSION` 5.
   - **The duplicate that acknowledgement creates is closed on the receiver.** A
     lost `Got` costs a redelivery, so a contact carries `seen`, the lowest id
     not yet accepted. A redelivery costs one frame and never a second line on
     screen.

   The cap is per contact and reported: 64, oldest dropped, and the sender is
   told how many and how many remain.
4. **History**, opt-in, last, and declinable. Still undecided, and still the one
   that should not be built on autopilot — see above.

Step 1 is what makes murmure stop feeling slow — the second call to someone is
free. Steps 1-3 together deliver the actual prize: a message sent to someone who
is out arrives when they come back. Step 4 is a separate decision.

## Open questions

- Keepalive interval and timeout multiplier — has to be measured against real Tor
  latency, not guessed.
- What the interface shows. A contact list with dots is the obvious thing and it
  is also a screen that says, continuously, who you talk to. It should probably
  not be on by default either.
- Whether an outbox message that expires is deleted or surfaced. Silently
  dropping a message is the failure mode users never forgive.

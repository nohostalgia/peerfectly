# roster-sync

How two nodes reconcile their rosters over an authenticated session.

Five earlier changes built a roster that decides who is in a network, an identity
that gives a node its keys, and a transport that turns *"this peer holds a key the
roster knows"* into a session. None of them moved a signed operation from one
node to another. Every test until now handed operations to a second roster by
calling a function.

DESIGN.md §4.7 is the whole distribution model, and it is one paragraph:

> No privileged channel. Whenever two nodes connect, they exchange the ids of the
> operations they know and pass each other what is missing. [...] a node off for
> a month catches up at its first connection with anyone, and revocations spread
> by contagion.

Contagion is what makes the central property hold. A revocation is worth nothing
while it sits on the admin's phone.

`FORMAT.md` is the wire specification — the document a second implementation
works from. This one is the reasoning.

## What it decides, and what it does not

It decides **which bytes are sent** and **how many are accepted from a given
peer**.

It decides nothing else. Every operation and snapshot received goes through
`Roster::offer_bytes` or `Roster::offer_snapshot`, which is the only authority on
what is true. A sync layer that decided validity, membership or authority would
be a second authority — consulted far more often than the signed log, and
disagreeing with it under exactly the conditions that matter. A scan test asserts
there is no path into derived state that skips admission.

## The exchange

Both sides send what they hold the moment a session opens, without waiting to be
asked, and each answers with what the other's offer did not name.

**The full id set, not heads plus a walk-back.** A roster holds at most 4096
operations, so the largest possible offer is 139 312 bytes against a 262 144-byte
payload bound. The bound roster already enforces makes the naive protocol viable,
and the naive protocol has no resumption state — nowhere to stall. A stalled
reconciliation is a revocation that did not arrive.

A Bloom filter or an IBLT would be much smaller and is the standard answer at
scale. It also introduces false positives, which here means *silently failing to
send an operation the peer lacks*. A probabilistic protocol whose failure mode is
a missing revocation is the wrong trade at this size.

**Symmetric.** There is no server. §4.7's *"no privileged channel"* is a
security property rather than a convenience: a protocol where one side asks and
the other answers has a role in it that a rendezvous or a relay would eventually
be given.

**Push carries the operation, not a notification.** An operation admitted locally
goes whole to every open session except the one it came from. Announcing would
cost a round trip on every operation the peer lacks, and a revocation is exactly
where that round trip is expensive. Forwarding only what *newly* entered the
verified set, and never back to the sender, is what makes a cycle of nodes
terminate.

## Two policies, and the attacks behind them

### Refuse at the door, never evict

Pending entries — operations whose parents have not arrived — are **unverified by
necessity**: the author's key is resolved from state derived from the very
ancestors that are missing. The set is bounded at 256.

The attack roster's `FORMAT.md` §19 names: a peer sends 256 well-formed orphans,
the set fills, and the `revoke_device` naming that peer arrives to find nowhere to
wait. **It fills the pending set to block its own revocation.** Reserving space
for revocations does not help — an attacker labels junk as one.

So each peer **device** is capped at 32 entries, an eighth of the bound, and at
least eight distinct devices can always make progress. Keyed on the device rather
than the session: sessions are cheap to open, and a per-session quota is renewed
by reconnecting, which is the same as having none. This is exactly what
`transport-session` established the authenticated identity for, and what §19 said
roster could not do alone.

Over quota, the operation is refused *before the roster sees it*. Nothing already
pending is displaced.

The asymmetry is the point. A refused operation stays with its sender, which
offers it again — after supplying the parents it was waiting for, or at the next
reconciliation. An evicted one is gone from a node that already reported
accepting it, and the entry displaced might have been the revocation. This is
admission control, not cache management, which also removes the question of
*what* to evict — a question with no safe answer.

Dividing the bound by the number of connected peers is fairer under load and lets
a lone peer use everything. But the quota then shrinks as peers connect, so either
existing entries are evicted, or they exceed their new quota and the hole reopens.
A guaranteed floor plus a shared pool has the same flaw: the floor is not
guaranteed without eviction, and carving it out permanently is the fixed cap with
extra steps.

### Throttle, never disconnect

A refusal costs the sender a quota slot. Nothing else. **Sync closes no
sessions**, and a scan test asserts it.

The reason is the one that is easy to miss. A node that punished a peer for the
*content* it relays can be aimed: an attacker forges one operation, gets an honest
node to relay it, and honest nodes drop each other. One operation, no key
required, and a node is removed from everyone's view — cheaper than attacking the
roster. The peer that relays an operation is not its author, and a node cannot
tell the two apart from the operation alone.

Membership stays the only ground for ending a session, and that decision already
lives in the transport, derived from the signed log.

The cost is real and accepted: a hostile member can waste bandwidth for the life
of a session. It is a *member* — someone an admin admitted — and the answer to a
hostile member is to revoke it, which closes its sessions through the mechanism
that already exists.

### The rule that would make a stricter policy safe

A node relays only from its **verified** set, never from pending. Beyond
amplification, this preserves attribution: an operation arriving with a bad
signature was produced or corrupted by the peer that sent it, not passed along in
good faith. That property is what would make content-based penalties safe to
introduce later. It is not used for that here — but destroying it now would
foreclose the option.

## Refusals are reported, never swallowed

Two kinds, kept distinguishable:

| Refusal | Says |
|---|---|
| `OverQuota` | something about the **sender**, nothing about the operation |
| `Malformed`, `OfferTooLarge`, `CountExceedsPayload`, `SnapshotWouldRegress`, `Roster(..)` | something about the **operation**, nothing about the sender |

An operator reading a node needs this to tell a chatty peer from a hostile one.
And a node that quietly dropped what it would not accept would also quietly drop
the evidence that an author equivocated, which `equivocation-detection` will need.

## The syncer owns no runtime

`Syncer` is synchronous: messages in, messages out. It spawns nothing.

`windows-daemon` will decide the concurrency shape, and it knows things this crate
does not — how many peers, on what schedule, under what power constraints. A
crate that spawned its own tasks would have to be worked around. It also makes
partition, interleaving and interruption expressible as tests that call functions
in a chosen order rather than as races.

The tests run it over both `MemoryTransport` and `DirectTransport`. Those two are
behaviourally interchangeable by construction — one suite, two independent
internals — so a reconciliation working over both works over anything satisfying
that suite, which `transport-iroh` must.

## What is tested

- Convergence over generated histories, and over genuine **branches**: two nodes
  admitting concurrent operations while apart, then reconciling.
- That the outcome does not depend on which side dialled.
- That no sequence of offers from one peer, however hostile, prevents a second
  peer's revocation from landing — the quota guarantee stated over arbitrary
  traffic rather than one chosen flood.
- That push terminates on a ring, with each node receiving an operation a bounded
  number of times.
- That an interrupted reconciliation loses nothing.

## Deliberately elsewhere

| Deferred | To | Why |
|---|---|---|
| Dialling, addressing, NAT, relays | `transport-iroh` | needs a real-world NAT test; this crate needs no network at all |
| The relay path that lets two nodes meet | `rendezvous-service` | signed records with a monotone sequence, a separate concern |
| Multicast announcement on a LAN | `local-discovery` | |
| Detecting that an author equivocated across peers | `equivocation-detection` | this crate must preserve the evidence, not act on it |
| Timers, scheduling, the concurrency shape | `windows-daemon` | it will know the session lifetimes and power constraints |

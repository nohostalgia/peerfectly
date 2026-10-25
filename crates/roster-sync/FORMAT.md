# The reconciliation format

What crosses a session between two nodes, byte for byte, and the rules a second
implementation must follow to interoperate. Roster's `FORMAT.md` is the
companion document: it defines the operations and snapshots this protocol
carries. Nothing here re-specifies those.

## 1. Scope

This document covers the messages of reconciliation and the accounting a
receiver must apply to them. It does not cover dialling, addressing, NAT
traversal or relays — see `crates/transport/README.md` — nor the validity of what
is carried, which is entirely roster's.

## 2. The trust model, stated first

**A session is already authenticated.** Before any message here is sent, the peer
has proved possession of a transport key the roster names, and that its device is
not revoked. The identity is a `DeviceId` and it is fixed for the session's life.

**Messages are not signed.** Signing the envelope would prove the same thing the
session already proved, and a second signing context is a second place to get
domain separation wrong. What is *inside* is signed: operations and snapshots
carry their own signatures and are verified over the exact bytes received.

**Nothing is trusted because of where it came from.** Every operation and every
snapshot received goes through the roster's admission path. A receiver that
skipped verification for a peer it liked would have made itself an authority.

## 3. Encoding

Canonical CBOR, under roster's rules and using roster's encoder — not a second
one. Restated for a reimplementer:

- definite lengths only; no indefinite-length items;
- minimal integer widths;
- map keys in **length-first** order: shorter keys precede longer ones, and keys
  of equal length compare bytewise. This is *not* alphabetical ordering;
- every key in the schema present exactly once, no key outside it;
- no trailing bytes after the top-level item.

Rejection is always an error returned to the caller. Nothing is reordered,
deduplicated or repaired. Two byte strings that differ must never decode to the
same message.

## 4. The envelope

Every message is a two-key map.

| Key | Type | Meaning |
|---|---|---|
| `body` | byte string | the encoded message body |
| `kind` | unsigned | which message (§5–§7) |

Both keys are four bytes long, so length-first ordering falls through to a byte
comparison: **`body` precedes `kind`**.

`kind` values:

| `kind` | Message | § |
|---|---|---|
| 1 | offer | 5 |
| 2 | transfer | 6 |
| 3 | root (a signed snapshot) | 7 |
| 4 | attestation | 16 |
| 5 | digest | 16 |
| 6 | batch pieces | 17 |
| 7 | extended offer: an offer naming its root, or batches held in part | 18 |
| 8 | state request | 19 |
| 9 | state | 19 |

**An unrecognised kind is refused, never skipped** — the message that cannot be
parsed might be the one carrying a revocation. The kinds that existed keep their
numbers.

The body is nested as a byte string rather than inlined. That gives it an
explicit length, so a truncated message is a decoding failure rather than a
partial parse.

## 5. Offer (`kind` = 1)

What the sender holds.

| Key | Type | Meaning |
|---|---|---|
| `ids` | array of 32-byte strings | every operation the sender holds **verified** |
| `snap` | bool | whether the sender holds a snapshot |
| `snapseq` | unsigned | that snapshot's sequence, or `0` |

Key lengths 3, 4, 7 — strictly increasing, so canonical.

**`snapseq` MUST be 0 when `snap` is false.** Otherwise two encodings would mean
the same offer, and the format would not be canonical.

**`ids` names only the verified set.** Operations held pending are never offered
and never relayed (§9). A batch's header waiting for its pieces is verified, and
is named (§17).

An offer that names the root it holds, or batches it holds in part, is sent as
kind 7 instead (§18). An offer with neither is kind 1, and encodes to the bytes
it always did.

### Size

The full id set, not heads plus a walk-back. A roster holds at most
`MAX_OPERATIONS` = 4096 operations, so the largest legal offer is bounded:

| | bytes |
|---|---|
| empty offer | 34 |
| per operation id | ~34 |
| largest legal offer (4096 ids) | **139 312** |
| transport payload bound | 262 144 |

It fits in one payload with room to spare, which is why reconciliation needs no
fragmenting and therefore no resumption protocol. A resumption protocol is
somewhere to stall, and a stalled reconciliation is a revocation that did not
arrive.

A receiver MUST refuse an offer declaring more than `MAX_OPERATIONS` ids, on the
declared count alone.

## 6. Transfer (`kind` = 2)

Operations the peer's offer did not name.

| Key | Type | Meaning |
|---|---|---|
| `ops` | array of byte strings | operations, each as its exact signed bytes |

Each element MUST be at most `MAX_OPERATION_SIZE` = 8192 bytes. The array MUST
name at most `MAX_OPERATIONS` entries.

**The bytes MUST be the exact bytes the sender verified.** Re-encoding a decoded
operation and sending that risks the receiver computing a different id for the
same operation, and the id is what the whole graph is addressed by.

## 7. Snapshot (`kind` = 3)

| Key | Type | Meaning |
|---|---|---|
| `snap` | byte string | a signed root, as its exact bytes |

At most `MAX_SNAPSHOT_SIZE` = 65 536 bytes. A root commits to the state by its
Merkle root and carries no state (roster `FORMAT.md` §22), so it is the same size
for any network.

**A root newly adopted is passed on to every other session at once**, a light
member's included: it is all a light member is given. One already held, or
lighter than the one held, is not passed on, which is what ends a cycle.

## 8. The exchange

On session establishment **both sides send a digest immediately** (§16), without
waiting to be asked. Where the digests agree that is the whole exchange. Where
they differ, each sends its offer and answers the other's with what it did not
name.

```
A ──── digest ───▶ B
A ◀─── digest ──── B      (equal: done)
A ──── offer ────▶ B
A ◀─── offer ──── B
A ◀─── root? ──── B       (only if B's root is heavier)
A ◀── transfer ── B       (what A's offer did not name)
A ◀── pieces* ─── B       (what A lacks of the batches B holds)
```

**Symmetric.** There is no server. A node that has just joined and the node that
founded the network run the same exchange. §4.7 says there is no privileged
channel, and a protocol where one side asks and the other answers has a
privileged role in it — one a relay would eventually be given.

**Terminating by structure, not by negotiation.** Each side sends one offer and
one answer. There is no state machine to be left waiting in, and an interrupted
exchange loses nothing: both sides keep what they held, and reconciling again
completes what was left.

**Snapshot before transfer.** A node far enough behind cannot place operations
that build on a foundation it does not have, and would hold every one of them
pending — spending its quota to learn nothing.

**A sender sends its root only where it is heavier than the peer's**: the higher
generation, then the greater root hash — the rule roster keeps (roster
`FORMAT.md` §25). The generation is `snapseq`; the hash is the extended offer's
`root` (§18). A peer whose offer names no root is sent the root held, whatever
its generation. Two siblings of one generation therefore reach each other, and
every node converges on the heavier.

## 9. Relay only from the verified set

A node MUST offer and transfer only operations in its verified set. It MUST NOT
forward an operation it holds pending.

Pending operations have passed only self-contained checks — bounded size,
canonical encoding, id matching the bytes. Forwarding them would make every node
an amplifier for content it has not checked, would let one peer's flood consume
quota on nodes it never contacted, and would destroy attribution: a receiver
seeing a bad signature could no longer tell whether the sender produced it or
merely passed it on.

## 10. Push

When an operation is admitted locally — authored here or received from a peer —
it is sent to every open session **except the one it arrived on**. A light
member's session is the exception (§20): operations never cross it.

- The operation is sent **whole**, not announced. Announcing costs a round trip
  on every operation the peer lacks, and a revocation is exactly the case where
  the round trip is the expensive part.
- Only operations that **newly entered the verified set** are forwarded. One
  already held produces nothing to forward, which is what makes a cycle of nodes
  terminate rather than echo.

Together these bound traffic by edges rather than by paths.

## 11. The per-peer quota

The rule this protocol exists to make possible, and the one roster cannot enforce
alone.

**A receiver MUST cap the pending entries attributable to any one peer device at
`MAX_PENDING_OPERATIONS / 8` = 32.**

### Why

Pending entries are unverified by necessity: the author's key is resolved from
state derived from the very ancestors that are missing. The set is bounded at
256. Without per-peer accounting one peer fills it, and the `revoke_device`
naming that peer arrives to find nowhere to wait. Reserving space for revocations
does not help — an attacker labels junk as one.

An eighth means at least eight distinct devices can hold pending entries
whatever any other peer does.

### The rules

1. **Keyed on the authenticated device, never the session.** Sessions are cheap
   to open; a per-session quota is renewed by reconnecting, which is the same as
   having none.
2. **Decided before the roster sees the operation.** A receiver determines
   whether an operation would be held — by checking whether its parents are
   present — and refuses it if the sender is at its cap.
3. **Refuse at the door; never evict.** Nothing already pending may be displaced
   to make room. A refused operation stays with its sender, which offers it again
   later; the refusal is recoverable. An evicted one is gone from a node that has
   already reported accepting it, and the entry displaced might have been the
   revocation.
4. **A charge is released when the roster stops holding it pending** — because it
   was integrated or refused. This MUST be derived from the roster's own view of
   what is pending, not from a separately maintained counter, which would drift.
5. **The same operation is charged once.** Re-offering something already pending
   is not billed again.

## 12. Refusals

A refusal MUST be reported, never swallowed. A node that quietly dropped what it
would not accept would also quietly drop the evidence that an author had
equivocated, which `equivocation-detection` will need.

Refusals fall into two kinds, and they MUST be distinguishable:

| Kind | Says |
|---|---|
| over quota; operations from a light member | something about the **sender**, nothing about the operation |
| malformed, oversized, bad count, roster refusal | something about the **operation**, nothing about the sender |

An operator reading a node's log needs this distinction to tell a chatty peer
from a hostile one.

## 13. Misbehaviour

**A node MUST NOT close a session, or otherwise penalise a peer, on account of
the content of an operation that peer sent.** A refusal costs the sender the
opportunity it consumed and nothing more.

A node that punished a peer for content can be aimed. An attacker forges one
operation, gets an honest node to relay it, and honest nodes drop each other:
one operation, no key required, and a node is removed from everyone's view —
cheaper than attacking the roster.

Membership is the only ground on which a session ends, and that decision belongs
to the transport, derived from the signed log. A second one here would mean two
components deciding who a node talks to, disagreeing under load.

The accepted cost: a hostile member can waste bandwidth for the life of a
session. It is a member — someone an admin admitted — and the answer to a hostile
member is to revoke it, which closes its sessions through the mechanism that
already exists.

## 14. What a receiver must not do

Collected, because each is a way to be subtly wrong:

- MUST NOT allocate to a declared count before reading the bytes backing it.
- MUST NOT normalize a non-canonical encoding; refuse it.
- MUST NOT skip a message kind it does not recognise; refuse it.
- MUST NOT re-encode an operation it relays.
- MUST NOT evict a pending entry.
- MUST NOT relay a pending operation.
- MUST NOT close a session over content.
- MUST NOT decide validity, membership or authority. That is the roster's,
  entirely.

## 15. Deliberately absent

| Not here | Where |
|---|---|
| Dialling, addressing, NAT, relays | `transport`, `transport-convesso` |
| How two nodes meet: announcements on a LAN, and the relay elsewhere | `local-discovery`, `transport-convesso` |
| Detecting that an author equivocated across peers | `equivocation-detection` |
| Timers, scheduling, the concurrency shape | `windows-daemon` |

## 16. Digest (`kind` = 5) and attestation (`kind` = 4)

A digest is a hash of what the sender would offer:

| Key | Type | Meaning |
|---|---|---|
| `hash` | 32-byte string | the digest |

Computed under the BLAKE3 context `"peerfectly roster digest v1"` over, in order:
a flag and the snapshot's generation (`0` alone, or `1` then the generation as a
big-endian `u64`); the count of operation ids as a `u64`; the ids, sorted
bytewise and without repeats; then, **only where present**, the batches held in
part — their count, then for each, sorted by batch, the batch id, its piece count
as a `u64` and its bitmap (§18) — and the root held, after the four bytes
`root`. With neither, the digest is the one it always was.

Recomputed from the set rather than kept incrementally: a hash kept as a sum or
exclusive-or of per-operation hashes is linear, and a chosen set could cancel out.

An attestation carries one signed attestation as `att`, at most
`MAX_ATTESTATION_SIZE` bytes. It is passed on when accepted as newer, and only
then.

## 17. Batch pieces (`kind` = 6)

| Key | Type | Meaning |
|---|---|---|
| `pieces` | array of byte strings | batch pieces, each as its exact bytes |

At most `MAX_PIECES_PER_MESSAGE` = 24 pieces, each at most 8192 bytes, so one
message fits a payload; a batch's pieces cross in as many messages as they need.
Each piece proves on its own against its header (roster `FORMAT.md` §37).

- **A piece follows its header.** A sender sends a peer the header in its
  transfer, ahead of the pieces; a receiver refuses a piece whose header it does
  not hold.
- **Passed on once checked, before the batch is whole.** A piece newly taken is
  forwarded like an operation newly admitted (§10), and kept; one already held is
  neither.
- **Only what is missing.** Of each batch the sender holds, whole or in part, it
  sends: nothing where the peer's offer names the batch and does not hold it in
  part (the peer holds it whole); the pieces the peer's bitmap lacks where it
  holds it in part; every piece where the offer does not name the batch at all.
- A batch held whole is sent as the canonical cut of its entries, which is the
  bytes its author sent.

## 18. Extended offer (`kind` = 7)

An offer that also names the root the sender holds, or the batches it holds in
part.

| Key | Type | Meaning |
|---|---|---|
| `ids` | array of 32-byte strings | as §5 |
| `root` | byte string | the root held, 32 bytes, or empty |
| `snap` | bool | as §5 |
| `partial` | array of holdings | batches held in part, sorted by batch |
| `snapseq` | unsigned | as §5 |

Key order: `ids` (3); `root`, `snap` (4, and `r` before `s`); `partial`,
`snapseq` (7, and `p` before `s`).

A holding is `{ "held": bstr, "batch": bstr(32), "pieces": uint }`: the batch, how
many pieces its header declares, and one bit per piece — the lowest bit of the
first byte for piece 0 — set where the piece is held. The bitmap is exactly as
many bytes as the pieces need, with every bit past the last piece clear.

One spelling: kind 7 with an empty `root` and no holding is refused (that offer
is kind 1); a `root` with `snap` false is refused; a holding with a stray bit, a
wrong length, no pieces or more than `MAX_BATCH_ENTRIES`, or holdings out of
order, is refused. At most `MAX_PARTIAL_BATCHES` = 8 holdings — as many batches as
a roster holds incomplete — so the largest extended offer still fits a payload.

## 19. State request (`kind` = 8) and state (`kind` = 9)

How a full member that holds nothing gets in where its peers have compacted: the
operations beneath their base are gone from every one of them.

| Message | Key | Type | Meaning |
|---|---|---|---|
| request | `root` | 32-byte string | the root the state must make |
| state | `last` | bool | whether these are the last pieces |
| state | `root` | 32-byte string | the root they make |
| state | `pieces` | array of byte strings | state pieces (roster `FORMAT.md` §36) |

At most `MAX_STATE_PIECES_PER_MESSAGE` = 3 pieces per message, each at most
`MAX_STATE_PIECE_SIZE` = 65 536 bytes.

1. A node whose graph is empty, given a root it cannot check, asks the peer that
   sent it for the state behind it. One request at a time.
2. A peer holding that state — its current state, its base, or the state its held
   root was checked against — answers with the operations the root's heads name,
   as a transfer, then the state in pieces. A peer holding none sends nothing.
3. The asker takes pieces only from the peer it asked, for the root it asked, and
   believes nothing until the last is in: the state is taken only if its leaves
   make the root, and if a piece is refused the whole transfer is dropped.
4. With the state whole, the asker rests on it as on a base it compacted to, with
   the heads beside it, and keeps both. Reconciliation then brings the window.

At most `MAX_STATE_DEVICES` = 4 194 304 devices are taken: what a lying sender
could make a node hold before the root shows the lie.

A node that is behind but not empty is not served by this exchange.

## 20. Light members

A light member holds one root and its own proof, and none of the graph. A full
member reads which of its peers are light from the roster — the mode in each
device's settings — and:

- **sends it** roots and attestations, and in place of a digest, which would
  invite an offer, the root it holds;
- **never sends it** an offer, a transfer, pieces, or a state request or state;
- **refuses from it**, unread, an offer, a transfer, pieces, or a state request or
  state. The refusal is about the sender (§12), and the session stays open (§13).

Every message a full member sends on a roster channel passes through this rule,
so it holds on every path that produces one: an answer, a push, a greeting, a
root just published.

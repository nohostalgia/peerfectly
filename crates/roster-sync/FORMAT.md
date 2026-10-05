# The reconciliation format

What crosses a session between two nodes, byte for byte, and the rules a second
implementation must follow to interoperate. Roster's `FORMAT.md` is the
companion document: it defines the operations and snapshots this protocol
carries. Nothing here re-specifies those.

## 1. Scope

This document covers the three messages of reconciliation and the accounting a
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

`kind` values: `1` offer, `2` transfer, `3` snapshot. **An unrecognised kind is
refused, never skipped** — the message that cannot be parsed might be the one
carrying a revocation.

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
and never relayed (§9).

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
| `snap` | byte string | a signed snapshot, as its exact bytes |

At most `MAX_SNAPSHOT_SIZE` = 65 536 bytes.

## 8. The exchange

On session establishment **both sides send an offer immediately**, without
waiting to be asked. Each then answers with what the other's offer did not name.

```
A ──── offer ────▶ B
A ◀─── offer ──── B
A ◀─ snapshot? ── B      (only if B's sequence is higher)
A ◀── transfer ── B      (what A's offer did not name)
A ── snapshot? ─▶ B
A ─── transfer ─▶ B
```

**Symmetric.** There is no server. A node that has just joined and the node that
founded the network run the same exchange. §4.7 says there is no privileged
channel, and a protocol where one side asks and the other answers has a
privileged role in it — one a rendezvous or relay would eventually be given.

**Terminating by structure, not by negotiation.** Each side sends one offer and
one answer. There is no state machine to be left waiting in, and an interrupted
exchange loses nothing: both sides keep what they held, and reconciling again
completes what was left.

**Snapshot before transfer.** A node far enough behind cannot place operations
that build on a foundation it does not have, and would hold every one of them
pending — spending its quota to learn nothing.

**A sender MUST NOT send a snapshot whose sequence is not higher than the
sequence in the peer's offer.** This is what `snapseq` is for: the regression is
visible before any snapshot bytes are sent.

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
it is sent to every open session **except the one it arrived on**.

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
| over quota | something about the **sender**, nothing about the operation |
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
| Dialling, addressing, NAT, relays | `transport`, `transport-iroh` |
| The relay path that lets two nodes meet | `rendezvous-service` |
| Multicast announcement on a LAN | `local-discovery` |
| Detecting that an author equivocated across peers | `equivocation-detection` |
| Timers, scheduling, the concurrency shape | `windows-daemon` |

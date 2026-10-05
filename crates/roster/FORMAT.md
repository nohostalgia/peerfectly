# Roster wire format, version `roster/v1`

This document is the specification a second implementation works from. If this
file and the Rust code disagree, that is a bug in one of them; the test-vector
corpus in [`vectors/`](vectors/) is the tie-breaker, because it is what both
sides actually have to satisfy.

The format's whole purpose is that two independent implementations agree, byte
for byte, on which operations exist and what they say. A disagreement is not a
serialization nuisance — it forks the log, and a fork can silently drop a
revocation.

## 1. Canonical CBOR

Encoding is RFC 8949 §4.2.1 core deterministic encoding, narrowed:

- **Definite lengths only.** An indefinite-length marker (additional info 31)
  is an error. So are the reserved values 28–30.
- **Minimal integer width.** `5` encodes as `05` and in no other way. A value
  that fits in the header byte must use it; a value below 256 must use the
  one-byte form; and so on.
- **Map keys in canonical order.** Keys are compared as their *encoded* bytes.
  Every key in this format is a text string shorter than 24 bytes, so its
  header is one byte carrying the length, and the comparison reduces to
  `(length, contents)`.

  **Length dominates.** This is not alphabetical order, and it is the single
  easiest rule to get wrong: the core map begins `ts`, `alg`, `body`, not
  `alg`, `author`, `body`. `vectors/negative.json` contains a vector named for
  alphabetical ordering precisely to catch an implementation that sorts the
  obvious way.
- **No unknown keys, no repeated keys, no missing keys.** Every map has exactly
  the fields its schema names, in schema order. The optional keys are `ipv4`
  and `leaving` in `NetworkParams`; see §7.
- **No trailing bytes** after the top-level item.

A decoder must *reject* input that breaks any of these, with an error. It must
never reorder, deduplicate, or otherwise repair input. Two byte strings that
differ must never decode to the same value, or one operation acquires two ids.

## 2. Operation

```text
Operation = { "id": bstr(32), "sig": bstr(64), "core": bstr }
```

Key order: `id`, `sig`, `core` (lengths 2, 3, 4).

`core` is an embedded byte string holding the canonical encoding of the core
map, not a nested map. This is deliberate: verification must run over the exact
bytes received, and holding the signed region as a byte string means a decoder
can hand those bytes back as a slice of its input rather than re-encoding a
parsed structure. An implementation that re-serializes before verifying will
work until its encoder differs from someone else's by one byte, and then fail
in a way that looks like a crypto bug.

## 3. Core

```text
Core = { "ts": uint, "alg": tstr, "body": bstr, "type": tstr,
         "author": bstr(32), "network": bstr(32), "parents": [ bstr(32) ... ] }
```

Key order: `ts`, `alg`, `body`, `type`, `author`, `network`, `parents`.

| Field | Meaning |
|---|---|
| `ts` | Milliseconds since the Unix epoch, unsigned 64-bit. **Display only** — see §8 |
| `alg` | `"ed25519"` or `"p256"`. Inside the signed bytes, so it cannot be swapped after signing |
| `body` | Embedded canonical CBOR of the body, decoded only once `type` is known |
| `type` | One of the seven names in §5 |
| `author` | The key id (§4) of the key that produced `sig` |
| `network` | The network id. Present so a signature cannot be replayed into another network |
| `parents` | Ids of operations the author knew when authoring this one. At most 32 |

`body` is a byte string rather than an inline map because canonical order puts
`body` before `type`: a body decoded in place would have to be parsed before the
schema governing it was known.

## 4. Identifiers

Every identifier is an untruncated 256-bit BLAKE3 digest. None is ever
shortened, and none is ever a signature.

| Identifier | Derivation |
|---|---|
| Operation id | `blake3(core_bytes)` — the same bytes that are signed, excluding `id` and `sig` |
| Key id | `blake3(public_key_value)` |
| Device id | The key id of the device's identifying signing key (§6) |
| Network id | The operation id of the `create_network` that founded it (see §13) |

**The id excludes the signature.** ECDSA need not be deterministic — the root
key lives in a phone's secure enclave, which signs with a random nonce — so the
same core signed twice can yield two different signatures. Were `sig` hashed,
one logical operation would enter the DAG twice under two ids, and re-signing a
revocation would disguise it as a different operation.

A decoder recomputes the id from the received bytes and rejects an operation
whose stated id disagrees. The id is therefore redundant on the wire; it costs
32 bytes and converts a whole class of encoder bug into a loud rejection.

## 5. Operation types and bodies

The set is closed at seven. Adding an eighth means deciding how it merges
against all seven existing types, so it is a change to the roster's semantics,
not an additive one. An unrecognized `type` is an error — never a skip, because
the operation you cannot read might be a revocation.

| `type` | Body |
|---|---|
| `create_network` | `{ "device": DeviceSpec, "params": NetworkParams }` |
| `add_device` | A `DeviceSpec` map directly |
| `revoke_device` | `{ "device": bstr(32), "reason": tstr }` |
| `promote` | `{ "device": bstr(32), "founder": bool }` |
| `demote` | `{ "device": bstr(32) }` |
| `rename` | `{ "name": tstr, "device": bstr(32) }` |
| `set_network` | A `NetworkParams` map directly |

Note `rename`'s key order: `name` (4) precedes `device` (6), by length.

A body that is well formed but belongs to a different type is reported as a
body-schema error rather than as whatever structural complaint the mismatch
happened to trigger first.

### DeviceSpec

```text
DeviceSpec = { "keys": [ KeyEntry ... ], "name": tstr, "role": tstr,
               "founder": bool, "capabilities": [ tstr ... ] }
```

`role` is `"admin"` or `"member"`. `founder` is required, never omitted.

### KeyEntry

```text
KeyEntry = { "alg": tstr, "value": bstr, "purpose": tstr }
```

`purpose` is `"signing"` or `"transport"`.

### DeviceRecord

Derived state, not carried in an operation body, but its encoding is pinned
here so later capabilities do not invent one:

```text
DeviceRecord = { "id": bstr(32), "keys": [...], "name": tstr, "role": tstr,
                 "founder": bool, "added_by": bstr(32), "capabilities": [...] }
```

A `DeviceSpec` in a body carries neither `id` nor `added_by`: both are derived,
and `added_by` would be the enclosing operation's own id, which cannot be known
before that operation is encoded.

### NetworkParams

```text
NetworkParams = {
  "ula": bstr,
  ? "ipv4": bstr(5),
  "relay": [] / [tstr],
  "suffix": tstr,
  ? "leaving": Leaving,
  "relay_cert": [] / [bstr],
  "rendezvous": [] / [tstr],
  "snapshot_window": uint
}

Leaving = {
  "relay": tstr,
  "until": uint,
  "relay_cert": [] / [bstr]
}
```

Key order is length-first, so `relay` (5 bytes) sits between `ula` (3) and
`suffix` (6), and the two ten-byte keys between `suffix` and `snapshot_window`
(15). `relay_cert` precedes `rendezvous` because equal lengths are settled by
bytes and `l` precedes `n`. Alphabetical order would put `relay_cert` next to
`relay` and produce bytes a conforming decoder refuses.

`ipv4` is the IPv4 range the network's devices derive their IPv4 addresses in:
four address bytes, then the prefix length. It is one of the **two optional
keys** in the format, with `leaving` below. It sorts after `ula` (three bytes against its four) and before
`relay` (five). A map without it has six entries and is byte for byte what
parameters were before the key existed; a map with it has seven. Absence has
exactly one spelling, the key left out: an empty byte string is refused
(`invalid_value`), as is any other length, a repeated key (`duplicate_key`), and
a range with host bits set, a prefix length outside 8 to 28, or a range not
wholly inside `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`
or `198.18.0.0/15` (all `invalid_value`). Parameters without it use
`100.64.0.0/10`.

Software predating the key refuses a seven-entry map, so a network that sets a
range cannot be read by it. A network that does not is unaffected.

`leaving` is the relay a network is **moving away from**, and when the move
ends. A change of relay is a transition rather than a switch: devices learn of a
change by synchronising, they synchronise through the relay, and a device
switched off during the change wakes knowing only the old one. Until `until` the
devices that already moved stay reachable on the relay being left too.

It sorts after `suffix` (six bytes against its seven) and before the ten-byte
keys. It is **one key holding all three fields**, so a relay being left without
an end, or an end without a relay, is not something the encoding can say — a
`Leaving` map missing a field is `missing_field`. Its own keys are ordered as
every map's are: `relay` before `until` (equal lengths, `r` before `u`), then
`relay_cert`.

`until` is milliseconds since the epoch, the clock operations are dated by.
Past it the relay being left is no longer used, with nothing signed to say so.
`relay_cert` is an array of nothing or one, as the relay's own is.

`leaving` is refused (`invalid_value`) where it cannot mean anything: when the
parameters name no relay to move to, when it names the relay itself, and when
its relay is empty or its certificate empty. Parameters without it are byte for
byte what they were before the key existed — the rule `ipv4` set.

`snapshot_window` is in seconds. The suffix is a roster parameter rather than a
compile-time constant, so changing it does not require replacing every client.

`ula` is the network's overlay prefix: exactly **eight bytes**, the first of
which is `0xfd` — a `/64` inside the locally assigned unique local range of
RFC 4193. Any other first byte is `invalid_value` ("prefix not unique local"),
any other length `invalid_value` ("prefix not a /64"). Both are refused at
decoding, so no node can be told to route a prefix outside that range: a prefix
in global space would send real hosts into the tunnel, and one shorter than a
`/64` would claim more unique local space than the network uses — including the
prefixes home routers assign themselves. `fc00::/8`, reserved for a centrally
assigned range that was never defined, is refused with everything else.

`suffix` is the name suffix the network claims, and it is bounded for the same
reason: on each member's machine it becomes a rule sending a whole branch of the
DNS to that network's resolver.

```text
suffix = label *("." label) "." "internal"
label  = 1*63( %x61-7A / DIGIT / "-" )   ; not beginning or ending with "-"
       ; at most 64 bytes in all
```

`internal` is the top-level name reserved for private use, so a rule for a name
beneath it cannot take a public name away from anybody. There is exactly one
spelling: uppercase, a trailing dot and an empty label are refused rather than
normalised, because two spellings of one suffix would be two parameter values.
At least one label is required — `internal` alone would capture every private
name on the machine — and the label directly under `internal` may not be
`docker`, `google`, `ec2` or `compute`, which widely deployed software already
answers for on the machines it runs on. Each refusal is `invalid_value` naming
the rule it broke, except a suffix over 64 bytes, which is `limit_exceeded`.

The shared vector corpus was regenerated when these two rules landed: every
operation id in it moved, because the parameters in every genesis did.

`relay` is the address of the relay this network uses, as an array of **zero or
one** text strings. The array is what gives absence exactly one encoding: an
empty array is a network with no relay — one confined to a LAN, or one still
being set up — and an empty *string* inside the array is refused, so no byte
sequence means "a relay whose address is nothing". Two addresses are refused as
well: a network with two answers to one question is not a network with a relay.

`relay_cert` is the certificate that relay presents, DER, as an array of zero or
one byte strings — absence encoded the same way as for `relay`, and an empty byte
string refused for the same reason.

It is here because the relay is the one service in this design a node speaks to
before it has authenticated anything, and the ordinary answer to "is this the
right server" — a public certificate authority — is exactly the third party this
network is built to do without. A network that pins its relay trusts the
certificate its own signed parameters name and nothing else: not a public
authority, and so not anyone who can persuade one to issue a certificate for that
address. It also makes a relay you run yourself, on an address with no domain
name, an ordinary arrangement rather than a workaround.

A pin is optional. A network whose relay presents a publicly signed certificate
may leave it empty and be verified the usual way.

`rendezvous` is where devices publish the addresses they believe they can be
reached at, and where they look for a peer's. Zero or one text strings, absence
encoded as for `relay`, empty refused for the same reason.

It is signed for the reason the relay's address is signed: whoever answers it
learns which devices are looking for which others and when. Less than the relay
learns, and still more than a third party should decide for itself. What it
cannot do is lie — the records it stores are signed and sequence-numbered by the
devices themselves, so a hostile rendezvous can withhold and delay but cannot
forge an address or roll one back. That is why an address suffices here while
the relay also needs a pinned certificate.

The same argument that keeps the suffix out of the code applies with a sharper
edge here. Whoever supplies a relay address learns who talks to whom and when,
and can withhold service, even though the traffic it carries is end-to-end
encrypted and it can read none of it. Held in each node's local configuration,
no two nodes would necessarily agree and anyone able to write that file could
substitute their own. Held here, it is one signed answer, changed by a
`set_network` operation like any other parameter — and a change propagates by the
ordinary means, so moving a network's relay costs one operation rather than a
reinstallation.

## 6. Device key rules

- The `keys` array is **strictly ordered** by each entry's canonical encoded
  bytes. An unordered list would let one key set encode two ways, which is one
  device with two ids.
- **No key value appears twice.** This is what enforces the rule that a
  device's signing key and transport key are different keys: one value serving
  two protocols invites cross-protocol attacks.
- At least one entry must have `purpose = "signing"`.
- The **identifying signing key** is the first signing entry in that canonical
  order, and the device id is its key id. A device's key set never changes —
  none of the seven operations adds a key to an existing device — so this is
  fixed for the device's lifetime.
- `author` is a *key id*, not a device id. They coincide for a device holding
  one signing key and differ for a device that also holds an enclave key.
  Mapping a key id to its device needs derived roster state.

## 7. Nothing is optional, with one exception

Every field is required, including booleans. An optional field would give one
logical value two encodings — one omitting it, one spelling out the default —
and therefore two ids for one operation.

The exceptions are `ipv4` and `leaving` in `NetworkParams`, added after
networks existed. What follows is said of `ipv4`, and holds of `leaving` for the
same reasons.
Writing it always would have changed the bytes, and so the id, of every
operation carrying parameters. It avoids the two-encodings problem by having no
second spelling: absent is the key left out, and an empty value is refused
rather than read as absence. Writing `100.64.0.0/10` explicitly is a range
chosen, a different value that happens to route the same, not a second spelling
of absence. Software that
predates the key refuses a map carrying it, which is the cost the next paragraph
describes, paid only by networks that choose a range.

The same reasoning drives the strict unknown-field rule. Tolerating unknown
fields would mean an old client silently discards a field a new client
considers meaningful. The cost is accepted: a format change means a new domain
tag (§9) and a migration, not a quiet field addition.

## 8. Timestamps are never authoritative

`ts` exists so a person can be shown when something happened. Nothing may read
it to decide ordering, validity, or identity, and no operation may be rejected
for a timestamp in the past or the future. Causal order comes from `parents`. A
device with a wrong clock must still be able to administer its own network.

## 9. Signature envelope

The signature covers

```text
u16be(len) || "roster/v1"  ||
u16be(len) || network_id   ||
u16be(len) || op_type      ||
u16be(len) || core_bytes
```

Each variable-length component is preceded by its length as a big-endian
`u16`. Plain concatenation would let a crafted `network_id` borrow bytes from
the component after it and produce the same signing input as a different,
legitimate tuple.

`"roster/v1"` is the format's version boundary. Changing the encoding means
changing this string, which invalidates every existing signature by
construction rather than by convention.

### ed25519

Strict profile, fixed here because ed25519 has no single standard notion of a
canonical signature and permissive implementations accept signatures that
strict ones do not:

- small-order public keys and small-order `R` rejected;
- `s` required to be canonically reduced;
- verification **not** cofactored.

Public keys are 32 bytes.

### P-256

- Signatures are **fixed 64-byte `r || s`**. DER never enters the format.
- A signature whose `s` is not in low form is **rejected**, not normalized.
  `(r, s)` and `(r, n − s)` are both mathematically valid; refusing the high
  form leaves exactly one encoding per signature.
- Public keys are the **33-byte compressed** SEC1 point. The 65-byte
  uncompressed encoding describes the same key and is refused, because one key
  with two encodings is one device with two ids.

### What verification proves

That the signature was produced by the holder of a given key over exactly these
bytes. **Not** that the key had authority to author the operation. Authority is
derived from the state implied by an operation's causal ancestors, which this
capability does not build.

## 10. Limits

Protocol constants, not tuning knobs. A node that raises one accepts operations
its peers reject, which is a fork. They change only with the domain tag.

| Limit | Value |
|---|---|
| Encoded operation size | 8192 bytes |
| Parents per operation | 32 |
| Key entries per device | 8 |
| Device name | 64 bytes |
| Capabilities per device | 16 |
| Capability string | 128 bytes |
| Revocation reason | 256 bytes |
| Network suffix | 64 bytes |
| Relay address | 128 bytes |
| Relay certificate | 4096 bytes |
| Rendezvous address | 128 bytes |
| Identifier | 32 bytes |
| Signature | 64 bytes |
| Map key | 23 bytes |
| Operations per roster | 4096 |
| Of those, operations that are not revocations | 3584 |

A declared length is checked against its bound *before* any buffer is reserved,
so a peer cannot make a client allocate merely by claiming a large size.

The last two are one bound with a reserve inside it. A roster holds at most 4096
operations; at most 3584 of them may be anything other than a revocation, and the
512 that remain are reachable only by revocations. Exceeding either is
`limit_exceeded`, and the refusals name different bounds.

Without the reserve the ceiling is reached by whatever arrives first, and a
network that has reached it can no longer expel the device that filled it —
compaction does not give the ceiling back, so that state is permanent and the only
remedy is to abandon the network. 512 is more than a household-scale network is
likely to produce in its whole life, and every revocation must name a device that
was really added, so the reserve cannot be filled with revocations of devices
nobody created.

## 11. The founder flag

`founder` is a required boolean on `DeviceSpec`, `DeviceRecord`, and the
`promote` body, and it is covered by the signature.

The governing rule is a **self-revocable founder set**: the admin named by
`create_network` is a founder, an admin may grant founder status to another key,
and a `revoke_device` or `demote` targeting a founder is valid only when the
author is the target. This blocks a compromised co-admin from expelling the
owner while still allowing a deliberate handover.

**That rule is not enforced at this version.** Enforcing it requires knowing
whether a target is a founder, which requires derived roster state. This
capability guarantees only that the flag is present, explicit, and signed;
enforcement arrives with conflict resolution.

## 12. Test vectors

[`vectors/positive.json`](vectors/positive.json) — bytes that must be accepted,
with the id each must produce and the key each must verify under. One vector per
operation type per algorithm.

[`vectors/negative.json`](vectors/negative.json) — bytes that must be rejected,
with the reason. One vector per rejection reason. Accepting one of these, *or
rejecting it for a different reason*, is a divergence.

Both files hex-encode every byte string, so a person can read them, and are
JSON rather than CBOR so that a fault in the CBOR layer cannot also break the
harness meant to diagnose it.

Regenerate with `cargo run -p roster --bin gen_vectors`. The corpus is
committed and regenerating must produce a visible diff: a corpus rebuilt
automatically on every build would bless whatever the implementation currently
does, which is the opposite of what it is for.

---

# Derivation semantics

Sections 1–12 describe what an operation *is*. What follows describes the roster
an operation *set* implies. A second implementation needs both: agreeing on the
bytes and disagreeing on the merge still leaves two households.

## 13. Network identity

The network id is the operation id of its `create_network`.

The founding operation itself carries a `network` field of **32 zero bytes**, and
must be rejected if it carries anything else. It cannot name its own id: that
field is inside the bytes the id is computed over, so naming the result would
require a hash of a structure containing that hash. A network is defined by its
genesis, so the field has nothing to say there. Every other operation carries the
derived value and is rejected if it does not match.

Exactly one `create_network` exists per roster, and it is the only operation with
an empty parent list.

## 14. Causal depth

`depth(genesis) = 0`, and otherwise one greater than the greatest parent depth.
A function of the operation set alone. Timestamps never enter it.

## 15. Validity

An operation is valid when **both** hold:

1. **Ancestor-relative authority.** Its author held the admin role in the state
   derived from that operation's *own causal ancestors* — never current state.
   Anything else would make demoting an admin retroactively void everything they
   ever wrote.
2. **The causal authorship rule.** It is *not* causally concurrent with an
   operation that demoted or revoked its author's device.

Rule 2 closes what rule 1 alone leaves open. An ex-admin can anchor a new
operation to parents from before losing authority, where ancestor-derived state
still shows them as an admin. Conflict rule 1 (below) does not help, because it
governs an operation's *target* and never its author: a forged `add_device` would
introduce a device no rule removes, surviving sync permanently on any node that
admitted it. Under rule 2 that operation is void on every node the moment the
demotion is known, so a lagging node self-heals without anyone revoking anything.

Work done *before* losing authority is a causal ancestor of the removal and stays
valid. Only concurrent work is void. An honest operation still in flight when its
author is revoked is therefore voided too — which fails safe: a device is not
added, rather than an unaccountable one being admitted.

**Validity is a fixpoint, not a single pass.** Rule 2 makes an operation's verdict
depend on *concurrent* operations, whose own verdicts may depend back on it — two
admins demoting each other is the smallest case. It is computed in rounds:
everything starts valid, each round recomputes every verdict from the previous
round's set, and **an operation once marked invalid is never restored.** That last
clause is what terminates the computation instead of oscillating, and it settles
mutual demotion the safe way: both demotions void, both admins keep their roles,
a person resolves it deliberately. Each round reads only the previous round's set,
so no verdict depends on visit order.

The founding operation bootstraps the rule: its author must be one of the signing
keys of the device it declares, and that device must be an admin and a founder.

## 16. Conflict rules

**Rule 1 — revocation always wins.** A device any valid operation revokes is
revoked, in either causal direction. Revocation is definitive: a revoked device id
is never restored, not even by a causally later `add_device` naming it. Returning
needs a new key, and therefore a new device id.

**Rule 2 — demote beats promote among concurrent branches.** Where a `demote` and
a `promote` on one device are concurrent, the result is member. Where they are
causally ordered, the deeper one wins, so a `promote` descending from a `demote`
is a deliberate re-promotion and grants admin. Demotion is therefore reversible;
revocation is not.

**Rule 3 — last-writer-wins, deterministic tie-break.** Greater causal depth wins;
at equal depth, the greater operation id, compared as bytes. Arbitrary, but
identical on every node.

Rule 3 governs `rename` and `set_network`. Device **capabilities are immutable**:
none of the seven operation types changes them, so no capability conflict can
arise. A later change introducing capability mutability must extend this rule.

Where two concurrent `add_device` operations name the same device id — the same
signing key, a different transport key — the whole record comes from the winner
under rule 3, rather than being spliced from both.

Founder status is granted and never withdrawn: a founder leaves by revoking
itself, not by ceasing to be one.

## 17. Founder enforcement

A `revoke_device` or `demote` targeting a founder is valid **only when its author
is that same device**. Founder-ness is judged in the same ancestor-relative state
as authority. This blocks a compromised co-admin from expelling the owner, while
leaving a founder able to retire its own key.

## 18. Admission is not derivation

Two layers, and the boundary is load-bearing:

- **Deterministic.** The graph and the derived roster. A pure function of the
  operation set.
- **Local.** Admission: the pending set, and a staleness filter that refuses
  operations anchored further behind the local frontier than a configured depth.

Two nodes may legitimately reach different *admission* decisions, because they
know different things. They must never reach different *rosters* from the same
operations. Moving the staleness check inside derivation would make identical
operation sets derive different households, order-dependently — a consensus split
dressed as a configuration option. In this implementation `derive` takes the graph
and not the node, so the mistake does not compile.

The staleness threshold is therefore **not** a protocol constant, and is
deliberately absent from the shared corpus: two conforming implementations may
configure it differently and both be right.

### What admission refuses before the graph

An operation that can never have an effect must never occupy a slot. The graph is
bounded, and every node forwards what it admits, so an operation admitted and then
disregarded costs every node in the network a place it cannot recover. Before
inserting, a node refuses:

| Refused | Reason |
|---|---|
| an author that is not an admin, or is revoked, in the state this operation's own ancestors imply | `unauthorized_author` |
| an author that ancestor state does not name at all | `unauthorized_author` |
| a `revoke_device`, `promote`, `demote` or `rename` naming a device absent or already revoked there | `unknown_target` |

The same checks apply wherever an operation enters the graph, including when one
that was waiting for its parents is integrated: offering a child before its parent
is otherwise a way past them.

**Judged inside the operation's own ancestors, and nothing else.** The set of
ancestors is fixed when the author signs, so every node holding those parents
reaches the same verdict, in whatever order things arrived. Equivocation is the
reason this must be said explicitly: whether an operation has a concurrent sibling
by the same author is a property of the whole graph, so consulting it would make a
refusal depend on what else a node had received — and since the children of a
refused operation can never be placed, two nodes would end up deriving different
rosters.

Admission is therefore strictly more permissive than derivation. It may admit an
operation derivation later disregards, which costs one slot; it never refuses one
another node honours. A refusal is also not permanent: the same operation offered
again, once the ancestors that give its author authority have arrived, is judged
again on what the node then holds.

## 19. Operations awaiting their parents

An operation whose parents are absent is held in a bounded pending set, never
discarded — the one you cannot place may be a revocation. It is integrated
automatically when its parents arrive, and contributes nothing until then.

Pending entries are **unverified by necessity**: an author's key is resolved from
roster state, derived from the very ancestors that are missing. They have passed
only the self-contained checks (bounded size, canonical encoding, id matches
bytes). Signature verification happens at integration.

Reaching the bound is reported, never silent.

**A requirement this crate cannot satisfy alone.** Bounding the pending set
*fairly* needs per-peer accounting, and that needs authenticated peer identity,
which lives in the transport. A flood of junk orphans can otherwise crowd out a
legitimate operation waiting for its parent. Reserving space for `revoke_device`
does not fix it, because an attacker can label junk as a revocation.

**Discharged in `roster-sync`.** It caps the pending entries attributable to any
one authenticated peer *device* at `MAX_PENDING_OPERATIONS / 8`, so at least eight
distinct devices can always make progress. Two rules there matter to a reader of
this document: the cap is decided **before** an operation is offered to a roster,
so nothing already pending is ever displaced to make room; and it is keyed on the
device rather than the session, so it cannot be renewed by reconnecting. See
`crates/roster-sync/FORMAT.md` §11.

## 20. Additional limits

| Limit | Value |
|---|---|
| Operations per roster | 4096 |
| Pending operations | 256 |
| Staleness depth (local, configurable) | 64 |

The first two are protocol-adjacent: a node that raises them accepts rosters its
peers refuse. The third is local policy and cannot affect derived state.

## 21. Merge vectors

[`vectors/merge.json`](vectors/merge.json) — operation sets and the roster each
must derive, with the operations that must be disregarded and why. Every set is
applied in more than one order and must give the same result each time; a vector
run in a single order would test derivation but not the property that matters.

Coverage of rejection reasons spans `negative.json` and `merge.json` together. Two
reasons are deliberately outside the corpus and named as such in the runner:
`stale_operation` (local policy) and `cyclic_history` (not constructible, since an
operation id covers its parent list).

---

# Snapshots and compaction

## 22. The snapshot artifact

A snapshot is an admin's signed attestation that the state up to here is X. It
is **not** an operation: it has no place in the DAG, is never named as a parent,
and never takes part in merge. That is the structural reason §4.6 can call it
"not authoritative in a strong sense" without needing a rule to enforce it — a
snapshot cannot suppress an operation, because it does not live in the graph the
operations live in. It also keeps the seven operation types closed.

```text
Snapshot     = { "seq": uint, "heads": [ bstr(32) ... ], "state": bstr,
                 "author": bstr(32), "depths": [ uint ... ],
                 "network": bstr(32) }
SignedSnapshot = { "sig": bstr(64), "body": bstr }
```

Key order follows the same length-first rule as everything else: `seq`, `heads`,
`state`, `author`, `depths`, `network`; and `sig`, `body`.

| Field | Why it is there |
|---|---|
| `seq` | Monotone counter; the rollback defence |
| `heads` | Defines the covered set: everything causally at or beneath these |
| `state` | `RosterState` canonical bytes for the covered set |
| `author` | The key id that signed. Lets a verifier check one named key rather than trying every admin, so a bad signature and an unauthorised signer stay distinguishable |
| `depths` | The causal depth of each head |
| `network` | So a snapshot cannot be lifted between networks |

**`depths` is the field most easily thought unnecessary and most damaging to
omit.** Depth is the primary key of the last-writer-wins rule, so a node that
compacted and then guessed depths would resolve concurrent renames differently
from a node that kept its history — a fork appearing only when two admins rename
the same device at once.

The covered set of a snapshot is every causal ancestor of its heads, together
with the heads themselves.

## 23. Snapshot signatures

Snapshots sign under the tag `"roster-snapshot/v1"`, framed exactly as the
operation envelope is — each variable-length component preceded by its length as
a big-endian `u16`:

```text
u16be(len) || "roster-snapshot/v1" ||
u16be(len) || network_id           ||
u16be(len) || body_bytes
```

Two tags rather than reusing the operation tag: the operation envelope's third
component is an operation type from a closed set, and smuggling snapshots
through it would put a value there that no operation may hold. A signature over
an operation must not verify as one over a snapshot, or the reverse.

Verification against a key the snapshot does not name is a **key mismatch**,
reported distinctly from a signature that fails to verify.

## 24. Verification before trust

Where a node holds every operation a snapshot covers, it derives that state
itself and compares. **Its own derivation is authoritative**; a snapshot that
disagrees is refused and the disagreement reported. A snapshot can never
correct, override or replace state a node can derive. That is what stops a
compromised admin rewriting history.

Holding *some* of the covered operations counts as holding none: the claimed
state cannot be reproduced, so nothing has been checked.

### The bootstrapping limit — accepted, not mitigated

A device receiving its first roster has nothing to compare against and adopts
the snapshot **on the admin's signature alone**. A compromised admin can hand it
a fabricated network.

This is a real hole and belongs in the public threat model beside §6.2. It is
bounded by two things and neither removes it:

- it requires the admin key, which is what the whole trust model rests on; and
- it is **detected on the first sync** with any peer holding the underlying
  operations, because the node then derives the covered state and finds it
  disagrees.

A node in this position never compacts, so it discards nothing on the strength
of a claim it could not check.

## 25. Monotone sequence, and conflict

A snapshot's sequence must be **strictly greater** than the highest accepted, or
it is refused. This is what stops a compromised rendezvous serving an old
roster.

Two snapshots sharing a sequence number and differing in content cause **both to
be refused**, and the number is closed permanently. Considered and rejected:
accepting whichever arrived first (order-dependent, so two nodes keep different
snapshots and compact differently), and picking a winner by `(seq, id)`
(deterministic, but it quietly chooses between two claims one of which may be a
forgery — the worst property for an equivocation signal).

Recovery is a higher sequence number, which any admin can issue; the block is
self-healing and needs no intervention.

Because compaction requires local verification (§26), a node that already
compacted had verified the state first, so a later conflicting snapshot cannot
retroactively invalidate what it discarded.

## 26. Compaction

**Whole operations go — body, signature and all.** The covered *heads* are
retained as complete signed operations, so that later operations naming them as
parents remain placeable.

Nothing partial is kept. Retaining a skeleton of parent links and depths while
dropping bodies and signatures would be smaller, and is not allowed: such data
is **authenticated by nothing**, and a fault or a hostile local process could
alter it undetected. The invariant is worth more than the bytes:

> Every byte a node retains is covered by a signature — an operation's own, or
> the snapshot's.

### The three gates

A node discards a covered region only when **all three** hold:

1. **Nothing held is concurrent with the region.** Otherwise a held operation's
   ancestor-relative validity still needs what is being discarded.
2. **The region lies more than `staleness_depth` behind the frontier.** Any
   later operation anchoring into it has anchor depth below
   `frontier − staleness_depth` and is already refused as stale (§18). The
   frontier only advances, so this stays true.
3. **The snapshot was verified locally.** Discarding on an unverified claim
   would throw away the evidence needed to notice it lied.

**Gate 1 is not sufficient on its own**, and the counterexample matters: on a
divergent history an operation at depth 100 on one branch is genuinely
concurrent with one at depth 5 on another, so "held operations are deep" does
not imply "held operations descend from the region". Gate 2 is what makes the
region unreachable rather than merely old.

Compaction is deliberate — never a side effect of accepting a snapshot. Nothing
is discarded because a message arrived.

## 27. Deriving across the boundary

A compacted node derives from its snapshot's state plus the operations it still
holds, and must produce **byte-identical** state to a node that discarded
nothing.

Every post-snapshot operation descends from a covered head, so its depth
strictly exceeds every depth in the covered set. Each phase then composes:

| Phase | Composes because |
|---|---|
| Revocations | Set union: the snapshot's revoked set ∪ later revocations |
| Roles | Covered and later operations are causally ordered, never concurrent, so rule 2's concurrency arm cannot fire across the boundary and depth decides |
| Last-writer-wins | A post-snapshot value always outranks a covered one on depth |
| Founders | Monotone union |
| Ancestor-relative authority | `state(ancestors(O))` = snapshot state + the retained operations between |

Covered heads are retained as anchors and **excluded from derivation**: their
effects are already inside the snapshot's state, and applying them again would
count them twice.

That composition argument is the kind that convinces and is wrong. It is not the
guarantee — the property test comparing a compacted and an uncompacted node is.

## 28. An operation has no effect before its target exists

A `rename`, `promote` or `demote` that **causally precedes** the `add_device`
introducing its target changes nothing, and does not apply retroactively when
the device is later added.

Compaction is what forces this to be pinned. A latent effect waiting for a
device to appear cannot be represented in a snapshot's state, which holds only
devices that exist, so a compacted node would lose it and derive a different
roster. This was found by the compaction property test, not by reasoning.

Causally concurrent operations still apply: they do not precede the add, and
compaction is refused for any region a held operation is concurrent with.
Revocation is exempt and stays a set union — a revoked device id remains revoked
whenever the revocation was written, and the snapshot carries the revoked set
explicitly, so nothing is lost.

## 29. Freshness is local

A node records when it **received** each accepted snapshot, by its own clock,
and raises a stale-roster indication once `snapshot_window` elapses with nothing
fresher. §3.3's cautious mode consumes that indication.

**No timestamp from the data is ever read.** `DESIGN.md` §0 forbids timestamps
influencing validity, and §4.6 asks for a validity window; measuring elapsed
local time since receipt satisfies both, because freshness is *liveness* — it
changes what a node is willing to do, never what the operations mean. Two nodes
disagreeing about staleness derive identical rosters.

A signer-chosen expiry would be worse than no window at all: a compromised admin
sets a far-future value once and the revocation window becomes unbounded on
every node that accepts it, while still looking like a protection.

A monotonic source is preferred. A clock moving backwards is **reported**, not
absorbed: a correction and tampering are indistinguishable from inside, and only
one is benign.

The threshold is therefore not a protocol constant and is deliberately absent
from the shared corpus — two conforming implementations may configure it
differently and both be right.

## 30. What compaction does not do

Compaction reclaims **bytes, not the operation ceiling**. `MAX_OPERATIONS`
(§20) still bounds causal history, because the retained heads and everything
after them still count. Lifting that ceiling needs a rule for retiring the
retained heads too, which this version does not address.

## 31. Snapshot vectors

[`vectors/snapshot.json`](vectors/snapshot.json) — snapshots and the verdict
each must receive, given the operations a node holds. An `accepted` vector
carrying `error_kind: snapshot_unverified` means the node may adopt the state
but must not treat it as checked.

Rejection-reason coverage spans `negative.json`, `merge.json` and
`snapshot.json` together. Three reasons are deliberately outside the corpus and
named in the runner: `stale_operation` and `compaction_refused` (both local
policy, where conforming implementations may differ and both be right) and
`cyclic_history` (not constructible).

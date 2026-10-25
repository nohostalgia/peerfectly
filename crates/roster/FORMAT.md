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

  A decoder reads each map against its schema, key by key. A key the schema does
  not name is `unknown_field`, and so is a map declaring more entries than its
  schema has keys, refused before any key is read. A key of the schema in the
  wrong place is `key_ordering`, the same key twice `duplicate_key`, and a map
  with fewer entries than its required keys `missing_field`.
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
| `type` | One of the nine names in §5 |
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

The set is closed at nine. Adding a tenth means deciding how it merges
against all nine existing types, so it is a change to the roster's semantics,
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
| `set_device` | A `SettingsChange` map (below) |
| `admit_batch` | A `BatchHeader` map (§37) |

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

`purpose` is `"signing"`, `"transport"` or `"attestation"`.

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

### SettingsChange

```text
SettingsChange = { "ipv4": [] / [bstr], "mode": [] / [tstr],
                   "relay": [] / [bstr], "device": bstr(32),
                   "groups": [] / [[ tstr ... ]] }
```

What an admin changes about a device after admitting it, one field at a time.
Each field is an array of **zero or one** values: empty leaves the field alone,
one value sets it. A value of the empty byte string clears an address or a
relay. At least one field must be set. The settings themselves are §33's.

### NetworkParams

```text
NetworkParams = {
  "ula": bstr,
  ? "ipv4": bstr(5),
  "relay": [] / [tstr],
  ? "policy": [ Rule ... ],
  "suffix": tstr,
  ? "anchors": [ bstr(32) ... ],
  ? "leaving": Leaving,
  ? "snapshot_window": uint
}

Rule = { "to": tstr, "from": tstr }

Leaving = {
  "relay": tstr,
  "until": uint
}
```

Key order is length-first: `ula` (3 bytes), `ipv4` (4), `relay` (5), `policy`
and `suffix` (6, `p` first), `anchors` and `leaving` (7, `a` first),
`snapshot_window` (15). Alphabetical order would produce bytes a conforming
decoder refuses.

These eight are the whole of `NetworkParams`. A map carrying any other key is
refused as `unknown_field` (§1), never read past. Three entries are required —
`ula`, `relay`, `suffix` — and each optional key present adds one. Each optional key is left out when absent,
never written empty, so parameters without it encode as they did before it
existed.

`anchors` names the full members light members fall back to: device ids, sorted,
without repeats, at most 32. An entry naming a device that is not a member is
ignored by derivation. `policy` is the access policy: rules letting members of
group `from` open sessions to members of group `to`, sorted, without repeats, at
most 256. With no policy every member may reach every other.

In derived state the parameters are leaves, one per parameter (§33), and a
`set_network` changes only the leaves it changes (§16).

`ipv4` is the IPv4 range the network's devices derive their IPv4 addresses in:
four address bytes, then the prefix length. It is one of the **two optional
keys** in the format, with `leaving` below. It sorts after `ula` (three bytes
against its four) and before `relay` (five). A map without it is byte for byte
what parameters were before the key existed; a map with it has one entry more.
Absence has exactly one spelling, the key left out: an empty byte string is refused
(`invalid_value`), as is any other length, a repeated key (`duplicate_key`), and
a range with host bits set, a prefix length outside 8 to 28, or a range not
wholly inside `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`
or `198.18.0.0/15` (all `invalid_value`). Parameters without it use
`100.64.0.0/10`.

Software predating the key refuses a map carrying it, so a network that sets a
range cannot be read by it. A network that does not is unaffected.

`leaving` is the relay a network is **moving away from**, and when the move
ends. A change of relay is a transition rather than a switch: devices learn of a
change by synchronising, they synchronise through the relay, and a device
switched off during the change wakes knowing only the old one. Until `until` the
devices that already moved stay reachable on the relay being left too.

It sorts after `suffix` (six bytes against its seven) and before
`snapshot_window`. It is **one key holding both fields**, so a relay being left
without an end, or an end without a relay, is not something the encoding can
say — a `Leaving` map missing a field is `missing_field`, and one carrying any
other key `unknown_field`. Its own keys are ordered as every map's are: `relay`
before `until` (equal lengths, `r` before `u`).

`until` is milliseconds since the epoch, the clock operations are dated by.
Past it the relay being left is not used, with nothing signed to say so. Its
`relay` is written as the network's own is, below, under the same bound.

`leaving` is refused (`invalid_value`) where it cannot mean anything: when the
parameters name no relay to move to, when it names the relay itself, and when
its relay is empty. Parameters without it are byte for byte what they were
before the key existed — the rule `ipv4` set.

`snapshot_window` is in seconds, and **optional**: a network with no window
leaves the key out, and its roster never reads as stale (§29). Zero written out
is refused (`non_canonical`): absence has one spelling. A relay move in a network
with no window keeps the relay being left for seven days. The suffix is a roster parameter rather than a
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

The address names the relay's key as well as where it is:

```text
<64 hexadecimal digits>@host:port
tls://<64 hexadecimal digits>@host:port     a link wrapped in TLS
```

To this format the string is opaque text, at most 128 bytes: it checks
presence, emptiness and length, and the transport reads the key and the address
out of it. The `tls://` form wraps the link to the relay in TLS for networks that
let only TLS out; it authenticates nothing.

The key is here because the relay is the one service in this design a node
speaks to before it has authenticated anything, and the ordinary answer to "is
this the right server" — a public certificate authority — is exactly the third
party this network is built to do without. A node dials the relay under the key
its own signed parameters name and accepts no other in its place, so the roster
authenticates the relay with nothing beside it. It also makes a relay you run
yourself, on an address with no domain name, an ordinary arrangement rather than
a workaround.

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
- At least one entry must have `purpose = "signing"`, and at least one
  `purpose = "attestation"`.
- The **identifying signing key** is the first signing entry in that canonical
  order, and the device id is its key id. A device's key set never changes —
  none of the nine operations adds a key to an existing device — so this is
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
| Identifier | 32 bytes |
| Signature | 64 bytes |
| Map key | 23 bytes |
| Operations per roster | 4096 |
| Of those, operations that are not revocations | 3584 |
| Groups per device | 16 |
| Group name | 32 bytes |
| Anchors | 32 |
| Access policy rules | 256 |
| Entries per batch | 65 536 |
| Batch label | 64 bytes |
| Batch entry serial | 64 bytes |
| State piece | 65 536 bytes |
| Root heads | 32 |
| Encoded root | 65 536 bytes |

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

**Rule 1 — revocation wins over every admission it does not precede.** An
admission — an `add_device`, or a batch entry (§38) — stands only if it
**descends from every valid revocation of its device**. A revocation concurrent
with the admission, or after it, removes the device, in whichever order the two
arrived. An admission that causally follows every revocation is a deliberate act
and admits the device again. In practice a device that returns does so with
fresh keys and a new id: a join always mints them.

The set of revoked devices is **not** part of the state a root commits to. A node
knows a device as revoked only while the revocation is among the operations it
holds; once a checkpoint absorbs it, the device is simply absent, and a node
holding the window and one holding the whole history agree on everything the
root commits to.

**Rule 2 — demote beats promote among concurrent branches.** Where a `demote` and
a `promote` on one device are concurrent, the result is member. Where they are
causally ordered, the deeper one wins, so a `promote` descending from a `demote`
is a deliberate re-promotion and grants admin. Demotion is therefore reversible;
revocation is not.

**Rule 3 — last-writer-wins, deterministic tie-break.** Greater causal depth wins;
at equal depth, the greater operation id, compared as bytes. Arbitrary, but
identical on every node.

Rule 3 governs `rename`, `set_network` and `set_device`, at the grain of what
each changes:

- `set_network` **per parameter leaf**. A `set_network` changes the leaves that
  differ from those its own ancestors' parameters hold, and each leaf takes the
  latest writer. Two admins changing different parameters at once both take
  effect. Where merged leaves no longer make valid parameters, the `leaving`
  leaf is dropped.
- `set_device` **per field**: mode, groups, address and relay each take their
  latest writer. A device admitted by a batch starts from the header's mode and
  groups and its entry's address.

Device **capabilities are immutable**: no operation type changes them.

**Rule 4 — admins are full.** An admin signs roots and must hold the state it
vouches for. Where a device would be both an admin and light, the later of the
two decisions stands, by rule 3's order: a promotion after the device went light
leaves it a member, and a switch to light after it became an admin leaves it
full.

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

# Roots and compaction

## 22. The root

A root is an admin's signed statement that the state is X, committed to by its
Merkle root (§34). It is **not** an operation: it has no place in the DAG, is
never named as a parent, and never takes part in merge. That is the structural
reason §4.6 can call it "not authoritative in a strong sense" without a rule to
enforce it — a root cannot suppress an operation, because it does not live in
the graph the operations live in. The encoded type keeps its old name,
`Snapshot`.

```text
Snapshot = { "root": bstr(32), "delta": [ bstr(32) ... ],
             "heads": [ bstr(32) ... ], "proof": MembershipProof,
             "author": bstr(32), "depths": [ uint ... ],
             "signer": DeviceLeaf, "network": bstr(32),
             "previous": [ bstr(32) ... ], "generation": uint }
SignedSnapshot = { "sig": bstr(64), "body": bstr }
```

| Field | Why it is there |
|---|---|
| `generation` | One more than the highest generation among the roots it follows; `1` for a root that follows nothing |
| `previous` | The state roots of the roots it follows, sorted, without repeats. Empty exactly when `generation` is 1 |
| `root` | The state root (§34) |
| `heads` | The covered set: every causal ancestor of these, with the heads themselves |
| `depths` | The causal depth of each head |
| `delta` | The devices whose leaves differ from the first root it follows: what a light member looks at for revocations |
| `signer` | The signer's device leaf |
| `proof` | That leaf's membership proof (§35) against the first root in `previous`, or against `root` itself when there is none |
| `author` | The key id that signed |
| `network` | So a root cannot be lifted between networks |

A root is the same size for five devices or five million: it carries no state.
At most 32 heads, and at most 65 536 bytes.

**`depths` is the field most easily thought unnecessary and most damaging to
omit.** Depth is the primary key of the last-writer-wins rule, so a node that
compacted and then guessed depths would resolve concurrent renames differently
from a node that kept its history.

**One root per act.** An admin's node publishes a root as soon as an act of its
takes effect — a batch is one act — and sends it to every open session. Nothing
is debounced.

## 23. Root signatures

Roots sign under the tag `"roster-snapshot/v1"`, framed exactly as the operation
envelope is — each variable-length component preceded by its length as a
big-endian `u16`:

```text
u16be(len) || "roster-snapshot/v1" ||
u16be(len) || network_id           ||
u16be(len) || body_bytes
```

Two tags rather than reusing the operation tag, so a signature over an operation
never verifies as one over a root, or the reverse.

`author` names a key of the signer's: its **attestation key**, which signs
without asking anybody, so an admin's node publishes roots unattended. A
signing key is accepted too. The signer must be an admin, and not revoked, in
the state the verifier holds; a verifier holding no state checks the signer's
leaf and proof instead (§24). A key the root does not name is a key mismatch,
reported apart from a signature that fails.

## 24. Verification before trust

Where a node holds every operation a root covers, it derives that state itself —
over exactly the covered region — and compares roots. **Its own derivation is
authoritative**; a root that disagrees is refused (`snapshot_state_mismatch`). A
root can never correct, override or replace state a node can derive. That is
what stops a compromised admin rewriting history.

Holding *some* of the covered operations counts as holding none: the claimed
state cannot be reproduced, so nothing has been checked.

A light member holds no operations. It checks a root against the root before
it: the signer's leaf must prove against that root and name an admin there, and
no root it holds may have revoked or demoted the signer since. It keeps one
current root and its own proof against it.

### The bootstrapping limit — accepted, not mitigated

A device receiving its first root has nothing to compare against and adopts it
**on the admin's signature alone**. A compromised admin can hand it a fabricated
network.

It is bounded by two things and neither removes it: it requires an admin key,
which is what the whole trust model rests on; and it is **detected on the first
sync** with a peer holding the underlying operations, which derives the covered
state and finds it disagrees. A node in this position never compacts on that
root, so it discards nothing on the strength of a claim it could not check.

## 25. The heavier root

There is no monotone sequence and no conflict rule between roots: the rule that
refused a sequence not strictly greater, and refused both of two roots sharing
one, is gone. Admins acting at once publish **siblings** by design.

Of two valid roots a node holds the **heavier**: the higher `generation`, then
the greater `root` hash, compared bytewise. The same rule on every node, so every
node holds the same root once it has seen both, without anyone talking. A
lighter root is not an error (`Lighter`), and it is not passed on.

Revocations are the exception a light member keeps: a revocation in the `delta`
of any validly signed root applies at once, even from a sibling that loses, and
stays until a root that covers it is adopted.

Rollback is what the old sequence rule was for, and it does not return: an old
root is lighter than the one a node holds, so it changes nothing there.

## 26. Compaction

**Whole operations go — body, signature and all.** The covered heads are
retained as complete signed operations, so that later operations naming them as
parents remain placeable.

> Every byte a node retains is covered by a signature — an operation's own, or
> the root's.

A node remembers the roots it verified itself (§24) as **checkpoints**, up to
256. Compaction tries them newest first and discards beneath the first that
passes every gate; the checkpoints beneath it are dropped. The root a node holds
is usually at the frontier and fails gate 2, which is why it is not simply
compacted against: an older verified root is.

### The three gates

A node discards a covered region only when **all three** hold, gate 2 checked
first because it is one subtraction:

1. **Nothing held is concurrent with the region.** Otherwise a held operation's
   ancestor-relative validity still needs what is being discarded.
2. **The region lies more than `staleness_depth` behind the frontier.** Any
   later operation anchoring into it is already refused as stale (§18), and the
   frontier only advances.
3. **The root was verified locally**, by deriving the region again now.
   Discarding on an unverified claim would throw away the evidence needed to
   notice it lied.

Gate 1 is not sufficient on its own: on a divergent history an operation deep on
one branch is genuinely concurrent with a shallow one on another. Gate 2 is what
makes the region unreachable rather than merely old.

Compaction is deliberate — never a side effect of accepting a root. A node that
compacted keeps its **base**: the root and the state it commits to, with the
retained heads; restarted, it rests on the base and replays only what follows.

## 27. Deriving across the boundary

A compacted node derives from its base state plus the operations it still
holds, and must produce **byte-identical** state to a node that discarded
nothing. Every held operation descends from a covered head, so its depth exceeds
every depth in the covered set, and each phase composes:

| Phase | Composes because |
|---|---|
| Revocations | The base holds no revoked device; a held revocation of a base device follows its admission |
| Roles | Covered and later operations are causally ordered, never concurrent |
| Last-writer-wins | A held value always outranks a covered one on depth |
| Settings | A device starts from the settings its base leaf holds, where that admission still stands |
| Founders | Monotone union |
| Ancestor-relative authority | The state of an operation's ancestors is the base plus the held operations between |

Covered heads are retained as anchors and **excluded from derivation**: their
effects are already in the base state.

That composition argument is the kind that convinces and is wrong. The guarantee
is the property test comparing a compacted node and an uncompacted one.

## 28. An operation has no effect before its target exists

A `rename`, `promote`, `demote` or `set_device` that **causally precedes** the
admission introducing its target changes nothing, and does not apply
retroactively when the device is later added. A latent effect waiting for a
device to appear cannot be represented in a root's state, so a compacted node
would lose it.

Causally concurrent operations still apply: they do not precede the add, and
compaction is refused for any region a held operation is concurrent with.

## 29. Freshness is local

A node records when it **received** each accepted root and attestation, by its
own clock, and raises a stale-roster indication once `snapshot_window` elapses
with nothing fresher. A network with no window never raises it: an island with
an admin of its own keeps working for as long as it is cut off. No timestamp from the data is ever read: freshness is
liveness — it changes what a node is willing to do, never what the operations
mean.

A clock moving backwards is reported, not absorbed. The threshold is not a
protocol constant.

## 30. What compaction gives back

The operation ceiling bounds the **window**, not the history. Each compaction
moves the base forward and the retained heads with it, so a network that keeps
publishing roots keeps its window under `MAX_OPERATIONS` (§20) indefinitely; a
history of ten thousand operations derives with the window never passing the
ceiling.

What still reaches the ceiling is a window that cannot be compacted: no verified
root old enough, or an operation held concurrent with the region.

## 31. Root vectors

[`vectors/snapshot.json`](vectors/snapshot.json) — roots and the verdict each
must receive, given the operations a node holds. An `accepted` vector carrying
`error_kind: snapshot_unverified` means the node may adopt the root but must not
treat it as checked.

Rejection-reason coverage spans `negative.json`, `merge.json` and
`snapshot.json` together. Reasons deliberately outside the corpus are named in
the runner: `stale_operation` and `compaction_refused` (local policy),
`cyclic_history` (not constructible), and `snapshot_sequence_regressed`, which
only attestations still raise.

---

# The state as a tree

## 32. The tree

The state is committed as a **compressed sparse Merkle tree** over 256-bit keys.
Every leaf sits at a key that is a hash of what it names, so where it goes
depends on the leaf alone, never on the order things were added; a node that
derived the state from history and one that received it as leaves compute the
same root.

```text
leaf(key, value)  = BLAKE3-derive("peerfectly membership tree leaf v1",   key || value)
branch(l, r)      = BLAKE3-derive("peerfectly membership tree branch v1", l || r)
EMPTY             = 32 zero bytes
```

A key's bits are read from the most significant bit of its first byte; `0` goes
left. A subtree holding one leaf **is** that leaf, at the depth where it is
alone, never padded down to depth 256. A subtree holding nothing is `EMPTY`.

A proof is the siblings on the path from the root to the leaf, top first:

```text
Proof = { "bits": bstr, "depth": uint, "hashes": [ bstr(32) ... ] }
```

`depth` is the number of levels; `bits` holds one bit per level, most significant
first, set where that sibling is not empty, padded with zero bits to whole bytes;
`hashes` are the non-empty siblings in order. Padding bits set, a count that
disagrees with the bitmap, or `EMPTY` spelled out as a hash, are refused.

## 33. Leaves

**Devices.** A device's leaf is its record and its settings:

```text
DeviceLeaf     = { "record": DeviceRecord, "settings": DeviceSettings }
DeviceSettings = { "ipv4": bstr, "mode": tstr, "relay": bstr, "groups": [ tstr ... ] }
key   = BLAKE3-derive("peerfectly membership position v1", device_id)
value = BLAKE3-derive("peerfectly device leaf v1", DeviceLeaf bytes)
```

`ipv4` is an assigned address, four bytes, or empty; `relay` a relay key, 32
bytes, or empty; `mode` is `"full"` or `"light"`; groups are sorted, without
repeats, at most 16 of at most 32 bytes each. Every field is present: an address
not set is the empty string, which has one spelling.

**Parameters.** Each parameter is a leaf of its own, so it can be proved, fetched
and changed alone:

```text
key   = BLAKE3-derive("peerfectly parameter position v1", name)
value = BLAKE3-derive("peerfectly parameter leaf v1", value bytes)
```

| Name | Value |
|---|---|
| `prefix` | the ULA prefix, `bstr` |
| `suffix` | the DNS suffix, `tstr` |
| `ipv4` | the IPv4 range, `bstr(5)` |
| `relays` | `[ tstr ]`, exactly one in this version |
| `leaving` | `{ "relay": tstr, "until": uint }` |
| `anchors` | device ids, sorted, without repeats, at most 32 |
| `policy` | rules `{ "to": tstr, "from": tstr }`, sorted, without repeats, at most 256 |
| `window` | the freshness window in seconds, `uint` |

**A leaf is absent when its parameter has its default** — no IPv4 range, no
relay, not moving, no anchors, no policy — and a present leaf must carry
something else: an empty anchor list written out would be a second spelling of
none, and so a second root for one state. A leaf whose name this format does not
know is refused, never skipped.

## 34. The state root

```text
state root = BLAKE3-derive("peerfectly state root v1",
                           network_id || devices tree root || parameters tree root)
```

A function of the state alone, so a node holding the whole history and one
holding only the window compute the same root. The set of revoked devices is not
in it (§16).

## 35. Membership proofs

```text
MembershipProof = { "devices": Proof, "parameters": bstr(32) }
```

The device leaf's proof in the devices tree, and the parameters tree's root
beside it: with the network id they recompute the state root, and nothing else
does. A member holding no roster checks one with a handful of hashes.

## 36. Moving a state

A root commits to its state by hash, so the state itself travels apart to a full
member that holds nothing yet: as its leaves, in pieces of at most 65 536 bytes.

```text
StatePiece = { "devices": [ bstr ... ], "parameters": [ { "name": tstr, "value": bstr } ... ] }
```

`devices` are encoded device leaves, in the order of their ids; `parameters` are
present in the first piece only. **Nothing is believed until the last piece is
in**: the receiver rebuilds both trees, and takes the state only if it makes the
root asked for. A device or a parameter given twice is refused. A piece that lies
costs the receiver the download, never a wrong state. How pieces cross a session
is `roster-sync`'s `FORMAT.md` §19.

---

# Batches

## 37. A signed header, unsigned pieces

An `admit_batch` operation is a batch's **header**. It commits to two roots: one
over its entries, by device, and one over the pieces those entries travel in, by
index — the **layout**.

```text
BatchHeader = { "mode": tstr, "block": bstr, "count": uint, "label": tstr,
                "groups": [ tstr ... ], "layout": bstr(32), "pieces": uint,
                "entries": bstr(32) }
BatchEntry  = { "ipv4": bstr, "keys": [ KeyEntry ... ], "name": tstr, "serial": bstr }
BatchPiece  = { "batch": bstr(32), "index": uint, "proof": Proof,
                "entries": [ BatchEntry ... ] }
```

- `count` is 1 to 65 536; `pieces` is 1 to `count`. `block` is an IPv4 range, or
  empty. `label` is at most 64 bytes. `mode` and `groups` are what every entry is
  admitted with; the role is always member.
- An entry is a device's public keys, name, serial (at most 64 bytes, or empty)
  and the address assigned from the block, or empty. It carries the rules every
  device keeps, checked as it arrives.
- **Entries tree:** each entry at `BLAKE3-derive("peerfectly batch entry position
  v1", device_id)`, valued `BLAKE3-derive("peerfectly batch entry v1", entry
  bytes)`. Two entries naming one device are refused.
- **The cut is canonical:** entries in device order, each piece filled until the
  next entry would not fit, every piece within 8192 bytes. Every node that holds
  the whole batch rebuilds the same pieces.
- **Layout tree:** piece *i* at `BLAKE3-derive("peerfectly batch piece position
  v1", u64be(i))`, valued `BLAKE3-derive("peerfectly batch piece v1", u64be(i) ||
  encoded entries array)`.
- A piece is checked on its own: its batch, an index below `pieces`, and its
  proof against the layout. It carries no signature: the header's covers it.

**Why the layout is committed.** A node holding part of a batch must say which
part, and pass on what it holds before it holds everything. With the layout
signed, a piece proves which piece it is, so a node's holding is a bitmap and no
peer can make it believe it holds a piece it lacks.

## 38. A batch takes effect only when it is whole

- **A header waits** until every piece is in, as an operation waits for its
  parents (§19). Until then it changes nothing, and what follows it waits with it.
- **A piece is refused before its header**: nothing could check it.
- **At most 8 incomplete batches**, declaring at most 131 072 entries between
  them; a header past either bound is refused before anything is stored.
- **Whole means matching.** Once every piece is in, the entries must number
  `count` and rebuild `entries`; otherwise the batch is refused, on every node
  alike.

Derivation treats each entry as an `add_device` at the header's depth and id
(§16), with the header's mode and groups and the entry's address. **An entry
that collides with what the header's own ancestors hold is skipped, and the rest
stand**: a device already a member, an address another device holds, or an
address outside the block or with no block. Of two entries assigned one address
the smaller device id keeps it. The same function decides this on an admin's
device before signing and in derivation, so the preview and the outcome agree.

**An urgent act never waits for a batch.** An admin's device names as parents of
a revocation or demotion every head except batches younger than five minutes and
what rests on them: a node still fetching such a batch takes the revocation at
once. Revoking an admin keeps that admin's whole batches as ancestors, so they
stand; what the revocation is concurrent with — the admin's batches held only by
their header, and its acts resting on another's recent batch — is voided, and is
reported before signing.

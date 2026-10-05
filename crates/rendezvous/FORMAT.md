# The rendezvous format

What a device publishes about where it can be reached, and the rules a second
implementation must follow to interoperate. Roster's `FORMAT.md` is the
companion document: this reuses its encoder, its framing convention and its
strictness, and does not restate them beyond what a reader needs here.

## 1. Scope

Two operations on one kind of record. It does not cover how a peer is dialled
once an address is known — that is `transport` — nor how the roster decides who
belongs, which no record here influences.

## 2. The trust model, stated first

Per DESIGN.md §6.1, a compromised rendezvous:

- **cannot inject devices.** Membership is the roster's. A record is not evidence
  of it.
- **cannot alter a record.** The device signed it; an altered one fails
  verification at the client.
- **cannot produce a record that verifies.** It holds no key a client accepts.

It **can censor, delay and observe.** Those are accepted, and they are why a
network must keep working when the rendezvous is unreachable.

**There is no authentication.** §2.8: the signatures do everything. The service
has no accounts, no tokens and no notion of a caller. There is nothing in it to
steal.

**What it observes, since v2 (F-12).** From a record: the device's transport key,
the sequence number, and the size of the sealed contents. The transport key is a
pseudonym, since every device has a separate identity per network. The network
and the addresses are sealed: it cannot learn which network a record belongs to,
nor where the device is, nor that two records belong to one network.

What no record format can hide is **the IP address** each publication and fetch
comes from. An operator can follow one pseudonym's addresses over time and see
which addresses look it up. That is accepted and stated, not solved here.

**The seal is obfuscation, not confidentiality.** Its key derives from the
network's id, which every member knows — and so does every revoked ex-member.
Opening a record is never evidence of who published it; the signature is.

## 3. Encoding

Canonical CBOR under roster's rules, using roster's encoder. Restated for a
reimplementer:

- definite lengths only;
- minimal integer widths;
- map keys in **length-first** order — shorter keys first, equal lengths
  compared bytewise. This is *not* alphabetical;
- every key in the schema present exactly once, none outside it;
- no trailing bytes after the top-level item.

Rejection is an error returned to the caller. Nothing is reordered,
deduplicated or repaired: two byte strings that differ must never verify as the
same record.

## 4. The record

Two layers: what travels in the clear, and what is sealed inside it.

```text
Wire = {
  "key":    bstr .size 32,  ; the device's ed25519 transport public key
  "seq":    uint,           ; increases with every publication
  "sealed": bstr            ; nonce (12) || ChaCha20-Poly1305 ciphertext
}

Sealed = {                  ; the plaintext of "sealed"
  "net":   bstr .size 32,   ; the network id
  "addrs": [* tstr]         ; addresses, opaque to this format
}
```

Key order is length-first. In `Wire`, `key` and `seq` are three bytes and compare
bytewise, and `sealed` is six and follows. In `Sealed`, `net` is three and
`addrs` five. Alphabetical order would produce bytes a conforming decoder
refuses.

**The seal.** `k_seal = blake3::derive_key("peerfectly rendezvous seal v1", network
id)`, ChaCha20-Poly1305, a random 12-byte nonce per publication, no associated
data. The context is not local discovery's, so one network's announcement key
never opens its records. A client refuses a record that does not open with its
network's key, and one whose `net` inside is not its network. It never uses an
address from a record it did not open.

**What a device publishes.** Only addresses a peer elsewhere on the internet could
reach. Never a private IPv4 range, CGNAT, loopback, link-local, unique-local
IPv6, or the network's own ranges. The local network is local discovery's.

**`key` is the transport key, never the signing key.** It is what a peer
authenticates the resulting session against, so the key that says *I am here* is
the key that will prove *I am me*. A record signed with a device's signing key is
refused.

**`addrs` are opaque strings.** This format does not parse them. The transport
decides what an address means, and a rendezvous that parsed them would need
changing whenever the transport's addressing changed.

### Bounds

| | |
|---|---|
| Record contents, encoded | 8192 bytes |
| Seal overhead | 28 bytes (nonce and tag) |
| Addresses per record | 16 |
| One address | 256 bytes |
| Minimum interval between publications, per key | 5 s |
| Keys one source address may create | 64 |
| Records in total | 100 000 |

A declared count is checked against its bound, and against the bytes that could
back it, before any buffer is reserved.

## 5. What is signed

```text
signing input = framed("rendezvous-record/v2")
             || framed(canonical Wire bytes)
```

**The network's id is not in it**, so the service verifies every publication
without learning the network. The sealed bytes are, so an altered ciphertext is
refused by the signature before anything tries to open it.

**v1 is withdrawn.** It signed the network's id alongside a record carrying it in
the clear. No v1 record verifies as v2, nor the reverse; nothing was ever in
operation under v1.

`framed(x)` is `len(x)` as a big-endian `u16` followed by `x`. Framing is what
stops two different component tuples concatenating to the same bytes.

**`rendezvous-record/v2`** is the fourth signing context in the system, after
`roster/v1`, `roster-snapshot/v1` and `transport-session/v1`. A record must not
verify as any of those, and none of those as a record — the transport key already
signs session challenges, and without separation a record could be presented as a
handshake or the reverse.

A change to the encoding is a change to this string, which invalidates every
existing signature by construction rather than by convention.

## 6. On the wire

A published or served body is the canonical `Wire` bytes followed by the 64-byte
signature:

```text
body = Wire bytes || signature
```

A receiver splits the last 64 bytes, decodes the rest, and verifies over the
bytes **as received** — never over a re-encoding of the decoded value, which
would verify what the receiver understood rather than what the signer signed.

## 7. Operations

### `PUT /r/{key}`

`{key}` is the device's key id — BLAKE3 of the transport public key — in lower
case hex, 64 characters.

The service accepts the record if, and only if:

1. it decodes canonically and is within every bound;
2. the signature verifies under the `key` the record carries;
3. that key's id equals `{key}` in the path — without this a device could file
   its own perfectly valid record where another device's belongs;
4. its `seq` **exceeds** the stored one, if any;
5. the publisher is within its rate, and its source within its key allowance.

| Response | Meaning |
|---|---|
| `204` | stored |
| `400` | did not decode, did not verify, or was filed under the wrong key |
| `409` | sequence not newer, or two different records at one sequence |
| `403` | too many addresses, or this source has created its keys |
| `413` | record over the size bound |
| `429` | published too soon, or the store is full — **wait and try again** |

`429` is the only status that invites retrying the same record. A client that
retried a `400` forever would be hammering the one piece of shared
infrastructure the project runs.

### `GET /r/{key}`

Serves the stored body to anyone, or `404` if nothing is held. The bytes served
are the bytes the device signed.

## 8. The sequence rule

**A record is accepted only if its sequence exceeds the one already held** — at
the service, and again at the client against the highest it has itself accepted.

This is the whole freshness mechanism. There is deliberately **no timestamp**:
`DESIGN.md` §0 forbids timestamps deciding validity, a device-signed time is
signer-chosen so a wrong clock would silently remove a device from reach, and a
server-recorded time trusts the party §6.1 says may delay.

**Two different records at the same sequence are both refused**, rather than one
being chosen. A device that signed both has equivocated, and picking a winner
would hide the evidence.

**The client's rule is the one that matters.** The service's copy is a
convenience; the client's is what makes rollback impossible even against a
compromised service, or one that has restarted with an empty store and so
accepts a sequence it previously held.

### A restart is not a rollback

Storage is in memory. A restart resets every sequence, so a device whose record
was at 40 can publish 41 into an empty store. A client that saw 40 still refuses
anything at or below it, so nothing is rolled back — the client is simply not
updated until the device publishes above what that client last saw.

## 9. What a receiver must not do

- MUST NOT accept a record whose key id differs from where it is filed.
- MUST NOT verify over a re-encoding of a decoded record.
- MUST NOT normalize a non-canonical encoding; refuse it.
- MUST NOT allocate to a declared count before the bytes backing it are read.
- MUST NOT choose between two records at one sequence.
- MUST NOT treat a record as evidence of membership, role, or anything the
  roster decides.
- MUST NOT require the rendezvous to be reachable in order to use an address it
  already holds.

## 10. Deliberately absent

| Not here | Where |
|---|---|
| Storing the roster, which §4.7 contemplates | `roster-sync` |
| Finding peers on a LAN | `local-discovery` — §8 means nothing there may depend on this |
| Caching, scheduling, deciding when to publish | `windows-daemon` |
| TLS, supervision, deployment | operations |

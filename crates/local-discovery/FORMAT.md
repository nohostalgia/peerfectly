# The local announcement format

What a device puts on a local network to say it is there, and the rules a second
implementation must follow. Roster's `FORMAT.md` defines the canonical encoding
and the framing convention; rendezvous's defines the record. Neither is restated
here beyond what a reader needs.

## 1. Scope

One packet, sent to a multicast group, repeated. It does not cover how a peer is
dialled once an address is known — that is `transport` — nor anything about
membership, which no announcement influences.

## 2. The trust model, stated first

**A discovered device is never proof of anything.** Anyone on a local network can
announce any key. Discovery *proposes*; the roster *authorises*. An announcement
yields candidate addresses and nothing else.

**The obfuscation is obfuscation.** Packets are encrypted under a key derived
from the network id, which is **not a secret**: every member knows it, and so
does every *former* member whose device was revoked. It defends against an
observer who never held the roster and against nobody else. **Successful
decryption is never authentication.**

**Only the signature is evidence**, and even it proves key possession, not
membership.

## 3. The channel

| | |
|---|---|
| Group | `239.255.61.41` |
| Port | `41641` |
| Transport | UDP |

`239.0.0.0/8` is the administratively scoped block, so a correctly configured
router does not forward announcements off the local network — which is the whole
intent.

**Not mDNS, and not port 5353.** §8 is explicit: the name is already in the
roster, so all that is needed is to discover that a key is present and where.
Using mDNS would also collide with the Bonjour and Avahi responders already
running on most networks, which own 5353 and would answer for us.

A listener SHOULD set `SO_REUSEADDR` before binding, so two nodes on one host can
both hear.

## 4. The payload

The announcement body is a **rendezvous record**, exactly as
`crates/rendezvous/FORMAT.md` §4 defines it:

```text
Record = {
  "key":   bstr .size 32,   ; the device's ed25519 transport public key
  "net":   bstr .size 32,   ; the network id
  "seq":   uint,            ; increases with every announcement
  "addrs": [* tstr]         ; addresses, opaque to this format
}
```

Same struct, same canonical encoding, same length-first key ordering. A second
format for one thing would drift, which this project has already had to correct
once.

### Bounds

| | |
|---|---|
| Packet, sealed | 1200 bytes |
| Addresses per peer | 8 |
| Announcement interval | 15 s |
| Cached peers | 256 |
| Cache entry age | 3600 s |

The packet bound is set so an announcement never needs fragmenting: a fragmented
multicast datagram on a wireless network is a datagram that does not arrive.

## 5. What is signed

```text
signing input = framed("local-announce/v1")
             || framed(network id)
             || framed(canonical record bytes)
```

`framed(x)` is `len(x)` as a big-endian `u16` followed by `x`.

**`local-announce/v1`, never `rendezvous-record/v1`.** This is the fifth signing
context in the system, and the separation is not cosmetic.

Without it an announcement *is* a valid rendezvous record. Anyone sharing a café
network could capture one and publish it, and because the device itself signed it
at a sequence above whatever it last published globally, it would **replace that
device's published addresses with LAN-only ones**. Peers elsewhere would fetch
`192.168.x` and fail until the device published again — reachability destroyed by
an observer holding no key at all.

An implementation MUST reject an announcement that verifies only under the
rendezvous tag, and vice versa.

## 6. The packet

```text
key    = BLAKE3::derive_key("peerfectly local-announce v1 packet key", network id)
packet = nonce (12 random bytes) || ChaCha20-Poly1305(key, nonce, record || signature)
```

**Nothing else is in the clear.** There is deliberately no per-network
discriminator: a stable tag would let an observer track a network's presence over
time without reading anything, which is most of what the encryption is for. A
listener attempts decryption instead, which on a dedicated port costs one AEAD
failure per foreign packet.

The nonce is fresh per packet, so two announcements of the same content produce
unrelated bytes.

An AEAD rather than a bare cipher: the payload is already signed, so integrity is
arguably covered, but relying on that means reasoning about malleability and a
decoder fed attacker-chosen bytes.

## 7. Receiving

In this order, and the order matters:

1. **Length** — refuse anything over the packet bound.
2. **Decrypt** — failure means *not ours*. Ordinary; the port is shared with
   every other network in range. Not an error to report.
3. **Decode** — canonical CBOR, rejection rather than repair.
4. **Check the network** — a record naming another network is not ours.
5. **Verify** — over the bytes as received, never a re-encoding.
6. **Compare the sequence** — accept only if it exceeds what is cached for that
   key.

Step 5 is the only one that produces evidence. Steps 2 and 4 produce none: they
say a sender knew a value every member and ex-member knows.

## 8. Repeating, and the cache

Announcements are **repeated**, not sent once. §8 warns that multicast on
wireless networks is filtered by the access point outright or delivered at the
lowest available bitrate, so one send may never arrive.

The last known local addresses are **tried before anything is heard**. A design
that waited for an announcement would be slowest exactly where §2.6b's 500 ms
budget is measured.

A cached address that no longer works costs one attempt; the other paths proceed
alongside it.

## 9. Ordering candidates

§2.9's order: local, then globally routable, then the rendezvous. An address on
an interface the node currently holds ranks first whatever it was labelled when
it was learned.

Recomputed **on every interface change**. A node that computed an order once
would stay on the relay after arriving home — a failure nobody notices quickly,
because the connection works and is merely going the long way round.

Where a caller supplies evidence that both peers sit behind one external address,
local candidates rank first outright. That evidence is a parameter; gathering it
belongs to whoever holds the transport.

## 10. What a receiver must not do

- MUST NOT treat decryption as authentication.
- MUST NOT treat an announcement as evidence of membership, role, or authority.
- MUST NOT verify over a re-encoding of a decoded record.
- MUST NOT accept a sequence that does not exceed the cached one.
- MUST NOT report a foreign packet as a fault.
- MUST NOT require any service beyond the local network.

## 11. Deliberately absent

| Not here | Where |
|---|---|
| When to announce, how often, on which interfaces | `windows-daemon` |
| Gathering reflexive addresses for the same-NAT check | whoever holds the transport |
| Membership, roles, authority | the roster |
| IPv6 multicast | open; the same code path serves it |

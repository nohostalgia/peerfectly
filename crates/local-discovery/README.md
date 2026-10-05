# local-discovery

Finding a peer on the same network, with no internet at all.

[`FORMAT.md`](FORMAT.md) is the wire specification. This is the reasoning.

## Why it exists

Every path built before this one leaves the building. `transport-iroh` reaches a
peer through a relay on a VPS; `rendezvous-service` says where a peer was last
seen, from a server on the internet. Both stop working when the internet does.

DESIGN.md §8 states the requirement and the failure it prevents:

> **The network works with the internet off.** If LAN candidates came only
> through the rendezvous, failing to connect half a metre from the device would
> be an absurd failure for a product that sells itself on not depending on anyone.

Half a metre from your own server, unable to connect, because someone else's
machine was down. For a product sold on sovereignty that is not a missing
feature — it is the promise failing in the case a user would find least
forgivable.

§2.9 makes the local network the **first** path tried, ahead of global
addressing, hole punching and the relay.

## Discovery proposes; the roster authorises

§8 is explicit: anyone on a local network can announce any key. What comes out of
this crate is **candidate addresses** — never a device, never a membership
answer.

The interface is built so it cannot say otherwise. There is no `DiscoveredDevice`
and no `is_member`, and a test asserts neither appears. The cheapest way to keep
a distinction true is to have nothing that could express the other thing.

A session opened to a discovered address is authenticated exactly as one opened
to an address learned any other way. An impostor announcing a key it does not
hold is discarded at the signature; one announcing a key the roster does not name
gets the transport's ordinary membership refusal.

## The announcement is obfuscated, and that is all it is

Packets are encrypted under a key derived from the network id, so a stranger on
the same wifi sees random-looking bytes rather than a public key and a presence
beacon. For a product sold on sovereignty, broadcasting a stable device identity
to every café is a poor default.

**It is obfuscation, not confidentiality.** The network id is not a secret. Every
member knows it, and so does every *former* member whose device was revoked. It
defends against an observer who never held the roster, and against nobody else.

A revoked device can therefore still read announcements on a network it is
already on, and learn who is present. It cannot join: the roster refuses it and
the transport refuses the session. That is accepted and recorded rather than
quietly hoped about.

**Decryption is never authentication.** A packet that decrypts proves only that
its sender knew that non-secret value. Only the signature is evidence, and even
it proves key possession rather than membership.

**No plaintext discriminator.** The obvious optimisation — a per-network tag in
the clear, so a listener skips foreign packets cheaply — would hand an observer a
stable identifier and let them track a network's presence over time without
reading anything. That is most of what the encryption is for. A listener attempts
decryption instead.

## Its own signing context

`local-announce/v1`, never the rendezvous tag, even though the payload is the
same record.

Without the separation an announcement *is* a valid rendezvous record. Anyone on
a café network could capture one and publish it — and because the device signed
it at a sequence above whatever it last published globally, it would **replace
that device's published addresses with LAN-only ones**. Peers elsewhere would
fetch `192.168.x` and fail until the device published again. Reachability
destroyed by an observer holding no key.

Two tags make that impossible in both directions, and a test asserts it.

## The medium is assumed to fail

§8 warns that multicast on wireless networks is filtered by the access point
outright, or delivered at the lowest available bitrate.

So **announcements repeat** — that is the design, not a retry — and **the last
known local addresses are tried before anything is heard**. A design that waited
for an announcement would be slowest exactly where §2.6b's 500 ms budget is
measured.

Being wrong is cheap: a stale cached address costs one attempt while §2.9's other
paths proceed alongside it. That is why the cache's age bound is generous rather
than cautious.

**What no test here can prove** is whether a real access point forwards multicast
at all. The suite runs over loopback; a hostile access point is not something a
loopback socket can simulate. The cache and the repetition exist because that
case is assumed, not hoped against.

## Ordering is a pure function

Candidates in, ordered candidates out, given the interface addresses and
optionally the evidence that two peers share an external address.

Pure because §8 requires reordering on **every interface change**, and a function
of its inputs can simply be called again. Anything holding state would need
invalidating correctly, and the symptom of getting that wrong is one §8 names
specifically: staying on the relay after arriving home. Nobody notices quickly —
the connection works, it is merely going the long way round.

The same-NAT evidence is a **parameter**. Gathering reflexive addresses belongs to
whoever holds the transport; taking the conclusion keeps this crate out of it and
keeps the ordering testable without a network.

## One coupling worth naming

The announcement payload is `rendezvous::Record`. §8 and §2.8 describe the same
thing — a public key plus an endpoint — and a second copy would drift, which this
project has already had to correct once.

If a third channel ever carries that record, the type should move below both
rather than being copied a second time.

## Deliberately elsewhere

| Deferred | To | Why |
|---|---|---|
| When to announce, how often, on which interfaces | `windows-daemon` | it owns the schedule and interface-change notification |
| Gathering reflexive addresses for the same-NAT check | whoever holds the transport | this crate must not reach into it |
| Membership, roles, authority | the roster | discovery proposes, and stops |
| IPv6 multicast | open question | the same code path serves it; the requirement is a working LAN, not coverage of every addressing mode |

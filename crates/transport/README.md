# transport

The interface a connectivity layer must satisfy, and what an authenticated
session means.

Four earlier changes built a roster that decides which keys belong to a network,
and an identity that gives a node its keys. This crate turns *"this peer holds a
key the roster knows"* into a channel you can send bytes over — and refuses to,
when it does not. A session established with a peer the roster does not name is a
device in the network that no admin added.

## `iroh` is not here, on purpose

`DESIGN.md` §0 forbids merging network code without a test against a real-world NAT
edge case, and that test cannot run in CI. The binding is **`transport-iroh`**,
which carries that obligation.

That deferral serves DESIGN.md §2.1 rather than compromising it. §2.1 asks for the
transport to sit behind an interface of about four methods *"so that replacing it
touches nothing else"* — and an interface with one implementation is an untested
claim. This crate ships **two**, and runs one behavioural suite against both. The
iroh binding inherits that suite, so its remaining job is connectivity rather
than semantics.

## The interface

```rust,ignore
#[async_trait]
pub trait Transport: Send + Sync {
    async fn connect(&self, peer: &PublicKey) -> Result<Box<dyn Session>>;
    async fn accept(&self) -> Result<Box<dyn Session>>;

    fn addresses(&self) -> Vec<String> { Vec::new() }
    fn learned(&self, peer: &PublicKey, addresses: &[String]) {}
}

#[async_trait]
pub trait Session: Send + Sync {
    fn peer(&self) -> DeviceId;
    async fn send(&self, payload: &[u8]) -> Result<()>;
    async fn recv(&self) -> Result<Vec<u8>>;
    async fn close(&self) -> Result<()>;
}
```

The last two carry addresses and default to doing nothing. `addresses` says
where this node believes it can be reached; `learned` offers addresses where a
peer was seen. Both exist because §2.9 puts the local network and the rendezvous
ahead of the relay, and something above the transport has to be able to say what
it heard — but an address means whatever the implementation that produced it says
it means, so they are opaque strings and the layer above never parses one.

They are hints and never authority. A session established over a learned address
is authorised from the signed roster exactly like any other, so an address from a
liar reaches a peer that refuses it or reaches nobody. The in-memory
implementations ignore both, which is right for a transport with no notion of an
address, and the default implementations are why adding them changed no
implementation that did not want them.

§2.1 names four operations: `connect`, `send`, `recv`, `close`. `accept` is the
fifth and is not padding — a transport that can only dial is half a transport,
and giving the in-memory implementation a private back channel the real one lacks
is how an interface stops describing reality.

**Async, and dyn-compatible.** QUIC, hole punching and connection migration are
asynchronous; a synchronous facade would hide a runtime behind blocking calls,
and blocking a phone's UI thread on a relay handshake is a failure mode worth
designing out. `async-trait` boxes the futures, which buys the dyn-compatibility
that "replaceable without touching the rest" actually requires.

`peer()` is synchronous and infallible: the identity is settled at establishment,
so asking for it can neither fail nor wait.

## What a session proves — and what it does not

**Proves:** the peer holds the private half of a transport key that the roster
state this node derived names, and that device is not revoked.

**Does not prove authority.** Roles, admin rights and founder status are derived
state. Asking the transport about them would make it a second authority.

**Promises no confidentiality.** A real transport gets that from QUIC and
TLS 1.3 (§2.1); the in-memory ones have no wire to protect. This is stated in the
interface itself, because *"it goes through the transport"* is exactly the phrase
a later reader takes to mean *"it is encrypted"*. Anything needing
confidentiality independent of the connectivity layer must arrange it above this
interface.

## Authentication, in two steps

1. **Possession** — the peer signs a challenge with the private half of the key
   it presents. Checked **first**, because a peer that cannot prove possession
   has told us nothing worth looking up: resolving an unproven key would let
   anyone learn whether a given key is a member by presenting it.
2. **Membership** — the key is resolved to a device *for the transport purpose*
   and checked against `revoked`.

The challenge is domain-separated under `"transport-session/v1"`, so a signature
gathered here cannot be replayed as a roster operation or a snapshot, and nothing
signed elsewhere can be presented as a handshake.

### The transport key, never the signing key

Resolution asks for a device holding this key **for the transport purpose**. A
device's two keys are distinct by construction precisely so one cannot stand in
for the other, and a lookup ignoring purpose would let a signing key open a
session — the cross-protocol confusion the separation exists to prevent.

A test presents a valid *signing* key that names a real device and asserts
refusal. That is the case which looks like it should work.

## The transport holds no authority of its own

It is given a `RosterState` — not a `Roster`, not a `Dag` — and it **caches
nothing**. Every membership question is re-asked of the state it currently holds.

A transport that remembered "this peer is allowed" would be a second, quieter
roster, consulted far more often than the signed one. When the two disagreed, the
cache would be the thing actually deciding who is in the network. The way to not
have that bug is to have nowhere to put it.

State changes reach a transport by handing it a newer `RosterState`. How a daemon
arranges that is its own business.

## One session, one device

A session is **bound to a single device at establishment**, and `peer()` returns
that device for the session's whole life. This is what makes bytes attributable:
everything arriving on a session came from one device the roster names, so a
caller above can act on that without re-deriving it.

Two sessions with different peers stay distinct — a property test drives
arbitrary interleavings of sends and receives and asserts the peer never moves.

## A session ends when its peer does

When a device stops being a member, **every open session with it closes**, and
the closure is reported distinctly from an ordinary hang-up.

The tempting implementation — check at connect, then leave the session alone — is
wrong in a way that is easy to miss. §6.2's revocation window is about a node that
has not *heard*; a session left open after the node has heard is a window we
opened ourselves, on a channel already carrying traffic.

## Failure states, kept apart

DESIGN.md §3.3 lists the states where a person loses confidence. They call for
different responses, and a generic error can produce none of them:

| Outcome | What it means |
|---|---|
| `PeerUnreachable` | could not be reached at all — says nothing about membership |
| `NotAMember` | reached; holds a key no device is named by. A stranger |
| `Revoked` | reached; the device was removed from the network |
| `PossessionNotProven` | presented a key it does not hold. Lying or broken |
| `ClosedByPeer` | the other end hung up |
| `ClosedOnMembershipLoss` | the network expelled this device |
| `PayloadTooLarge` | refused at the sender, never truncated |

A refusal originating in the roster or in identity carries that reason rather
than replacing it, so *"the roster refused this device"* stays distinguishable
from *"the network failed"*.

## Payload boundaries are part of the contract

What is sent as one payload arrives as one payload; the interface neither splits
nor joins. QUIC offers both datagrams and streams, so this is a real choice:
message boundaries are what `roster-sync` needs to frame an operation, and
pushing framing above the interface would mean every implementation reinventing
it slightly differently.

An oversized payload is refused **at the sender**. A truncated payload becomes a
decoding failure at the far end, blamed on the sender, and diagnosed nowhere near
where it went wrong.

## What `transport-iroh` must satisfy

Implement `Transport` and `Session`, then run the behavioural suite:

```rust,ignore
transport::suite::run_all(harness).await;
```

The suite is written against the traits and never names a concrete type. It is
run here against both in-crate implementations, so a behaviour only one of them
has fails immediately — which is what stops the interface becoming a description
of whichever was written first.

## Deliberately elsewhere

| Deferred | To | Why |
|---|---|---|
| The iroh binding, path selection (§2.9) | `transport-iroh` | needs a real-world NAT test |
| §4.7's operation gossip, and the **per-peer quota** on the roster's pending set | `roster-sync` | bounding that set fairly needs the authenticated peer identity established here — see roster's `FORMAT.md` §19 |
| Packet-level source validation (§2.5) | `tunnel` | happens at the TUN interface; this crate establishes the session-level equivalent that makes it meaningful |

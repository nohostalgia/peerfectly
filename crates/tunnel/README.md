# tunnel

Addresses on the overlay, and the rule that a packet's source must match its
session.

[`FORMAT.md`](FORMAT.md) is the specification. This is the reasoning.

## What the source rule is actually for

DESIGN.md §2.5:

> Routing becomes authentication: a packet whose source does not match the
> hash of the key of the session it arrived on is dropped.

Read as a defence against outsiders, that rule looks redundant — the transport
already refuses a peer the roster does not name, before a single packet flows.
Read that way, it is also the kind of rule somebody eventually deletes as dead
weight.

It is aimed at **a member spoofing another member's source address inside its own
legitimate session**: claiming to be someone else to a service on the far side.
Without it, membership buys an attacker the ability to impersonate every other
member at the IP layer, and every access rule written in terms of addresses
becomes decoration.

That is why the refusal names the session. The interesting fact about a spoofed
packet is not that it happened — it is **which member sent it**.

## Derived from the device id, not the transport key

§2.5 says "the session's key". This uses the device id, and the departure is
recorded rather than quiet.

**On the threat above the two are identical.** Under either derivation a member
can present only the address its session resolves to, and cannot forge another's
without holding a key the roster names for it.

**They differ on stability.** Deriving from the transport key would move a device
whenever that key rotated — and transport keys are the ones most likely to
rotate, being software-held and used constantly. Every name, cached route and
address-shaped access rule pointing at the old address would dangle. §3.2 has a
person typing `name.<suffix>`; an address that moves under a name is a broken
name.

**And on cost.** A `Session` exposes an authenticated `DeviceId` and no key.
Deriving from the transport key would mean adding an accessor to the shared
interface that every transport implementation and the behavioural suite must
carry, for a derivation that can use what is already there.

An address is stable while a device's *identity* is. Rotating a **signing** key
does move it — but that is already a re-enrolment, since the roster then sees a
different device.

## Validation consults nothing beyond the session

The transport resolved a key to a device once, at establishment. At packet time
the check is `address_of(session.peer()) == source`. No roster lookup, no cache,
no membership list.

Consulting anything further would put a second authority in the path of every
packet — one that could disagree with the roster under exactly the conditions
where it matters. A scan test asserts none of that state exists here.

## Split routing is enforced, not configured

§2.6 requires the tunnel to carry only the network's prefix and never a default
route. The product reason is blunt: a VPN that captures everything drains the
battery, breaks streaming, and gets switched off — and a tunnel a person switched
off protects nothing.

Checking the destination in code means a misconfigured routing table cannot
quietly turn this into a full tunnel. There is nowhere for a default route to
come from.

An outbound refusal is a **different outcome** from an inbound drop. One says a
caller addressed the wrong place; the other says a peer lied. They are separate
types, so an ordinary application mistake cannot be read as an attack.

## An incomplete header is never parsed

A 39-byte packet contains bytes 8 to 24, so a naive implementation reads a source
address out of it quite happily. This refuses anything shorter than a complete
40-byte header.

Reading a field out of an incomplete header is how a truncated packet becomes a
plausible-looking lie — and the first version of this crate did exactly that
until a test caught it.

## This layer decides nothing the roster decides

A packet is accepted because it arrived on an authenticated session and its
source matches. That is a statement about the packet, never about the peer's
standing, which the roster has settled and may settle differently a moment later.

There is no `Role`, no `is_admin`, no permitted-device set, and a scan asserts
so. The cheapest way to keep a distinction true is to have nothing that could
express the other thing.

## What a real device would still have to prove

Nothing here creates a TUN device. The rules are the valuable part and they are
testable with no privileges; a real device needs administrator rights and a
platform driver, and binding an untestable requirement to a testable one leaves
the testable part unverified in practice — which is what happened to the NAT
matrix before it was separated out.

So carrying packets sits behind a small interface with an in-memory
implementation, and the expectations are written against the interface. A
`windows-daemon` or `android-client` device inherits them unchanged. **What no test
here can prove** is that a real TUN device delivers packets the way this expects.

## Deliberately elsewhere

| Deferred | To |
|---|---|
| Creating the device, routes, resolver | `windows-daemon` |
| The same through `VpnService` | `android-client` |
| Deciding when the tunnel is up | §2.6b — a person's deliberate act |
| Resolving names under the suffix | whoever serves the suffix |
| Address-to-device reverse lookup | open; a table, since the hash does not invert |

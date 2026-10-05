# Overlay addressing and packet rules

How an address is computed, and what makes a packet acceptable. A second
implementation following this computes the same addresses and reaches the same
verdicts.

## 1. Scope

Addressing and packet judgement. It does not cover creating a TUN device,
installing routes, or resolving names — see §7.

## 2. Addressing

```text
device part = BLAKE3::derive_key("peerfectly tunnel address v1", device id)
address     = network prefix || leading bytes of device part
```

The device id is the 32-byte identifier the roster assigns a device, itself
derived from that device's **signing** key.

A keyed derivation rather than a plain hash, so an address cannot collide with
any other value derived in this system, and so a change to the scheme is a
change to that context string.

### Why the device id, not the transport key

DESIGN.md §2.5 says the `/128` derives from "its public key" and that a
packet is dropped unless its source matches "the hash of the key of the session".
This uses the **device id**, which is a deliberate reading of what §2.5 is *for*
rather than of its letter.

- **On the threat the rule exists for, the two are identical.** A member can
  present only the address its session resolves to, and cannot forge another's
  without a key the roster names for it.
- **They differ on stability.** Deriving from the transport key moves a device
  whenever that key rotates — and transport keys rotate most, being software-held
  and used constantly. Every name, cached route and address-shaped rule pointing
  at the old address would dangle.
- **And on cost.** A session exposes an authenticated device id and no key.

An address is stable while a device's *identity* is. Rotating a **signing** key
changes the device id and so the address — but that is already a re-enrolment,
because the roster then sees a different device.

## 3. The prefix

Taken from the `ula` field of the network parameters, as signed. Each byte is
eight bits of network.

| | |
|---|---|
| Longest prefix | 64 bits |
| Shortest device part | 64 bits |

**A prefix longer than the bound is an error, not a truncation.** Overlapping
device parts would put two devices at one address, which is the confusion this
whole layer exists to prevent.

A founder may derive a prefix:

```text
prefix = 0xfd || first 7 bytes of BLAKE3::derive_key("peerfectly tunnel prefix v1", network id)
```

`0xfd` is the locally assigned half of the unique local range, so a derived
prefix is a valid ULA. **This is offered and not enforced**: a node reading a
prefix that was not derived this way still uses it, because the roster is the
authority on what the parameters are. An admin who chooses badly can collide with
another network — which matters only on a host in both, and is a
misconfiguration to warn about rather than a packet to drop.

## 4. Inbound packets

A packet arrives on a session. The session carries the device identity the
transport authenticated at establishment; **that is the whole input** beyond the
packet itself. No roster lookup, no cache, no membership list — anything more
would put a second authority in the path of every packet.

In this order:

1. **Length above the bound** → refused.
2. **Length below a complete 40-byte IPv6 header** → refused as too short. Note
   this refuses a 39-byte packet even though bytes 8–24 are present: reading a
   field out of an incomplete header is how a truncated packet becomes a
   plausible-looking lie.
3. **Source outside the network prefix** → dropped.
4. **Source not equal to `address_of(session device)`** → dropped, and this is
   the case the rule exists for.
5. **Destination not an address this device holds** → dropped. For IPv6 that is
   `address_of(own device)`; for IPv4 the address the holdings give this device,
   and a device holding none accepts no IPv4 packet at all.
6. Otherwise → accepted.

The source is bytes 8 to 24 of the header; the destination is bytes 24 to 40. A
complete header holds both, so step 2 already guarantees the destination is
within the packet wherever the source was, and the IPv4 rules do the same at
twenty bytes.

Multicast, broadcast and link-local get no case of their own. None of them is an
address this device holds, so step 5 refuses them like anything else — a rule
with no exceptions has no exception to get wrong.

**Every drop is reported, and a drop for a wrong source or a wrong destination
names the session.** A rule that fires silently is a rule nobody can trust, and
the interesting fact about such a packet is which member sent it. There is no
exemption on the way in, unlike the way out, where this machine's own
link-local and multicast chatter is refused constantly and not recorded: an
inbound packet addressed elsewhere had to pass its sender's own outbound rule to
arrive, so it is not ordinary noise.

### The destination half

Checking only the source leaves a member — inside its own session, with its own
honest source — able to put a packet addressed to *anything* onto this device's
interface: another member's address, which the host above then handles as though
this device were that member; a multicast group, reaching every listener on the
machine; a link-local or local address, injected into the host from the overlay.
The way **out** has refused a destination the network does not cover since §2.6.
The way in is no more trusting.

A tunnel therefore belongs to one device and is built with it. There is no
constructor that makes one without: a tunnel that does not know which device it
is has exactly one behaviour available, which is to accept whatever a packet is
addressed to.

### What the rule is actually for

Read as a defence against outsiders it looks redundant — the transport already
refuses a peer the roster does not name before a packet flows. It is aimed at a
**member spoofing another member's source address inside its own legitimate
session**. Without it, membership buys an attacker the ability to impersonate
every other member at the IP layer, and every access rule written in terms of
addresses becomes decoration.

## 5. Outbound packets

The destination is bytes 24 to 40.

- **Below a complete header** → refused as too short.
- **Destination outside the network prefix** → refused.
- Otherwise → carried.

An outbound refusal is a **distinct outcome** from an inbound drop: one says a
caller addressed the wrong place, the other says a peer lied. Collapsing them
would make an ordinary application mistake look like an attack.

## 6. Claimed prefixes

Exactly the network's prefix, and never a default route. §2.6's split routing is
a property of the code rather than a hope about what an installer wrote into a
routing table: a misconfigured route cannot turn this into a full tunnel, because
there is nowhere for a default route to come from.

Nothing widens the claim short of different signed network parameters.

## 7. What a receiver must not do

- MUST NOT parse a field out of an incomplete header.
- MUST NOT accept a source other than the session's own derived address.
- MUST NOT consult a roster, cache, or membership list at packet time.
- MUST NOT treat accepting a packet as a statement about the peer's standing. A
  verdict here is about the packet, **never about the peer** — the roster has
  settled that, and may settle it differently a moment later.
- MUST NOT claim a default route.
- MUST NOT truncate a device part to fit an over-long prefix.

## 8. Deliberately absent

| Not here | Where |
|---|---|
| Creating a TUN device, routes, resolver | `windows-daemon`; `android-client` via `VpnService` |
| Deciding when the tunnel is up | §2.6b — a person's deliberate act |
| Resolving names under the suffix | whoever serves the suffix |
| Address-to-device reverse lookup | open; a table, since the hash does not invert |

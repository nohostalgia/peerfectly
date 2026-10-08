# Design

The principles peerfectly is built on, and the reasons for them. Code comments cite these sections
as `DESIGN.md §2.6c` or, within a file that already names this document, simply `§2.6c`. The numbers
are kept stable because they are cited. Where a number is missing, that section isn't published
here.

Most sections are **constraints**: changing one means redesigning, not editing. A few record a
decision that was open and is now settled.

## 0. Ground rules

Not negotiated, and cited from the code as `DESIGN.md §0`:

- **No cryptographic primitive is written by hand.** The cryptographic code is almost entirely
  composition and serialisation over reviewed libraries.
- **Every signature carries domain separation with the network id,** so a signature made for one
  purpose or one network is never valid for another.
- **The canonical CBOR decoder refuses input that isn't canonical.**
- **Timestamps never decide order,** nor validity. Causal order comes from the graph.
- **The transport sits behind a replaceable interface** (§2.1).
- **A network's suffix is a signed roster parameter,** never a constant in the code (§2.5).

And for testing:

- **The roster's merge is tested with property-based tests.**
- **Cryptographic test vectors are shared** and run on every platform.
- **No network code is merged without a test against a real-world NAT edge case.**

## 1. What this is

A peer-to-peer overlay network that lets a person reach their own devices from anywhere, by simple
names (`nas.<suffix>`), without registering a domain, without an account, and **without the operator
of any service being able to enter the person's network**.

**The central property:**

> No key controlled by an operator can be admitted into a person's network, and the network keeps
> working if the operator disappears.

Every technical decision is judged against that sentence. A choice that weakens it is refused, or
declared as a compromise.

**Not goals:** an anonymity VPN or exit nodes; a multi-tenant product for organisations; sharing
between separate people's networks; beating other products on features. The aim is a different
trust model, not more features.

## 2. Architecture

### 2.1 Transport

[iroh](https://github.com/n0-computer/iroh) provides connectivity: QUIC with TLS 1.3, an endpoint
identity per key, hole punching, relays and discovery. It removes the hardest part of the project
(NAT traversal, relays, path migration), leaves the UDP socket under control for hole punching, and
QUIC migrates connections natively, which a phone changing networks needs.

Considered and set aside: userspace WireGuard, which is more conservative cryptographically but does
no NAT traversal and is hostile to hole punching; WebRTC, kept in mind only for a future
browser-only mode.

**Design requirement:** the transport sits behind an internal interface of about four methods
(connect to a key, send, receive, close), so replacing it touches nothing else.

### 2.3 Root of trust

An admin's signing key lives in the device's secure hardware where it has one (a phone's keystore,
a PC's TPM), **not exportable**, and its use is gated by the person: biometrics, a PIN, Windows
Hello or a passphrase.

Consequences:
- **The roster supports more than one algorithm from day one.** Phone secure elements impose P-256,
  while device and transport keys are Ed25519.
- **Recovery cannot rely on exporting the key.** It has to come from more than one independent
  admin, or from a recovery mechanism that authorises a reserve key in advance. Neither exists yet:
  see §10.2.

### 2.5 Naming and addressing

Names live under `.internal`, reserved by ICANN in 2024 for private use: `nas.<network>.internal`.
**Never an invented top-level domain that isn't reserved:** it risks being delegated one day, leaks
queries to the root servers, and can't be changed without breaking every certificate.

**The suffix is a signed network parameter in the roster, never a constant in the code.** That keeps
the choice reversible.

**Addressing:** an IPv6 ULA prefix derived from the network, and a `/128` for each device derived
from its public key. **Routing becomes authentication:** a packet whose source does not match the
hash of the key of the session it arrived on is dropped. Each device also gets an IPv4 address in
the CGNAT range, for software that only speaks IPv4.

### 2.6 Network mode

A TUN interface with **split routing**: only the network's own prefixes are routed into the tunnel,
never a default route. Ordinary traffic does not go through it. A VPN that captures everything costs
battery and bandwidth, breaks streaming services, and gets switched off.

### 2.6b Activation on request

On a phone the tunnel is **not** always on. The person switches it on and off deliberately, like a
connection to their own home. That makes a background process being killed a non-problem for
correctness, because nothing promised continuity. It also removes the most fragile onboarding step,
"always-on VPN". *Your network is off until you switch it on.*

Binding consequences:
- **Fast restore is the main performance metric.** From switching on to the first useful session:
  under 500 ms, from cached endpoints, without waiting for the rendezvous.
- **Switching on is reachable outside the app:** a Quick Settings tile, a shortcut.
- **"Always-on" stays an advanced option,** never a requirement.

### 2.6c Nothing outside the node

**With the network off, a device sends nothing to any infrastructure.** No separate HTTPS channel, no
polling, no background sync. There is one engine: when the person switches on, the node starts and
syncs; when they switch off, everything stops. This is a property anyone can check with a packet
sniffer, and an app that talks to infrastructure while the person believes it is off contradicts the
central promise.

Binding consequences:
- **Admin acts made with the network off wait in a local queue.** The roster's structure supports
  that natively: the operation enters the local graph and spreads at the next sync.
- **An admin act switches the network on,** visibly. The gesture is the consent. Without this, a
  revocation can sit in a queue for days while the person believes it took effect: the most
  dangerous silent failure in the system.
- **The device list shown with the network off is the last known state, with its time,** never a
  presumed current one.
- **Operations not yet synchronised are shown,** clearly and persistently.

### 2.8 Rendezvous and relay

- **Rendezvous:** written here, deliberately small. A device publishes a signed, sealed record of
  where it can be reached, with a sequence number; anyone can fetch it. There is no authentication:
  the signatures do all of it. A record whose sequence does not increase is refused.
- **Relay:** `iroh-relay`, self-hosted. Don't write a relay.
- **Address discovery** runs on the relay's own host, so production depends on no public service.
- **Limits per key** (bandwidth, concurrent sessions) from the first day.
- **An admin only reaches its own network's relay.** A join payload that names another relay is
  refused before any endpoint exists.
- **Changing a network's relay is a signed admin act.** It carries the new relay and, for a window,
  the one being left, so devices move together without the tunnel dropping.

### 2.9 Path selection

In order:
1. Direct on the LAN: local candidates, multicast discovery, the last LAN address known.
2. Direct over global IPv6, when there is one.
3. A UDP hole, punched with simultaneous open.
4. The relay.

**The relay is opened at once, in parallel with the direct attempt.** Nobody waits for hole
punching: the session migrates when a direct path succeeds. Realistically some connections stay on
the relay for good, since carrier-grade NAT is common on mobile and fixed-wireless networks. **The
relay is permanent infrastructure, not an edge case.**

**Sessions exist while something uses them.** The first packet for a member opens one, and what
arrives while it opens waits rather than being dropped. A session that carries nothing for ten
minutes is closed. While open, a path is kept alive every three seconds and left after about nine
seconds of silence. Nobody is dialled for merely being in the roster.

The cost is a pause of tens to hundreds of milliseconds before the first packet after ten idle
minutes, and a `peers` report that looks when asked rather than remembering.

**With no session open, the transport sends one thing: the relay keep-alive, once a minute,** with
the relay set to match. Finding this device's public address pauses until a session opens, and runs
alongside its handshake. iroh's defaults spend about a gigabyte a month on those two things, an
address probe every twenty-odd seconds and a ping every fifteen, whatever the network's size.
Neither could be configured up to iroh 1.3, so they come from the project's fork of iroh until a
release carries them (`deny.toml` names it and its exit condition). The cost is a dead relay
connection noticed within a minute instead of fifteen seconds, and a direct path found a moment
later after a rest.

## 3. The product surface

### 3.1 First use

The intended flow:
1. A person creates a network on their phone: a device name and the VPN permission. The phone makes
   the admin key in its secure hardware and founds the network.
2. They install the daemon on another device, which makes its own keys and shows a QR code, as a
   picture or in a terminal.
3. From the phone they scan it. The phone shows the key's fingerprint, a name and its capabilities,
   then asks for the biometric confirmation and signs the admission.
4. The new device receives the whole roster. **Every device appears at once,** not one by one.
5. Right after, the app offers a second admin and recovery, instead of burying them in a settings
   menu.

Founding from a desktop works too.

### 3.2 Everyday use

On a desktop or a server the tunnel stays up: a person types `name.<suffix>` and that's it. On a
phone they switch the network on (tile or app), then use `name.<suffix>` in a browser.

A name typed while the tunnel is off fails like any unknown name. The app should turn that into an
action, *your network is off, tap to switch it on*, rather than leave a browser error.

**An address that moves is worse than a name that stays:** people type names, and anything that
pins an address breaks when the address changes.

### 3.3 Error states handled explicitly

This is where people lose confidence, so none of it is optional:

| State | Required behaviour |
|---|---|
| A device offline | "`laptop` is offline, last seen 3 hours ago", never a bare DNS error |
| Client isolation on the Wi-Fi | detect it and say so: same network, not reachable |
| Tunnel off, and a name is tried | an actionable notification to switch it on |
| Operations queued, not yet synced | a persistent, visible indication. Never let a revocation look effective before it is |
| A phone's service killed while in use | restart. It isn't a correctness problem: the tunnel promised no continuity |
| A roster that can't be confirmed as recent | a cautious mode: serve who was already allowed, refuse new connections |
| Only one admin left | a permanent warning that can't be dismissed |

## 4. The roster

### 4.1 The operations

Seven kinds, and resist adding more, since each new kind multiplies against every conflict rule:
`create_network`, `add_device`, `revoke_device`, `promote`, `demote`, `rename`, `set_network`.

**What is not in the roster:** current addresses, online state, exposed ports. Those are ephemeral
facts a device knows about itself. It signs them itself and distributes them through the rendezvous.
The roster holds only what needs authority.

### 4.2 An operation

An operation's id is the BLAKE3 hash of its canonical bytes, **256 bits, never truncated**. Its
parents are the operations its author knew, which makes the roster a graph. It carries the network
id, against replay across networks. Its timestamp is **for display only, never authoritative**:
causal order never depends on clocks.

### 4.6 Snapshots and compaction

An admin periodically signs a snapshot, *the state up to here is X*, and nodes may drop the
operations before it.

**A snapshot is not authoritative in a strong sense:** operations an isolated node holds that the
snapshot does not include are still merged. Snapshots carry a **monotone number**, and a node refuses
to go backwards, which blocks a rollback through a compromised rendezvous.

How long a roster stays valid without news is a signed network parameter, `snapshot_window`, 7 days
by default. What dates a roster is an *attestation*, which carries no state: see
`crates/daemon/README.md`.

### 4.7 Distribution

No privileged channel. Whenever two nodes connect, they exchange a digest of the operations they
hold, and only where the digests differ the ids, and they pass each other what is missing. On a LAN
that happens by itself. Elsewhere it happens through any peer, and a rendezvous could hold the roster
without being able to alter it.

**Every operation is pushed the moment it is admitted**, to the open sessions and to the device's
**neighbours**. These are three members chosen by rendezvous hashing over the ids of their admission
operations, plus the members that chose this device, a claim the roster can check. Neighbours pass
on what they receive, so an operation crosses a network of thousands in a handful of hops while no
device contacts more than a few others in the background. A burst of operations is pushed once. A
device that comes up, or changes network, reconciles with its neighbours straight away, and every
hour as a safety net.

Attestations travel the same way. Each carries the time its admin signed it, and freshness is
measured from the earlier of that and its receipt, so an attestation relayed late reads as old as
it is, and a signed time can make a roster read older but never fresher. An admin on a phone gives
its attestation to its neighbours and need not meet every member.

The effect: a node off for a month catches up at its first connection with anyone, and revocations
spread by contagion.

## 6. Threat model and accepted limits

These are documented publicly rather than left for a researcher to find.

### 6.1 What the model guarantees

- A compromised rendezvous **cannot inject a device**. It can censor, delay, and see metadata.
- The relay sees only bytes encrypted end to end.
- **The signing key is not extractable, and how much that's worth depends on the platform:**
  - **Android:** made in the keystore, not exportable.
  - **Windows with a TPM:** made in the TPM through CNG, not exportable. **Consent is enforced by the
    key**, not by a prompt of ours.
  - **Linux:** in the TPM behind a passphrase where there is one; otherwise a file sealed with a
    passphrase.
  - **A machine that can't protect a signing key is a member, not an admin, and says so.**
- **The transport key is a software secret,** sealed to the machine and kept where only the system
  and administrators can read it. A process running as a person can't read it; one running as an
  administrator can. That is declared, not solved.
- Causal order does not depend on clocks.
- No operation can be replayed: its id is the hash of its content, and its parents fix its place.

### 6.2 Accepted limits

| Limit | Mitigation |
|---|---|
| **Equivocation:** a compromised admin can show different branches to different nodes | **Detection.** Every node tracks the last head seen from each author and compares at every meeting. Incompatible heads from one author raise a strong alarm. It doesn't prevent it, it makes it visible |
| **Revocation window:** an isolated node accepts a revoked key until its roster stops being fresh | Bounded by `snapshot_window` (7 days by default). Past it, a node carries no traffic to or from non-admins, and keeps syncing to catch up |
| **Any admin can expel the others** | open: whether the founder should be irremovable |
| **A person doesn't check the fingerprint when pairing** | pairing in both directions, with a short code derived from both keys shown on both screens (as Signal and Bluetooth do) |
| **No access list per peer:** every member reaches every exposed service | known, not yet built. Nothing is open until the person opens it: `expose` opens a port to **one** network, through its interface only. What is exposed to a network is reachable by all its members. On Windows, `expose` *opens*, it does not close: a program Windows' own prompt allowed stays reachable from the LAN regardless |
| **We write the client:** an update could exfiltrate keys | open source and **reproducible builds**. Without them, the central property is a promise instead of something you can check |
| **One VPN tunnel at a time** on Android and iOS | none: a platform limit |

## 7. Platform constraints

### 7.1 Android

The tunnel is switched on by the person (§2.6b), so being killed in the background matters far less
than for an always-on client.

- **`VpnService` has no per-domain split DNS.** Declaring a DNS server on the tunnel sends it every
  query. The app runs a resolver that answers for the network's suffix and **forwards the rest** to
  the system's own resolver, so it is on the critical path of every lookup while the tunnel is on.
- **A foreground service with a permanent notification** while the tunnel is on. The notification is
  also the quick way to switch it off.
- **The Quick Settings tile** is the main way to switch on, not an extra.
- **With the engine off, the app sends nothing:** no periodic background job towards any
  infrastructure (§2.6c).

### 7.3 Desktop

- **TUN:** `wintun` on Windows, `/dev/net/tun` on Linux, `utun` on macOS.
- **Split DNS:** NRPT rules on Windows, `systemd-resolved` with `~<suffix>` on Linux,
  `/etc/resolver/<suffix>` on macOS.
- **A local web interface, if there is one, is served on `127.0.0.1`** with a session token from the
  daemon and an `Origin` check: any web page open in the browser can try requests to `127.0.0.1`.
  Not built yet.

## 8. Local discovery

Requirement: **the network works with the internet off.** If LAN candidates came only through the
rendezvous, failing to connect half a metre from the device would be an absurd failure for a product
that sells itself on not depending on anyone.

- **A signed multicast announcement on a dedicated UDP port:** a public key and its endpoints. **Not
  mDNS with names.** The name is already in the roster; what's needed is only that a key is present,
  and where. It also avoids colliding with Bonjour or Avahi.
- **Multicast on Wi-Fi is unreliable,** filtered or sent at low bitrates. So announcements repeat, and
  **the last known LAN addresses are tried first.**
- Paths are re-evaluated at every interface change, or a device stays on the relay while at home.
- **A discovered device proves nothing.** Anyone on the LAN can announce a key. Discovery proposes;
  an admin's signature authorises.

## 10. Scope

### 10.2 Outside the first version, and said so

- A local certificate authority and certificates. Connectivity is shown with `ssh`, `curl` and
  overlay addresses.
- A desktop app beyond the daemon and its command line.
- iOS.
- Public bindings, public DNS, ACME, an SNI proxy.
- **A second administrator and delegation, and a recovery phrase.** With one admin, **a lost admin
  device is a lost network.** Tell anyone trying it.
- Subnets, exit nodes, access lists.

### 10.4 The measurement that gates the architecture

Before anything else: two daemons on different networks, and **one number, the share of connections
that go direct versus through the relay**, including from mobile data. If real networks almost never
let a direct path through, the whole plan changes. `crates/transport-iroh`'s `natprobe` exists to
take that measurement.

## 13. Decisions that were open

### 13.3 The name

**peerfectly**, published by *nohostalgia*. It replaced a placeholder everywhere, protocol constants
included, before anything was published. The suffix is a different question: it stays a signed
parameter chosen per network (§2.5).

### 13.7 No idle timeout

Should the tunnel switch itself off after a while without use? **No.** It stays on until the person
switches it off. A timer would save some battery and add a second way for the network to "not work"
without the person having decided it. Measure real consumption before adding one.

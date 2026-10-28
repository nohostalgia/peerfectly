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

Sessions between devices open with a **Noise IK handshake over UDP**, from convesso. A device is
known by its transport key, and the dialler must know the key it dials before its first packet.
There is no certificate authority and no name service: the roster decides which keys are let in,
inside the handshake. The link to the relay is TCP, which keeps a resting device reachable and
carries traffic where UDP does not get through; it can be wrapped in TLS where only TLS gets out.

This removes the hardest part of the project: NAT traversal, relaying, and following a device that
moves. One UDP socket serves the relay and peers alike, so the address the relay sees is the one
peers will reach, and a peer that moved is followed through the relay within about a second, which
a phone changing networks needs.

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
  under 500 ms, from cached endpoints, without waiting for the relay.
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

### 2.8 Relay

- **Relay:** convesso's relay, self-hosted, run as one container, `peerfectly-relay`. Don't write
  a relay.
- **Pinned by its key.** The roster signs a relay as `key@host:port`, or `tls://key@host:port` for
  a link wrapped in TLS, so it authenticates the relay with nothing beside it. A node accepts no
  other relay in its place, and an impostor fails the handshake.
- **Its key is asked of its host, and confirmed by a person.** Beside the relay, the container
  answers `GET /relay` over HTTPS with the key and port it serves. A device founding a network on
  that host, or moving a network to it, asks, shows the key, and signs nothing until its person
  confirms it against the line the container printed when it started. That is trust on first use:
  TLS there hides the request and authenticates nothing. A join asks nothing: the invite names the
  relay as `key@host:port`, taken from the inviting admin's roster, and what the device uses
  afterwards is the relay in the signed roster it is brought.
- **No address service.** Devices hear each other's addresses on the local network (§8).
  Elsewhere, the two ends of a session swap theirs through the relay and probe them at once.
- **Address discovery** runs on the relay itself: it tells each device the address it sees it at,
  inside their session, so production depends on no public service.
- **Limits per key** from the first day.
- **An admin only reaches its own network's relay.** A join payload that names another relay is
  refused before any endpoint exists.
- **Changing a network's relay is a signed admin act.** It carries the new relay and, for a window,
  the one being left, so devices move together without the tunnel dropping.

### 2.9 Path selection

In order:
1. Direct on the LAN: the addresses local discovery heard (§8), and the last LAN address known.
2. Direct over global IPv6, when there is one.
3. Direct over IPv4, through a hole both sides open by probing each other at the same moment.
4. The relay.

**Nobody waits for a direct path.** A dial tries every address it knows at once, and the relay a
quarter of a second later. A session that opens through the relay moves to a direct path as soon as
one has been seen to work both ways. No ports are guessed: behind a NAT that gives each destination
a port of its own, the session stays on the relay. Realistically some connections stay on the relay
for good, since carrier-grade NAT is common on mobile and fixed-wireless networks. **The relay is
permanent infrastructure, not an edge case.**

**Sessions exist while something uses them.** The first packet for a member opens one, and what
arrives while it opens waits rather than being dropped. A session that carries nothing for ten
minutes is closed. A direct path is trusted for fifteen seconds after its last packet; after a
longer pause the next packet takes the relay while one probe checks the path. Nobody is dialled for
merely being in the roster.

The cost is a pause of tens to hundreds of milliseconds before the first packet after ten idle
minutes, and a `peers` report that looks when asked rather than remembering.

**One session per peer.** When two devices dial each other at once, both keep the session the
device with the lower id dialled, and close the other.

**With no session open, the transport sends one thing: the relay keep-alive,** one packet when the
link to the relay has been silent for a minute, about 4.6 MB a month. Addresses, probes and the
search for a direct path are all caused by a session in use, and a device learns its public address
from the relay, inside their session, rather than by probing for it. The cost is a dead relay link
noticed within about eighty seconds, and a direct path found a moment later after a rest.

## 3. The product surface

### 3.1 First use

The intended flow:
1. A person creates a network on their phone: a device name and the VPN permission. The phone makes
   the admin key in its secure hardware and founds the network.
2. To add a device, they make an **invite** for it: a name, full or light, its groups, and how long
   it stays open (a day by default). The invite is a QR code or a line of text, sent by whatever
   channel reaches the person who will use it.
3. On the new device, `join <invite>` (or a scan in the app) makes fresh keys, sends a **request**,
   shows its key's fingerprint, and returns. Nobody has to wait: the admin's daemon collects the
   request when it next can, and keeps it as **pending**.
4. The admin approves the request when they choose, from the pending list (`peerfectly pending`, a
   page of the app, a notification on the phone). Where the two are in one room, they compare the
   fingerprint. Approving asks for the person's consent and signs the admission.
5. The new device receives the whole roster, from the admin or, when the admin is off by then, from
   a member near it. **Every device appears at once,** not one by one.
6. Right after, the app offers a second admin and recovery, instead of burying them in a settings
   menu.

Founding from a desktop works too. Every step survives a restart on either side (§3.4).

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

### 3.4 Enrolment and the trust it rests on

**Every design needs an anchor outside the protocol for the first contact.** The invite reaches the
right person, or a payload comes from them, or both people stand in one room, or an identity provider
vouches for the person (Tailscale's login; its pre-authorised keys are bearer tokens like these
invites). peerfectly takes the first: **the invite is a bearer token**, delivered by the admin out of
band. It carries the relay as `key@host:port`, the network id and a 16-byte secret, from which both
sides derive a rendezvous key. The joining device waits at the relay under that key and under its own
transport key. The admin's daemon only dials, as it always has; it never listens.

What defends an invite is what remains around it:
- **Single use and an expiry.** The expiry, a day by default, bounds only the arrival of a request.
  A request that arrived is approved and delivered whenever that happens.
- **A person's review before signing.** A request waits as pending, asking nobody; the list shows
  which request each invite brought, the name it proposes, its key's fingerprint and when it arrived.
- **Both keys proved.** The request proves possession of the signing key once, at the join, and of
  the transport key on every channel. Its proof is bound to the network, the rendezvous and the
  keys, so it cannot be carried to another invite.

The device cannot count on learning that its invite was taken. Once a request has arrived nobody
dials the rendezvous again until it is approved, and a device brought an admission that does not name
its keys refuses it and says so. A theft shows mostly as a person whose join never ends, and an
approved request the admin cannot match to them.

**There is no six-digit code any more.** It assumed both people present, and it protected less than
it seemed:
- *Remotely it was a second bearer secret.* Read off the admin's screen and sent the way the invite
  was, it reached whoever read the invite.
- *It could be ground.* It was derived from the handshake hash of `Noise_IKpsk2`, where the responder
  chooses its ephemeral after seeing the initiator's. Someone holding the invite could answer the
  admin's dial and search ephemerals until the code matched: about 2^20 Curve25519 operations,
  seconds on a few cores. A short code resists that only with a commitment from each side made before
  seeing the other's, and it had none.

In person, the **fingerprint of the joining device's signing key** replaces it: 20 hexadecimal
characters, shown on the joining device and beside the pending request. It comes from the key, not
from a channel, so no choice of ephemerals moves it, and finding another key with the same one is out
of reach.

**The pending state is believed only as the daemon wrote it.** Invites, requests and a join in
progress are covered by the network's checkpoint (§6.1), and a join file is also signed by the
machine key. Records changed outside the daemon, while it runs or while it is stopped, are not used,
and that is said. This does not stop someone running as root on the machine, who can use the machine
key as the daemon does. They still cannot approve, because approving needs the network's signing key
and its person. A genuine older copy put back is bounded by the expiry and by the roster, which
records what was admitted.

**Delivery proves nothing on its own.** The roster a joining device is brought is adopted only where
it names the invited network, carries admins' signatures and names the device's own keys. That is
why anybody may deliver it. The admin that approved, the device's anchors and the members that would
choose it as a neighbour all dial it, with backoff. The admin stops once it has delivered. The others
stop once they have met the device, or three days after the admission was signed. The joining device
is the only side that ever accepts an unauthenticated peer, and a call from anybody else costs it one
refused exchange.

### 3.5 Which acts need an administrator

One rule, in the daemon, on every platform, and the command lines' usage is derived from it:
- **Anyone, on their own networks:** `status`, `peers`, `address`, `exposed`, `pending`, `up` and
  `down`.
- **An administrator** (an elevated console on Windows, `sudo` on Linux): everything else, `forget`
  included.

The command lines refuse before an act starts, not at its signature. On the phone, with one person,
the same acts ask for the phone's lock before they are sent.

## 4. The roster

### 4.1 The operations

Nine kinds, and resist adding more, since each new kind multiplies against every conflict rule:
`create_network`, `add_device`, `revoke_device`, `promote`, `demote`, `rename`, `set_network`,
`set_device` and `admit_batch`. `set_device` changes one device's mode, groups, assigned IPv4
address or relay, each field resolving on its own (last writer wins). `set_network` sets one
parameter, so concurrent changes to different parameters both stand. `admit_batch` admits many
devices as one act (§5.2).

**What is not in the roster:** current addresses, online state, exposed ports. Those are ephemeral
facts a device knows about itself. It signs them itself and announces them on the local network
(§8); between networks, two devices swap them through the relay, inside their own session. The
roster holds only what needs authority.

### 4.2 An operation

An operation's id is the BLAKE3 hash of its canonical bytes, **256 bits, never truncated**. Its
parents are the operations its author knew, which makes the roster a graph. It carries the network
id, against replay across networks. Its timestamp is **for display only, never authoritative**:
causal order never depends on clocks.

### 4.6 Snapshots and compaction

Right after every admin act takes effect, the admin's daemon signs a **root**, *the state up to
here is X*, with its attestation key and nobody present. A batch is one act. The root carries the
Merkle root of the state (§5.1), the root before it, a generation number, the change from that root,
and the signer's own leaf and proof. Full members verify a root by deriving it; light members by the
signer's proof against the root before, so they hold no admin keys. A full member compacts beneath
every root it has verified, so the graph it keeps is a window, not the whole history.

**A root is not authoritative in a strong sense:** operations an isolated node holds that the root
does not include are still merged. Roots carry a **monotone generation**, and a node refuses to go
backwards, which blocks a rollback by anyone replaying an old root. Between two sibling roots from
admins acting at once, the heavier (generation, then hash) is followed, and the revocations of both
apply.

How long a roster stays valid without news is a signed network parameter, `snapshot_window`, chosen
when the network is founded and **none by default**: an island keeps working (§6.2). Where a network
sets one, what dates a roster is an *attestation*, which carries no state: see
`crates/daemon/README.md`.

### 4.7 Distribution

No privileged channel. Whenever two nodes connect, they exchange a digest of the operations they
hold, and only where the digests differ the ids, and they pass each other what is missing. On a LAN
that happens by itself. Elsewhere it happens through any peer, and whoever carries the roster can
withhold it but never alter it.

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

## 5. Scale

The same network serves five devices at home and a fleet of millions. A light member's costs stay
constant as the network grows; a full member's grow with the logarithm of its size, or linearly and
small. A five-device network behaves as it always has.

### 5.1 State as a Merkle tree

The state root is the hash of two subtrees. The **devices** subtree is a compressed sparse Merkle
tree, with each device's leaf at a position derived from its id, so a leaf's place does not depend on
the order of admission. The **parameters** subtree is a small tree keyed by name. A membership proof is
a leaf and about log2(N) hashes. Someone grinding keys to share long prefixes lengthens proofs near
their own leaves only, by the bits they ground; that is accepted.

The roster's permanent set of revoked devices is gone. It only stopped the same key coming back, and a
thief can always present a new one. A join always makes fresh keys. Revocation still wins over
concurrent work inside the window; after compaction a revoked device is simply absent.

### 5.2 Batches

`admit_batch` admits up to 65,536 devices with one signature and one consent. Its signed header
commits to the Merkle root of the entries and to their layout: how many pieces, and the root of their
hashes by index. The entries travel unsigned, in pieces of at most 8 KB, each with its proof against
the layout. A piece proves which piece it is, so a node can say what it holds as a bitmap and pass
on what it has before it has everything, and nobody can make it believe it holds a piece it lacks.

**A batch takes effect only when it is whole.** Pieces that arrive before their header are refused,
so storage is spent only on authenticated data, and a node keeps only a few incomplete batches.
Revocations are anchored off batches younger than a few minutes, so a revocation never waits for a
batch to finish arriving. Revoking an admin keeps that admin's whole batches as ancestors, and the
person is told before signing which acts would be voided.

A batch declares an IPv4 block and its entries carry their addresses. An assigned address beats a
derived one; two admins assigning one address at once resolve by last writer, and the loser falls
back to its derived address and gets the assigned one back if the winner leaves it.

### 5.3 Light members

A light member holds no roster, no admin keys and no clock: its own leaf and proof, one current root,
and the changes since. Microcontrollers are the extreme case. It has the same rights on the network
as a full member, and is given its mode by the admin that invites it (full by default) or by a batch.
Admins are always full.

- **One chain, every revocation.** It adopts a root that follows its own; between siblings it keeps
  the heavier. It applies the change carried by every valid root, sibling or not, so the branch it
  follows decides only which admissions it sees first, never which revocations hold.
- **No renewal parameter.** A peer's proof is accepted while the light member still remembers the
  changes from that proof's root to its own. How many it remembers is bounded by its memory. A home
  network practically never asks it to renew; a busy fleet asks within hours.
- **It receives roots, not operations,** and asks for what it needs.
- **It is checked at every session.** Each side of a session sends its leaf, proof and root as the
  first frame, before any payload. A full member always sends its own, because the other side may be
  light. Access groups, held in the leaf, are judged once per session from the initiator's verified
  leaf, so nothing is added to the packet path.

### 5.4 Anchors

An admin can name up to 32 **anchors** (`set-anchors`): full members that stay on. Each light member
picks two to four of them by rendezvous hashing. A light member can reach only full members whose
leaves it holds, so it keeps the leaves and proofs of up to three full members besides the admin that
admitted it: its anchors where the list names any, otherwise full members seen in the last week. It
gets them from the roster it held when it became light, then from the full member that brings it
newer roots. A microcontroller gets them at provisioning. Each one is believed only by its proof
against a signed root, so whoever hands them over can withhold one but never forge one.

On every start, and whenever its admitter does not answer, a light member tries its anchors, its
admitter, the other full members it keeps, the members it has a session with, then the LAN. A light
member whose every known full member is off, and which shares no LAN with one, stays out until one
returns.

An anchor is a full member with no packet interface, run headless. **Never beside the relay:** the
relay's machine holds only the relay's keys, and an anchor there would make whoever takes that machine
a member of every network it anchors.

A big full member keeps its state on disk, in an indexed store (redb), so a phone can be full at a
million devices: about 2 GB on disk, opened and queried within 64 MB of memory. Nothing the store
holds is believed on its own. Every node read is checked to hash to what its parent names, down from
the signed root the checkpoint names (§6.1), so a store changed behind the daemon can hide a device
but never add one.

## 6. Threat model and accepted limits

These are documented publicly rather than left for a researcher to find.

### 6.1 What the model guarantees

- A compromised relay **cannot inject a device**. It sees only bytes encrypted end to end, and can
  censor, delay, and see metadata: which keys use it, and which pairs talk.
- A relay key confirmed wrongly, at founding or at a move, costs availability and metadata, never
  content or membership.
- **The signing key is not extractable, and how much that's worth depends on the platform:**
  - **Android:** made in the keystore, not exportable.
  - **Windows with a TPM:** made in the TPM through CNG, not exportable. **Consent is enforced by the
    key**, not by a prompt of ours.
  - **Linux:** in the TPM behind a passphrase where there is one; otherwise a file sealed with a
    passphrase.
  - **A machine that can't protect a signing key is a member, not an admin, and says so.**
- **The transport key is a software secret,** because sessions are Noise over Curve25519, which no
  TPM computes. It is in memory while the daemon runs. On disk it is sealed to the TPM where there is
  one, so a copied disk is not the key; elsewhere to the machine, behind an access control. A process
  running as the daemon can use it; that is declared, not solved.
- **What a network's folder says is believed only through a checkpoint this machine signed,** with a
  key that lives in the TPM (Windows, Linux) or the hardware keystore (Android), needs nobody, and
  signs nothing a network sees. A roster swapped for another network's, a folder dropped in, a light
  member's state edited, freshness times moved, an invite planted: each leaves the network down and
  reported, and nothing is removed. Nothing is trusted for being there, not even on a first start.
  The checkpoint names what the daemon itself wrote, not what a file holds when it is signed, so a
  file changed while the daemon runs is not vouched for either. Invite records and pending requests
  changed that way are dropped when read, and said.
- **An invite admits nobody on its own.** A request it brings waits for an admin's review and
  signature (§3.4).
- Causal order does not depend on clocks.
- No operation can be replayed: its id is the hash of its content, and its parents fix its place.

### 6.2 Accepted limits

| Limit | Mitigation |
|---|---|
| **Equivocation:** a compromised admin can show different branches to different nodes | **Detection.** Every node tracks the last head seen from each author and compares at every meeting. Incompatible heads from one author raise a strong alarm. It doesn't prevent it, it makes it visible |
| **The eclipse of a single device:** a device that nobody reaches, or that someone keeps from every update, trusts a revoked peer until it hears of the revocation | Connected members hear a revocation within seconds, through roots and gossip, and a light member applies the revocations of every root it sees, sibling or not. No fuse by default: an island keeps working, and its own admin can still revoke there. A network may set a freshness window when it is founded; past it, a node carries no traffic to or from non-admins, and keeps syncing to catch up |
| **Relay abuse:** the relay serves whoever registers, since it cannot know who is a member, and anybody can spend its bandwidth | Limits per key. Accepted. Should abuse become real, a network-PSK admission policy can be asked of convesso; an allowlist cannot work, since the relay cannot know an invite's rendezvous key |
| **Someone holding a disk, on a machine without a TPM**, can read the transport key and the software machine key, and forge a checkpoint for what they plant | Disk encryption. With a TPM, the keys open only on that TPM and a checkpoint cannot be forged off it |
| **A genuine older copy of a network's folder** can be put back, moving that network back to an earlier state of its own | Never to another network. Peers bring it forward at the next sync; only an isolated device stays behind, as in the revocation window |
| **A cleared TPM or replaced hardware** loses every network on the machine | Said, never papered over with a fresh key: each network is joined again, under fresh keys. A network's only admin loses its network, as it would with its signing key |
| **Someone running as the daemon** (SYSTEM, root) can use every key the daemon can | none: no design stops the code that holds the keys |
| **Any admin can expel the others** | open: whether the founder should be irremovable |
| **An invite is a bearer token:** whoever holds it can send a request in its name | Single use, an expiry (a day by default), and the admin's review before signing, which shows each request's key fingerprint and arrival time. In person, compare the fingerprint the joining device shows. A theft shows mostly as a join that never ends (§3.4) |
| **A person doesn't compare the fingerprint** | nothing more: the invite is the anchor of trust, and the fingerprint is the check for those who can make it. A short code was removed because remotely it was a second bearer secret and it could be ground (§3.4) |
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
relay, failing to connect half a metre from the device would be an absurd failure for a product that
sells itself on not depending on anyone.

- **A signed multicast announcement on a dedicated UDP port:** a public key and its endpoints. **Not
  mDNS with names.** The name is already in the roster; what's needed is only that a key is present,
  and where. It also avoids colliding with Bonjour or Avahi.
- **Multicast on Wi-Fi is unreliable,** filtered or sent at low bitrates. So announcements repeat, and
  **the last known LAN addresses are tried first.**
- Paths are re-evaluated at every interface change, or a device stays on the relay while at home.
- **The LAN does not wait for the relay.** A member's fresh announcement ends the wait a failed
  attempt put it on, and every attempt of a dial tries the announced addresses. Two devices on one
  LAN reach each other with the relay unreachable, and with its name unresolvable.
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
let a direct path through, the whole plan changes. `peerfectly peers` says, for each device it
reaches, whether the path is direct or through the relay: that is where the number is read.

## 13. Decisions that were open

### 13.3 The name

**peerfectly**, published by *nohostalgia*. It replaced a placeholder everywhere, protocol constants
included, before anything was published. The suffix is a different question: it stays a signed
parameter chosen per network (§2.5).

### 13.7 No idle timeout

Should the tunnel switch itself off after a while without use? **No.** It stays on until the person
switches it off. A timer would save some battery and add a second way for the network to "not work"
without the person having decided it. Measure real consumption before adding one.

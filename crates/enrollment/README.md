# enrollment

How a device that belongs to no network becomes a member of one.

Every other crate here assumes a roster already exists. This one is about the
moment before that, when a device has keys and nothing else.

`FORMAT.md` has the bytes. This is the reasoning.

## The joiner is the side that waits

A device with no network is **unreachable in both directions**. It registers at
no relay, so nobody can dial it; and it cannot announce on the local network
either, because announcements are sealed with a network identifier it does not
have. Something has to break that symmetry before any conversation can happen.

An admin breaks it by issuing an **invite**: the network's relay, the network's
id, and sixteen random bytes. The device derives a rendezvous key from the
secret, registers under it at that relay, and waits. The admin that issued the
invite derives the same key and dials it.

**Why that direction and not the other.** Dialling needs the peer's key —
thirty-two bytes, which nobody types. The invite's secret lets both sides derive
one without anybody typing it, and the side that dials is the one that has
something to lose: the admin has a network, and it initiates; the joiner has
nothing, and it waits. What the device will be — its name, role, mode, groups,
address — stays in the admin's local record of the invite, never in the invite.

## The exception, and why it lands where it does

Everywhere else in this system, a peer is authorised from the signed roster and
from nothing else. A device waiting to join **accepts a peer no roster names**,
because it has no roster with which to name anyone.

That exception is deliberately placed on the device with nothing to lose: no
roster, no routes, no data, no names being served. It is bounded by a person
starting it, by a time limit, by a protocol that carries nothing else, and by
everything received being verified afterwards against signatures the peer cannot
forge.

The other side gets no such exception. An admitting endpoint **dials and has no
listener at all** — it offers no protocol, so nothing can open an enrolment
exchange against a machine that holds a roster. That is enforced by there being
no method to call, not by a check somebody could omit.

## No code, and what replaces it

There is none. A six-digit code compared on two screens assumed both people
present at once, and protected less than it seemed: sent remotely, the way the
invite was, it is a second bearer secret that reaches whoever read the invite;
and its material is the handshake hash of `Noise_IKpsk2`, where the responder
chooses its ephemeral after the initiator's — whoever holds the invite answers
the admin's dial and searches ephemerals until the two codes match, about 2^20
operations.

Enrolment is asynchronous instead. The joining device's **request** — its keys,
the proofs that it holds them, the name it proposes — is kept by the admin's
daemon as a pending request, asking nobody, until a person approves or rejects
it, however much later that is. Approving shows the name the device will be
admitted under, the name it proposed, the **fingerprint** of its signing key and
when the request arrived. In person, that fingerprint is compared with the one
the joining device shows: it is derived from the key and from nothing a channel
chose, so it cannot be ground.

## Both keys are proved, not taken on trust

The channel of an invite proves only the rendezvous key. It says nothing about
the **signing** key the device presents — and a device's identity is derived
from its signing key — nor about the **transport** key its sessions will be
authenticated by.

Without proofs, an introduction pairing one device's signing key with an
attacker's transport key would have an admin sign an operation binding that
identity, and that overlay address, to the attacker. Worse, a roster keeps the
**first** admission of a device id and ignores later ones, so the real holder of
that key could never afterwards be admitted under its own identity. The damage
would not be repairable.

So the signing key signs the join's **request** — the invite it answers and the
other two keys it brings — once, when the person runs the join, because the key
may be one only a person can unlock and the exchanges happen whenever the
daemons meet. The transport key signs each channel's material, so its proof
cannot be gathered on one channel and presented on another. A request copied off
one device is worth nothing to anybody else: it names keys they do not hold.

## Delivery proves nothing

A roster is signed operations. Who hands it over changes nothing about whether
it is true, so a joining device asks only what it contains: an operation
admitting **its own keys**, signed by an admin, deriving to a consistent state,
of the network the invite names. Where the roster was compacted, the state
beneath it arrives too, and is believed only once it makes the signed root. That
is why a delivery may come from the admin that approved it or from any full
member the admission reached, at the rendezvous or at the device's own transport
key, and why a call from anybody else costs one refused exchange.

The relay needs no such check. Its address names its key (`key@host:port`), so
the invite that tells a joining device where the relay is also tells it who
must answer there, and nothing is ever accepted on sight.

## What the invite is

A bearer token. Whoever holds it can make the request it opens, and nothing in
the protocol can tell them from the device it was meant for — every design needs
an anchor outside the protocol for that first contact. What remains is single
use, an expiry that bounds only how long a request may take to arrive, and the
review before approval, where the list shows which request used each invite.

One exchange at a time on the joining device, each with its own deadline, and
paced rather than counted: a join ends only when it is admitted or cancelled, so
somebody calling over and over costs it little and never ends it.

**Denial of the enrolment remains possible** and nothing here prevents it. The
rendezvous is known to anyone who has seen the invite, so anyone can make noise
at it, or make the request first. What a person sees then is a request they do
not recognise, which they reject, and a join that does not end, which they
cancel.

## Deliberately elsewhere

| Deferred | To |
|---|---|
| Sockets, waiting, deadlines, the terminal | `windows-daemon` and the daemon |
| The enrolment endpoint and its channel material | `transport-convesso` |
| Membership, roles, authority | the roster's, entirely |
| Scanning a code with a camera | a client with a camera; this renders one and reads its text |
| Recovery phrases, a second admin, delegation | §10.2 puts all three outside the MVP |

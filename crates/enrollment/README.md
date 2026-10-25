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

## What the code is worth

Six decimal digits, shown on both screens, derived from the joining device's
three keys, the admitting device's transport key, and **material exported from
the established channel**.

The channel material is the part that matters, and the reason is not obvious.
Every key in the derivation is **public** once presented, and the admin's keys
are in a roster every member holds. A code derived from keys alone could
therefore be matched by an attacker generating key pairs of their own until one
produces the same six digits. Six digits is a space of one
million; the search takes seconds. Both screens would then show the same number.

Channel material closes that, because the value being matched does not exist
until the channel does, and the attacker's channel is not the one being matched.
It also breaks a forwarded exchange: two legs export two different values, so
the codes differ at each end.

## What each confirmation defends against

They are not the same check twice.

**The joining device confirms by typing the digits the admin displays.** Typing
rather than agreeing, because an invite travels by message and photograph, and
anybody who has seen it can dial the waiting device and offer a well-formed
network of their own. A person pressing "yes" on both machines would accept it;
a person typing what the other screen says would not. The device also refuses
any network but the one the invite names.

**The admitting device confirms by comparing.** This catches a different attack:
the invite intercepted or substituted on its way to the device, so that another
machine waits at the rendezvous. If the machine the admin reached is not the one
the person is standing at, the admin's code will not be the code on that
machine — and the admin's prompt must therefore **name the screen it has to
match**. A prompt that shows a number and asks for a yes defends nothing here.

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

So the joining device signs the exchange's channel material with each key, and
the admitting side verifies both against the keys the introduction named. No
extra round trip — the channel material already exists for the code — and
because the signatures cover that material they cannot be gathered on one
channel and presented on another.

## Delivery proves nothing

A roster is signed operations. Who hands it over changes nothing about whether
it is true, so a joining device asks only what it contains: an operation
admitting **its own keys**, signed by an admin, deriving to a consistent state,
of the network the invite names. Where the admin's roster was compacted, the
state beneath it arrives too, and is believed only once it makes the signed root.

The relay needs no such check. Its address names its key (`key@host:port`), so
the invite that tells a joining device where the relay is also tells it who
must answer there, and nothing is ever accepted on sight.

## The bounds, and what they do not buy

One exchange at a time, each with its own deadline, and a limited number of
attempts within one wait.

One at a time is necessary — two would mean two codes on one screen. But on its
own it hands anyone who has seen the invite a way to keep the admin out: open
an exchange, say nothing, hold the only slot for the whole wait while the person
watches nothing happen. The per-exchange deadline is what stops that, and the
attempt cap is what keeps a six-digit code out of reach of guessing.

**Denial of the enrolment remains possible** and nothing here prevents it. The
rendezvous is known to anyone who has seen the invite, so anyone can make noise
at it. What the bounds buy is that an indefinite silent stall becomes a bounded
failure that names itself, and a retry costs one command.

## What a person still has to do

Compare six digits on two screens.

§6.2 lists *the user does not verify the fingerprint at pairing* as an accepted
limit of this design, and it stays one. This narrows it — one side types what the
other displays, so a mismatch is caught by somebody looking rather than by
somebody agreeing — but a person can still read from the wrong screen, or be
talked into it. That is written here rather than left to be discovered.

## Deliberately elsewhere

| Deferred | To |
|---|---|
| Sockets, waiting, deadlines, the terminal | `windows-daemon` and the daemon |
| The enrolment endpoint and its channel material | `transport-convesso` |
| Membership, roles, authority | the roster's, entirely |
| Scanning a code with a camera | a client with a camera; this renders one and reads its text |
| Recovery phrases, a second admin, delegation | §10.2 puts all three outside the MVP |

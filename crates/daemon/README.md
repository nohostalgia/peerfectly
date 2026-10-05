# daemon

The node as a program: what it decides, what it answers, and the loops that drive it.

Everything here is ordinary Rust and builds anywhere. It decides which routes should exist, what a
name resolves to, which session a packet belongs to, when to sync, publish and announce, and what to
tell a person who asks. It never touches a machine itself: creating an adapter, writing a route or
listening on a control channel sits behind a trait (`Machine`, `Connectivity`, `Resolving`, `Keys`),
implemented by a platform crate (`windows-daemon`, `linux-daemon`) that decides nothing.

`SURFACE.md` lists what the control channel accepts and answers.

## How a device knows its roster is current

A device that cannot confirm its copy of the roster is recent goes into a cautious mode, because a
roster it cannot date might be missing a revocation. What dates a roster is not the snapshot. It is
an **attestation**.

An attestation carries the network, the heads the admin holds, a sequence number and the id of the
key that signed it. It **carries no state**: no membership, no parameters, nothing a device could
adopt. A device counts one only when it names heads the device itself holds. An admin knowing about
heads the device lacks tells the device it is behind, which is the opposite of fresh.

An attestation is signed by a third key of every device, `attestation`, beside `signing` and
`transport`. It is the one key a device uses **with nobody present**. Because the object it signs
holds no state, a stolen attestation key can declare a roster fresh and nothing else. That is not
because a rule refuses the rest, but because the rest cannot be expressed in it. Snapshots do carry
state, and they are still signed by the signing key, which needs a person.

An admin's daemon issues an attestation when its heads change, and in any case every twelve hours,
for every session it has open. It never relays somebody else's. A member issues none.

**The phone limit is gone.** Before attestations, every signature on a phone asked for the screen
lock. So a phone that was a network's only admin kept that network current only while somebody kept
opening the app, and the advice was "add an admin on a machine that stays on": advice in place of a
mechanism. The attestation key is the mechanism. It asks nothing, so a phone dates its roster with
the app closed.

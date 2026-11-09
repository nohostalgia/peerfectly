# The enrolment formats

What a second implementation has to agree with, byte for byte. Everything here
is the roster's canonical CBOR under the same narrowed rules: definite lengths,
minimal integer widths, length-first map key ordering, every field exactly once,
no trailing bytes, and **rejection rather than repair**.

## 0. The invite

What an admin hands a device so that it can join. It opens a door, once: the
device waits at a rendezvous key derived from the invite's secret, and the admin
that issued it dials that key. Nobody else knows where the device waits.

```text
Invite = {
  "net":    bstr .size 32,   ; the network id: the only network the device accepts
  "block":  bstr .size 5,    ; the network's IPv4 block: its base, then its prefix length
  "relay":  tstr,            ; the network's relay, key@host:port
  "secret": bstr .size 16    ; random
}
```

Roster's canonical encoding: length-first keys, every field exactly once, no
trailing bytes. The relay is 1 to 128 bytes. An invite carries **no** name,
role, mode or groups: those stay in the admin's local record of the invite,
with its expiry and whether it was used, and never enter the roster.

The block is the network's IPv4 block when the invite was issued, `/10` to `/28`
inside the private blocks. It is there so the joining device can say, before it
asks, where the network's addresses would coincide with its other networks or the
subnets it is on. Nothing signs it: an invite that lied about it misleads only
that warning, and the block a member holds is the one its roster says.

The text form is `peerfectly-invite-v2:` followed by the bytes in lowercase
hexadecimal; surrounding whitespace is ignored. A scannable code carries the
text.

The rendezvous identity's seed is
`BLAKE3-derive("peerfectly invite rendezvous v1", network id || secret)`: an
ed25519 seed, bound to the network as well as the secret, so one secret cannot
meet in two networks.

## 2. No confirmation code

There is none. Enrolment is asynchronous: the joining device's request is kept by
the admitting side until a person approves it, and nobody compares two screens.
A short code compared remotely is a second bearer secret, sent the way the
invite was, and over `Noise_IKpsk2` the responder chooses its ephemeral after
the initiator's, so whoever holds the invite could search ephemerals until two
codes matched. In person, the admin compares the fingerprint of the joining
device's signing key, which is derived from the key and cannot be ground.

## 3. The proofs of possession

```text
request   = blake3-derive-key( "peerfectly join request v1",
                               network id || rendezvous key || transport key || attestation key )
challenge(m) = blake3-derive-key( "peerfectly enrolment possession v1", m )
proof     = sign( challenge(request) ) with the device's SIGNING key
tproof    = sign( challenge(channel) ) with the device's TRANSPORT key
```

`network id` and `rendezvous key` are the invite's: the network it names and the
key its secret derives (§0). The keys are their 32 raw bytes. Both proofs are
verified against the keys the introduction presents.

The channel of an invite authenticates only the rendezvous key the invite's
secret derives, which says nothing about the device's own keys. The signing key
is where a device's identity comes from, and the transport key is what its
sessions will be authenticated by. Without these proofs an introduction could
pair one device's signing key with another's transport key, and because a roster
keeps the **first** admission of a device id and ignores later ones, that binding
could never be corrected.

`proof` covers the join's **request** rather than a channel because it is made
once, when the person runs the join: the signing key may be one only a person can
unlock, and the exchanges of a join happen whenever the daemons meet, with nobody
there. It names the other two keys and the invite, so it cannot be moved to
another device's keys or another invite; a copy of it is worth nothing to anybody
else, who holds none of those keys. `tproof` covers each channel, since the
transport key answers without a person.

The derivation contexts are distinct, and none is used anywhere else in the
system. A signature made for another purpose cannot serve as these proofs, and
these proofs cannot serve elsewhere.

## 3b. The exchange, and what is said when

Every exchange is opened by the admitting side — the admin that issued the invite,
or a full member bringing an admission — and the joining device answers. It has
one of two shapes. Each side knows which messages it expects, and one arriving
out of turn ends the exchange rather than being acted on.

```text
joiner -> admin   introduce { alg, kind, name, sign, proof, trans, attest, tproof, conflicts }

then, before a person has approved the request:
admin  -> joiner  received  { kind }                         (the exchange ends)

or, once a person has approved it:
admin  -> joiner  base      { kind, root, pieces }           (zero or more)
admin  -> joiner  batch     { kind, pieces }                 (zero or more)
admin  -> joiner  admit     { kind, roster, snapshot? }
joiner -> admin   outcome   { kind, taken }
```

A device opens with `introduce`: it presents all three of its keys and proves
two — `proof` and `tproof` of §3. `alg` covers the signing key only: transport
and attestation keys are ed25519. Both proofs SHALL be checked before the request
is kept. `conflicts` is an array of at most 16 text strings of at most 200 bytes,
each saying in the device's words where the invite's block coincides with its
other networks or the subnets it is on; the admin's daemon keeps them with the
request for the person approving it, and decides nothing by them. `name` is the
name it proposes; the admin's record of the invite decides
the name, role, mode, groups and address it is admitted with, and an admission
whose record chose any of the last four is followed, in the same delivery, by the
`set_device` that sets them.

`received` carries **nothing but its kind**, and proves nothing: whoever holds the
invite can send it. It tells the joining device that its request is kept and that
waiting on is the next thing. A delivery comes later, in another exchange, from the
admin or from any full member holding the admission, at the rendezvous or at the
joining device's own transport key.

Where the admitting side's roster was compacted, its operations no longer reach
the genesis, and `admit` alone derives nothing. The admitting side then sends,
before it, the state its roster rests on: `root` is the signed root beneath the
window, `pieces` are the state's pieces as roster-sync's state transfer cuts
them (at most 64 KiB each, at most 14 to a message, so that a part fits one
message beside the root). Every `base` carries the same root. The joiner
gathers the pieces and believes the state only once every one is in, it makes
the root, and the root's signature checks against its author in that state; it
then rests on it and takes the operations of `admit` that follow the root's
heads. A base that does not hold is refused like a roster that does not admit
the device: nothing is written, and `outcome` says `taken: false`.

`batch` carries pieces of the batches among the operations to come, at most 120
to a message, each as large as an operation may be. A batch's operation is only
its header; the joiner offers each batch its pieces as soon as it holds the
header, and takes into the graph whatever was signed after it once it is whole.

Every message travels in the same envelope, `{ body, kind }`, where `body` is the
embedded canonical encoding of the map above and `kind` repeats its name. An
envelope whose `kind` disagrees with its body is refused: a reader that trusted
the label over the contents is a reader that can be talked into the wrong branch.

`admit` carries the network's current **snapshot** beside the roster, where the
admitting side holds one. The field is optional and absence has one spelling: the
key is not written. A `null` would be a second way to say the same thing, and two
spellings of one fact are two things for implementations to disagree about.

It is there because freshness is measured from the last snapshot a device
accepted, and a device that joined without one would have accepted none — which
is the state a device reaches when it has been out of touch for longer than the
network allows. A member that has just arrived and one that has been unreachable
for a month must not look alike.

The snapshot is **not evidence of anything**, exactly as the operations beside it
are not. A joiner SHALL check it by the roster's own rules — signed by a device
the delivered operations name as an admin, over heads those operations contain —
and never because of who sent it.

A snapshot that does not check SHALL be dropped **without refusing the roster**.
The operations prove the membership; the snapshot only dates it, and it is
allowed to be missing altogether. An admitting side that sends none, and one
whose snapshot does not check, leave the joiner in the same place: a member, with
nothing yet to measure freshness from, and told so.

## 4. Bounds

| | |
|---|---|
| Proposed name | 64 bytes (the roster's own) |
| Relay address | 128 bytes (the roster's own) |
| One exchange message | 1 MiB |
| State pieces in one `base` | 14 |
| Batch pieces in one `batch` | 120 |
| `base` or `batch` messages in one exchange | 4096 each |
| One exchange | 60 seconds |

A declared length is checked against its bound **before** any buffer is reserved,
so a peer cannot make a device allocate merely by claiming a large size.

The exchange's deadline is a security parameter rather than a size. An invite is
a bearer token, so anyone who has read one can open an exchange with the device
waiting behind it: the deadline stops one silent peer occupying the only slot.
A join has no deadline of its own: it ends when it is admitted, rejected,
withdrawn or cancelled, and the exchanges it answers are paced rather than counted.

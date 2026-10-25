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
  "relay":  tstr,            ; the network's relay, key@host:port
  "secret": bstr .size 16    ; random
}
```

Roster's canonical encoding: length-first keys, every field exactly once, no
trailing bytes. The relay is 1 to 128 bytes. An invite carries **no** name,
role, mode or groups: those stay in the admin's local record of the invite,
with its expiry and whether it was used, and never enter the roster.

The text form is `peerfectly-invite-v1:` followed by the bytes in lowercase
hexadecimal; surrounding whitespace is ignored. A scannable code carries the
text.

The rendezvous identity's seed is
`BLAKE3-derive("peerfectly invite rendezvous v1", network id || secret)`: an
ed25519 seed, bound to the network as well as the secret, so one secret cannot
meet in two networks.

## 2. The confirmation code

Six decimal digits, leading zeros kept, derived as:

```text
code = decimal( first 8 bytes, big-endian, of
                blake3-derive-key( "peerfectly enrolment confirmation code v1",
                                     len||joining-signing-key
                                  || len||joining-transport-key
                                  || len||joining-attestation-key
                                  || len||admitting-transport-key
                                  || len||channel )
              ) mod 1 000 000
```

Every length is a four-byte big-endian prefix: without it two different sets of
fields could concatenate to the same input, and two different exchanges could
produce one code.

The joining device's **attestation** key is covered although nothing establishes
possession of it, unlike the signing key — proven by the possession proof — and
the transport key, proven by the channel. The code is not only a proof of
possession: it is what makes the admitting side's signature cover what both
people compared. That key goes into the device record, so a code that left it out
would allow an introduction substituted in flight to name an attestation key of
the attacker's choosing while showing the same six digits.

The two roles are fixed and different, so there is no order to agree on. The
joining device contributes its keys — its signing and transport keys are each
established by a proof of possession below. The admitting
device contributes only its transport key, because that is all the joining device
can know about it: the channel authenticates transport keys, and the admitting
device's signing key is in the roster that has not arrived yet. Asserting it over
the wire and mixing it in would look like a binding and be none — an impostor
would assert its own and compute the same code. What exposes an impostor is that
its channel is a different channel.

**`channel` is required and must not be empty.** It is material exported from the
established channel, and it is what makes six digits safe. Every key above is
public once presented — the admin's keys are in a roster every member holds —
so a derivation over keys alone could be matched by generating key pairs until
one produced the same six digits. That search is over a space of one million.
Channel material defeats it because the value being matched does not exist until
the channel does.

## 3. The proof of possession

```text
challenge = blake3-derive-key( "peerfectly enrolment possession v1", channel )
proof     = sign( challenge ) with the device's SIGNING key
tproof    = sign( challenge ) with the device's TRANSPORT key
```

Verified against the keys the introduction presents.

The channel of an invite authenticates only the rendezvous key the invite's
secret derives, which says nothing about the device's own keys. The signing key
is where a device's identity comes from, and the transport key is what its
sessions will be authenticated by. Without these proofs an introduction could
pair one device's signing key with another's transport key, and because a roster
keeps the **first** admission of a device id and ignores later ones, that binding
could never be corrected.

The two derivation contexts are distinct, and neither is used anywhere else in
the system. A signature made for another purpose cannot serve as this proof, and
this proof cannot serve elsewhere.

## 3b. The exchange, and what is said when

Four messages, in one order — five kinds, where the roster was compacted. Each side knows which it expects, and one arriving
out of turn ends the exchange rather than being acted on.

```text
joiner -> admin   introduce { alg, kind, name, sign, proof, trans, attest, tproof }
                  (the admin shows the code it computed; its person is asked
                   whether the device being enrolled says the code was accepted)
joiner -> admin   accepted  { kind }
admin  -> joiner  base      { kind, root, pieces }      (zero or more)
admin  -> joiner  admit     { kind, roster, snapshot? }
joiner -> admin   outcome   { kind, taken }
```

A device opens with `introduce`: it presents all three of its keys and proves
two — `proof` is the possession proof of §3 by the signing key, `tproof` the
same by the transport key. `alg` covers the signing key only: transport and
attestation keys are ed25519. Both SHALL be checked before a code is shown. `name` is the
name it proposes; the admin's record of the invite decides the name, role, mode,
groups and address it is admitted with, and an admission whose record chose any
of the last four is followed, in the same delivery, by the `set_device` that
sets them.

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

Every message travels in the same envelope, `{ body, kind }`, where `body` is the
embedded canonical encoding of the map above and `kind` repeats its name. An
envelope whose `kind` disagrees with its body is refused: a reader that trusted
the label over the contents is a reader that can be talked into the wrong branch.

`accepted` carries **nothing but its kind**. Both sides derived the same code
from the channel, so a field repeating it would be a second source for one fact;
and sending back the digits a person typed would put them on the channel, which
is precisely what an attacker who dialled the waiting device first controls.

What it carries is *when*. The joining side sends it once a person has entered
the code the admitting side displayed and it matched. Until it arrives, the
admitting side does not know whether anyone compared anything — and signing
before it would deliver the whole roster, and an admission for that device, to a
machine whose person has confirmed nothing.

An implementation SHALL NOT sign before reading `accepted`, SHALL read it under
the exchange's own deadline, and SHALL refuse one that arrives before
`introduce`, twice, or in place of `outcome`.

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
allowed to be missing altogether. A joiner that discarded a membership its person
had just confirmed on two screens, over a field that need not have been sent,
would be trading the thing it came for against the thing it could do without. An
admitting side that sends none, and one whose snapshot does not check, leave the
joiner in the same place: a member, with nothing yet to measure freshness from,
and told so.

## 4. Bounds

| | |
|---|---|
| Proposed name | 64 bytes (the roster's own) |
| Relay address | 128 bytes (the roster's own) |
| One exchange message | 1 MiB |
| State pieces in one `base` | 14 |
| `base` messages in one exchange | 4096 |
| A wait | 600 seconds |
| One exchange within a wait | 60 seconds |
| Attempts within a wait | 10 |
| Confirmation code | 6 digits |

A declared length is checked against its bound **before** any buffer is reserved,
so a peer cannot make a device allocate merely by claiming a large size.

The last three are security parameters rather than sizes. An invite travels by
message, so anyone who has seen one can open an exchange with the device waiting
behind it:
the per-exchange deadline stops one silent peer occupying the only slot, and the
attempt cap is what keeps six digits out of reach of guessing.

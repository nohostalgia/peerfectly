# The enrolment formats

What a second implementation has to agree with, byte for byte. Everything here
is the roster's canonical CBOR under the same narrowed rules: definite lengths,
minimal integer widths, length-first map key ordering, every field exactly once,
no trailing bytes, and **rejection rather than repair**.

## 1. The joining payload

```text
Joining = {
  "alg":    tstr,   ; the signing key's algorithm: "ed25519" or "p256"
  "name":   tstr,   ; the name the device proposes for itself
  "sign":   bstr,   ; the signing key, from which the device id is derived
  "relay":  tstr,   ; where the device is waiting to be reached
  "trans":  bstr,   ; the transport key, which a session authenticates
  "attest": bstr    ; the attestation key, which will date the device's roster
}
```

Key order is length-first, so the three-byte key comes first, then the two
four-byte keys ordered by their bytes (`name` before `sign`), then the two
five-byte ones (`relay` before `trans`), and the six-byte `attest` last.
Alphabetical order would put `alg`, `attest`, `name`, `relay`, `sign`, `trans`
and produce bytes a conforming decoder refuses.

`alg` covers the **signing** key only. Neither the transport key's algorithm nor
the attestation key's is carried: §2.3 fixes device transport keys as ed25519 and
the binding refuses anything else when it binds an endpoint, and an attestation
key is ed25519 for a reason of its own — it is never held in an enclave, because
a key in one is a key that asks a person. A field for either would be a second
place to state one thing.

`attest` is here because the device record the admission signs must carry an
attestation key, and the admitting side has nowhere else to learn it from. The
joining device cannot attest to anything until it is admitted; what this field
does is let the record be complete at the moment it is created, since none of the
roster's operations adds a key to a device that already exists.

`name` and `relay` are refused when empty. Absence is not one of the things this
format can say, and a device asking for the empty name is not the same request
as a device asking for nothing.

**What is deliberately absent**: a role, a founder flag, capabilities, an expiry,
and any secret. A joining device says who it is and asks for a name. What it is
permitted to be is decided by the admin that admits it, and a field here for any
of that would be a field somebody eventually honours.

### The text form

```text
peerfectly-join-v1:<lowercase hex of the canonical bytes>
```

The prefix is the version. A later format changes it, so an older reader refuses
new bytes instead of misreading them. Surrounding whitespace is ignored on
reading, because a person copying out of a terminal picks some up.

The scannable form carries **the same bytes**. It is a rendering, not a second
format, and a test asserts the two round-trip to one payload.

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
would allow a payload substituted in flight to name an attestation key of the
attacker's choosing while showing the same six digits.

The two roles are fixed and different, so there is no order to agree on. The
joining device contributes **both** of its keys — its signing key is established
by the proof of possession below, its transport key by the channel. The admitting
device contributes only its transport key, because that is all the joining device
can know about it: the channel authenticates transport keys, and the admitting
device's signing key is in the roster that has not arrived yet. Asserting it over
the wire and mixing it in would look like a binding and be none — an impostor
would assert its own and compute the same code. What exposes an impostor is that
its channel is a different channel.

**`channel` is required and must not be empty.** It is material exported from the
established channel, and it is what makes six digits safe. Every key above is
public — the payload is on a screen, the admin's keys are in a roster everyone
holds — so a derivation over keys alone could be computed in advance by anyone
who had seen the payload, and then matched by generating key pairs until one
produced the same six digits. That search is over a space of one million.
Channel material defeats it because the value being matched does not exist until
the channel does.

## 3. The proof of possession

```text
challenge = blake3-derive-key( "peerfectly enrolment possession v1", channel )
proof     = sign( challenge ) with the device's SIGNING key
```

Verified against the signing key the payload carries.

The channel authenticates the transport key — the admitting side dials it, and
nobody else can answer. It says nothing about the signing key, which is where a
device's identity comes from. Without this proof a payload could pair one
device's signing key with another's transport key, and because a roster keeps the
**first** admission of a device id and ignores later ones, that binding could
never be corrected.

The two derivation contexts are distinct, and neither is used anywhere else in
the system. A signature made for another purpose cannot serve as this proof, and
this proof cannot serve elsewhere.

## 3b. The exchange, and what is said when

Four messages, in one order. Each side knows which it expects, and one arriving
out of turn ends the exchange rather than being acted on.

```text
joiner -> admin   hello     { kind, proof }
                  (the admin shows the code it computed; its person is asked
                   whether the device being enrolled says the code was accepted)
joiner -> admin   accepted  { kind }
admin  -> joiner  admit     { kind, roster, snapshot? }
joiner -> admin   outcome   { kind, taken }
```

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
the exchange's own deadline, and SHALL refuse one that arrives before `hello`,
twice, or in place of `outcome`.

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
| Joining payload, encoded | 512 bytes |
| Proposed name | 64 bytes (the roster's own) |
| Relay address | 128 bytes (the roster's own) |
| One exchange message | 1 MiB |
| A wait | 600 seconds |
| One exchange within a wait | 60 seconds |
| Attempts within a wait | 10 |
| Confirmation code | 6 digits |

A declared length is checked against its bound **before** any buffer is reserved,
so a peer cannot make a device allocate merely by claiming a large size.

The last three are security parameters rather than sizes. The payload is public,
so anyone who has seen one can open an exchange with the device that produced it:
the per-exchange deadline stops one silent peer occupying the only slot, and the
attempt cap is what keeps six digits out of reach of guessing.

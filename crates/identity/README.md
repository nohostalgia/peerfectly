# identity

How a node obtains, holds and uses the keys that make it a device.

The `roster` crate can verify a signature and derive a household from a set of
operations. It cannot produce a key — every key there comes from a caller-supplied
seed, which exists so the shared vector corpus stays reproducible and which no
real device may use. This crate closes that gap.

It depends on `roster`; roster never depends on it. That keeps roster's audited
dependency list — no networking, no async runtime, no `iroh` — exactly as it is,
while this crate is free to touch the filesystem and, on Windows, the platform's
secret store.

## Generating an identity

```rust
use identity::{NodeIdentity, Role};

let node = NodeIdentity::generate()?;
let spec = node.device_spec("laptop", Role::Member, false, vec![])?;
assert_eq!(spec.device_id()?, node.device_id());
# Ok::<(), identity::Error>(())
```

`generate` takes **no key material**. A caller cannot supply, influence or observe
the bytes drawn; they come from the operating system and nothing else. There is no
fallback if the system will not provide entropy, because every other source
available to a node is predictable.

A generated key is validated by exactly the code that validates a *received* one —
roster's `PublicKey::new` and `KeyEntry::new`. Trusting our own generator because
it is ours is how a wrong-length encoding reaches disk and is first noticed by a
peer.

`PrivateKey::from_material` builds a key from bytes you choose. It is **for tests
and vectors, not for a device**, and says so in its own documentation; a test
asserts that warning survives edits.

## Three keys, kept apart

A node holds a **signing key** (roster operations and snapshots), a **transport
key** (session establishment; `transport-iroh` turns it into an iroh `NodeId`)
and an **attestation key** (attestations, which date a roster and describe none).
They are drawn separately and no two are ever equal.

Deriving one from another would make a single compromise into two, and would make
"the keys are distinct" an accident of the derivation rather than a property.
Reusing one value across two purposes would invite cross-protocol attacks, where a
signature produced in one context is meaningful in the other. An identity assembled
with one value for two purposes is refused here, rather than left for the roster
to catch later.

A phone's enclave imposes P-256 on the root key, so `generate_with` chooses the
signing algorithm while the transport and attestation keys stay ed25519.

### Why the attestation key is a third key rather than a use of the first

It is the key a device may use with **nobody present**.

On a phone every signature the custodian makes raises a lock prompt, so a device
whose only key asked could date its roster only while somebody was holding it. A
network whose only admin was a phone therefore stayed current only while that
person kept opening the app — a limitation that was written down rather than
fixed.

A key that both dated a roster unattended and signed operations would hand the
unattended property to the signing power. So the two are different keys, and what
the unattended one can express is bounded by the object it signs: an attestation
carries heads and no state, so a stolen attestation key can declare a roster fresh
and can do nothing else.

## Storage, and what it does not protect against

`store::save` and `store::load` write an identity and read it back. **The two
platforms give different guarantees, and this is not a detail to gloss:**

| | Another local user | A privileged process | A backup or a stolen disk |
|---|---|---|---|
| Unix — file mode `0600` | defended | **not** defended | **not** defended |
| Windows — DPAPI | defended | **not** defended | defended |

### Presence, per platform

| | Signing key | Transport key | Attestation key |
|---|---|---|---|
| Desktop | no presence required | no presence required | no presence required |
| Android | **lock required each use** (keystore custodian) | none: in the process, sealed by a keystore key that does not require the lock | none: the same shape as the transport key |

What the third row concedes on Android is that somebody with the unlocked
device's storage obtains a key able to **date** a roster and unable to alter one.
That is the trade the key exists to make: the alternative is an admin phone that
dates its roster only while a person is holding it, which is a network that goes
stale for a reason nobody chose.

- **Unix** stores the material in the clear and relies on the file mode. Anything
  that can read the file gets the signing key — root, a filesystem backup, a disk
  pulled from a machine — and with it the ability to author operations as that
  device. For an admin device, that includes adding devices of its own.
- **Windows** seals the material to the user account with DPAPI. The sealing key
  derives from the account's credentials rather than sitting beside the file, so a
  copied file alone is not enough.

Two rules the implementation follows and a reader should be able to rely on:

- The file is **created** with `0600` on Unix — not created and then tightened.
  However brief, a window where the file is world-readable is one an attacker can
  wait for.
- Loading **refuses** a file readable by group or others, naming the permissions.
  A check that warns and continues is advice, not a control.

An explicit owner-only DACL was considered for Windows and rejected: SID lookup and
ACE ordering are fiddly, and a subtly wrong access control is worse than none
because it claims a protection it does not deliver. DPAPI is what the platform
provides for exactly this job.

The identity file is **not a wire format**. It is local, never signed, never
exchanged, and never parsed by a second implementation, so roster's canonical
encoding — which exists so two implementations agree on bytes — buys nothing here.
What it does need is strictness, and it has that: a file that does not decode
exactly is refused rather than half-read.

## Detached signing

`roster::sign::Signer` is synchronous, which suits a key this process holds. It does
not suit the root key: that lives in a phone's secure enclave, behind a biometric
prompt, on the far side of a UniFFI boundary. Rust cannot call it synchronously
without blocking on a person — on Android, risking an ANR — and cannot hold the
private material at all, by design.

So there is a second path:

```text
prepare_operation(core, key)  ->  SigningRequest { message, key, algorithm }
                                        |
                          (a custodian signs `message`)
                                        |
finish(request, key, signature)  ->  the assembled artifact
```

Three things follow, and the third is why this exists now rather than when Android
forces it:

1. **Nothing here blocks on a person.**
2. **An enclave key needs no Rust implementation.** It never implements `Signer`,
   because it cannot.
3. **An offline queue is a queue of requests.** DESIGN.md §2.6c has operations
   written while the network is off waiting locally. A prepared-but-unsigned
   request is precisely that, so `offline-operation-queue` inherits this type
   rather than inventing one.

The signature is **checked, not trusted**: `finish` verifies it against the
request's own bytes and the key the request names before assembling anything. A
custodian returning a wrong or truncated signature is a bug worth catching here,
cheaply, rather than shipping an artifact that fails on a peer where the cause is
far harder to see.

A property test asserts the synchronous and detached paths produce **byte-identical**
artifacts. If they drifted, an operation signed on a phone would verify on one
device and not another — a divergence that would look like a crypto bug and be
nothing of the sort.

## What the Android client must satisfy

Implement `KeyCustodian`:

```rust,ignore
pub trait KeyCustodian {
    fn public_key(&self) -> PublicKey;
    fn sign_request(&self, request: &SigningRequest) -> Result<Vec<u8>>;
    fn key_id(&self) -> KeyId { /* defaults */ }
}
```

**There is deliberately no method yielding a seed, a scalar, or an export, and one
must not be added.** A custodian that could produce private material would not be
modelling an enclave, and code written against such a method would come to depend
on something Keystore cannot provide — at which point removing it is far harder
than never having added it. A test scans the trait's signatures and fails if such
a method appears.

Returning `Error::Declined` means a person said no, or a prompt timed out. That is
an ordinary outcome for an interface to render — `Error::is_declined` distinguishes
it from a failure — not a fault to log and retry.

Every software key implements the trait through a blanket impl, so one call site
serves both a local key and an enclave.

## Key rotation is not missing

A device's key set is fixed when it is added: none of the roster's seven operations
adds a key to an existing device. Rotating a key therefore means **revoking the
device and adding a new one under a new device id** — roster work, not identity
work. There is no rotation API here because there is nothing for one to do.

## Memory

Private key bytes are zeroized on drop, and `Debug` is implemented by hand so a
private key never reaches a log line someone adds while chasing a bug.

This is a mitigation, not a guarantee. It defends against a key lingering in a
freed allocation to be recovered from a core dump or handed to the next caller who
asks for memory. It does not defend against a process whose live memory is already
readable, and it cannot undo a copy the compiler made before the value reached the
wrapper.

## Out of scope

The recovery phrase and the second administrator are outside the first version
(DESIGN.md §10.2): **one admin, and a lost phone is a lost network** — a limit to tell trial
users plainly. Also out: platform keystore bindings (`android-client`), threshold
signing, and any change to the roster.

//! Signing in two steps, for a key this process cannot call.
//!
//! # Why this exists
//!
//! [`roster::sign::Signer`] is synchronous, which suits a key held here. It does
//! not suit the root key: that lives in a phone's secure enclave, behind a
//! biometric prompt, on the far side of a UniFFI boundary. Rust cannot call it
//! synchronously without blocking on a person, which on Android means risking
//! an ANR — and it cannot hold the private material at all, by design.
//!
//! So: this crate produces the exact bytes to be signed, somebody else signs
//! them, and the artifact is assembled from the result. Three things fall out,
//! and the third is why this is built now rather than when Android forces it.
//!
//! 1. **Nothing here blocks on a person.**
//! 2. **An enclave key needs no Rust implementation.** It never implements
//!    `Signer`, because it cannot.
//! 3. **An offline queue is a queue of requests.** DESIGN.md §2.6c has
//!    operations written while the network is off waiting locally. A
//!    prepared-but-unsigned request is precisely that, so the change that builds
//!    the queue inherits this type rather than inventing one.
//!
//! # The signature is checked, not trusted
//!
//! [`finish`] verifies before assembling. A custodian returning a wrong or
//! truncated signature is a bug worth catching here, cheaply, rather than
//! shipping an artifact that fails on a peer where the cause is far harder to
//! see.

use core::fmt;

use roster::id::KeyId;
use roster::sign::{PublicKey, Signer, assemble_operation, signing_input};
use roster::snapshot::{Snapshot, assemble_snapshot, snapshot_signing_input};
use roster::types::{Algorithm, OperationCore};

use crate::error::{Error, Result};

/// What a signing request will become.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// A roster operation.
    Operation,
    /// A roster snapshot.
    Snapshot,
    /// A proof of possession: the signature itself is the artifact.
    ///
    /// A joining device signs a challenge derived from its channel, and what
    /// travels is the signature alone. So assembling one is verifying it and
    /// handing it back.
    Possession,
}

/// Bytes awaiting a signature.
///
/// Inert: holding one grants no authority and reveals no private material. It
/// carries what must be signed and which key is expected to sign it, and
/// nothing else.
#[derive(Clone, PartialEq, Eq)]
pub struct SigningRequest {
    /// The exact bytes to sign — the same bytes the synchronous path signs.
    message: Vec<u8>,
    /// The artifact this will become.
    kind: RequestKind,
    /// The key expected to sign.
    key: KeyId,
    /// That key's algorithm.
    algorithm: Algorithm,
    /// The payload the signature will be attached to.
    payload: Vec<u8>,
}

impl SigningRequest {
    /// The bytes a custodian must sign.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// The key expected to produce the signature.
    #[must_use]
    pub const fn key(&self) -> KeyId {
        self.key
    }

    /// That key's algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// What this will become once signed.
    #[must_use]
    pub const fn kind(&self) -> RequestKind {
        self.kind
    }

    /// The encoded artifact the signature will be attached to.
    ///
    /// Public data — an operation's core, or a snapshot's body — and the reason
    /// it is reachable is that somebody has to tell a person what they are being
    /// asked to authorise. Reading it from here is reading the bytes that will be
    /// signed; accepting a description sent alongside them would let whoever
    /// supplies the bytes also supply what they claim to be.
    ///
    /// Empty for a proof of possession, whose signature is the whole artifact.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl fmt::Debug for SigningRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The message and payload are public data, but printing them in full
        // turns every log line into a wall. The shape is what a reader wants.
        f.debug_struct("SigningRequest")
            .field("kind", &self.kind)
            .field("key", &self.key)
            .field("algorithm", &self.algorithm)
            .field("message_len", &self.message.len())
            .finish()
    }
}

/// Prepares an operation for signing by a key held elsewhere.
///
/// The bytes are exactly what `roster::sign::signing_input` produces, so an
/// artifact assembled from a detached signature cannot be told from one signed
/// directly.
#[must_use]
pub fn prepare_operation(core: &OperationCore, key: &PublicKey) -> SigningRequest {
    let payload = core.encode();
    SigningRequest {
        message: signing_input(&core.network, core.operation_type(), &payload),
        kind: RequestKind::Operation,
        key: key.key_id(),
        algorithm: key.algorithm(),
        payload,
    }
}

/// Prepares a snapshot for signing by a key held elsewhere.
#[must_use]
pub fn prepare_snapshot(body: &Snapshot, key: &PublicKey) -> SigningRequest {
    let payload = body.encode();
    SigningRequest {
        message: snapshot_signing_input(&body.network, &payload),
        kind: RequestKind::Snapshot,
        key: key.key_id(),
        algorithm: key.algorithm(),
        payload,
    }
}

/// Prepares a proof of possession for signing by a key held elsewhere.
///
/// `challenge` is the exact bytes the synchronous proof signs — `enrollment`
/// derives them, domain-separated, from the channel. Nothing here adds to them,
/// so a proof made this way verifies exactly as one signed directly.
#[must_use]
pub fn prepare_possession(challenge: &[u8], key: &PublicKey) -> SigningRequest {
    SigningRequest {
        message: challenge.to_vec(),
        kind: RequestKind::Possession,
        key: key.key_id(),
        algorithm: key.algorithm(),
        payload: Vec::new(),
    }
}

/// Assembles the artifact from a signature over a request.
///
/// The signature is verified against the request's own bytes and the key it
/// names, before anything is assembled. A signature from the wrong key, or one
/// that does not verify, is refused here rather than emitted.
pub fn finish(request: &SigningRequest, key: &PublicKey, signature: &[u8]) -> Result<Vec<u8>> {
    if key.key_id() != request.key {
        return Err(Error::WrongSigningKey);
    }
    key.verify(&request.message, signature).map_err(|_| Error::SignatureMismatch)?;

    let bytes: [u8; 64] = signature.try_into().map_err(|_| Error::SignatureMismatch)?;
    Ok(match request.kind {
        RequestKind::Operation => assemble_operation(&request.payload, &bytes),
        RequestKind::Snapshot => assemble_snapshot(&request.payload, &bytes),
        RequestKind::Possession => bytes.to_vec(),
    })
}

/// Why a batch of signatures was not assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchRefusal {
    /// The answer did not carry exactly one signature per request.
    Count {
        /// How many requests the batch held.
        requests: usize,
        /// How many signatures came back.
        signatures: usize,
    },
    /// One item's signature did not verify.
    Item {
        /// Which item, counted from one as a person reading the list would.
        number: usize,
        /// What was wrong with it.
        cause: Error,
    },
}

impl fmt::Display for BatchRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Count { requests, signatures } => write!(
                f,
                "the batch held {requests} item{} and {signatures} signature{} came back",
                if *requests == 1 { "" } else { "s" },
                if *signatures == 1 { "" } else { "s" },
            ),
            Self::Item { number, cause } => write!(f, "item {number}: {cause}"),
        }
    }
}

/// Assembles every artifact of a batch, or none of them.
///
/// One act can need several signatures — an operation and the snapshot over the
/// roster once it is in — and they are authorised together, so they are checked
/// together: every signature is verified against its own request and the key
/// before anything is handed back. A caller that gets `Ok` holds every artifact;
/// one that gets `Err` holds nothing, and applies nothing.
///
/// # Errors
///
/// When the count differs from the requests', or when any item's signature is
/// refused by [`finish`] — reported with its number.
pub fn finish_all(
    requests: &[SigningRequest],
    key: &PublicKey,
    signatures: &[Vec<u8>],
) -> core::result::Result<Vec<Vec<u8>>, BatchRefusal> {
    if requests.len() != signatures.len() {
        return Err(BatchRefusal::Count { requests: requests.len(), signatures: signatures.len() });
    }
    let mut assembled = Vec::with_capacity(requests.len());
    for (index, (request, signature)) in requests.iter().zip(signatures).enumerate() {
        let artifact = finish(request, key, signature)
            .map_err(|cause| BatchRefusal::Item { number: index.saturating_add(1), cause })?;
        assembled.push(artifact);
    }
    Ok(assembled)
}

/// A holder of a private key this process may not have.
///
/// Deliberately absent: any method yielding a seed, a scalar, or an export.
/// **Do not add one.** A custodian that could produce private material would
/// not be modelling an enclave, and code written against such a method would
/// come to depend on something the real Android implementation cannot provide —
/// at which point removing it is far harder than never having added it.
pub trait KeyCustodian {
    /// The public key this custodian holds the private half of.
    fn public_key(&self) -> PublicKey;

    /// Signs a prepared request.
    ///
    /// Returning [`Error::Declined`] means a person said no, or a prompt timed
    /// out. That is an ordinary outcome for an interface to render, not a fault
    /// to log and retry.
    fn sign_request(&self, request: &SigningRequest) -> Result<Vec<u8>>;

    /// The id of the key held.
    fn key_id(&self) -> KeyId {
        self.public_key().key_id()
    }

    /// Whether [`Self::sign_request`] can be answered from this process.
    ///
    /// True for every key this process holds, and for a custodian that reaches
    /// its key by a call — a phone's keystore is one: [`Self::sign_request`]
    /// blocks, somebody is asked, and the signature comes back on the same call.
    /// The caller never learns a person was involved, and does not need to.
    ///
    /// False when the key is not reachable from here at all. A desktop whose key
    /// is in the machine's key store, usable only in the session of the person
    /// who owns it, is the case this exists for: the process holding the roster
    /// is not the process that can sign, and there is nothing here to block on.
    /// A caller that gets `false` must **prepare** the request and have somebody
    /// else answer it, rather than calling [`Self::sign_request`] and waiting.
    ///
    /// Defaulting to `true` is what keeps this free where it is not needed. It
    /// describes the custodian rather than the platform deliberately: a device
    /// may hold one network's key in one place and another's somewhere else, and
    /// a platform that later gains a custodian able to sign here changes that
    /// custodian and nothing above it.
    fn answers_here(&self) -> bool {
        true
    }
}

/// Every key this process holds is also a custodian of itself.
///
/// So the two paths are one at the call site: code written against
/// [`KeyCustodian`] works with a software key and with an enclave alike.
///
/// `?Sized` so that `dyn Signer` is covered too — a boxed or borrowed signer is
/// the ordinary way a caller holds one, and it would be a poor seam that only
/// accepted concrete types.
impl<T: Signer + ?Sized> KeyCustodian for T {
    fn public_key(&self) -> PublicKey {
        Signer::public_key(self)
    }

    fn sign_request(&self, request: &SigningRequest) -> Result<Vec<u8>> {
        Ok(Signer::sign(self, request.message())?)
    }
}

/// Runs a request past a custodian and assembles the result.
///
/// Generic rather than taking `&dyn KeyCustodian`, because one trait object
/// cannot be coerced into another: a caller holding a `&dyn Signer` — which is
/// the ordinary way to hold one — could not otherwise pass it, despite every
/// signer being a custodian.
pub fn sign_with_custodian<C: KeyCustodian + ?Sized>(
    request: &SigningRequest,
    custodian: &C,
) -> Result<Vec<u8>> {
    let signature = custodian.sign_request(request)?;
    finish(request, &custodian.public_key(), &signature)
}

#[cfg(test)]
mod tests {
    use super::{RequestKind, SigningRequest, prepare_operation};
    use crate::identity::NodeIdentity;
    use roster::id::{KeyId, NetworkId};
    use roster::types::{Algorithm, OperationBody, OperationCore, Role};

    /// Builds a small operation core authored by an identity.
    fn core(identity: &NodeIdentity) -> OperationCore {
        OperationCore::new(
            1,
            identity.signing_key().algorithm(),
            OperationBody::CreateNetwork {
                device: identity.device_spec("phone", Role::Admin, true, vec![]).expect("spec"),
                params: roster::types::NetworkParams::new(
                    vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
                    "example.internal",
                    2_592_000,
                )
                .expect("valid"),
            },
            vec![],
            identity.signing_key().key_id(),
            NetworkId::from_bytes([0; 32]),
        )
        .expect("well-formed")
    }

    #[test]
    fn a_request_carries_no_private_material() {
        let identity = NodeIdentity::generate().expect("generates");
        let request = prepare_operation(&core(&identity), &identity.signing_key().public_key());

        let secret = identity.signing_key().material().expect("held").expose();
        assert!(
            !request.message().windows(secret.len()).any(|window| window == secret),
            "the message must not contain the private key"
        );

        let rendered = format!("{request:?}");
        let hex: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
        assert!(!rendered.contains(&hex), "and neither must the debug output");
        assert!(rendered.contains("message_len"));
    }

    #[test]
    fn a_request_names_the_key_expected_to_sign() {
        let identity = NodeIdentity::generate().expect("generates");
        let request = prepare_operation(&core(&identity), &identity.signing_key().public_key());
        assert_eq!(request.key(), identity.signing_key().key_id());
        assert_eq!(request.algorithm(), identity.signing_key().algorithm());
        assert_eq!(request.kind(), RequestKind::Operation);
        assert_ne!(request.key(), KeyId::from_bytes([0; 32]));
    }

    /// A batch is assembled whole or not at all, and a refusal names the item.
    #[test]
    fn a_batch_is_finished_whole_or_not_at_all() {
        use super::{BatchRefusal, finish, finish_all, prepare_snapshot};
        use roster::snapshot::Snapshot;

        let identity = NodeIdentity::generate().expect("generates");
        let key = identity.signing_key().public_key();
        let operation = prepare_operation(&core(&identity), &key);
        let body = Snapshot::new(
            1,
            vec![0xa0],
            vec![core(&identity).id()],
            vec![0],
            identity.signing_key().key_id(),
            NetworkId::from_bytes([7; 32]),
        )
        .expect("well-formed");
        let snapshot = prepare_snapshot(&body, &key);
        let requests = vec![operation.clone(), snapshot.clone()];

        let first = identity.signer().sign(operation.message()).expect("signs");
        let second = identity.signer().sign(snapshot.message()).expect("signs");

        let whole = finish_all(&requests, &key, &[first.clone(), second.clone()]).expect("whole");
        assert_eq!(
            vec![
                finish(&operation, &key, &first).expect("one"),
                finish(&snapshot, &key, &second).expect("two"),
            ],
            whole,
            "the same artifacts, one at a time or together"
        );

        // The second signed over the first's bytes: refused, and named.
        let refused = finish_all(&requests, &key, &[first.clone(), first.clone()]);
        assert!(matches!(refused, Err(BatchRefusal::Item { number: 2, .. })), "{refused:?}");

        let short = finish_all(&requests, &key, &[first]);
        assert_eq!(Err(BatchRefusal::Count { requests: 2, signatures: 1 }), short);
    }

    #[test]
    fn requests_are_comparable_and_cloneable() {
        let identity = NodeIdentity::generate().expect("generates");
        let request = prepare_operation(&core(&identity), &identity.signing_key().public_key());
        let clone: SigningRequest = request.clone();
        assert_eq!(request, clone);
        assert_eq!(Algorithm::Ed25519, request.algorithm());
    }
}

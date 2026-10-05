//! Detached signing, and keys this process cannot reach.
//!
//! The test that matters most is that the two signing paths produce identical
//! bytes. If they ever drift, an operation signed on a phone would verify on
//! one device and not another — a divergence that would look like a crypto bug
//! and be nothing of the sort.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

use std::cell::Cell;

use identity::detached::{
    KeyCustodian, RequestKind, SigningRequest, finish, prepare_operation, prepare_snapshot,
    sign_with_custodian,
};
use identity::{Error, NodeIdentity};
use roster::dag::Dag;
use roster::id::{NetworkId, OperationId};
use roster::sign::{Ed25519Signer, P256Signer, PublicKey, RawOperation, Signer, sign_operation};
use roster::snapshot::{RawSnapshot, Snapshot, sign_snapshot};
use roster::state::derive;
use roster::types::{Algorithm, NetworkParams, OperationBody, OperationCore, Role};

/// Fixture network parameters.
fn params() -> NetworkParams {
    NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 2_592_000)
        .expect("valid")
}

/// A founding operation core authored by an identity.
fn genesis_core(identity: &NodeIdentity) -> OperationCore {
    OperationCore::new(
        1_735_689_600_000,
        identity.signing_key().algorithm(),
        OperationBody::CreateNetwork {
            device: identity.device_spec("phone", Role::Admin, true, vec![]).expect("spec"),
            params: params(),
        },
        vec![],
        identity.signing_key().key_id(),
        NetworkId::from_bytes([0; 32]),
    )
    .expect("well-formed")
}

// ---------------------------------------------------------------------------
// The two paths agree
// ---------------------------------------------------------------------------

#[test]
fn a_detached_signature_produces_the_same_operation() {
    let identity = NodeIdentity::generate().expect("generates");
    let core = genesis_core(&identity);

    let direct = sign_operation(&core, identity.signer()).expect("signs");

    let request = prepare_operation(&core, &identity.signing_key().public_key());
    let signature = identity.signer().sign(request.message()).expect("signs");
    let detached =
        finish(&request, &identity.signing_key().public_key(), &signature).expect("assembles");

    assert_eq!(direct, detached, "the two paths must not drift");
}

#[test]
fn a_detached_signature_produces_the_same_snapshot() {
    let identity = NodeIdentity::generate().expect("generates");
    let core = genesis_core(&identity);
    let bytes = sign_operation(&core, identity.signer()).expect("signs");

    let mut dag = Dag::new();
    let raw = RawOperation::decode(&bytes).expect("decodes");
    dag.insert(raw.verify(&identity.signing_key().public_key()).expect("verifies"))
        .expect("inserts");

    let network = NetworkId::from_bytes(*core.id().as_bytes());
    let body = Snapshot::new(
        1,
        derive(&dag).expect("derives").to_bytes(),
        vec![core.id()],
        vec![0],
        identity.signing_key().key_id(),
        network,
    )
    .expect("well-formed");

    let direct = sign_snapshot(&body, identity.signer()).expect("signs");

    let request = prepare_snapshot(&body, &identity.signing_key().public_key());
    let signature = identity.signer().sign(request.message()).expect("signs");
    let detached =
        finish(&request, &identity.signing_key().public_key(), &signature).expect("assembles");

    assert_eq!(direct, detached);
    assert!(RawSnapshot::decode(&detached).is_ok());
}

/// The two request kinds sign different bytes even over related content, so a
/// signature cannot be moved between them.
#[test]
fn operation_and_snapshot_requests_never_share_their_bytes() {
    let identity = NodeIdentity::generate().expect("generates");
    let core = genesis_core(&identity);
    let key = identity.signing_key().public_key();

    let operation = prepare_operation(&core, &key);
    let body = Snapshot::new(
        1,
        core.encode(),
        vec![core.id()],
        vec![0],
        identity.signing_key().key_id(),
        NetworkId::from_bytes([9; 32]),
    )
    .expect("well-formed");
    let snapshot = prepare_snapshot(&body, &key);

    assert_ne!(operation.message(), snapshot.message());
    assert_eq!(operation.kind(), RequestKind::Operation);
    assert_eq!(snapshot.kind(), RequestKind::Snapshot);
}

/// A detached operation is a real operation: it verifies and derives.
#[test]
fn a_detached_operation_is_accepted_by_the_roster() {
    let identity = NodeIdentity::generate().expect("generates");
    let core = genesis_core(&identity);

    let request = prepare_operation(&core, &identity.signing_key().public_key());
    let signature = identity.signer().sign(request.message()).expect("signs");
    let bytes =
        finish(&request, &identity.signing_key().public_key(), &signature).expect("assembles");

    let mut node = roster::roster::Roster::new();
    assert!(node.offer_bytes(&bytes).is_accepted());
    let state = node.state().expect("derives");
    assert!(state.devices.contains_key(&identity.device_id()));
}

// ---------------------------------------------------------------------------
// Assembly refuses what it should
// ---------------------------------------------------------------------------

#[test]
fn a_signature_that_does_not_verify_is_refused() {
    let identity = NodeIdentity::generate().expect("generates");
    let core = genesis_core(&identity);
    let key = identity.signing_key().public_key();
    let request = prepare_operation(&core, &key);

    let mut signature = identity.signer().sign(request.message()).expect("signs");
    if let Some(first) = signature.first_mut() {
        *first ^= 0xff;
    }
    assert_eq!(finish(&request, &key, &signature).map(|_| ()), Err(Error::SignatureMismatch));
}

#[test]
fn a_signature_from_another_key_is_refused() {
    let identity = NodeIdentity::generate().expect("generates");
    let stranger = NodeIdentity::generate().expect("generates");
    let core = genesis_core(&identity);
    let request = prepare_operation(&core, &identity.signing_key().public_key());

    // A perfectly valid signature — over the right bytes — by the wrong key.
    let signature = stranger.signer().sign(request.message()).expect("signs");
    assert_eq!(
        finish(&request, &stranger.signing_key().public_key(), &signature).map(|_| ()),
        Err(Error::WrongSigningKey),
        "the request names a key, and only that key answers it"
    );
}

#[test]
fn a_truncated_signature_is_refused() {
    let identity = NodeIdentity::generate().expect("generates");
    let core = genesis_core(&identity);
    let key = identity.signing_key().public_key();
    let request = prepare_operation(&core, &key);
    let signature = identity.signer().sign(request.message()).expect("signs");

    assert!(finish(&request, &key, signature.get(..32).unwrap_or_default()).is_err());
    assert!(finish(&request, &key, &[]).is_err());
}

// ---------------------------------------------------------------------------
// Custodians
// ---------------------------------------------------------------------------

/// A custodian that holds its key where the caller cannot reach it, standing in
/// for an enclave.
struct SealedCustodian {
    /// Unreachable from outside this struct — the point of the exercise.
    inner: Ed25519Signer,
    /// Whether the next attempt is declined, as a person might.
    declines: Cell<bool>,
    /// Whether the next attempt fails for another reason.
    fails: Cell<bool>,
}

impl SealedCustodian {
    fn new(seed: u8) -> Self {
        Self {
            inner: Ed25519Signer::from_seed([seed; 32]),
            declines: Cell::new(false),
            fails: Cell::new(false),
        }
    }

    fn decline_next(&self) {
        self.declines.set(true);
    }

    fn fail_next(&self) {
        self.fails.set(true);
    }
}

impl KeyCustodian for SealedCustodian {
    fn public_key(&self) -> PublicKey {
        Signer::public_key(&self.inner)
    }

    fn sign_request(&self, request: &SigningRequest) -> identity::Result<Vec<u8>> {
        if self.declines.replace(false) {
            return Err(Error::Declined);
        }
        if self.fails.replace(false) {
            return Err(Error::CustodianFailed { detail: "hardware unavailable".to_owned() });
        }
        Ok(Signer::sign(&self.inner, request.message())?)
    }
}

#[test]
fn a_custodian_signs_without_the_caller_reaching_its_key() {
    let custodian = SealedCustodian::new(7);
    let core = OperationCore::new(
        1,
        Algorithm::Ed25519,
        OperationBody::Demote { device: roster::id::DeviceId::from_bytes([2; 32]) },
        vec![OperationId::from_bytes([1; 32])],
        custodian.key_id(),
        NetworkId::from_bytes([5; 32]),
    )
    .expect("well-formed");

    let request = prepare_operation(&core, &custodian.public_key());
    let bytes = sign_with_custodian(&request, &custodian).expect("signs and assembles");

    let raw = RawOperation::decode(&bytes).expect("decodes");
    assert!(raw.verify(&custodian.public_key()).is_ok(), "the assembled operation verifies");
}

/// A person saying no is an ordinary outcome, and must be distinguishable from
/// something going wrong.
#[test]
fn a_declined_prompt_is_an_ordinary_error() {
    let custodian = SealedCustodian::new(8);
    let core = OperationCore::new(
        1,
        Algorithm::Ed25519,
        OperationBody::Demote { device: roster::id::DeviceId::from_bytes([2; 32]) },
        vec![OperationId::from_bytes([1; 32])],
        custodian.key_id(),
        NetworkId::from_bytes([5; 32]),
    )
    .expect("well-formed");
    let request = prepare_operation(&core, &custodian.public_key());

    custodian.decline_next();
    let outcome = sign_with_custodian(&request, &custodian);
    assert_eq!(outcome.as_ref().err(), Some(&Error::Declined));
    assert!(outcome.err().is_some_and(|error| error.is_declined()));

    custodian.fail_next();
    let failure = sign_with_custodian(&request, &custodian);
    assert!(
        failure.as_ref().err().is_some_and(|error| !error.is_declined()),
        "a hardware failure is not a decline"
    );

    // And once neither is armed, it signs.
    assert!(sign_with_custodian(&request, &custodian).is_ok());
}

/// The enclave imposes P-256 on the root key, so a P-256 custodian must work
/// exactly as an ed25519 one does.
#[test]
fn a_p256_custodian_works_the_same_way() {
    let signer = P256Signer::from_scalar([0x33; 32]).expect("in range");
    let core = OperationCore::new(
        1,
        Algorithm::P256,
        OperationBody::Demote { device: roster::id::DeviceId::from_bytes([2; 32]) },
        vec![OperationId::from_bytes([1; 32])],
        Signer::key_id(&signer),
        NetworkId::from_bytes([5; 32]),
    )
    .expect("well-formed");

    let key = Signer::public_key(&signer);
    let request = prepare_operation(&core, &key);
    assert_eq!(request.algorithm(), Algorithm::P256);

    let bytes = sign_with_custodian(&request, &signer).expect("signs");
    let raw = RawOperation::decode(&bytes).expect("decodes");
    assert!(raw.verify(&key).is_ok());
}

/// Every software key is a custodian of itself, so one call site serves both.
#[test]
fn a_software_key_is_also_a_custodian() {
    let identity = NodeIdentity::generate().expect("generates");
    let core = genesis_core(&identity);
    let request = prepare_operation(&core, &identity.signing_key().public_key());

    let direct = sign_operation(&core, identity.signer()).expect("signs");
    let via_trait = sign_with_custodian(&request, identity.signer()).expect("signs");
    assert_eq!(direct, via_trait);
}

/// The trait exposes a public key and a signing call, and nothing that would
/// yield private material.
#[test]
fn a_custodian_exposes_no_export() {
    let custodian = SealedCustodian::new(9);
    let key = custodian.public_key();
    assert_eq!(custodian.key_id(), key.key_id());
    assert_eq!(key.as_bytes().len(), 32);

    // Scan the trait's *method signatures*, not its prose: the documentation
    // explaining why there is no export necessarily uses these very words.
    let source = include_str!("../src/detached.rs");
    let trait_body = source
        .split("pub trait KeyCustodian {")
        .nth(1)
        .and_then(|rest| rest.split("\n}").next())
        .expect("the trait is declared");
    let signatures: String = trait_body
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("fn "))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(signatures.contains("fn public_key"), "the scan found the real signatures");
    assert!(signatures.contains("fn sign_request"));
    for forbidden in ["export", "seed", "scalar", "private", "material", "secret"] {
        assert!(
            !signatures.contains(forbidden),
            "the custodian trait must expose no `{forbidden}`; adding one would let code \
             depend on something an enclave cannot provide. Signatures were:\n{signatures}"
        );
    }
}

/// A person cannot be told what they are authorising unless the bytes themselves
/// can be read, and they must be read rather than described by whoever sent them.
///
/// So the request carries its payload where a caller can reach it — and it is the
/// same payload the artifact is assembled from, not a copy that could differ.
#[test]
fn a_request_carries_the_artifact_it_will_become() {
    let identity = NodeIdentity::generate().expect("an identity");
    let core = genesis_core(&identity);
    let request = prepare_operation(&core, &identity.signing_key().public_key());

    assert_eq!(core.encode(), request.payload(), "what is read is what was prepared");
    assert!(!request.payload().is_empty(), "an operation has a body to show a person");

    // And the assembled artifact is built from those bytes, so reading them is
    // reading the act, not a description of it.
    let signed = sign_with_custodian(&request, identity.signing_key().signer()).expect("signs");
    assert!(
        signed.windows(request.payload().len()).any(|window| window == request.payload()),
        "the artifact contains the payload that was shown"
    );
}

/// A proof of possession has no artifact but its signature, and says so rather
/// than offering bytes that mean nothing.
#[test]
fn a_possession_request_has_no_payload_to_show() {
    let identity = NodeIdentity::generate().expect("an identity");
    let request = identity::detached::prepare_possession(
        b"the channel's challenge",
        &identity.signing_key().public_key(),
    );
    assert!(request.payload().is_empty(), "there is no artifact, only the signature");
    assert_eq!(RequestKind::Possession, request.kind());
}

//! An identity whose signing key a custodian holds.
//!
//! The phone's keystore will not hand over a private key, so the identity keeps
//! only the public half and asks. These check that nothing about the device, or
//! about what it signs, changes because of where the key lives.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

use std::sync::Arc;

use identity::detached::{KeyCustodian, SigningRequest};
use identity::{Error, NodeIdentity, PrivateKey};
use roster::id::NetworkId;
use roster::sign::{P256Signer, PublicKey, Signer};
use roster::types::{Algorithm, NetworkParams, OperationBody, OperationCore, Role};

/// The scalar both the custodian and the held key are built from.
const SCALAR: [u8; 32] = [0x21; 32];

/// The transport key both identities share.
fn transport() -> PrivateKey {
    PrivateKey::from_material(Algorithm::Ed25519, [0x42; 32]).expect("valid")
}

/// A custodian over a P-256 key, as a keystore would be.
fn custodian() -> Arc<dyn KeyCustodian + Send + Sync> {
    Arc::new(P256Signer::from_scalar(SCALAR).expect("inside the order"))
}

/// The same keys, with the signing key held here.
fn attestation() -> PrivateKey {
    PrivateKey::from_material(Algorithm::Ed25519, [0x5a; 32]).expect("valid")
}

fn held() -> NodeIdentity {
    let signing = PrivateKey::from_material(Algorithm::P256, SCALAR).expect("valid");
    NodeIdentity::assemble(signing, transport(), attestation()).expect("distinct keys")
}

/// The same keys, with the signing key held by the custodian.
fn held_elsewhere() -> NodeIdentity {
    NodeIdentity::with_custodian("peerfectly.casa.signing", custodian(), transport(), attestation())
        .expect("a key the roster accepts")
}

/// A founding, authored by whoever `identity` is.
fn founding(identity: &NodeIdentity) -> OperationCore {
    OperationCore::new(
        1_757_000_040_000,
        identity.signing_key().algorithm(),
        OperationBody::CreateNetwork {
            device: identity.device_spec("pixel", Role::Admin, true, vec![]).expect("spec"),
            params: NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "home.internal", 2_592_000)
                .expect("valid"),
        },
        vec![],
        identity.signing_key().key_id(),
        NetworkId::from_bytes([0; 32]),
    )
    .expect("well-formed")
}

#[test]
fn where_the_key_lives_changes_nothing_about_the_device() {
    let (here, elsewhere) = (held(), held_elsewhere());
    assert_eq!(here.device_id(), elsewhere.device_id());
    assert_eq!(
        here.device_spec("pixel", Role::Member, false, vec![]).expect("spec"),
        elsewhere.device_spec("pixel", Role::Member, false, vec![]).expect("spec")
    );
    assert!(elsewhere.signing_key().material().is_none(), "no private material is held");
    assert_eq!(
        elsewhere.signing_key().custodian().map(identity::CustodianKey::reference),
        Some("peerfectly.casa.signing")
    );
}

/// ECDSA over P-256 here is deterministic, so the same key over the same bytes
/// gives the same signature whichever path asked for it.
#[test]
fn an_operation_signed_through_the_custodian_is_the_same_bytes() {
    let (here, elsewhere) = (held(), held_elsewhere());
    let core = founding(&here);

    let direct = here.sign_operation(&core).expect("signs directly");
    let detached = elsewhere.sign_operation(&core).expect("signs through the custodian");
    assert_eq!(direct, detached);

    let mut roster = roster::roster::Roster::new();
    assert!(roster.offer_bytes(&detached).is_accepted(), "and the roster accepts it");
}

/// A person saying no is an outcome, and nothing is produced.
#[test]
fn a_declining_custodian_signs_nothing() {
    struct Declining(PublicKey);
    impl KeyCustodian for Declining {
        fn public_key(&self) -> PublicKey {
            self.0.clone()
        }
        fn sign_request(&self, _request: &SigningRequest) -> identity::Result<Vec<u8>> {
            Err(Error::Declined)
        }
    }

    let public = Signer::public_key(&P256Signer::from_scalar(SCALAR).expect("valid"));
    let identity = NodeIdentity::with_custodian(
        "peerfectly.casa.signing",
        Arc::new(Declining(public)),
        transport(),
        attestation(),
    )
    .expect("valid");

    assert_eq!(identity.sign_operation(&founding(&identity)), Err(Error::Declined));
}

/// Anything still reaching for the synchronous signer is refused, not handed a
/// signature it could not tell was declined.
#[test]
fn the_synchronous_signer_refuses_a_custodians_key() {
    let identity = held_elsewhere();
    assert!(identity.signer().sign(b"anything").is_err());
}

/// A custodian's key is checked like a generated one, against each of the two
/// keys held here rather than only against the transport key.
#[test]
fn a_custodian_offering_a_key_already_held_is_refused() {
    let reused: Arc<dyn KeyCustodian + Send + Sync> =
        Arc::new(roster::sign::Ed25519Signer::from_seed([0x42; 32]));

    assert_eq!(
        NodeIdentity::with_custodian("x", Arc::clone(&reused), transport(), attestation())
            .map(|_| ()),
        Err(Error::KeyReuse),
        "the transport key"
    );
    assert_eq!(
        NodeIdentity::with_custodian("x", reused, attestation(), transport()).map(|_| ()),
        Err(Error::KeyReuse),
        "and the attestation key"
    );
}

/// And the two keys held here must differ from each other.
#[test]
fn a_transport_key_reused_to_attest_is_refused() {
    assert_eq!(
        NodeIdentity::with_custodian("x", custodian(), transport(), transport()).map(|_| ()),
        Err(Error::KeyReuse)
    );
}

/// A custodian somewhere this process cannot reach, as a desktop's machine key
/// store is: the process that holds the roster is not the one that can sign.
struct Elsewhere {
    /// The key it would use, if it could be used from here.
    public: PublicKey,
}

impl KeyCustodian for Elsewhere {
    fn public_key(&self) -> PublicKey {
        self.public.clone()
    }

    fn sign_request(&self, _request: &SigningRequest) -> Result<Vec<u8>, Error> {
        panic!("nothing may reach this: the caller must ask `answers_here` and prepare instead");
    }

    fn answers_here(&self) -> bool {
        false
    }
}

/// The default is what keeps this free everywhere it is not needed.
///
/// `detached` blanket-implements `KeyCustodian` for every `Signer`, so a key this
/// process holds is a custodian of itself — and inherits the default without a
/// line. A keystore custodian that blocks and returns a signature inherits it
/// too, which is why the phone's path is untouched by this.
#[test]
fn a_key_that_can_be_used_here_says_so_without_being_told() {
    assert!(held().signing_key().answers_here(), "a key held here answers here");
    assert!(
        held_elsewhere().signing_key().answers_here(),
        "and so does a custodian that answers on the call, as a keystore does"
    );
}

/// A custodian that cannot answer here says so, and the identity carries that up.
#[test]
fn a_key_that_cannot_be_used_here_says_so_too() {
    let custodian = Arc::new(Elsewhere { public: held().signing_key().public_key() });
    let identity = NodeIdentity::with_custodian(
        "peerfectly.home.signing".to_owned(),
        custodian,
        transport(),
        attestation(),
    )
    .expect("an identity");

    assert!(!identity.signing_key().answers_here(), "the caller must prepare instead");
}

/// The net under a caller that did not ask.
///
/// Whether to prepare or to sign is decided by `answers_here`, before signing.
/// This is what happens to code that skipped that: a refusal naming the reason,
/// rather than a call that blocks on something which will never answer.
#[test]
fn signing_a_key_that_is_elsewhere_is_refused_rather_than_awaited() {
    let custodian = Arc::new(Elsewhere { public: held().signing_key().public_key() });
    let identity = NodeIdentity::with_custodian(
        "peerfectly.home.signing".to_owned(),
        custodian,
        transport(),
        attestation(),
    )
    .expect("an identity");

    let refusal = identity.sign_operation(&founding(&identity)).expect_err("refused");
    assert_eq!("signed_elsewhere", refusal.kind(), "and says which reason it is");
    assert!(!refusal.is_declined(), "nobody declined; the key is simply not here");
}

/// **The attestation key is never held by a custodian, on any platform.**
///
/// Not an omission. Dating a roster happens with nobody present, and a key in a
/// custodian's hands is a key that may ask — so an admin device whose
/// attestation key was a custodian's could date its roster only while somebody
/// was holding the machine, and a network whose only admin was such a device
/// would go stale whenever that person stopped looking at it. That is the defect
/// `membership-freshness` closed, and this is what stops it coming back.
///
/// What the shape concedes is bounded by what an attestation can say, which is a
/// date and nothing else.
///
/// Structural: an identity offers no way to build one from a custodian, so this
/// asserts the surface rather than a habit.
#[test]
fn an_attestation_key_is_held_here_on_every_platform() {
    let identity = held_elsewhere();
    assert!(
        identity.signing_key().custodian().is_some(),
        "the signing key is a custodian's, which is the case this is about"
    );
    assert!(
        identity.attestation_key().signer().sign(b"dating a roster").is_ok(),
        "and the attestation key signs here, with nobody asked"
    );

    // And the way an identity is built offers no other option: `with_custodian`
    // takes the attestation key by value, as private material this process holds.
    let source = include_str!("../src/identity.rs");
    let signature = source
        .split("pub fn with_custodian(")
        .nth(1)
        .and_then(|rest| rest.split(") -> Result<Self>").next())
        .expect("the constructor is declared");
    assert!(
        signature.contains("attestation: PrivateKey"),
        "the attestation key is private material this process holds, and the constructor \
         says so: {signature}"
    );
    assert!(
        !signature.contains("attestation: Arc<dyn KeyCustodian"),
        "nothing may build an identity whose attestation key is somebody else's"
    );
}

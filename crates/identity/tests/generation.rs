//! Generating an identity, and the device it presents.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

use identity::{Error, NodeIdentity, PrivateKey};
use roster::dag::Dag;
use roster::id::{DeviceId, NetworkId, OperationId};
use roster::roster::Roster;
use roster::sign::{RawOperation, sign_operation};
use roster::types::{
    Algorithm, Capability, KeyPurpose, NetworkParams, OperationBody, OperationCore, Role,
};

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

#[test]
fn two_generated_identities_differ_everywhere_that_matters() {
    let first = NodeIdentity::generate().expect("generates");
    let second = NodeIdentity::generate().expect("generates");

    assert_ne!(first.signing_key().public_key(), second.signing_key().public_key());
    assert_ne!(first.transport_key().public_key(), second.transport_key().public_key());
    assert_ne!(first.device_id(), second.device_id());
}

/// Twenty identities, no collisions. A generator seeded from a clock or a
/// counter would show up here long before it showed up in the field.
#[test]
fn generation_does_not_repeat_itself() {
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..20 {
        let identity = NodeIdentity::generate().expect("generates");
        assert!(seen.insert(identity.device_id()), "a generated device id repeated");
    }
    assert_eq!(seen.len(), 20);
}

/// The signing and transport keys are drawn separately. If one were derived
/// from the other, one compromise would be two.
#[test]
fn the_two_keys_are_independent() {
    for _ in 0..10 {
        let identity = NodeIdentity::generate().expect("generates");
        let signing = identity.signing_key().public_key();
        let transport = identity.transport_key().public_key();
        assert_ne!(signing.as_bytes(), transport.as_bytes());
        assert_ne!(
            identity.signing_key().material().expect("held").expose(),
            identity.transport_key().material().expose(),
            "the private material must differ too, not only the public keys"
        );
    }
}

/// Two identities generated from the same process share nothing: neither key is
/// a function of anything the caller supplied, because the caller supplies
/// nothing.
#[test]
fn generation_accepts_no_caller_supplied_material() {
    // `generate` takes no arguments at all; this compiles only because that is
    // true, and would stop compiling if a seed parameter were ever added.
    let make: fn() -> identity::Result<NodeIdentity> = NodeIdentity::generate;
    let identity = make().expect("generates");
    assert_ne!(identity.device_id(), DeviceId::from_bytes([0; 32]));
}

#[test]
fn a_signing_key_may_be_p256_as_an_enclave_imposes() {
    let identity = NodeIdentity::generate_with(Algorithm::P256).expect("generates");
    assert_eq!(identity.signing_key().algorithm(), Algorithm::P256);
    assert_eq!(
        identity.transport_key().algorithm(),
        Algorithm::Ed25519,
        "the transport key stays ed25519 whatever the enclave imposes on the root"
    );
}

#[test]
fn an_identity_refuses_one_key_for_two_purposes() {
    let material = [5u8; 32];
    let other = [6u8; 32];
    let key = |bytes| PrivateKey::from_material(Algorithm::Ed25519, bytes).expect("valid");

    for (a, b, c) in
        [(material, material, other), (material, other, material), (other, material, material)]
    {
        assert_eq!(
            NodeIdentity::assemble(key(a), key(b), key(c)).map(|_| ()),
            Err(Error::KeyReuse)
        );
    }
}

// ---------------------------------------------------------------------------
// The device an identity presents
// ---------------------------------------------------------------------------

#[test]
fn the_device_id_follows_from_the_signing_key() {
    let identity = NodeIdentity::generate().expect("generates");
    assert_eq!(
        identity.device_id(),
        DeviceId::of_signing_key(identity.signing_key().public_key().as_bytes())
    );
}

#[test]
fn a_presented_specification_carries_the_identitys_own_keys() {
    let identity = NodeIdentity::generate().expect("generates");
    let spec = identity
        .device_spec("laptop", Role::Member, false, vec![Capability::new("serves").expect("short")])
        .expect("builds");

    let signing =
        spec.keys.iter().find(|entry| entry.purpose == KeyPurpose::Signing).expect("a signing key");
    let transport = spec
        .keys
        .iter()
        .find(|entry| entry.purpose == KeyPurpose::Transport)
        .expect("a transport key");

    assert_eq!(signing.value, identity.signing_key().public_key().as_bytes());
    assert_eq!(transport.value, identity.transport_key().public_key().as_bytes());
    assert_eq!(spec.device_id().expect("has a signing key"), identity.device_id());
}

#[test]
fn a_specification_declares_exactly_one_key_of_each_purpose() {
    let identity = NodeIdentity::generate().expect("generates");
    let spec = identity.device_spec("nas", Role::Member, false, vec![]).expect("builds");
    assert_eq!(spec.keys.iter().filter(|e| e.purpose == KeyPurpose::Signing).count(), 1);
    assert_eq!(spec.keys.iter().filter(|e| e.purpose == KeyPurpose::Transport).count(), 1);
    for entry in &spec.keys {
        assert!(matches!(entry.alg, Algorithm::Ed25519 | Algorithm::P256));
    }
}

/// End to end: a generated identity founds a network and is present in the
/// roster the operations derive.
#[test]
fn a_generated_identity_is_accepted_by_the_roster() {
    let founder = NodeIdentity::generate().expect("generates");
    let spec = founder
        .device_spec("phone", Role::Admin, true, vec![Capability::new("serves").expect("short")])
        .expect("builds");

    let core = OperationCore::new(
        1_735_689_600_000,
        founder.signing_key().algorithm(),
        OperationBody::CreateNetwork {
            device: spec,
            params: NetworkParams::new(
                vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
                "example.internal",
                2_592_000,
            )
            .expect("valid"),
        },
        vec![],
        founder.signer().key_id(),
        NetworkId::from_bytes([0; 32]),
    )
    .expect("well-formed");
    let bytes = sign_operation(&core, founder.signer()).expect("signs");

    let mut node = Roster::new();
    assert!(node.offer_bytes(&bytes).is_accepted(), "the roster accepts a generated identity");

    let state = node.state().expect("derives");
    let record = state.devices.get(&founder.device_id()).expect("the founder is present");
    assert_eq!(record.keys.len(), 3, "all three keys reached derived state");
    assert!(record.founder);
    assert_eq!(record.role, Role::Admin);
}

/// A second generated identity is added by the first, and both end up in the
/// derived roster with their own keys.
#[test]
fn a_generated_identity_can_be_added_by_another() {
    let founder = NodeIdentity::generate().expect("generates");
    let joiner = NodeIdentity::generate().expect("generates");

    let genesis_core = OperationCore::new(
        1,
        founder.signing_key().algorithm(),
        OperationBody::CreateNetwork {
            device: founder.device_spec("phone", Role::Admin, true, vec![]).expect("builds"),
            params: NetworkParams::new(
                vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
                "example.internal",
                2_592_000,
            )
            .expect("valid"),
        },
        vec![],
        founder.signer().key_id(),
        NetworkId::from_bytes([0; 32]),
    )
    .expect("well-formed");
    let genesis_bytes = sign_operation(&genesis_core, founder.signer()).expect("signs");
    let network = NetworkId::from_bytes(*genesis_core.id().as_bytes());

    let add_core = OperationCore::new(
        2,
        founder.signing_key().algorithm(),
        OperationBody::AddDevice(
            joiner.device_spec("laptop", Role::Member, false, vec![]).expect("builds"),
        ),
        vec![genesis_core.id()],
        founder.signer().key_id(),
        network,
    )
    .expect("well-formed");
    let add_bytes = sign_operation(&add_core, founder.signer()).expect("signs");

    let mut node = Roster::new();
    assert!(node.offer_bytes(&genesis_bytes).is_accepted());
    assert!(node.offer_bytes(&add_bytes).is_accepted());

    let state = node.state().expect("derives");
    assert!(state.devices.contains_key(&founder.device_id()));
    assert!(state.devices.contains_key(&joiner.device_id()));
}

/// The reproducible constructors still work, and are documented as being for
/// tests and vectors rather than for a device.
#[test]
fn the_reproducible_constructors_are_reproducible_and_marked() {
    let a = PrivateKey::from_material(Algorithm::Ed25519, [1u8; 32]).expect("valid");
    let b = PrivateKey::from_material(Algorithm::Ed25519, [1u8; 32]).expect("valid");
    assert_eq!(a.public_key(), b.public_key(), "same material, same key");

    let docs = include_str!("../src/identity.rs");
    assert!(
        docs.contains("tests and vectors") || docs.contains("test-and-vector"),
        "the warning that these are not for a device must survive edits"
    );
}

/// Silences an unused-import warning while keeping the imports honest about
/// what an operation needs.
#[allow(dead_code, reason = "kept so the import list mirrors a real caller")]
fn unused_shape(_: OperationId, _: Dag, _: RawOperation<'_>) {}

/// A P-256 signing key is 33 bytes and an ed25519 transport key is 32, so the
/// two entries encode to different lengths. An ordering that approximates the
/// roster's canonical entry order — rather than using it — agrees for two
/// ed25519 keys and disagrees here. Found by the storage property test.
#[test]
fn a_p256_identity_orders_its_key_entries_correctly() {
    let identity = NodeIdentity::generate_with(Algorithm::P256).expect("generates");
    let spec = identity
        .device_spec("phone", Role::Admin, true, vec![])
        .expect("the entries must be in the order the roster requires");

    assert_eq!(spec.device_id().expect("has a signing key"), identity.device_id());

    // And the order really is the roster's own, applied to these two entries.
    let mut expected = spec.keys.clone();
    expected.sort_by_key(roster::types::KeyEntry::order_key);
    assert_eq!(spec.keys, expected);
}

/// Both algorithm combinations round-trip through a device specification.
#[test]
fn every_signing_algorithm_produces_a_usable_specification() {
    for algorithm in [Algorithm::Ed25519, Algorithm::P256] {
        let identity = NodeIdentity::generate_with(algorithm).expect("generates");
        let spec = identity.device_spec("device", Role::Member, false, vec![]).expect("builds");
        assert_eq!(spec.device_id().expect("has a signing key"), identity.device_id());
        assert_eq!(identity.signing_key().algorithm(), algorithm);
    }
}

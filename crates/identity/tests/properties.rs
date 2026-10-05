//! Property-based tests over identity.
//!
//! The fixed tests check the cases we thought of. These check that generation
//! keeps working over many draws, that the two signing paths never drift, and
//! that a stored identity is the identity that comes back.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

use identity::detached::{finish, prepare_operation};
use identity::{Error, NodeIdentity};
use proptest::prelude::*;
use roster::id::{DeviceId, NetworkId, OperationId};
use roster::roster::Roster;
use roster::sign::sign_operation;
use roster::types::{Algorithm, Capability, NetworkParams, OperationBody, OperationCore, Role};

/// A body an identity can author, chosen by the generator.
///
/// The rename carries a tag so successive draws differ; the other shapes need
/// no payload, because the device they target comes from a second identity the
/// property generates alongside.
#[derive(Debug, Clone, Copy)]
enum Body {
    /// Add a device.
    Add,
    /// Rename one, to a name the tag distinguishes.
    Rename(u8),
    /// Promote one.
    Promote,
    /// Revoke one.
    Revoke,
}

/// Generates a body shape.
fn body_strategy() -> impl Strategy<Value = Body> {
    prop_oneof![
        Just(Body::Add),
        any::<u8>().prop_map(Body::Rename),
        Just(Body::Promote),
        Just(Body::Revoke),
    ]
}

/// Turns a generated shape into an operation body.
fn build_body(shape: Body, other: &NodeIdentity) -> OperationBody {
    match shape {
        Body::Add => OperationBody::AddDevice(
            other.device_spec("device", Role::Member, false, vec![]).expect("spec"),
        ),
        Body::Rename(tag) => {
            OperationBody::Rename { device: other.device_id(), name: format!("n{tag}") }
        }
        Body::Promote => OperationBody::Promote { device: other.device_id(), founder: false },
        Body::Revoke => OperationBody::RevokeDevice {
            device: other.device_id(),
            reason: "generated".to_owned(),
        },
    }
}

proptest! {
    /// A generated identity always produces a device the roster accepts.
    #[test]
    fn a_generated_identity_is_always_accepted(name in "[a-z]{1,12}", admin in any::<bool>()) {
        let identity = NodeIdentity::generate().expect("generates");
        let role = if admin { Role::Admin } else { Role::Member };
        let spec = identity
            .device_spec(name, role, admin, vec![Capability::new("serves").expect("short")])
            .expect("builds");

        prop_assert_eq!(spec.device_id().expect("has a signing key"), identity.device_id());

        let core = OperationCore::new(
            1,
            identity.signing_key().algorithm(),
            OperationBody::CreateNetwork {
                device: identity.device_spec("phone", Role::Admin, true, vec![]).expect("spec"),
                params: NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 2_592_000)
                    .expect("valid"),
            },
            vec![],
            identity.signing_key().key_id(),
            NetworkId::from_bytes([0; 32]),
        )
        .expect("well-formed");
        let bytes = sign_operation(&core, identity.signer()).expect("signs");

        let mut node = Roster::new();
        prop_assert!(node.offer_bytes(&bytes).is_accepted());
    }

    /// The synchronous and detached paths never drift.
    #[test]
    fn the_two_signing_paths_agree(shape in body_strategy(), ts in any::<u64>()) {
        let founder = NodeIdentity::generate().expect("generates");
        let other = NodeIdentity::generate().expect("generates");

        let core = OperationCore::new(
            ts,
            founder.signing_key().algorithm(),
            build_body(shape, &other),
            vec![OperationId::from_bytes([1; 32])],
            founder.signing_key().key_id(),
            NetworkId::from_bytes([4; 32]),
        )
        .expect("well-formed");

        let direct = sign_operation(&core, founder.signer()).expect("signs");
        let request = prepare_operation(&core, &founder.signing_key().public_key());
        let signature = founder.signer().sign(request.message()).expect("signs");
        let detached = finish(&request, &founder.signing_key().public_key(), &signature)
            .expect("assembles");

        prop_assert_eq!(direct, detached);
    }

    /// A stored identity is the identity that comes back.
    #[test]
    fn storage_round_trips(p256 in any::<bool>(), name in "[a-z]{1,10}") {
        let identity = if p256 {
            NodeIdentity::generate_with(Algorithm::P256).expect("generates")
        } else {
            NodeIdentity::generate().expect("generates")
        };

        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("identity");
        roster_store_save(&identity, &path);
        let loaded = identity::store::load(&path).expect("loads");

        prop_assert_eq!(loaded.device_id(), identity.device_id());
        prop_assert_eq!(
            loaded.signing_key().public_key().as_bytes().to_vec(),
            identity.signing_key().public_key().as_bytes().to_vec()
        );
        prop_assert_eq!(
            loaded.device_spec(name.clone(), Role::Member, false, vec![]).expect("spec"),
            identity.device_spec(name, Role::Member, false, vec![]).expect("spec")
        );
    }

    /// Assembly never accepts a signature it should not.
    #[test]
    fn a_mutated_signature_is_never_accepted(position in 0usize..64, delta in 1u8..=255) {
        let identity = NodeIdentity::generate().expect("generates");
        let core = OperationCore::new(
            1,
            identity.signing_key().algorithm(),
            OperationBody::Demote { device: DeviceId::from_bytes([3; 32]) },
            vec![OperationId::from_bytes([1; 32])],
            identity.signing_key().key_id(),
            NetworkId::from_bytes([4; 32]),
        )
        .expect("well-formed");

        let key = identity.signing_key().public_key();
        let request = prepare_operation(&core, &key);
        let signature = identity.signer().sign(request.message()).expect("signs");
        prop_assert!(finish(&request, &key, &signature).is_ok(), "the real one works");

        let mut mutated = signature;
        if let Some(slot) = mutated.get_mut(position) {
            *slot = slot.wrapping_add(delta);
        }
        prop_assert_eq!(
            finish(&request, &key, &mutated).map(|_| ()),
            Err(Error::SignatureMismatch)
        );
    }

    /// Generated identities keep their two keys apart, however many are drawn.
    #[test]
    fn generated_keys_stay_separate(count in 1usize..6) {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..count {
            let identity = NodeIdentity::generate().expect("generates");
            prop_assert_ne!(
                identity.signing_key().public_key().as_bytes().to_vec(),
                identity.transport_key().public_key().as_bytes().to_vec()
            );
            prop_assert!(seen.insert(identity.device_id()), "a device id repeated");
        }
    }
}

/// Saves an identity, so the property above reads clearly.
fn roster_store_save(identity: &NodeIdentity, path: &std::path::Path) {
    identity::store::save(identity, path).expect("saves");
}

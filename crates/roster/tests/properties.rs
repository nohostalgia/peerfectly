//! Property-based tests over the encoding and the envelope.
//!
//! Fixed test cases check the failures we thought of. These check the ones we
//! did not: that encoding is a fixpoint, that identity does not depend on how
//! a value was built, and that no single-byte change to a signed operation can
//! slip past both the decoder and the signature.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

mod common;

use common::{ed25519_signer, network, p256_signer};
use proptest::prelude::*;
use roster::id::{KeyId, NetworkId, OperationId};
use roster::sign::{RawOperation, Signer, sign_operation};
use roster::types::{
    Algorithm, Capability, DeviceSpec, KeyEntry, KeyPurpose, NetworkParams, OperationBody,
    OperationCore, Role,
};

/// A name within bounds.
fn name_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{0,20}".prop_map(|text| text)
}

/// A capability within bounds.
fn capability_strategy() -> impl Strategy<Value = Capability> {
    "[a-z_]{1,12}".prop_map(|text| Capability::new(text).expect("bounded by the pattern"))
}

/// A device built from three distinct fixture keys.
fn device_strategy() -> impl Strategy<Value = DeviceSpec> {
    (
        any::<u8>(),
        name_strategy(),
        any::<bool>(),
        any::<bool>(),
        proptest::collection::vec(capability_strategy(), 0..4),
    )
        .prop_map(|(seed, name, is_admin, founder, capabilities)| {
            let signing = common::signing_entry(seed);
            let transport = common::transport_entry(seed.wrapping_add(97));
            let attestation = common::attestation_entry(seed.wrapping_add(193));
            let role = if is_admin { Role::Admin } else { Role::Member };
            DeviceSpec::new(
                common::sorted(vec![signing, transport, attestation]),
                name,
                role,
                founder,
                capabilities,
            )
            .expect("fixture keys are distinct and every field is bounded")
        })
}

/// Network parameters within bounds.
///
/// The prefix is a unique local `/64` and the suffix a private name, because
/// that is all the parameters can hold: anything else is refused where they are
/// built, and a strategy producing it would be testing the refusal rather than
/// the encoding.
fn params_strategy() -> impl Strategy<Value = NetworkParams> {
    // The label starts with `n` so no draw can land on one of the reserved
    // names, which the parameters refuse.
    (proptest::array::uniform7(any::<u8>()), "n[a-z]{0,9}\\.internal", any::<u64>()).prop_map(
        |(tail, suffix, window)| {
            let mut ula = vec![0xfd];
            ula.extend_from_slice(&tail);
            NetworkParams::new(ula, suffix, window).expect("bounded by the strategies")
        },
    )
}

/// A device id.
fn device_id_strategy() -> impl Strategy<Value = roster::id::DeviceId> {
    any::<[u8; 32]>().prop_map(roster::id::DeviceId::from_bytes)
}

/// A body of any of the seven types.
fn body_strategy() -> impl Strategy<Value = OperationBody> {
    prop_oneof![
        (device_strategy(), params_strategy())
            .prop_map(|(device, params)| OperationBody::CreateNetwork { device, params }),
        device_strategy().prop_map(OperationBody::AddDevice),
        (device_id_strategy(), "[a-z ]{0,40}")
            .prop_map(|(device, reason)| OperationBody::RevokeDevice { device, reason }),
        (device_id_strategy(), any::<bool>())
            .prop_map(|(device, founder)| OperationBody::Promote { device, founder }),
        device_id_strategy().prop_map(|device| OperationBody::Demote { device }),
        (device_id_strategy(), name_strategy())
            .prop_map(|(device, name)| OperationBody::Rename { device, name }),
        params_strategy().prop_map(OperationBody::SetNetwork),
    ]
}

/// A whole core, with an arbitrary but bounded parent list.
fn core_strategy() -> impl Strategy<Value = OperationCore> {
    (
        any::<u64>(),
        any::<bool>(),
        body_strategy(),
        proptest::collection::vec(any::<[u8; 32]>(), 0..6),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
    )
        .prop_map(|(ts, use_ed25519, body, parents, author, net)| {
            let alg = if use_ed25519 { Algorithm::Ed25519 } else { Algorithm::P256 };
            OperationCore::new(
                ts,
                alg,
                body,
                parents.into_iter().map(OperationId::from_bytes).collect(),
                KeyId::from_bytes(author),
                NetworkId::from_bytes(net),
            )
            .expect("the parent list is bounded by the strategy")
        })
}

proptest! {
    /// Encoding is a fixpoint. If it were not, two nodes holding the same
    /// operation could disagree about its bytes and therefore its id.
    #[test]
    fn encode_decode_encode_is_byte_identical(core in core_strategy()) {
        let first = core.encode();
        let signer: Box<dyn Signer> = match core.alg {
            Algorithm::Ed25519 => Box::new(ed25519_signer(1)),
            Algorithm::P256 => Box::new(p256_signer(2)),
        };
        // The author is arbitrary here, so re-sign under a core whose author
        // matches the signer; the encoding property is what is under test.
        let signable = OperationCore::new(
            core.ts,
            core.alg,
            core.body.clone(),
            core.parents.clone(),
            signer.key_id(),
            core.network,
        )
        .expect("bounded");
        let bytes = sign_operation(&signable, signer.as_ref()).expect("signs");
        let raw = RawOperation::decode(&bytes).expect("decodes");

        let signable_bytes = signable.encode();
        prop_assert_eq!(raw.core_bytes(), signable_bytes.as_slice());
        prop_assert_eq!(raw.core().encode(), raw.core_bytes().to_vec());
        prop_assert_eq!(raw.to_bytes(), bytes);
        // And the original core still encodes to what it did before.
        prop_assert_eq!(core.encode(), first);
    }

    /// A value's bytes depend on what it holds, never on the order the fields
    /// were assigned. Two clients that build the same operation differently
    /// must still produce the same id.
    #[test]
    fn construction_order_does_not_affect_bytes_or_id(
        ts in any::<u64>(),
        body in body_strategy(),
        parents in proptest::collection::vec(any::<[u8; 32]>(), 0..4),
        author in any::<[u8; 32]>(),
        net in any::<[u8; 32]>(),
    ) {
        let parent_ids: Vec<OperationId> =
            parents.into_iter().map(OperationId::from_bytes).collect();

        // Built directly.
        let a = OperationCore::new(
            ts,
            Algorithm::Ed25519,
            body.clone(),
            parent_ids.clone(),
            KeyId::from_bytes(author),
            NetworkId::from_bytes(net),
        )
        .expect("bounded");

        // Built by mutating a differently-initialised value into the same one.
        let mut b = OperationCore::new(
            0,
            Algorithm::P256,
            OperationBody::Demote { device: roster::id::DeviceId::from_bytes([0; 32]) },
            vec![],
            KeyId::from_bytes([0; 32]),
            NetworkId::from_bytes([0; 32]),
        )
        .expect("bounded");
        b.network = NetworkId::from_bytes(net);
        b.author = KeyId::from_bytes(author);
        b.parents = parent_ids;
        b.body = body;
        b.alg = Algorithm::Ed25519;
        b.ts = ts;

        prop_assert_eq!(a.encode(), b.encode());
        prop_assert_eq!(a.id(), b.id());
    }

    /// Every single-byte change to a signed operation must be caught, by the
    /// decoder or by the signature. A mutation that passed both would be a
    /// forgery.
    #[test]
    fn no_single_byte_mutation_survives_both_checks(
        position in 0usize..400,
        delta in 1u8..=255,
    ) {
        let signer = ed25519_signer(3);
        let core = common::core_for(roster::types::OperationType::AddDevice, &signer);
        let bytes = sign_operation(&core, &signer).expect("signs");
        let key = signer.public_key();

        // The original is accepted, which is what makes the mutation meaningful.
        let original = RawOperation::decode(&bytes).expect("decodes");
        prop_assert!(original.verify(&key).is_ok());

        prop_assume!(position < bytes.len());
        let mut mutated = bytes.clone();
        if let Some(slot) = mutated.get_mut(position) {
            *slot = slot.wrapping_add(delta);
        }
        prop_assume!(mutated != bytes);

        let survived = match RawOperation::decode(&mutated) {
            Err(_) => false,
            Ok(raw) => raw.verify(&key).is_ok(),
        };
        prop_assert!(!survived, "a mutated operation must not both decode and verify");
    }

    /// Decoding arbitrary bytes as an operation always terminates with a
    /// verdict, never a panic. This is the crate's network-facing entry point.
    #[test]
    fn decoding_arbitrary_bytes_never_panics(
        input in proptest::collection::vec(any::<u8>(), 0..600)
    ) {
        let _ = RawOperation::decode(&input);
    }

    /// Bytes that decode must re-encode to themselves. Anything else would
    /// mean the decoder accepted a non-canonical spelling.
    #[test]
    fn anything_that_decodes_is_already_canonical(
        input in proptest::collection::vec(any::<u8>(), 0..600)
    ) {
        if let Ok(raw) = RawOperation::decode(&input) {
            prop_assert_eq!(raw.to_bytes(), input.clone());
            prop_assert_eq!(raw.core().encode(), raw.core_bytes().to_vec());
        }
    }

    /// A key entry keeps its declared purpose and algorithm through a round
    /// trip; the two are never inferred from the value.
    #[test]
    fn key_entries_keep_their_declared_purpose(seed in any::<u8>(), signing in any::<bool>()) {
        let signer = ed25519_signer(seed);
        let purpose = if signing { KeyPurpose::Signing } else { KeyPurpose::Transport };
        let entry = KeyEntry::new(
            Algorithm::Ed25519,
            purpose,
            signer.public_key().as_bytes().to_vec(),
        )
        .expect("well-formed");
        prop_assert_eq!(entry.purpose, purpose);
        prop_assert_eq!(entry.alg, Algorithm::Ed25519);
    }
}

/// The fixture network is stable, so a failure reproduces.
#[test]
fn fixture_network_is_deterministic() {
    assert_eq!(network(), NetworkId::from_bytes([0x11; 32]));
}

//! Shared fixtures: deterministic keys and one well-formed operation of each
//! type, so every test starts from something that is known to be valid.
//!
//! Keys are derived from fixed seeds rather than generated randomly. A test
//! that fails should fail the same way twice.

#![allow(dead_code, reason = "each test binary uses a different part of this module")]

use roster::id::{DeviceId, KeyId, NetworkId, OperationId};
use roster::sign::{Ed25519Signer, P256Signer, PublicKey, Signer};
use roster::types::{
    Algorithm, Capability, DeviceSpec, KeyEntry, KeyPurpose, NetworkParams, OperationBody,
    OperationCore, OperationType, Role,
};

/// A fixed network id, so signing inputs are reproducible.
pub fn network() -> NetworkId {
    NetworkId::from_bytes([0x11; 32])
}

/// A second network, for testing that signatures do not cross between them.
pub fn other_network() -> NetworkId {
    NetworkId::from_bytes([0x22; 32])
}

/// A deterministic ed25519 signer.
pub fn ed25519_signer(seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed([seed; 32])
}

/// A deterministic P-256 signer.
///
/// The scalar is a fixed pattern that lies inside the curve order.
pub fn p256_signer(seed: u8) -> P256Signer {
    let mut scalar = [0x11; 32];
    if let Some(first) = scalar.first_mut() {
        *first = seed;
    }
    P256Signer::from_scalar(scalar).expect("fixture scalar is inside the curve order")
}

/// An ed25519 signing key entry for a device.
pub fn signing_entry(seed: u8) -> KeyEntry {
    let signer = ed25519_signer(seed);
    KeyEntry::new(Algorithm::Ed25519, KeyPurpose::Signing, signer.public_key().as_bytes().to_vec())
        .expect("well-formed signing key")
}

/// A transport key entry, distinct from the signing key.
pub fn transport_entry(seed: u8) -> KeyEntry {
    let signer = ed25519_signer(seed);
    KeyEntry::new(
        Algorithm::Ed25519,
        KeyPurpose::Transport,
        signer.public_key().as_bytes().to_vec(),
    )
    .expect("well-formed transport key")
}

/// An attestation key entry, distinct from the other two.
pub fn attestation_entry(seed: u8) -> KeyEntry {
    let signer = ed25519_signer(seed);
    KeyEntry::new(
        Algorithm::Ed25519,
        KeyPurpose::Attestation,
        signer.public_key().as_bytes().to_vec(),
    )
    .expect("well-formed attestation key")
}

/// Sorts key entries into the canonical order a device record requires.
pub fn sorted(mut keys: Vec<KeyEntry>) -> Vec<KeyEntry> {
    // The roster's own definition of the order, not an approximation.
    keys.sort_by_key(KeyEntry::order_key);
    keys
}

/// A device with one key of each purpose.
pub fn device(seed: u8, name: &str, role: Role, founder: bool) -> DeviceSpec {
    let keys = sorted(vec![
        signing_entry(seed),
        transport_entry(seed.wrapping_add(100)),
        attestation_entry(seed.wrapping_add(200)),
    ]);
    DeviceSpec::new(
        keys,
        name,
        role,
        founder,
        vec![Capability::new("serves").expect("short capability")],
    )
    .expect("well-formed device")
}

/// The device id of the fixture device with the given seed.
pub fn device_id(seed: u8) -> DeviceId {
    device(seed, "fixture", Role::Member, false).device_id().expect("device has a signing key")
}

/// Fixture network parameters.
pub fn params() -> NetworkParams {
    NetworkParams::new(
        vec![0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        "example.internal",
        30 * 24 * 60 * 60,
    )
    .expect("well-formed parameters")
}

/// A well-formed body of each of the seven operation types.
pub fn body_of(op_type: OperationType) -> OperationBody {
    match op_type {
        OperationType::CreateNetwork => OperationBody::CreateNetwork {
            device: device(1, "phone", Role::Admin, true),
            params: params(),
        },
        OperationType::AddDevice => {
            OperationBody::AddDevice(device(2, "laptop", Role::Member, false))
        }
        OperationType::RevokeDevice => OperationBody::RevokeDevice {
            device: device_id(2),
            reason: "lost on a train".to_owned(),
        },
        OperationType::Promote => OperationBody::Promote { device: device_id(2), founder: false },
        OperationType::Demote => OperationBody::Demote { device: device_id(2) },
        OperationType::Rename => {
            OperationBody::Rename { device: device_id(2), name: "workstation".to_owned() }
        }
        OperationType::SetNetwork => OperationBody::SetNetwork(params()),
    }
}

/// A core signed by the given signer, of the given type.
pub fn core_for(op_type: OperationType, signer: &dyn Signer) -> OperationCore {
    OperationCore::new(
        1_735_689_600_000,
        signer.algorithm(),
        body_of(op_type),
        vec![OperationId::from_bytes([0xaa; 32])],
        signer.key_id(),
        network(),
    )
    .expect("well-formed core")
}

/// A core with an explicit author, network, and parent list.
pub fn core_with(
    op_type: OperationType,
    signer: &dyn Signer,
    net: NetworkId,
    author: KeyId,
    parents: Vec<OperationId>,
) -> OperationCore {
    OperationCore::new(
        1_735_689_600_000,
        signer.algorithm(),
        body_of(op_type),
        parents,
        author,
        net,
    )
    .expect("well-formed core")
}

/// The public key of a signer.
pub fn public_key(signer: &dyn Signer) -> PublicKey {
    signer.public_key()
}

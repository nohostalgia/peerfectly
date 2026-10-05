//! A proof of possession made by a key this process does not hold.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

use std::sync::Arc;

use enrollment::exchange::Possession;
use identity::detached::KeyCustodian;
use identity::{NodeIdentity, PrivateKey};
use roster::sign::P256Signer;
use roster::types::Algorithm;

const CHANNEL: &[u8] = b"the material both ends of this channel derived";

fn transport() -> PrivateKey {
    PrivateKey::from_material(Algorithm::Ed25519, [0x42; 32]).expect("valid")
}

fn attestation() -> PrivateKey {
    PrivateKey::from_material(Algorithm::Ed25519, [0x5a; 32]).expect("valid")
}

#[test]
fn a_proof_through_a_custodian_verifies_as_a_direct_one_does() {
    let custodian: Arc<dyn KeyCustodian + Send + Sync> =
        Arc::new(P256Signer::from_scalar([0x21; 32]).expect("valid"));
    let elsewhere = NodeIdentity::with_custodian(
        "peerfectly.casa.signing",
        custodian,
        transport(),
        attestation(),
    )
    .expect("valid");
    let here = NodeIdentity::assemble(
        PrivateKey::from_material(Algorithm::P256, [0x21; 32]).expect("valid"),
        transport(),
        attestation(),
    )
    .expect("valid");
    let public = here.signing_key().public_key();

    let direct = Possession::prove(here.signer(), CHANNEL).expect("proves");
    let detached = Possession::prove_detached(&elsewhere, CHANNEL).expect("proves");

    detached.verify(&public, CHANNEL).expect("verifies exactly as the direct proof");
    assert_eq!(direct.as_bytes(), detached.as_bytes(), "the same deterministic signature");

    // And the request asks for exactly the bytes the direct path signs.
    let request = Possession::request(&public, CHANNEL).expect("a request");
    public.verify(request.message(), direct.as_bytes()).expect("the challenge is those bytes");
    assert!(detached.verify(&public, b"another channel").is_err());
}

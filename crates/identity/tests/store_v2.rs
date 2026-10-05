//! Storing an identity whose signing key lives in a key store.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

use std::collections::BTreeMap;
use std::sync::Arc;

use identity::detached::KeyCustodian;
use identity::store::{self, CUSTODIAN_VERSION, Custodians, NoCustodians, STORED_VERSION, Sealer};
use identity::{Error, NodeIdentity, PrivateKey};
use roster::sign::P256Signer;
use roster::types::Algorithm;

/// Leaves bytes as they are, so a test can read what would be sealed.
struct Clear;

impl Sealer for Clear {
    fn seal(&self, plain: &[u8]) -> identity::Result<Vec<u8>> {
        Ok(plain.to_vec())
    }
    fn unseal(&self, stored: &[u8]) -> identity::Result<Vec<u8>> {
        Ok(stored.to_vec())
    }
}

/// A key store that has lost its key.
struct Refusing;

impl Sealer for Refusing {
    fn seal(&self, plain: &[u8]) -> identity::Result<Vec<u8>> {
        Ok(plain.iter().map(|byte| byte ^ 0x5a).collect())
    }
    fn unseal(&self, _stored: &[u8]) -> identity::Result<Vec<u8>> {
        Err(Error::CustodianFailed { detail: "the sealing key is gone".to_owned() })
    }
}

/// Custodians by name.
#[derive(Default)]
struct Store(BTreeMap<String, Arc<dyn KeyCustodian + Send + Sync>>);

impl Custodians for Store {
    fn find(
        &self,
        reference: &str,
    ) -> identity::Result<Option<Arc<dyn KeyCustodian + Send + Sync>>> {
        Ok(self.0.get(reference).cloned())
    }
}

const SCALAR: [u8; 32] = [0x21; 32];

fn keystore_key(scalar: [u8; 32]) -> Arc<dyn KeyCustodian + Send + Sync> {
    Arc::new(P256Signer::from_scalar(scalar).expect("inside the order"))
}

fn custodian_identity() -> NodeIdentity {
    let transport = PrivateKey::from_material(Algorithm::Ed25519, [0x42; 32]).expect("valid");
    let attestation = PrivateKey::from_material(Algorithm::Ed25519, [0x43; 32]).expect("valid");
    NodeIdentity::with_custodian(
        "peerfectly.casa.signing",
        keystore_key(SCALAR),
        transport,
        attestation,
    )
    .expect("valid")
}

/// The version a stored plaintext carries: the element after the array header.
fn version_of(plain: &[u8]) -> u64 {
    let mut decoder = minicbor::Decoder::new(plain);
    decoder.array().expect("an array");
    decoder.u64().expect("a version")
}

#[test]
fn a_held_identity_is_still_written_as_version_one_and_loads() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("identity");
    let identity = NodeIdentity::generate().expect("generates");

    store::save_with(&identity, &path, &Clear).expect("saves");
    assert_eq!(version_of(&std::fs::read(&path).expect("reads")), STORED_VERSION);

    let loaded = store::load_with(&path, &Clear, &NoCustodians).expect("loads");
    assert_eq!(loaded.device_id(), identity.device_id());
    assert!(loaded.signing_key().material().is_some());
}

#[test]
fn a_custodian_identity_round_trips_without_its_signing_key() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("identity");
    let identity = custodian_identity();

    store::save_with(&identity, &path, &Clear).expect("saves");
    let plain = std::fs::read(&path).expect("reads");
    assert_eq!(version_of(&plain), CUSTODIAN_VERSION);
    assert!(
        !plain.windows(SCALAR.len()).any(|window| window == SCALAR),
        "the signing key's private material is not in what was stored"
    );

    let mut keys = Store::default();
    keys.0.insert("peerfectly.casa.signing".to_owned(), keystore_key(SCALAR));
    let loaded = store::load_with(&path, &Clear, &keys).expect("loads");
    assert_eq!(loaded.device_id(), identity.device_id());
    assert_eq!(loaded.transport_key().public_key(), identity.transport_key().public_key());
    assert!(loaded.signing_key().material().is_none());
}

#[test]
fn a_missing_custodian_key_is_named_and_nothing_is_generated() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("identity");
    store::save_with(&custodian_identity(), &path, &Clear).expect("saves");
    let before = std::fs::read(&path).expect("reads");

    match store::load_with(&path, &Clear, &Store::default()) {
        Err(Error::CustodianKeyMissing { reference }) => {
            assert_eq!(reference, "peerfectly.casa.signing")
        }
        other => panic!("expected the missing key to be named, got {other:?}"),
    }
    assert_eq!(std::fs::read(&path).expect("reads"), before, "the stored identity is untouched");
}

#[test]
fn a_different_key_under_the_same_name_is_refused() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("identity");
    store::save_with(&custodian_identity(), &path, &Clear).expect("saves");

    let mut keys = Store::default();
    keys.0.insert("peerfectly.casa.signing".to_owned(), keystore_key([0x22; 32]));
    match store::load_with(&path, &Clear, &keys) {
        Err(Error::CustodianKeyMismatch { reference }) => {
            assert_eq!(reference, "peerfectly.casa.signing")
        }
        other => panic!("expected a mismatch, got {other:?}"),
    }
}

#[test]
fn a_sealer_that_refuses_is_not_worked_around() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("identity");
    store::save_with(&NodeIdentity::generate().expect("generates"), &path, &Refusing)
        .expect("saves");

    assert!(
        matches!(
            store::load_with(&path, &Refusing, &NoCustodians),
            Err(Error::CustodianFailed { .. })
        ),
        "no fallback to reading the bytes as they are"
    );
}

/// The desktop's own entry points did not change.
#[test]
fn save_and_load_still_work_as_they_did() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("identity");
    let identity = NodeIdentity::generate().expect("generates");
    store::save(&identity, &path).expect("saves");
    assert_eq!(store::load(&path).expect("loads").device_id(), identity.device_id());
}

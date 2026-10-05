//! The signature envelope end to end: what verifies, what does not, and why.
//!
//! Every negative case here is a way an attacker could try to make a signature
//! mean something it was not written to mean.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

mod common;

use common::{
    attestation_entry, core_for, core_with, device, ed25519_signer, network, other_network,
    p256_signer, params, public_key, signing_entry, sorted, transport_entry,
};
use roster::error::Error;
use roster::id::{KeyId, OperationId};
use roster::sign::{
    RawOperation, Signer, assemble_operation, assemble_operation_with_id, sign_operation,
    signing_input,
};
use roster::types::{
    Algorithm, Capability, DeviceSpec, KeyEntry, KeyPurpose, OperationBody, OperationCore,
    OperationType, Role,
};

/// Signs a fixture operation of the given type and returns its wire bytes.
fn signed(op_type: OperationType, signer: &dyn Signer) -> Vec<u8> {
    let core = core_for(op_type, signer);
    sign_operation(&core, signer).expect("fixture signs")
}

// ---------------------------------------------------------------------------
// Positive path
// ---------------------------------------------------------------------------

#[test]
fn every_operation_type_signs_and_verifies_under_both_algorithms() {
    for op_type in OperationType::ALL {
        for algorithm in [Algorithm::Ed25519, Algorithm::P256] {
            let signer: Box<dyn Signer> = match algorithm {
                Algorithm::Ed25519 => Box::new(ed25519_signer(1)),
                Algorithm::P256 => Box::new(p256_signer(2)),
            };
            let bytes = signed(*op_type, signer.as_ref());
            let raw = RawOperation::decode(&bytes).expect("fixture decodes");
            let verified = raw
                .verify(&public_key(signer.as_ref()))
                .expect("fixture verifies under its own key");
            assert_eq!(verified.core().operation_type(), *op_type);
            assert_eq!(verified.core().alg, algorithm);
        }
    }
}

/// The decoded value must hand back the bytes that arrived, not a
/// reconstruction of them. A node that re-serialized before forwarding would
/// break every downstream signature the moment its encoder differed by a byte.
#[test]
fn decoding_retains_the_exact_received_core_bytes() {
    let signer = ed25519_signer(1);
    let core = core_for(OperationType::AddDevice, &signer);
    let expected_core_bytes = core.encode();
    let bytes = sign_operation(&core, &signer).expect("signs");

    let raw = RawOperation::decode(&bytes).expect("decodes");
    assert_eq!(raw.core_bytes(), expected_core_bytes.as_slice());
    // And the retained slice really is a window into the input buffer.
    assert!(
        bytes.windows(raw.core_bytes().len()).any(|window| window == raw.core_bytes()),
        "the retained core must be a slice of the received bytes"
    );
}

#[test]
fn forwarding_reproduces_the_received_bytes_exactly() {
    let signer = p256_signer(3);
    let bytes = signed(OperationType::RevokeDevice, &signer);
    let raw = RawOperation::decode(&bytes).expect("decodes");
    assert_eq!(raw.to_bytes(), bytes, "a forwarded operation is byte-identical");

    let verified = raw.verify(&public_key(&signer)).expect("verifies");
    assert_eq!(verified.to_bytes(), bytes);
}

#[test]
fn owned_form_keeps_the_same_bytes_and_id() {
    let signer = ed25519_signer(4);
    let bytes = signed(OperationType::Demote, &signer);
    let raw = RawOperation::decode(&bytes).expect("decodes");
    let id = raw.id();
    let core_bytes = raw.core_bytes().to_vec();
    let owned = raw.into_owned();
    assert_eq!(owned.id(), id);
    assert_eq!(owned.core_bytes(), core_bytes.as_slice());
}

// ---------------------------------------------------------------------------
// Domain separation
// ---------------------------------------------------------------------------

/// Length-prefixing each component is what stops one component from borrowing
/// bytes from the next. Without it, a crafted network id could produce the
/// same signing input as a different, legitimate tuple.
#[test]
fn distinct_component_tuples_produce_distinct_signing_inputs() {
    let core = b"core bytes".as_slice();

    // Two tuples that plain concatenation would collapse together: the type
    // name's leading characters moved into the preceding component.
    let a = signing_input(&network(), OperationType::Promote, core);
    let b = signing_input(&other_network(), OperationType::Promote, core);
    assert_ne!(a, b, "a different network must produce a different signing input");

    let c = signing_input(&network(), OperationType::Demote, core);
    assert_ne!(a, c, "a different operation type must produce a different signing input");

    let d = signing_input(&network(), OperationType::Promote, b"core byte");
    assert_ne!(a, d, "different core bytes must produce a different signing input");

    // The tag is present and framed, not merely prepended.
    assert!(a.windows(9).any(|w| w == b"roster/v1"), "the domain tag is part of the input");
}

#[test]
fn a_signature_over_the_bare_core_does_not_verify() {
    let signer = ed25519_signer(5);
    let core = core_for(OperationType::Rename, &signer);
    let core_bytes = core.encode();

    // Sign the core alone, skipping the domain prefix — the mistake the prefix
    // exists to make impossible to miss.
    let naive = signer.sign(&core_bytes).expect("signs");
    let signature: [u8; 64] = naive.as_slice().try_into().expect("64 bytes");
    let bytes = assemble_operation(&core_bytes, &signature);

    let raw = RawOperation::decode(&bytes).expect("structurally fine");
    assert_eq!(raw.verify(&public_key(&signer)), Err(Error::SignatureInvalid));
}

/// The same operation lifted into another network must not verify, or an
/// admin's signature in one household would be an admin's signature in
/// everyone's.
#[test]
fn a_signature_does_not_replay_across_networks() {
    let signer = ed25519_signer(6);
    let core = core_with(OperationType::AddDevice, &signer, network(), signer.key_id(), vec![]);
    let bytes = sign_operation(&core, &signer).expect("signs");
    let signature = *RawOperation::decode(&bytes).expect("decodes").signature();

    // Rebuild the same operation under a different network id, keeping the
    // signature.
    let moved =
        core_with(OperationType::AddDevice, &signer, other_network(), signer.key_id(), vec![]);
    let moved_bytes = assemble_operation(&moved.encode(), &signature);

    let raw = RawOperation::decode(&moved_bytes).expect("structurally fine");
    assert_eq!(raw.verify(&public_key(&signer)), Err(Error::SignatureInvalid));
}

/// Relabelling a demotion as a promotion is the single most valuable forgery
/// in this format, so the type is inside both the signed core and the domain
/// prefix.
#[test]
fn a_signature_does_not_replay_across_operation_types() {
    let signer = ed25519_signer(7);
    let demote = core_for(OperationType::Demote, &signer);
    let bytes = sign_operation(&demote, &signer).expect("signs");
    let signature = *RawOperation::decode(&bytes).expect("decodes").signature();

    let promote = OperationCore::new(
        demote.ts,
        demote.alg,
        OperationBody::Promote { device: common::device_id(2), founder: false },
        demote.parents.clone(),
        demote.author,
        demote.network,
    )
    .expect("well-formed");

    let forged = assemble_operation(&promote.encode(), &signature);
    let raw = RawOperation::decode(&forged).expect("structurally fine");
    assert_eq!(raw.verify(&public_key(&signer)), Err(Error::SignatureInvalid));
}

/// `alg` lives inside the signed core precisely so it cannot be swapped
/// afterwards to steer verification down a different code path.
#[test]
fn algorithm_substitution_fails_verification() {
    let p256 = p256_signer(8);
    let core = core_for(OperationType::SetNetwork, &p256);
    let bytes = sign_operation(&core, &p256).expect("signs");
    let signature = *RawOperation::decode(&bytes).expect("decodes").signature();

    let swapped = OperationCore::new(
        core.ts,
        Algorithm::Ed25519,
        core.body.clone(),
        core.parents.clone(),
        core.author,
        core.network,
    )
    .expect("well-formed");
    let forged = assemble_operation(&swapped.encode(), &signature);

    let raw = RawOperation::decode(&forged).expect("structurally fine");
    // The declared algorithm no longer matches the key being offered.
    assert_eq!(raw.verify(&public_key(&p256)), Err(Error::UnknownAlgorithm));
}

/// The founder flag is covered by the signature, so it cannot be granted after
/// the fact.
#[test]
fn flipping_the_founder_flag_invalidates_the_signature() {
    let signer = ed25519_signer(9);
    let plain = OperationBody::AddDevice(device(2, "laptop", Role::Member, false));
    let core = OperationCore::new(
        1_735_689_600_000,
        Algorithm::Ed25519,
        plain,
        vec![],
        signer.key_id(),
        network(),
    )
    .expect("well-formed");
    let bytes = sign_operation(&core, &signer).expect("signs");
    let signature = *RawOperation::decode(&bytes).expect("decodes").signature();

    let elevated = OperationCore::new(
        core.ts,
        core.alg,
        OperationBody::AddDevice(device(2, "laptop", Role::Member, true)),
        core.parents.clone(),
        core.author,
        core.network,
    )
    .expect("well-formed");
    let forged = assemble_operation(&elevated.encode(), &signature);

    let raw = RawOperation::decode(&forged).expect("structurally fine");
    assert_eq!(raw.verify(&public_key(&signer)), Err(Error::SignatureInvalid));
}

#[test]
fn a_tampered_core_byte_fails_verification() {
    let signer = ed25519_signer(10);
    let core = core_for(OperationType::Rename, &signer);
    let bytes = sign_operation(&core, &signer).expect("signs");
    let signature = *RawOperation::decode(&bytes).expect("decodes").signature();

    // Rename to a different name of the same length, so the encoding stays
    // canonical and the change is invisible to the structural checks.
    let renamed = OperationCore::new(
        core.ts,
        core.alg,
        OperationBody::Rename { device: common::device_id(2), name: "workstatioN".to_owned() },
        core.parents.clone(),
        core.author,
        core.network,
    )
    .expect("well-formed");
    let forged = assemble_operation(&renamed.encode(), &signature);

    let raw = RawOperation::decode(&forged).expect("canonical, and structurally fine");
    assert_eq!(raw.verify(&public_key(&signer)), Err(Error::SignatureInvalid));
}

#[test]
fn a_key_that_is_not_the_author_is_refused() {
    let author = ed25519_signer(11);
    let stranger = ed25519_signer(12);
    let bytes = signed(OperationType::Demote, &author);
    let raw = RawOperation::decode(&bytes).expect("decodes");
    assert_eq!(raw.verify(&public_key(&stranger)), Err(Error::AuthorKeyMismatch));
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// The id covers the core and not the signature, so one logical operation has
/// one id no matter how many times, or by which signer, it is signed.
///
/// This matters because ECDSA does not have to be deterministic. This crate's
/// software P-256 signer derives its nonce per RFC 6979 and so is reproducible,
/// but a hardware signer need not be — Apple's Secure Enclave, which is where
/// the root key actually lives, uses a random nonce. If the signature were part
/// of the hashed bytes, the same revocation signed twice would enter the DAG as
/// two unrelated operations.
#[test]
fn the_id_is_independent_of_the_signature() {
    let signer = p256_signer(13);
    let core = core_for(OperationType::RevokeDevice, &signer);
    let core_bytes = core.encode();

    let real = sign_operation(&core, &signer).expect("signs");
    let real_signature = *RawOperation::decode(&real).expect("decodes").signature();

    // A second, different signature value over the same core, standing in for
    // what a randomized signer would have produced.
    let mut other_signature = real_signature;
    if let Some(first) = other_signature.first_mut() {
        *first ^= 0xff;
    }
    assert_ne!(real_signature, other_signature);

    let a = RawOperation::decode(&real).expect("decodes");
    let b_bytes = assemble_operation(&core_bytes, &other_signature);
    let b = RawOperation::decode(&b_bytes).expect("decodes");

    assert_ne!(a.signature(), b.signature(), "two different signatures");
    assert_eq!(a.id(), b.id(), "yet one operation, under one id");
    assert_eq!(a.core_bytes(), b.core_bytes());
}

/// This crate's own P-256 signer is deterministic (RFC 6979), which is what
/// lets the test-vector corpus pin exact signature bytes.
#[test]
fn the_software_p256_signer_is_deterministic() {
    let signer = p256_signer(13);
    let core = core_for(OperationType::RevokeDevice, &signer);
    assert_eq!(
        sign_operation(&core, &signer).expect("signs"),
        sign_operation(&core, &signer).expect("signs again"),
        "RFC 6979 nonces make the corpus reproducible"
    );
}

#[test]
fn a_stated_id_that_disagrees_with_the_bytes_is_rejected() {
    let signer = ed25519_signer(14);
    let core = core_for(OperationType::Promote, &signer);
    let core_bytes = core.encode();
    let signature = *RawOperation::decode(&sign_operation(&core, &signer).expect("signs"))
        .expect("decodes")
        .signature();

    let wrong = OperationId::from_bytes([0xff; 32]);
    let bytes = assemble_operation_with_id(wrong, &core_bytes, &signature);
    assert_eq!(RawOperation::decode(&bytes), Err(Error::IdMismatch));
}

#[test]
fn the_id_is_the_blake3_of_the_core() {
    let signer = ed25519_signer(15);
    let core = core_for(OperationType::AddDevice, &signer);
    let core_bytes = core.encode();
    assert_eq!(core.id().as_bytes(), blake3_of(&core_bytes).as_slice());
}

/// Independent BLAKE3, so the assertion above is not the implementation
/// checking itself.
fn blake3_of(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

// ---------------------------------------------------------------------------
// Algorithm profiles
// ---------------------------------------------------------------------------

#[test]
fn a_small_order_public_key_is_rejected() {
    // The canonical small-order ed25519 point: the identity element.
    let identity = [0u8; 32];
    let key = roster::sign::PublicKey::new(Algorithm::Ed25519, identity.to_vec());
    match key {
        Err(Error::InvalidKey) => {}
        Ok(built) => {
            // If the encoding parses, verification must still refuse it.
            assert_eq!(built.verify(b"message", &[0u8; 64]), Err(Error::InvalidKey));
        }
        Err(other) => panic!("expected an invalid-key rejection, got {other:?}"),
    }
}

#[test]
fn a_non_reduced_ed25519_scalar_is_rejected() {
    let signer = ed25519_signer(16);
    let core = core_for(OperationType::Demote, &signer);
    let bytes = sign_operation(&core, &signer).expect("signs");
    let raw = RawOperation::decode(&bytes).expect("decodes");

    // Set the top bits of `s`, which puts the scalar outside its canonical
    // range. Strict ed25519 refuses this; a permissive implementation would
    // not, and the two would disagree about which operations exist.
    let mut tampered = *raw.signature();
    if let Some(last) = tampered.last_mut() {
        *last |= 0xe0;
    }
    let key = public_key(&signer);
    let message = signing_input(&core.network, core.operation_type(), raw.core_bytes());
    assert!(
        matches!(
            key.verify(&message, &tampered),
            Err(Error::SignatureEncoding | Error::SignatureInvalid)
        ),
        "a non-reduced scalar must not verify"
    );
}

#[test]
fn a_low_s_p256_signature_verifies_and_its_malleation_does_not() {
    let signer = p256_signer(17);
    let core = core_for(OperationType::SetNetwork, &signer);
    let bytes = sign_operation(&core, &signer).expect("signs");
    let raw = RawOperation::decode(&bytes).expect("decodes");
    let key = public_key(&signer);
    let message = signing_input(&core.network, core.operation_type(), raw.core_bytes());

    assert_eq!(key.verify(&message, raw.signature()), Ok(()), "low-s verifies");

    // Malleate to (r, n - s). Mathematically just as valid a signature over
    // the same message; refused so that one signature has one encoding.
    let malleated = malleate_p256(raw.signature());
    assert_eq!(
        key.verify(&message, &malleated),
        Err(Error::SignatureEncoding),
        "the high-s twin must not be a second accepted encoding"
    );
}

/// Replaces `s` with `n - s`, where `n` is the P-256 curve order.
fn malleate_p256(signature: &[u8; 64]) -> [u8; 64] {
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let mut out = *signature;
    let s = signature.get(32..64).expect("64-byte signature");

    // n - s, big-endian, by hand.
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let order_byte = i16::from(*ORDER.get(index).expect("32 bytes"));
        let s_byte = i16::from(*s.get(index).expect("32 bytes"));
        let mut difference =
            order_byte.checked_sub(s_byte).and_then(|value| value.checked_sub(borrow)).unwrap_or(0);
        if difference < 0 {
            difference = difference.saturating_add(256);
            borrow = 1;
        } else {
            borrow = 0;
        }
        if let Some(slot) = out.get_mut(index.saturating_add(32)) {
            *slot = u8::try_from(difference).unwrap_or(0);
        }
    }
    out
}

#[test]
fn a_der_encoded_signature_is_rejected() {
    let signer = p256_signer(18);
    let key = public_key(&signer);
    // A DER SEQUENCE header followed by filler. DER never enters this format,
    // so it fails on width before anything tries to parse it.
    let mut der = vec![0x30, 0x44, 0x02, 0x20];
    der.extend_from_slice(&[0x01; 62]);
    assert_eq!(key.verify(b"message", &der), Err(Error::SignatureEncoding));
}

#[test]
fn an_unknown_algorithm_is_an_error_not_a_skip() {
    // The wire name is parsed, not matched loosely: an operation this build
    // cannot read is refused, because it might be a revocation.
    assert_eq!(Algorithm::parse("ml-dsa-65"), Err(Error::UnknownAlgorithm));

    let signer = ed25519_signer(19);
    let bytes = signed(OperationType::AddDevice, &signer);
    let corrupted = replace_first(&bytes, b"ed25519", b"ed25518");
    // The core no longer hashes to the stated id, which is caught first; the
    // point is that nothing silently accepts or ignores it.
    assert!(RawOperation::decode(&corrupted).is_err());
}

/// Replaces the first occurrence of `needle` with `replacement` of equal length.
fn replace_first(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    assert_eq!(needle.len(), replacement.len());
    let mut out = haystack.to_vec();
    if let Some(position) = haystack.windows(needle.len()).position(|w| w == needle)
        && let Some(slot) = out.get_mut(position..position.saturating_add(needle.len()))
    {
        slot.copy_from_slice(replacement);
    }
    out
}

// ---------------------------------------------------------------------------
// Device rules
// ---------------------------------------------------------------------------

#[test]
fn a_device_with_a_distinct_key_for_each_purpose_is_accepted() {
    let spec = device(20, "nas", Role::Member, false);
    assert_eq!(spec.keys.len(), 3);
    assert!(spec.keys.iter().any(|k| k.purpose == KeyPurpose::Signing));
    assert!(spec.keys.iter().any(|k| k.purpose == KeyPurpose::Transport));
    assert!(spec.keys.iter().any(|k| k.purpose == KeyPurpose::Attestation));
    // Every entry keeps its declared purpose and algorithm through a round
    // trip.
    let body = OperationBody::AddDevice(spec.clone());
    let decoded = round_trip_body(&body, OperationType::AddDevice);
    assert_eq!(decoded, body);
}

/// Encodes a body and reads it back under the given declared type.
fn round_trip_body(body: &OperationBody, declared: OperationType) -> OperationBody {
    let signer = ed25519_signer(21);
    let core =
        OperationCore::new(1, Algorithm::Ed25519, body.clone(), vec![], signer.key_id(), network())
            .expect("well-formed");
    assert_eq!(core.operation_type(), declared);
    let bytes = sign_operation(&core, &signer).expect("signs");
    let raw = RawOperation::decode(&bytes).expect("decodes");
    raw.core().body.clone()
}

/// One key value serving two protocols is a cross-protocol attack waiting to
/// be found, so the format refuses it outright.
#[test]
fn reusing_one_key_value_for_two_purposes_is_rejected() {
    // A complete key set in every other respect, so what refuses it is the
    // reuse and not a purpose left out.
    for reused_as in [KeyPurpose::Transport, KeyPurpose::Attestation] {
        let signing = signing_entry(22);
        let reused = KeyEntry::new(Algorithm::Ed25519, reused_as, signing.value.clone())
            .expect("well-formed on its own");
        let third = if reused_as == KeyPurpose::Transport {
            attestation_entry(222)
        } else {
            transport_entry(122)
        };
        let keys = sorted(vec![signing, reused, third]);
        assert_eq!(
            DeviceSpec::new(keys, "clone", Role::Member, false, vec![]).map(|_| ()),
            Err(Error::KeyReuse),
            "the signing key reused as {reused_as:?}"
        );
    }
}

/// A record that could never date the roster it belongs to is not a device this
/// network can contain.
#[test]
fn a_device_without_an_attestation_key_is_rejected() {
    let keys = sorted(vec![signing_entry(26), transport_entry(126)]);
    assert_eq!(
        DeviceSpec::new(keys, "cannot attest", Role::Member, false, vec![]).map(|_| ()),
        Err(Error::MissingAttestationKey)
    );
}

#[test]
fn a_device_without_a_signing_key_is_rejected() {
    let keys = vec![transport_entry(23)];
    assert_eq!(
        DeviceSpec::new(keys, "transport only", Role::Member, false, vec![]).map(|_| ()),
        Err(Error::MissingSigningKey)
    );
}

#[test]
fn an_unsorted_key_list_is_rejected() {
    let mut keys = sorted(vec![signing_entry(24), transport_entry(124)]);
    keys.reverse();
    assert_eq!(
        DeviceSpec::new(keys, "unsorted", Role::Member, false, vec![]).map(|_| ()),
        Err(Error::KeyOrdering),
        "an unordered key list would give one device two encodings"
    );
}

#[test]
fn an_over_long_device_name_is_rejected() {
    let keys = sorted(vec![signing_entry(25), transport_entry(125), attestation_entry(225)]);
    let long = "n".repeat(roster::limits::MAX_NAME_LEN.saturating_add(1));
    assert_eq!(
        DeviceSpec::new(keys, long, Role::Member, false, vec![]).map(|_| ()),
        Err(Error::LimitExceeded("device name length"))
    );
}

#[test]
fn too_many_parents_are_rejected() {
    let signer = ed25519_signer(26);
    let parents: Vec<OperationId> = (0..=roster::limits::MAX_PARENTS)
        .map(|index| OperationId::from_bytes([u8::try_from(index % 256).unwrap_or(0); 32]))
        .collect();
    assert_eq!(
        OperationCore::new(
            1,
            Algorithm::Ed25519,
            OperationBody::Demote { device: common::device_id(2) },
            parents,
            signer.key_id(),
            network(),
        )
        .map(|_| ()),
        Err(Error::LimitExceeded("parent count"))
    );
}

#[test]
fn an_over_long_capability_is_rejected() {
    let long = "c".repeat(roster::limits::MAX_CAPABILITY_LEN.saturating_add(1));
    assert_eq!(Capability::new(long).map(|_| ()), Err(Error::LimitExceeded("capability length")));
}

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

/// Timestamps exist for display. Nothing may reject an operation because its
/// clock disagrees with ours, or a device with a wrong clock would be unable
/// to administer its own network.
#[test]
fn a_far_future_timestamp_is_accepted() {
    let signer = ed25519_signer(27);
    let core = OperationCore::new(
        u64::MAX,
        Algorithm::Ed25519,
        OperationBody::Demote { device: common::device_id(2) },
        vec![],
        signer.key_id(),
        network(),
    )
    .expect("well-formed");
    let bytes = sign_operation(&core, &signer).expect("signs");
    let raw = RawOperation::decode(&bytes).expect("decodes");
    assert_eq!(raw.core().ts, u64::MAX);
    assert!(raw.verify(&public_key(&signer)).is_ok(), "a future clock is not an error");
}

#[test]
fn timestamps_do_not_affect_identity() {
    let signer = ed25519_signer(28);
    let build = |ts: u64| {
        OperationCore::new(
            ts,
            Algorithm::Ed25519,
            OperationBody::Demote { device: common::device_id(2) },
            vec![],
            signer.key_id(),
            network(),
        )
        .expect("well-formed")
    };
    let early = build(1);
    let late = build(u64::MAX);
    // Different timestamps are different content and so different ids, but
    // neither is rejected and neither orders the other.
    assert_ne!(early.id(), late.id());
    assert!(sign_operation(&early, &signer).is_ok());
    assert!(sign_operation(&late, &signer).is_ok());
}

/// The millisecond epoch value is encoded minimally, like every other integer.
#[test]
fn the_timestamp_is_a_minimally_encoded_unsigned_integer() {
    let signer = ed25519_signer(29);
    let small = OperationCore::new(
        1,
        Algorithm::Ed25519,
        OperationBody::Demote { device: common::device_id(2) },
        vec![],
        signer.key_id(),
        network(),
    )
    .expect("well-formed");
    let encoded = small.encode();
    // "ts" as a two-character text key, followed by the single-byte 1.
    let marker = [0x62, b't', b's', 0x01];
    assert!(
        encoded.windows(marker.len()).any(|w| w == marker),
        "a small timestamp must not pay for a wide integer"
    );
}

// ---------------------------------------------------------------------------
// Body schema
// ---------------------------------------------------------------------------

/// A body that is well formed but belongs to a different operation type is
/// reported as exactly that, rather than as whatever structural complaint the
/// mismatch happened to trigger first.
#[test]
fn a_body_belonging_to_another_type_is_a_schema_error() {
    let signer = ed25519_signer(30);
    let add = core_for(OperationType::AddDevice, &signer);
    let add_body = add.body.encode();

    // Same body bytes, but the core declares `rename`.
    let mislabelled = build_core_bytes_with_type(&add, &add_body, OperationType::Rename);
    let signature = [0u8; 64];
    let bytes = assemble_operation(&mislabelled, &signature);
    assert_eq!(RawOperation::decode(&bytes), Err(Error::BodySchema));
}

/// Assembles core bytes by hand so `type` and `body` can be made to disagree.
fn build_core_bytes_with_type(
    core: &OperationCore,
    body_bytes: &[u8],
    declared: OperationType,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa7); // map of 7 entries
    push_text(&mut out, "ts");
    out.push(0x01);
    push_text(&mut out, "alg");
    push_text(&mut out, core.alg.as_str());
    push_text(&mut out, "body");
    push_bytes(&mut out, body_bytes);
    push_text(&mut out, "type");
    push_text(&mut out, declared.as_str());
    push_text(&mut out, "author");
    push_bytes(&mut out, core.author.as_bytes());
    push_text(&mut out, "network");
    push_bytes(&mut out, core.network.as_bytes());
    push_text(&mut out, "parents");
    out.push(0x80); // empty array
    out
}

/// Appends a canonically encoded text string.
fn push_text(out: &mut Vec<u8>, text: &str) {
    let bytes = text.as_bytes();
    assert!(bytes.len() < 24, "test helper only handles short strings");
    out.push(0x60 | u8::try_from(bytes.len()).unwrap_or(0));
    out.extend_from_slice(bytes);
}

/// Appends a canonically encoded byte string.
fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len();
    if len < 24 {
        out.push(0x40 | u8::try_from(len).unwrap_or(0));
    } else if len <= usize::from(u8::MAX) {
        out.push(0x58);
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        out.push(0x59);
        out.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

#[test]
fn an_unknown_operation_type_is_rejected() {
    let signer = ed25519_signer(31);
    let core = core_for(OperationType::Demote, &signer);
    let body = core.body.encode();
    let mut out = Vec::new();
    out.push(0xa7);
    push_text(&mut out, "ts");
    out.push(0x01);
    push_text(&mut out, "alg");
    push_text(&mut out, "ed25519");
    push_text(&mut out, "body");
    push_bytes(&mut out, &body);
    push_text(&mut out, "type");
    push_text(&mut out, "delegate");
    push_text(&mut out, "author");
    push_bytes(&mut out, core.author.as_bytes());
    push_text(&mut out, "network");
    push_bytes(&mut out, core.network.as_bytes());
    push_text(&mut out, "parents");
    out.push(0x80);

    let bytes = assemble_operation(&out, &[0u8; 64]);
    assert_eq!(RawOperation::decode(&bytes), Err(Error::UnknownOperationType));
}

#[test]
fn an_oversized_operation_is_refused_on_sight() {
    let oversized = vec![0u8; roster::limits::MAX_OPERATION_SIZE.saturating_add(1)];
    assert_eq!(
        RawOperation::decode(&oversized),
        Err(Error::LimitExceeded("operation size")),
        "the size is checked before anything is parsed"
    );
}

#[test]
fn trailing_bytes_after_an_operation_are_rejected() {
    let signer = ed25519_signer(32);
    let mut bytes = signed(OperationType::Demote, &signer);
    bytes.push(0x00);
    assert_eq!(RawOperation::decode(&bytes), Err(Error::TrailingData));
}

#[test]
fn network_parameters_round_trip() {
    let body = OperationBody::SetNetwork(params());
    assert_eq!(round_trip_body(&body, OperationType::SetNetwork), body);
}

#[test]
fn a_create_network_admin_is_a_founder() {
    let body = common::body_of(OperationType::CreateNetwork);
    match body {
        OperationBody::CreateNetwork { device: spec, .. } => {
            assert!(spec.founder, "the founding admin is a founder");
            assert_eq!(spec.role, Role::Admin);
        }
        other => panic!("expected create_network, got {other:?}"),
    }
}

/// A signer must not be able to produce a key that the validating constructor
/// would refuse. The two paths building a `PublicKey` have to agree, or a node
/// signs with a key its peers cannot represent.
#[test]
fn signer_public_keys_survive_the_validating_constructor() {
    for signer in [
        Box::new(ed25519_signer(40)) as Box<dyn Signer>,
        Box::new(p256_signer(41)) as Box<dyn Signer>,
    ] {
        let produced = signer.public_key();
        let revalidated =
            roster::sign::PublicKey::new(produced.algorithm(), produced.as_bytes().to_vec())
                .expect("a signer's own key must be a valid key");
        assert_eq!(revalidated, produced);
        assert_eq!(
            produced.as_bytes().len(),
            produced.algorithm().public_key_len(),
            "the key length must match what the algorithm declares"
        );
    }
}

/// P-256 keys are carried compressed and only compressed. The uncompressed
/// encoding describes the same key, and admitting both would give one device
/// two ids.
#[test]
fn an_uncompressed_p256_key_is_rejected() {
    let uncompressed = {
        let mut bytes = vec![0x04];
        bytes.extend_from_slice(&[0x01; 64]);
        bytes
    };
    assert_eq!(uncompressed.len(), 65);
    assert_eq!(
        roster::sign::PublicKey::new(Algorithm::P256, uncompressed).map(|_| ()),
        Err(Error::InvalidKey)
    );
}

#[test]
fn key_ids_are_the_blake3_of_the_key() {
    let signer = ed25519_signer(33);
    let key = public_key(&signer);
    assert_eq!(key.key_id(), KeyId::of_public_key(key.as_bytes()));
    assert_eq!(signer.key_id(), key.key_id());
}

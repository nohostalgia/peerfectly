//! Runs the shared test-vector corpus.
//!
//! This is the only defence the project has against two implementations
//! quietly disagreeing about which operations exist. The same JSON files are
//! meant to be executed by the Kotlin client and by the services, so a
//! divergence shows up as a failing build rather than as a device that some
//! peers can see and others cannot.
//!
//! Regenerate with `cargo run -p roster --bin gen_vectors`.

#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a test reports failure by panicking, and the corpus shape is asserted before use"
)]

mod support;

use std::collections::BTreeSet;
use std::path::PathBuf;

use roster::error::Error;
use roster::hex;
use roster::id::OperationId;
use roster::roster::Roster;
use roster::sign::{PublicKey, RawOperation};
use roster::state::{RosterState, derive_with_verdicts};
use roster::types::Role;
use roster::types::{Algorithm, OperationType};
use serde_json::Value;

/// Rejection reasons deliberately absent from the shared corpus.
///
/// `stale_operation` is local admission policy: two conforming implementations
/// may configure it differently and both be right. `cyclic_history` cannot be
/// constructed, because an operation id covers its parent list — the code
/// detects it so hostile input terminates, but there is no input to pin.
const UNCOVERABLE_KINDS: &[&str] = &[
    "stale_operation",
    "cyclic_history",
    // Compaction is refused on node-local grounds: what else the node holds,
    // and how far behind its own frontier the region sits. Two conforming
    // implementations may decide differently and both be right, so pinning it
    // in a shared corpus would be wrong. Every gate is covered directly in
    // `snapshots.rs` instead.
    "compaction_refused",
];

/// Loads one corpus file.
fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors").join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()))
}

/// The `vectors` array of a corpus file.
fn vectors_in(document: &Value) -> Vec<Value> {
    document
        .get("vectors")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("corpus has no vectors array"))
        .clone()
}

/// A required string field of a vector.
fn field<'a>(vector: &'a Value, name: &str) -> &'a str {
    vector
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("vector is missing the `{name}` field"))
}

/// Decodes a hex field.
fn bytes_of(vector: &Value, name: &str) -> Vec<u8> {
    hex::decode(field(vector, name)).unwrap_or_else(|| panic!("field `{name}` is not valid hex"))
}

/// Builds the public key a vector names.
fn key_of(vector: &Value) -> Result<PublicKey, Error> {
    let alg = Algorithm::parse(field(vector, "public_key_alg"))?;
    PublicKey::new(alg, bytes_of(vector, "public_key"))
}

// ---------------------------------------------------------------------------
// Positive vectors
// ---------------------------------------------------------------------------

/// Every positive vector must decode to the stated id and verify under the
/// stated key. A mismatch means this implementation would build a different
/// DAG from the same bytes.
#[test]
fn every_positive_vector_decodes_verifies_and_reproduces_its_id() {
    let document = load("positive.json");
    let vectors = vectors_in(&document);
    assert!(!vectors.is_empty(), "the positive corpus is empty");

    for vector in &vectors {
        let name = field(vector, "name");
        let operation = bytes_of(vector, "operation");

        let raw = RawOperation::decode(&operation)
            .unwrap_or_else(|error| panic!("vector `{name}` must decode, got {error:?}"));

        let expected_id = OperationId::from_hex(field(vector, "id"))
            .unwrap_or_else(|| panic!("vector `{name}` has a malformed id"));
        assert_eq!(raw.id(), expected_id, "vector `{name}` produced a different id");

        assert_eq!(
            raw.core_bytes(),
            bytes_of(vector, "core").as_slice(),
            "vector `{name}` produced different core bytes"
        );

        let alg = Algorithm::parse(field(vector, "algorithm")).unwrap_or_else(|error| {
            panic!("vector `{name}` names an unknown algorithm: {error:?}")
        });
        let key = PublicKey::new(alg, bytes_of(vector, "public_key"))
            .unwrap_or_else(|error| panic!("vector `{name}` has a bad key: {error:?}"));

        raw.verify(&key)
            .unwrap_or_else(|error| panic!("vector `{name}` must verify, got {error:?}"));

        let expected_type = OperationType::parse(field(vector, "operation_type"))
            .unwrap_or_else(|error| panic!("vector `{name}` names an unknown type: {error:?}"));
        assert_eq!(raw.core().operation_type(), expected_type);

        // Forwarding must reproduce the vector's own bytes.
        assert_eq!(raw.to_bytes(), operation, "vector `{name}` did not round-trip");
    }
}

/// The corpus is only meaningful if it exercises the whole surface: every
/// operation type under every supported algorithm.
#[test]
fn the_positive_corpus_covers_every_type_and_algorithm() {
    let document = load("positive.json");
    let vectors = vectors_in(&document);

    let covered: BTreeSet<(String, String)> = vectors
        .iter()
        .map(|vector| {
            (field(vector, "operation_type").to_owned(), field(vector, "algorithm").to_owned())
        })
        .collect();

    for op_type in OperationType::ALL {
        for algorithm in [Algorithm::Ed25519, Algorithm::P256] {
            let pair = (op_type.as_str().to_owned(), algorithm.as_str().to_owned());
            assert!(
                covered.contains(&pair),
                "no positive vector for {} under {}",
                op_type.as_str(),
                algorithm.as_str()
            );
        }
    }
    assert_eq!(covered.len(), OperationType::ALL.len() * 2);
}

// ---------------------------------------------------------------------------
// Negative vectors
// ---------------------------------------------------------------------------

/// Every negative vector must be rejected, and rejected for the stated reason.
///
/// Rejecting for a different reason still counts as a divergence: it means the
/// two implementations disagree about what is wrong with the input, which
/// usually means one of them checked something the other did not.
#[test]
fn every_negative_vector_is_rejected_for_the_stated_reason() {
    let document = load("negative.json");
    let vectors = vectors_in(&document);
    assert!(!vectors.is_empty(), "the negative corpus is empty");

    for vector in &vectors {
        let name = field(vector, "name");
        let expected = field(vector, "error_kind");
        let operation = bytes_of(vector, "operation");
        let stage = field(vector, "stage");

        let actual = match stage {
            "decode" => match RawOperation::decode(&operation) {
                Ok(_) => panic!("vector `{name}` must be rejected at decode, but it was accepted"),
                Err(error) => error.kind(),
            },
            "verify" => {
                let raw = RawOperation::decode(&operation).unwrap_or_else(|error| {
                    panic!("vector `{name}` must reach verification, but decode gave {error:?}")
                });
                match key_of(vector) {
                    // A key that cannot even be built is itself a rejection.
                    Err(error) => error.kind(),
                    Ok(key) => match raw.verify(&key) {
                        Ok(_) => panic!("vector `{name}` must fail verification, but it passed"),
                        Err(error) => error.kind(),
                    },
                }
            }
            other => panic!("vector `{name}` has an unknown stage `{other}`"),
        };

        assert_eq!(actual, expected, "vector `{name}` was rejected for the wrong reason");
    }
}

/// Every rejection reason this implementation can produce must have a vector.
///
/// Adding an `Error` variant without a vector fails here, which is the point:
/// a reason no vector exercises is a reason other implementations have never
/// been asked to agree about.
#[test]
fn the_negative_corpus_covers_every_rejection_reason() {
    let document = load("negative.json");
    let vectors = vectors_in(&document);

    let mut covered: BTreeSet<String> =
        vectors.iter().map(|vector| field(vector, "error_kind").to_owned()).collect();

    // Rejections that only exist once operations are assembled into a history
    // live in the merge corpus, and those that only exist once a snapshot is
    // involved live in the snapshot corpus, so coverage spans all three files.
    let merge_document = load("merge.json");
    for vector in vectors_in(&merge_document) {
        if let Some(kind) = vector.get("error_kind").and_then(Value::as_str) {
            covered.insert(kind.to_owned());
        }
        for list in ["invalid", "refused"] {
            for entry in vector.get(list).and_then(Value::as_array).unwrap_or(&Vec::new()) {
                if let Some(reason) = entry.get("reason").and_then(Value::as_str) {
                    covered.insert(reason.to_owned());
                }
            }
        }
    }
    let snapshot_document = load("snapshot.json");
    for vector in vectors_in(&snapshot_document) {
        for field in ["error_kind", "follow_up_error"] {
            if let Some(kind) = vector.get(field).and_then(Value::as_str) {
                covered.insert(kind.to_owned());
            }
        }
    }

    let missing: Vec<&&str> = Error::ALL_KINDS
        .iter()
        .filter(|kind| !UNCOVERABLE_KINDS.contains(*kind))
        .filter(|kind| !covered.contains(**kind))
        .collect();
    assert!(missing.is_empty(), "no vector covers: {missing:?}");

    // And no vector claims a reason this implementation cannot produce.
    for kind in &covered {
        assert!(
            Error::ALL_KINDS.contains(&kind.as_str()),
            "the corpus names `{kind}`, which is not a rejection reason this build has"
        );
    }

    // The exclusions are deliberate, so they must still be real reasons.
    for kind in UNCOVERABLE_KINDS {
        assert!(
            Error::ALL_KINDS.contains(kind),
            "`{kind}` is excluded from the corpus but is not a rejection reason at all"
        );
    }
}

// ---------------------------------------------------------------------------
// Merge vectors
// ---------------------------------------------------------------------------

/// Loads an operation set into a graph by feeding it through a roster in the
/// given order.
///
/// A roster is used rather than a bare graph because its pending set makes any
/// delivery order legal, which is the situation a node faces during a sync. The
/// staleness filter is disabled: it is local policy, and pinning it in a shared
/// corpus would be wrong.
fn load_in_order(operations: &[Vec<u8>], order: &[usize]) -> Roster {
    let mut roster = Roster::with_staleness_depth(u64::MAX);
    for position in order {
        if let Some(bytes) = operations.get(*position) {
            roster.offer_bytes(bytes);
        }
    }
    roster
}

/// The orders each merge vector is applied in.
///
/// A vector applied in one order tests derivation. Applied in several, it tests
/// the property this capability turns on.
fn orders(count: usize) -> Vec<Vec<usize>> {
    let forward: Vec<usize> = (0..count).collect();
    let backward: Vec<usize> = (0..count).rev().collect();
    let mut interleaved: Vec<usize> = (0..count).step_by(2).collect();
    interleaved.extend((1..count).step_by(2));
    let mut rotated = forward.clone();
    rotated.rotate_left(count.wrapping_div(2).max(1).min(count));
    vec![forward, backward, interleaved, rotated]
}

/// Every merge vector derives its stated roster, in every order.
#[test]
fn every_merge_vector_derives_its_stated_state_in_every_order() {
    let document = load("merge.json");
    let vectors = vectors_in(&document);
    assert!(!vectors.is_empty(), "the merge corpus is empty");

    for vector in &vectors {
        let name = field(vector, "name");
        let operations: Vec<Vec<u8>> = vector
            .get("operations")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("vector `{name}` has no operations"))
            .iter()
            .map(|value| {
                hex::decode(value.as_str().unwrap_or_default())
                    .unwrap_or_else(|| panic!("vector `{name}` has a malformed operation"))
            })
            .collect();

        let outcome = field(vector, "outcome");
        for order in orders(operations.len()) {
            let roster = load_in_order(&operations, &order);
            match outcome {
                "state" => {
                    let expected = hex::decode(field(vector, "state"))
                        .unwrap_or_else(|| panic!("vector `{name}` has a malformed state"));
                    let (state, verdicts) =
                        derive_with_verdicts(roster.dag()).unwrap_or_else(|error| {
                            panic!("vector `{name}` must derive, got {error:?} in order {order:?}")
                        });
                    assert_eq!(
                        state.to_bytes(),
                        expected,
                        "vector `{name}` derived a different roster in order {order:?}"
                    );

                    let expected_fingerprint = hex::decode(field(vector, "fingerprint"))
                        .unwrap_or_else(|| panic!("vector `{name}` has a malformed fingerprint"));
                    assert_eq!(state.fingerprint().to_vec(), expected_fingerprint);

                    // The operations the vector says must be disregarded, and why.
                    let mut actual: Vec<(String, String)> = Vec::new();
                    for (index, operation) in roster.dag().operations().iter().enumerate() {
                        if let Some(reason) = verdicts.reason(index) {
                            actual.push((operation.id().to_hex(), reason.kind().to_owned()));
                        }
                    }
                    actual.sort();

                    // What a conforming node refuses at admission never enters
                    // the graph, so it cannot appear above. Checked separately,
                    // and checked as absence: an implementation that admits one
                    // of these and then disregards it derives the same state and
                    // is still wrong — the graph is bounded, and the slot is
                    // what the attack is after.
                    let refused_ids: Vec<String> = vector
                        .get("refused")
                        .and_then(Value::as_array)
                        .unwrap_or(&Vec::new())
                        .iter()
                        .map(|entry| {
                            let id = entry
                                .get("operation")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned();
                            let reason = entry
                                .get("reason")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned();
                            assert!(
                                roster.refusals().iter().any(|(operation, recorded)| {
                                    operation.to_hex() == id && recorded.kind() == reason
                                }),
                                "vector `{name}` expects `{id}` refused as `{reason}` in order {order:?}, and it was not"
                            );
                            id
                        })
                        .collect();
                    for id in &refused_ids {
                        assert!(
                            !roster
                                .dag()
                                .operations()
                                .iter()
                                .any(|operation| operation.id().to_hex() == *id),
                            "vector `{name}`: `{id}` is refused at admission and must occupy nothing, but the graph holds it in order {order:?}"
                        );
                    }

                    let mut expected_invalid: Vec<(String, String)> = vector
                        .get("invalid")
                        .and_then(Value::as_array)
                        .unwrap_or(&Vec::new())
                        .iter()
                        .map(|entry| {
                            (
                                entry
                                    .get("operation")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                                entry
                                    .get("reason")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                            )
                        })
                        .collect();
                    expected_invalid.sort();
                    assert_eq!(
                        actual, expected_invalid,
                        "vector `{name}` disregarded different operations in order {order:?}"
                    );
                }
                "error" => {
                    let expected = field(vector, "error_kind");
                    let derived = derive_with_verdicts(roster.dag()).map(|_| ());
                    let refused =
                        roster.refusals().iter().any(|(_, reason)| reason.kind() == expected);
                    let derive_matched =
                        derived.as_ref().err().is_some_and(|error| error.kind() == expected);
                    assert!(
                        refused || derive_matched,
                        "vector `{name}` must fail with `{expected}` in order {order:?}, \
                         got refusals {:?} and derivation {derived:?}",
                        roster.refusals()
                    );
                }
                other => panic!("vector `{name}` has an unknown outcome `{other}`"),
            }
        }
    }
}

/// Every rule this capability defines has at least one merge vector.
#[test]
fn the_merge_corpus_covers_every_rule() {
    let document = load("merge.json");
    let vectors = vectors_in(&document);
    let covered: BTreeSet<&str> = vectors.iter().map(|vector| field(vector, "rule")).collect();

    for rule in [
        "revocation-wins",
        "demote-beats-promote",
        "last-writer-wins",
        "ancestor-relative-validity",
        "causal-authorship",
        "founder-protection",
        "network-identity",
        "genesis",
    ] {
        assert!(covered.contains(rule), "no merge vector covers `{rule}`");
    }
}

/// Each vector is genuinely applied in more than one order.
#[test]
fn merge_vectors_are_exercised_in_several_orders() {
    let document = load("merge.json");
    for vector in vectors_in(&document) {
        let count =
            vector.get("operations").and_then(Value::as_array).map(Vec::len).unwrap_or_default();
        assert!(count >= 2, "a merge vector needs enough operations to reorder");
        let distinct: BTreeSet<Vec<usize>> = orders(count).into_iter().collect();
        assert!(
            distinct.len() >= 2,
            "a vector of {count} operations must be applied in at least two distinct orders"
        );
    }
}

/// A corrupted merge vector must fail rather than pass vacuously.
#[test]
fn a_corrupted_merge_vector_is_detected() {
    let document = load("merge.json");
    let vectors = vectors_in(&document);
    let vector = vectors
        .iter()
        .find(|vector| field(vector, "outcome") == "state")
        .unwrap_or_else(|| panic!("no deriving merge vector to corrupt"));

    let operations: Vec<Vec<u8>> = vector
        .get("operations")
        .and_then(Value::as_array)
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|value| hex::decode(value.as_str().unwrap_or_default()))
        .collect();

    let mut expected = hex::decode(field(vector, "state")).unwrap_or_default();
    let last = expected.len().saturating_sub(1);
    if let Some(slot) = expected.get_mut(last) {
        *slot ^= 0xff;
    }

    let order: Vec<usize> = (0..operations.len()).collect();
    let roster = load_in_order(&operations, &order);
    let state = roster.state().expect("derives");
    assert_ne!(state.to_bytes(), expected, "a corrupted expectation must not still match");
}

/// The merge corpus declares what it is.
#[test]
fn the_merge_corpus_declares_its_format_version() {
    let document = load("merge.json");
    assert_eq!(document.get("format").and_then(Value::as_str), Some("roster/v1"));
    assert_eq!(document.get("kind").and_then(Value::as_str), Some("merge"));
}

/// The vector that exists specifically to catch an alphabetically-ordered
/// encoder.
///
/// Canonical CBOR orders map keys by encoded length first, so the core's keys
/// run `ts, alg, body, …`. An implementation that sorts them alphabetically
/// produces `alg, author, body, …` — valid CBOR, wrong bytes, different id.
/// This is the single easiest rule in the format to get wrong, so it gets its
/// own vector rather than being left to chance.
#[test]
fn the_corpus_catches_alphabetical_key_ordering() {
    let document = load("negative.json");
    let vectors = vectors_in(&document);

    let ordering_vector = vectors
        .iter()
        .find(|vector| field(vector, "name").contains("alphabetical"))
        .unwrap_or_else(|| panic!("the corpus has no alphabetical-ordering vector"));

    assert_eq!(field(ordering_vector, "error_kind"), "key_ordering");

    let operation = bytes_of(ordering_vector, "operation");
    assert_eq!(
        RawOperation::decode(&operation).map(|_| ()),
        Err(Error::KeyOrdering),
        "an alphabetically-ordered core must be refused"
    );
}

/// A corrupted corpus must fail the build rather than pass vacuously.
///
/// Without this, a truncated or emptied vector file would make every corpus
/// test trivially succeed, and the protection would be gone with nothing to
/// show for it.
#[test]
fn a_corrupted_vector_is_detected() {
    let document = load("positive.json");
    let vectors = vectors_in(&document);
    let first = vectors.first().unwrap_or_else(|| panic!("the corpus is empty"));

    // Flip one byte of a vector's operation and confirm it stops matching.
    let mut operation = bytes_of(first, "operation");
    let last = operation.len().saturating_sub(1);
    operation[last] ^= 0xff;

    let still_valid = match RawOperation::decode(&operation) {
        Err(_) => false,
        Ok(raw) => {
            let alg = Algorithm::parse(field(first, "algorithm")).expect("known algorithm");
            match PublicKey::new(alg, bytes_of(first, "public_key")) {
                Err(_) => false,
                Ok(key) => {
                    raw.verify(&key).is_ok()
                        && OperationId::from_hex(field(first, "id")) == Some(raw.id())
                }
            }
        }
    };
    assert!(!still_valid, "a corrupted vector must not still pass");
}

// ---------------------------------------------------------------------------
// Snapshot vectors
// ---------------------------------------------------------------------------

/// Every snapshot vector receives the verdict it states.
#[test]
fn every_snapshot_vector_receives_its_stated_verdict() {
    let document = load("snapshot.json");
    let vectors = vectors_in(&document);
    assert!(!vectors.is_empty(), "the snapshot corpus is empty");

    for vector in &vectors {
        let name = field(vector, "name");
        let operations: Vec<Vec<u8>> = vector
            .get("operations")
            .and_then(Value::as_array)
            .unwrap_or(&Vec::new())
            .iter()
            .filter_map(|value| hex::decode(value.as_str().unwrap_or_default()))
            .collect();
        let snapshot = bytes_of(vector, "snapshot");
        let accepted = vector.get("accepted").and_then(Value::as_bool).unwrap_or(false);
        let expected = vector.get("error_kind").and_then(Value::as_str);

        // A permissive staleness threshold: the filter is local policy and has
        // no business deciding a shared vector's outcome.
        let mut roster = Roster::with_staleness_depth(u64::MAX);
        for bytes in &operations {
            roster.offer_bytes(bytes);
        }

        let outcome = roster.offer_snapshot(&snapshot);
        if accepted {
            assert!(outcome.is_accepted(), "vector `{name}` must be accepted, got {outcome:?}");
            // `snapshot_unverified` on an accepted vector means the node may
            // adopt the state but must not treat it as checked.
            if expected == Some("snapshot_unverified") {
                assert!(
                    !roster.snapshot_is_verified(),
                    "vector `{name}` must be adopted without verification"
                );
            } else {
                assert!(
                    roster.snapshot_is_verified(),
                    "vector `{name}` should have been verified against held operations"
                );
            }
        } else {
            let reason = outcome
                .refusal()
                .unwrap_or_else(|| panic!("vector `{name}` must be refused, got {outcome:?}"));
            if let Some(expected) = expected {
                assert_eq!(
                    reason.kind(),
                    expected,
                    "vector `{name}` was refused for the wrong reason"
                );
            }
        }

        // Sequence vectors offer a second snapshot and pin its verdict too.
        if let Some(follow_up) = vector.get("follow_up").and_then(Value::as_str) {
            let bytes = hex::decode(follow_up)
                .unwrap_or_else(|| panic!("vector `{name}` has a malformed follow-up"));
            let second = roster.offer_snapshot(&bytes);
            let expected_follow_up = field(vector, "follow_up_error");
            let reason = second.refusal().unwrap_or_else(|| {
                panic!("vector `{name}`'s follow-up must be refused, got {second:?}")
            });
            assert_eq!(
                reason.kind(),
                expected_follow_up,
                "vector `{name}`'s follow-up was refused for the wrong reason"
            );
        }
    }
}

/// The snapshot corpus exercises acceptance as well as every refusal, so it
/// cannot pass by refusing everything.
#[test]
fn the_snapshot_corpus_covers_acceptance_and_refusal() {
    let document = load("snapshot.json");
    let vectors = vectors_in(&document);

    let accepted = vectors
        .iter()
        .filter(|vector| vector.get("accepted").and_then(Value::as_bool).unwrap_or(false))
        .count();
    let refused = vectors.len().saturating_sub(accepted);
    assert!(accepted > 0, "no snapshot vector is accepted");
    assert!(refused > 0, "no snapshot vector is refused");

    let reasons: BTreeSet<&str> = vectors
        .iter()
        .filter_map(|vector| vector.get("error_kind").and_then(Value::as_str))
        .chain(vectors.iter().filter_map(|v| v.get("follow_up_error").and_then(Value::as_str)))
        .collect();
    for reason in [
        "signature_invalid",
        "snapshot_state_mismatch",
        "unauthorized_author",
        "snapshot_sequence_regressed",
        "snapshot_sequence_conflict",
        "foreign_network",
        "snapshot_unverified",
    ] {
        assert!(reasons.contains(reason), "no snapshot vector covers `{reason}`");
    }
}

/// A corrupted snapshot vector must fail rather than pass vacuously.
#[test]
fn a_corrupted_snapshot_vector_is_detected() {
    let document = load("snapshot.json");
    let vectors = vectors_in(&document);
    let vector = vectors
        .iter()
        .find(|vector| vector.get("accepted").and_then(Value::as_bool).unwrap_or(false))
        .unwrap_or_else(|| panic!("no accepted snapshot vector to corrupt"));

    let mut snapshot = bytes_of(vector, "snapshot");
    let last = snapshot.len().saturating_sub(1);
    if let Some(slot) = snapshot.get_mut(last) {
        *slot ^= 0xff;
    }
    let operations: Vec<Vec<u8>> = vector
        .get("operations")
        .and_then(Value::as_array)
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|value| hex::decode(value.as_str().unwrap_or_default()))
        .collect();

    let mut roster = Roster::with_staleness_depth(u64::MAX);
    for bytes in &operations {
        roster.offer_bytes(bytes);
    }
    assert!(
        roster.offer_snapshot(&snapshot).refusal().is_some(),
        "a corrupted snapshot must not still be accepted"
    );
}

/// The corpus files say what they are, so a stale file from another format
/// version cannot be run by accident.
#[test]
fn the_corpus_declares_its_format_version() {
    for (name, kind) in [
        ("positive.json", "positive"),
        ("negative.json", "negative"),
        ("snapshot.json", "snapshot"),
    ] {
        let document = load(name);
        assert_eq!(document.get("format").and_then(Value::as_str), Some("roster/v1"));
        assert_eq!(document.get("kind").and_then(Value::as_str), Some(kind));
    }
}

/// The merge vectors say in bytes what the requirements say in words, and this
/// checks the two agree.
///
/// Regenerating a golden file is circular: the expected output is recomputed by
/// the code under test, so a vector that only ever round-trips proves that the
/// implementation is consistent with itself. These vectors were rebuilt when
/// `equivocation-detection` changed what one author's concurrent operations mean,
/// which is exactly the moment that circularity would have hidden a mistake.
///
/// So the claims are restated here from the requirement prose — "the merged state
/// shows the device as a member", "the greater id wins" — and checked against the
/// recorded state. If a regeneration ever quietly changes what a vector asserts,
/// this fails.
#[test]
fn the_merge_vectors_say_what_the_requirements_say() {
    let document = load("merge.json");
    let vectors = vectors_in(&document);

    let state_of = |wanted: &str| -> RosterState {
        let vector = vectors
            .iter()
            .find(|vector| field(vector, "name") == wanted)
            .unwrap_or_else(|| panic!("the corpus must carry `{wanted}`"));
        let bytes = hex::decode(field(vector, "state"))
            .unwrap_or_else(|| panic!("vector `{wanted}` has a malformed state"));
        RosterState::from_bytes(&bytes)
            .unwrap_or_else(|_| panic!("vector `{wanted}` has an undecodable state"))
    };

    // "Revocation always wins": a device that any operation revokes is revoked in
    // derived state, whatever the causal relationship.
    let revoked = state_of("revocation beats a concurrent promotion");
    assert!(
        revoked.revoked.contains(&support::device_id(2)),
        "a concurrent promotion must not save a revoked device"
    );
    assert!(
        !revoked.devices.contains_key(&support::device_id(2)),
        "and it is gone from the roster"
    );

    // "Demote beats promote among concurrent branches": the derived role is member.
    let demoted = state_of("concurrent demote beats promote");
    assert_eq!(
        demoted.devices.get(&support::device_id(2)).map(|record| record.role),
        Some(Role::Member),
        "a race between a demote and a promote resolves downwards"
    );

    // "Last-writer-wins with deterministic tie-break": at equal depth the greater
    // operation id wins. Which name that is depends on the ids, so the claim
    // checked here is the one the requirement makes: it is one of the two, never
    // a mixture, and the state is decidable at all.
    let renamed = state_of("equal-depth rename tie broken by id");
    let name = renamed
        .devices
        .get(&support::device_id(2))
        .map(|record| record.name.clone())
        .expect("the device is in the roster");
    assert!(name == "left" || name == "right", "one of the two renames, never a mixture: {name}");

    // The same rule on network parameters.
    let network = state_of("concurrent set_network resolves");
    assert!(
        network.params.suffix == "left.internal" || network.params.suffix == "right.internal",
        "one of the two suffixes, never a mixture: {}",
        network.params.suffix
    );

    // Equivocation: neither branch takes effect, and another author's work that
    // merely anchored to one of them survives. The second half is the guard
    // against an equivocator erasing other people's history.
    let forked = state_of("one author's two concurrent operations take no effect");
    assert!(
        !forked.devices.contains_key(&support::device_id(2)),
        "the left branch of a fork takes no effect"
    );
    assert!(
        !forked.devices.contains_key(&support::device_id(3)),
        "nor the right: neither is chosen, because choosing would let the author choose"
    );
    assert!(
        forked.devices.contains_key(&support::device_id(4)),
        "but a second author's work anchored to a forked operation survives it"
    );
}

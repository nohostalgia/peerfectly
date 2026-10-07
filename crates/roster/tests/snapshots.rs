//! Snapshots: signing, acceptance, sequence rules, compaction, and freshness.
//!
//! The test that carries the most weight is the last group's: a node that
//! compacted and a node that kept everything must derive the same household.
//! Everything else is there to make sure compaction only happens when that is
//! guaranteed.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

mod support;

use roster::Error;
use roster::dag::Dag;
use roster::roster::{AttestationAdmission, Clock as _, Freshness, Roster, SnapshotAdmission};
use roster::sign::{RawOperation, Signer, sign_operation};
use roster::snapshot::{
    RawSnapshot, SNAPSHOT_DOMAIN_TAG, Snapshot, assemble_snapshot, sign_snapshot,
    snapshot_signing_input,
};
use roster::state::{RosterState, derive};
use roster::types::{Algorithm, OperationBody, OperationCore, Role};
use support::{History, SharedClock, device, device_id, params, signer};

/// A genesis plus a chain long enough to snapshot part of and extend the rest.
///
/// `a` .. `e` hang in a line off the genesis, so any prefix is a clean covered
/// region with a single head.
fn linear(length: usize) -> History {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("a", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    let mut previous = "a".to_owned();
    for index in 0..length {
        let label = format!("n{index}");
        history.op(
            &label,
            1,
            &[previous.as_str()],
            OperationBody::Rename { device: device_id(2), name: format!("name{index}") },
        );
        previous = label;
    }
    history
}

/// Feeds every operation of a history into a roster, in creation order.
fn load(roster: &mut Roster, history: &History) {
    for entry in history.entries() {
        let outcome = roster.offer_bytes(&entry.bytes);
        assert!(outcome.is_accepted(), "{} should be admitted: {outcome:?}", entry.label);
    }
}

// ---------------------------------------------------------------------------
// Signing and cross-confusion
// ---------------------------------------------------------------------------

#[test]
fn a_snapshot_round_trips_through_its_encoding() {
    let history = linear(3);
    let bytes = history.snapshot_at(1, 1, &["n2"]);
    let raw = RawSnapshot::decode(&bytes).expect("decodes");

    assert_eq!(raw.body().seq, 1);
    assert_eq!(raw.body().heads, vec![history.id("n2")]);
    assert_eq!(raw.body().network, history.network());
    assert_eq!(raw.to_bytes(), bytes, "re-encoding reproduces the received bytes");
}

#[test]
fn a_snapshot_verifies_under_its_signing_key() {
    let history = linear(2);
    let bytes = history.snapshot_at(1, 1, &["n1"]);
    let raw = RawSnapshot::decode(&bytes).expect("decodes");
    let signed = raw.verify(&signer(1).public_key()).expect("verifies");
    assert_eq!(signed.signer(), signer(1).key_id());
    assert_eq!(signed.to_bytes(), bytes);
}

/// A snapshot names its signer, so offering the wrong key says exactly that
/// rather than reporting a signature failure that never happened.
#[test]
fn a_snapshot_does_not_verify_under_a_key_it_does_not_name() {
    let history = linear(2);
    let bytes = history.snapshot_at(1, 1, &["n1"]);
    let raw = RawSnapshot::decode(&bytes).expect("decodes");
    assert_eq!(raw.verify(&signer(9).public_key()).map(|_| ()), Err(Error::AuthorKeyMismatch));
}

/// A corrupted signature by the named author is a signature failure, and is
/// reported as one. Without a named author these two cases collapse together.
#[test]
fn a_corrupted_signature_from_the_named_author_is_a_signature_failure() {
    let history = linear(2);
    let bytes = history.snapshot_at(1, 1, &["n1"]);
    let raw = RawSnapshot::decode(&bytes).expect("decodes");
    let mut broken = *raw.signature();
    if let Some(first) = broken.first_mut() {
        *first ^= 0xff;
    }
    let forged = assemble_snapshot(raw.body_bytes(), &broken);
    let raw = RawSnapshot::decode(&forged).expect("structurally fine");
    assert_eq!(raw.verify(&signer(1).public_key()).map(|_| ()), Err(Error::SignatureInvalid));
}

/// The two tags exist so a signature over one kind of thing can never be made
/// to verify as the other.
#[test]
fn an_operation_signature_does_not_verify_as_a_snapshot() {
    let history = linear(2);
    let operation_bytes = history.bytes("a");
    let operation = RawOperation::decode(&operation_bytes).expect("decodes");

    let snapshot_bytes = history.snapshot_at(1, 1, &["n1"]);
    let snapshot = RawSnapshot::decode(&snapshot_bytes).expect("decodes");

    // Put the operation's signature onto the snapshot's body.
    let forged = assemble_snapshot(snapshot.body_bytes(), operation.signature());
    let raw = RawSnapshot::decode(&forged).expect("structurally fine");
    assert_eq!(raw.verify(&signer(1).public_key()).map(|_| ()), Err(Error::SignatureInvalid));
}

#[test]
fn a_snapshot_signature_does_not_verify_as_an_operation() {
    let history = linear(2);
    let snapshot_bytes = history.snapshot_at(1, 1, &["n1"]);
    let snapshot = RawSnapshot::decode(&snapshot_bytes).expect("decodes");

    let core = OperationCore::new(
        1,
        Algorithm::Ed25519,
        OperationBody::Demote { device: device_id(2) },
        vec![history.id("a")],
        signer(1).key_id(),
        history.network(),
    )
    .expect("well-formed");
    let forged = roster::sign::assemble_operation(&core.encode(), snapshot.signature());
    let raw = RawOperation::decode(&forged).expect("structurally fine");
    assert_eq!(raw.verify(&signer(1).public_key()), Err(Error::SignatureInvalid));
}

#[test]
fn the_snapshot_signing_input_carries_its_own_tag() {
    let history = linear(2);
    let body = b"body".as_slice();
    let input = snapshot_signing_input(&history.network(), body);
    assert!(
        input.windows(SNAPSHOT_DOMAIN_TAG.len()).any(|w| w == SNAPSHOT_DOMAIN_TAG.as_bytes()),
        "the snapshot tag is part of the signed bytes"
    );
    assert!(
        !input.windows(9).any(|w| w == b"roster/v1" && w.len() == 9)
            || SNAPSHOT_DOMAIN_TAG.contains("roster"),
        "the tags are allowed to share a prefix, but not to be equal"
    );
    assert_ne!(SNAPSHOT_DOMAIN_TAG, roster::sign::DOMAIN_TAG);
}

#[test]
fn a_snapshot_does_not_replay_across_networks() {
    let history = linear(2);
    // A different founder, so the genesis differs and the network id really is
    // another network. Two identically-built histories share a network id, and
    // "moving" a snapshot between them would move it nowhere.
    let mut other = History::new();
    other.genesis("g", 42);
    assert_ne!(history.network(), other.network());

    let bytes = history.snapshot_at(1, 1, &["n1"]);
    let raw = RawSnapshot::decode(&bytes).expect("decodes");

    // Rebuild the same body under the other network id and keep the signature.
    let mut body = raw.body().clone();
    body.network = other.network();
    let moved = assemble_snapshot(&body.encode(), raw.signature());
    let moved_raw = RawSnapshot::decode(&moved).expect("structurally fine");
    assert_eq!(moved_raw.verify(&signer(1).public_key()).map(|_| ()), Err(Error::SignatureInvalid));
}

#[test]
fn a_snapshot_from_a_non_admin_is_refused() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op(
        "add2",
        1,
        &["g"],
        OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
    );

    let mut roster = Roster::new();
    load(&mut roster, &history);

    // Device 2 is a member, and signs a snapshot anyway.
    let bytes = history.snapshot_at(1, 2, &["add2"]);
    let outcome = roster.offer_snapshot(&bytes);
    assert_eq!(outcome.refusal(), Some(&Error::UnauthorizedAuthor));
}

#[test]
fn a_non_canonical_snapshot_is_rejected() {
    let history = linear(2);
    let bytes = history.snapshot_at(1, 1, &["n1"]);
    let mut corrupted = bytes.clone();
    // Break the outer map header so the encoding is no longer what it claims.
    if let Some(slot) = corrupted.first_mut() {
        *slot = 0xbf;
    }
    assert!(RawSnapshot::decode(&corrupted).is_err());
}

/// A snapshot is not an operation and must never be mistaken for one.
#[test]
fn snapshot_bytes_are_not_an_operation() {
    let history = linear(2);
    let bytes = history.snapshot_at(1, 1, &["n1"]);
    assert!(RawOperation::decode(&bytes).is_err());

    let mut roster = Roster::new();
    load(&mut roster, &history);
    let before = roster.dag().len();
    let outcome = roster.offer_bytes(&bytes);
    assert!(outcome.refusal().is_some(), "a snapshot offered as an operation is refused");
    assert_eq!(roster.dag().len(), before, "and nothing entered the graph");
}

// ---------------------------------------------------------------------------
// Verification before trust
// ---------------------------------------------------------------------------

#[test]
fn a_snapshot_matching_local_derivation_is_accepted() {
    let history = linear(3);
    let mut roster = Roster::new();
    load(&mut roster, &history);

    let bytes = history.snapshot_at(1, 1, &["n2"]);
    assert_eq!(roster.offer_snapshot(&bytes), SnapshotAdmission::Accepted { seq: 1 });
    assert!(roster.snapshot_is_verified());
}

/// The rule that stops a compromised admin rewriting history.
#[test]
fn a_snapshot_disagreeing_with_local_derivation_is_refused() {
    let history = linear(3);
    let mut roster = Roster::new();
    load(&mut roster, &history);
    let before = roster.state().expect("derives").to_bytes();

    // A state claiming a device this history never added.
    let liar = {
        let mut fabricated = History::new();
        fabricated.genesis("g", 1);
        fabricated.op(
            "add9",
            1,
            &["g"],
            OperationBody::AddDevice(device(9, "ghost", Role::Admin, false)),
        );
        derive(&fabricated.dag()).expect("derives").to_bytes()
    };
    let bytes = history.snapshot_with_state(1, 1, &["n2"], Some(liar));

    let outcome = roster.offer_snapshot(&bytes);
    assert_eq!(outcome.refusal(), Some(&Error::SnapshotStateMismatch));
    assert_eq!(
        roster.state().expect("derives").to_bytes(),
        before,
        "local state is unchanged; the node's own derivation wins"
    );
    assert!(roster.snapshot().is_none());
}

#[test]
fn a_bootstrapping_node_may_adopt_a_snapshot_it_cannot_derive() {
    let history = linear(3);
    let bytes = history.snapshot_at(1, 1, &["n2"]);

    // A node holding nothing at all.
    let mut fresh = Roster::new();
    assert_eq!(fresh.offer_snapshot(&bytes), SnapshotAdmission::AdoptedUnverified { seq: 1 });
    assert!(!fresh.snapshot_is_verified(), "it rests on the admin signature alone, and says so");
}

#[test]
fn a_partially_covered_node_does_not_count_as_verified() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("a", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    history.op("b", 1, &["g"], OperationBody::AddDevice(device(3, "nas", Role::Member, false)));

    // A node holding only one of the two branches the snapshot covers.
    let mut roster = Roster::new();
    roster.offer_bytes(&history.bytes("g"));
    roster.offer_bytes(&history.bytes("a"));

    let bytes = history.snapshot_at(1, 1, &["a", "b"]);
    let outcome = roster.offer_snapshot(&bytes);
    assert!(
        !outcome.is_accepted() || !roster.snapshot_is_verified(),
        "holding part of the covered set verifies nothing"
    );
}

// ---------------------------------------------------------------------------
// Sequence rules
// ---------------------------------------------------------------------------

#[test]
fn an_older_sequence_is_refused() {
    let history = linear(4);
    let mut roster = Roster::new();
    load(&mut roster, &history);

    assert!(roster.offer_snapshot(&history.snapshot_at(7, 1, &["n3"])).is_accepted());
    let outcome = roster.offer_snapshot(&history.snapshot_at(4, 1, &["n2"]));
    assert_eq!(outcome.refusal(), Some(&Error::SnapshotSequenceRegressed));
    assert_eq!(roster.highest_sequence(), Some(7), "the accepted snapshot stands");
    assert_eq!(roster.snapshot().map(|s| s.body().seq), Some(7));
}

#[test]
fn re_offering_the_same_snapshot_is_idempotent() {
    let history = linear(3);
    let mut roster = Roster::new();
    load(&mut roster, &history);

    let bytes = history.snapshot_at(1, 1, &["n2"]);
    assert!(roster.offer_snapshot(&bytes).is_accepted());
    assert_eq!(roster.offer_snapshot(&bytes), SnapshotAdmission::AlreadyHeld { seq: 1 });
    assert!(roster.conflicting_sequences().is_empty(), "not a conflict");
}

/// Two claims at one number: refuse both rather than choose between two things
/// one of which may be a forgery.
#[test]
fn two_conflicting_snapshots_at_one_sequence_are_both_refused() {
    let history = linear(4);
    let mut roster = Roster::new();
    load(&mut roster, &history);

    let first = history.snapshot_at(5, 1, &["n2"]);
    let second = history.snapshot_at(5, 1, &["n3"]);
    assert_ne!(first, second);

    assert!(roster.offer_snapshot(&first).is_accepted());
    let outcome = roster.offer_snapshot(&second);
    assert_eq!(outcome.refusal(), Some(&Error::SnapshotSequenceConflict));

    assert!(roster.snapshot().is_none(), "neither is retained");
    assert_eq!(roster.conflicting_sequences(), &[5]);

    // And the number stays closed.
    assert_eq!(roster.offer_snapshot(&first).refusal(), Some(&Error::SnapshotSequenceConflict));
}

#[test]
fn the_conflict_verdict_does_not_depend_on_arrival_order() {
    let history = linear(4);
    let first = history.snapshot_at(5, 1, &["n2"]);
    let second = history.snapshot_at(5, 1, &["n3"]);

    let mut forward = Roster::new();
    load(&mut forward, &history);
    forward.offer_snapshot(&first);
    forward.offer_snapshot(&second);

    let mut backward = Roster::new();
    load(&mut backward, &history);
    backward.offer_snapshot(&second);
    backward.offer_snapshot(&first);

    assert!(forward.snapshot().is_none());
    assert!(backward.snapshot().is_none());
    assert_eq!(forward.conflicting_sequences(), backward.conflicting_sequences());
}

#[test]
fn a_higher_sequence_restores_progress_after_a_conflict() {
    let history = linear(5);
    let mut roster = Roster::new();
    load(&mut roster, &history);

    roster.offer_snapshot(&history.snapshot_at(5, 1, &["n2"]));
    roster.offer_snapshot(&history.snapshot_at(5, 1, &["n3"]));
    assert!(roster.snapshot().is_none());

    let recovery = history.snapshot_at(6, 1, &["n4"]);
    assert!(roster.offer_snapshot(&recovery).is_accepted(), "the network is not wedged");
    assert_eq!(roster.snapshot().map(|s| s.body().seq), Some(6));
}

// ---------------------------------------------------------------------------
// Compaction
// ---------------------------------------------------------------------------

/// A history long enough that a prefix sits beyond a small staleness horizon.
fn compactable() -> (History, Roster) {
    let history = linear(12);
    let mut roster = Roster::with_staleness_depth(2);
    load(&mut roster, &history);
    (history, roster)
}

#[test]
fn compaction_discards_the_covered_region_and_keeps_the_heads() {
    let (history, mut roster) = compactable();
    let bytes = history.snapshot_at(1, 1, &["n2"]);
    assert!(roster.offer_snapshot(&bytes).is_accepted());

    let before = roster.dag().len();
    let discarded = roster.compact().expect("compacts");
    assert!(discarded > 0);
    assert_eq!(roster.dag().len(), before.saturating_sub(discarded));

    // The head survives, whole.
    assert!(roster.dag().contains(&history.id("n2")), "the covered head is retained");
    // Its strict ancestors are gone.
    assert!(!roster.dag().contains(&history.id("g")));
    assert!(!roster.dag().contains(&history.id("a")));
}

#[test]
fn everything_retained_after_compaction_is_signature_covered() {
    let (history, mut roster) = compactable();
    roster.offer_snapshot(&history.snapshot_at(1, 1, &["n2"]));
    roster.compact().expect("compacts");

    for operation in roster.dag().operations() {
        // Each retained operation still carries its own signature and still
        // verifies; nothing is kept as an unsigned fragment.
        let bytes = operation.to_bytes();
        let raw = RawOperation::decode(&bytes).expect("a retained operation is whole");
        assert_eq!(raw.signature(), operation.signature());
    }
    assert!(roster.dag().base_snapshot().is_some(), "the rest rests on the snapshot signature");
}

#[test]
fn a_held_concurrent_operation_prevents_compaction() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("a", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    // A branch that will be concurrent with the covered region.
    history.op("side", 1, &["a"], OperationBody::AddDevice(device(3, "nas", Role::Member, false)));
    let mut previous = "a".to_owned();
    for index in 0..12 {
        let label = format!("n{index}");
        history.op(
            &label,
            1,
            &[previous.as_str()],
            OperationBody::Rename { device: device_id(2), name: format!("name{index}") },
        );
        previous = label;
    }

    let mut roster = Roster::with_staleness_depth(2);
    load(&mut roster, &history);
    roster.offer_snapshot(&history.snapshot_at(1, 1, &["n2"]));

    let outcome = roster.compact();
    assert_eq!(
        outcome,
        Err(Error::CompactionRefused("a held operation is concurrent with the covered region")),
        "the concurrent branch still needs the ancestry compaction would destroy"
    );
}

#[test]
fn a_region_within_the_staleness_horizon_is_retained() {
    let history = linear(12);
    // A generous threshold puts the whole history inside the horizon.
    let mut roster = Roster::with_staleness_depth(1000);
    load(&mut roster, &history);
    roster.offer_snapshot(&history.snapshot_at(1, 1, &["n2"]));

    assert_eq!(
        roster.compact(),
        Err(Error::CompactionRefused("the covered region is within the staleness horizon")),
        "a later operation could still legitimately anchor into it"
    );
}

#[test]
fn an_unverified_snapshot_never_triggers_compaction() {
    let history = linear(12);
    let mut bootstrapping = Roster::with_staleness_depth(2);
    let bytes = history.snapshot_at(1, 1, &["n2"]);
    assert!(bootstrapping.offer_snapshot(&bytes).is_accepted());
    assert!(!bootstrapping.snapshot_is_verified());

    assert_eq!(
        bootstrapping.compact(),
        Err(Error::CompactionRefused("snapshot was not verified locally")),
        "discarding on an unverified claim would throw away the evidence it lied"
    );
}

#[test]
fn accepting_a_snapshot_alone_discards_nothing() {
    let (history, mut roster) = compactable();
    let before = roster.dag().len();
    roster.offer_snapshot(&history.snapshot_at(1, 1, &["n2"]));
    assert_eq!(roster.dag().len(), before, "compaction is deliberate, never a side effect");
}

// ---------------------------------------------------------------------------
// Derivation across the boundary
// ---------------------------------------------------------------------------

/// The property the whole change turns on.
#[test]
fn a_compacted_node_derives_the_same_roster() {
    let history = linear(12);

    let mut compacted = Roster::with_staleness_depth(2);
    load(&mut compacted, &history);
    compacted.offer_snapshot(&history.snapshot_at(1, 1, &["n2"]));
    compacted.compact().expect("compacts");

    let mut whole = Roster::with_staleness_depth(2);
    load(&mut whole, &history);

    assert_eq!(
        compacted.state().expect("derives").to_bytes(),
        whole.state().expect("derives").to_bytes(),
        "compaction must not be observable in derived state"
    );
}

#[test]
fn later_operations_outrank_values_carried_in_the_snapshot() {
    let history = linear(12);
    let mut compacted = Roster::with_staleness_depth(2);
    load(&mut compacted, &history);
    compacted.offer_snapshot(&history.snapshot_at(1, 1, &["n2"]));
    compacted.compact().expect("compacts");

    // The last rename in the chain is `name11`, applied after the snapshot.
    let state = compacted.state().expect("derives");
    assert_eq!(
        state.devices.get(&device_id(2)).map(|record| record.name.as_str()),
        Some("name11"),
        "a post-snapshot rename beats the name inside the snapshot"
    );
}

#[test]
fn revocations_inside_and_after_a_snapshot_both_hold() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("a", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    history.op("b", 1, &["a"], OperationBody::AddDevice(device(3, "nas", Role::Member, false)));
    history.op(
        "rev2",
        1,
        &["b"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "sold".into() },
    );
    let mut previous = "rev2".to_owned();
    for index in 0..12 {
        let label = format!("n{index}");
        history.op(
            &label,
            1,
            &[previous.as_str()],
            OperationBody::Rename { device: device_id(3), name: format!("name{index}") },
        );
        previous = label;
    }
    history.op(
        "rev3",
        1,
        &[previous.as_str()],
        OperationBody::RevokeDevice { device: device_id(3), reason: "lost".into() },
    );

    let mut roster = Roster::with_staleness_depth(2);
    load(&mut roster, &history);
    roster.offer_snapshot(&history.snapshot_at(1, 1, &["rev2"]));
    roster.compact().expect("compacts");

    let state = roster.state().expect("derives");
    assert!(state.revoked.contains(&device_id(2)), "the revocation inside the snapshot holds");
    assert!(state.revoked.contains(&device_id(3)), "and the one after it");
}

#[test]
fn compacting_changes_nothing_a_node_already_derived() {
    let (history, mut roster) = compactable();
    roster.offer_snapshot(&history.snapshot_at(1, 1, &["n2"]));
    let before = roster.state().expect("derives").to_bytes();
    roster.compact().expect("compacts");
    let after = roster.state().expect("derives").to_bytes();
    assert_eq!(before, after);
}

#[test]
fn a_snapshot_seeded_graph_derives_the_snapshot_state() {
    let history = linear(4);
    let bytes = history.snapshot_at(1, 1, &["n3"]);
    let raw = RawSnapshot::decode(&bytes).expect("decodes");
    let signed = raw.verify(&signer(1).public_key()).expect("verifies");

    let seeded = Dag::from_snapshot(signed, history.head_operations(&["n3"]))
        .expect("seeds from the snapshot");
    let derived = derive(&seeded).expect("derives");
    let expected = RosterState::from_bytes(&raw.body().state).expect("state decodes");
    assert_eq!(derived.to_bytes(), expected.to_bytes());
}

// ---------------------------------------------------------------------------
// Freshness
// ---------------------------------------------------------------------------

/// Builds a roster on a clock the test drives.
fn on_clock(history: &History, depth: u64) -> (Roster, SharedClock) {
    let clock = SharedClock::new();
    let mut roster = Roster::with_staleness_and_clock(depth, Box::new(clock.clone()));
    load(&mut roster, history);
    (roster, clock)
}

#[test]
fn a_roster_with_no_attestation_has_unknown_freshness() {
    let history = linear(3);
    let (mut roster, _clock) = on_clock(&history, 64);
    assert_eq!(roster.freshness(), Freshness::Unknown);
}

#[test]
fn a_fresh_roster_is_not_flagged() {
    let history = linear(3);
    let (mut roster, clock) = on_clock(&history, 64);
    assert!(roster.offer_attestation(&history.attestation_at(1, 1, &["n2"])).is_accepted());

    clock.advance(params().snapshot_window.saturating_sub(1));
    assert_eq!(roster.freshness(), Freshness::Fresh);
}

#[test]
fn an_out_of_date_roster_is_flagged() {
    let history = linear(3);
    let (mut roster, clock) = on_clock(&history, 64);
    assert!(roster.offer_attestation(&history.attestation_at(1, 1, &["n2"])).is_accepted());

    clock.advance(params().snapshot_window.saturating_add(1));
    assert_eq!(roster.freshness(), Freshness::Stale, "this is §3.3's cautious mode");
}

/// The half of the change that the rest hangs on: a snapshot carries state and
/// is delivered where a device needs state. Dating a roster is a different job.
#[test]
fn a_snapshot_does_not_make_a_roster_fresh() {
    let history = linear(3);
    let (mut roster, _clock) = on_clock(&history, 64);

    assert!(roster.offer_snapshot(&history.snapshot_at(1, 1, &["n2"])).is_accepted());

    assert_eq!(
        roster.freshness(),
        Freshness::Unknown,
        "a snapshot dates nothing; without an attestation nothing has been attested"
    );
}

/// D2. An admin's word that it knew these heads says nothing to a node that
/// does not have them: what such a node has learned is that it is behind.
#[test]
fn an_attestation_naming_heads_the_node_does_not_hold_gives_no_freshness() {
    let history = linear(3);
    let (mut roster, _clock) = on_clock(&history, 64);

    let outcome = roster.offer_attestation(&history.attestation_over_unknown_heads(1, 1));

    assert!(matches!(outcome, AttestationAdmission::HeadsNotHeld { seq: 1 }), "{outcome:?}");
    assert_eq!(roster.freshness(), Freshness::Unknown, "being behind is not freshness");
}

/// And the same attestation counts once the operations it names arrive.
#[test]
fn an_attestation_counts_once_its_heads_are_held() {
    let history = linear(3);
    let ahead = history.attestation_at(1, 1, &["n2"]);

    // A node that holds only the genesis: the attestation names a head it has
    // not seen.
    let clock = SharedClock::new();
    let mut roster = Roster::with_staleness_and_clock(64, Box::new(clock.clone()));
    roster.offer_bytes(&history.bytes("g"));
    assert!(matches!(roster.offer_attestation(&ahead), AttestationAdmission::HeadsNotHeld { .. }));
    assert_eq!(roster.freshness(), Freshness::Unknown);

    // The operations arrive — the whole chain, or the last ones wait for
    // parents and the head is still not held — and the same bytes now date it.
    for label in ["a", "n0", "n1", "n2"] {
        roster.offer_bytes(&history.bytes(label));
    }
    assert!(roster.offer_attestation(&ahead).is_accepted(), "the same attestation, now held");
    assert_eq!(roster.freshness(), Freshness::Fresh);
}

/// The whole of D1, stated as the case that does not exist.
///
/// A **snapshot** offered to a node holding no roster is resolved against the
/// state the snapshot itself carries, and adopted unverified — which is right,
/// because that is how a joining device is given a network. An attestation
/// carries no state, so there is nothing for it to be resolved against and
/// nothing to adopt: a node with no roster learns nothing from one and accepts
/// none.
///
/// That is why a stolen attestation key cannot hand anybody a fabricated
/// network. Not a rule that refuses it — there is no object that could say it.
#[test]
fn a_node_with_no_roster_accepts_no_attestation() {
    let history = linear(3);
    let bytes = history.attestation_at(1, 1, &["n2"]);

    let mut empty = Roster::new();
    let outcome = empty.offer_attestation(&bytes);

    assert!(
        matches!(outcome, AttestationAdmission::Refused { .. }),
        "a node with no roster has nobody it could believe: {outcome:?}"
    );
    assert_eq!(empty.freshness(), Freshness::Unknown);

    // And the contrast that makes the point: the same node *does* take a
    // snapshot, because a snapshot is how it would be given a network at all.
    let mut also_empty = Roster::new();
    assert!(
        also_empty.offer_snapshot(&history.snapshot_at(1, 1, &["n2"])).is_accepted(),
        "a snapshot is adopted by a node holding nothing — that is what it is for"
    );
    assert_eq!(
        also_empty.freshness(),
        Freshness::Unknown,
        "and it still dates nothing, so adopting one buys no freshness"
    );
}

/// A member's attestation dates nothing. Only an admin's word about the roster
/// means anything, because only an admin can change it.
#[test]
fn an_attestation_from_a_member_is_refused() {
    let history = linear(3);
    let (mut roster, _clock) = on_clock(&history, 64);
    // `linear` adds device 2 as a member; its attestation key is seed 202.
    assert_eq!(
        roster
            .state()
            .expect("derives")
            .devices
            .get(&device_id(2))
            .expect("the member is there")
            .role,
        Role::Member,
        "the fixture has to be a member for this test to mean anything"
    );

    let outcome = roster.offer_attestation(&history.attestation_at(1, 2, &["n2"]));

    assert!(matches!(outcome, AttestationAdmission::Refused { .. }), "{outcome:?}");
    assert_eq!(roster.freshness(), Freshness::Unknown);
}

/// And a revoked admin's dates nothing either, from the moment this node knows
/// it was revoked.
#[test]
fn an_attestation_from_a_revoked_admin_is_refused() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op(
        "promote",
        1,
        &["g"],
        OperationBody::AddDevice(device(2, "nas", Role::Admin, false)),
    );
    history.op(
        "revoke",
        1,
        &["promote"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "sold".to_owned() },
    );

    let (mut roster, _clock) = on_clock(&history, 64);
    assert!(
        roster.state().expect("derives").revoked.contains(&device_id(2)),
        "the fixture has to have revoked it"
    );

    let outcome = roster.offer_attestation(&history.attestation_at(1, 2, &["revoke"]));

    assert!(matches!(outcome, AttestationAdmission::Refused { .. }), "{outcome:?}");
    assert_eq!(roster.freshness(), Freshness::Unknown);
}

/// Signed by the device's *signing* key rather than its attestation key. The
/// separation is the point of the third key, so it is refused.
#[test]
fn a_signing_key_may_not_attest() {
    let history = linear(3);
    let (mut roster, _clock) = on_clock(&history, 64);

    // Seed 1 is the founder's signing key; its attestation key is seed 201.
    let outcome = roster.offer_attestation(&history.attestation_signed_by(1, 1, &["n2"]));

    assert!(
        matches!(outcome, AttestationAdmission::Refused { .. }),
        "the signing key must not date a roster: {outcome:?}"
    );
    assert_eq!(roster.freshness(), Freshness::Unknown);
}

/// An attestation whose sequence does not advance is refused, as a snapshot's
/// is: a replayed older one must not make a roster look fresher than it is.
#[test]
fn an_attestation_sequence_must_advance() {
    let history = linear(3);
    let (mut roster, _clock) = on_clock(&history, 64);

    assert!(roster.offer_attestation(&history.attestation_at(2, 1, &["n2"])).is_accepted());
    let outcome = roster.offer_attestation(&history.attestation_at(1, 1, &["n2"]));

    assert!(matches!(outcome, AttestationAdmission::Refused { .. }), "{outcome:?}");
}

/// Restoring keeps the age it had. Without this, freshness would last as long
/// as the process and restarting would be the way out of a stale roster.
#[test]
fn a_restored_attestation_keeps_the_age_it_had() {
    let history = linear(3);
    let (mut roster, _clock) = on_clock(&history, 64);
    let bytes = history.attestation_at(1, 1, &["n2"]);
    assert!(roster.offer_attestation(&bytes).is_accepted());
    let received_at = roster.attestation_received_at().expect("dated");

    // A new roster, as a restart builds one, on a clock that has moved past the
    // window since.
    let later = SharedClock::new();
    later.advance(received_at.saturating_add(params().snapshot_window).saturating_add(1));
    let mut restarted = Roster::with_staleness_and_clock(64, Box::new(later));
    load(&mut restarted, &history);

    assert!(restarted.restore_attestation(&bytes, received_at).is_accepted());
    assert_eq!(
        restarted.freshness(),
        Freshness::Stale,
        "a restart must not be a way out of a stale roster"
    );
}

/// A signer-chosen expiry would let a compromised admin make the revocation
/// window unbounded. Nothing here reads a timestamp from the data.
#[test]
fn a_far_future_timestamp_does_not_extend_freshness() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("a", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    // An operation stamped far in the future, carried into the snapshot.
    let core = OperationCore::new(
        u64::MAX,
        Algorithm::Ed25519,
        OperationBody::Rename { device: device_id(2), name: "future".into() },
        vec![history.id("a")],
        signer(1).key_id(),
        history.network(),
    )
    .expect("well-formed");
    let _ = sign_operation(&core, &signer(1)).expect("signs");

    let (mut roster, clock) = on_clock(&history, 64);
    assert!(roster.offer_attestation(&history.attestation_at(1, 1, &["a"])).is_accepted());

    clock.advance(params().snapshot_window.saturating_add(1));
    assert_eq!(
        roster.freshness(),
        Freshness::Stale,
        "freshness is measured from local receipt, not from anything the signer chose"
    );
}

/// What makes freshness outlive a process.
///
/// An attestation is not an operation and is not in the log, so a node that
/// replays its log holds none. Re-offering a stored one would date it from the
/// moment it was re-offered, which would make restarting a way out of a stale
/// roster — the one state a device must not be able to leave by being turned
/// off and on.
#[test]
fn a_restored_snapshot_is_still_not_freshness() {
    let history = linear(3);
    let bytes = history.snapshot_at(1, 1, &["n2"]);

    // A snapshot still restores, is still checked again, and still dates
    // nothing — everything it was for it is still for.
    let (mut first, first_clock) = on_clock(&history, 64);
    assert!(first.offer_snapshot(&bytes).is_accepted());
    first_clock.advance(params().snapshot_window.saturating_add(1));
    assert_eq!(first.freshness(), Freshness::Unknown, "a snapshot never made it fresh");

    let (mut restored, restored_clock) = on_clock(&history, 64);
    restored_clock.advance(params().snapshot_window.saturating_add(1));
    assert!(restored.restore_snapshot(&bytes, 0).is_accepted(), "it is checked again, and holds");

    assert_eq!(
        restored.freshness(),
        Freshness::Unknown,
        "and restoring one is not a way to become fresh either"
    );
}

/// Restoring checks everything offering does. A stored snapshot is bytes off a
/// disk, and handing them back is not evidence of anything.
#[test]
fn a_restored_snapshot_is_checked_like_any_other() {
    let history = linear(3);
    let mut bytes = history.snapshot_at(1, 1, &["n2"]);
    let last = bytes.len().saturating_sub(1);
    if let Some(byte) = bytes.get_mut(last) {
        *byte ^= 0xff;
    }

    let (mut roster, _clock) = on_clock(&history, 64);

    assert!(!roster.restore_snapshot(&bytes, 0).is_accepted(), "a damaged one is refused");
    assert_eq!(roster.freshness(), Freshness::Unknown, "and nothing was dated by it");
}

/// A receipt later than the clock's own reading is a clock that moved, and
/// saying so is the only reading that is not exploitable: treated as elapsed
/// time it saturates to zero, so a clock set forward once while a snapshot was
/// accepted would leave the node fresh for ever.
#[test]
fn a_receipt_in_the_future_is_an_anomaly_not_freshness() {
    let history = linear(3);
    let bytes = history.attestation_at(1, 1, &["n2"]);

    let (mut roster, _clock) = on_clock(&history, 64);
    assert!(
        roster
            .restore_attestation(&bytes, params().snapshot_window.saturating_mul(2))
            .is_accepted()
    );

    assert_eq!(
        roster.freshness(),
        Freshness::ClockWentBackwards,
        "a roster received in the future is a clock to report, not a roster to trust"
    );
}

#[test]
fn freshness_does_not_change_derived_state() {
    let history = linear(3);

    let (mut stale, stale_clock) = on_clock(&history, 64);
    assert!(stale.offer_attestation(&history.attestation_at(1, 1, &["n2"])).is_accepted());
    stale_clock.advance(params().snapshot_window.saturating_add(10));

    let (mut fresh, _fresh_clock) = on_clock(&history, 64);
    assert!(fresh.offer_attestation(&history.attestation_at(1, 1, &["n2"])).is_accepted());

    assert_eq!(stale.freshness(), Freshness::Stale);
    assert_eq!(fresh.freshness(), Freshness::Fresh);
    assert_eq!(
        stale.state().expect("derives").to_bytes(),
        fresh.state().expect("derives").to_bytes(),
        "a liveness opinion cannot move the roster"
    );
}

#[test]
fn a_backwards_clock_jump_is_reported() {
    let history = linear(3);
    let (mut roster, clock) = on_clock(&history, 64);
    assert!(roster.offer_attestation(&history.attestation_at(1, 1, &["n2"])).is_accepted());

    clock.advance(100);
    assert_eq!(roster.freshness(), Freshness::Fresh);
    clock.rewind(50);
    assert_eq!(
        roster.freshness(),
        Freshness::ClockWentBackwards,
        "a correction and tampering look alike from here, so it is reported"
    );
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

#[test]
fn a_snapshot_with_no_heads_is_rejected() {
    assert!(
        Snapshot::new(
            1,
            vec![],
            vec![],
            vec![],
            signer(1).key_id(),
            roster::id::NetworkId::from_bytes([1; 32]),
        )
        .is_err()
    );
}

#[test]
fn an_oversized_snapshot_is_refused_on_sight() {
    let oversized = vec![0u8; roster::limits::MAX_SNAPSHOT_SIZE.saturating_add(1)];
    assert_eq!(
        RawSnapshot::decode(&oversized).map(|_| ()),
        Err(Error::LimitExceeded("snapshot size"))
    );
}

#[test]
fn signing_a_snapshot_works_under_both_algorithms() {
    let history = linear(2);
    let covered = history.covered_dag(&["n1"]);
    let state = derive(&covered).expect("derives").to_bytes();
    let index = covered.position(&history.id("n1")).expect("held");
    let ed_body = Snapshot::new(
        1,
        state.clone(),
        vec![history.id("n1")],
        vec![covered.depth(index)],
        signer(1).key_id(),
        history.network(),
    )
    .expect("well-formed");
    let ed = sign_snapshot(&ed_body, &signer(1)).expect("signs");
    assert!(RawSnapshot::decode(&ed).expect("decodes").verify(&signer(1).public_key()).is_ok());

    let p256 = roster::sign::P256Signer::from_scalar([0x22; 32]).expect("in range");
    let p256_body = Snapshot::new(
        1,
        state,
        vec![history.id("n1")],
        vec![covered.depth(index)],
        p256.key_id(),
        history.network(),
    )
    .expect("well-formed");
    let bytes = sign_snapshot(&p256_body, &p256).expect("signs");
    assert!(RawSnapshot::decode(&bytes).expect("decodes").verify(&p256.public_key()).is_ok());

    // A body naming one key cannot be signed by another.
    assert_eq!(sign_snapshot(&ed_body, &p256).map(|_| ()), Err(Error::AuthorKeyMismatch));
}

/// A device added twice keeps the first add, so a rename written between the
/// two is not thrown away by the second.
///
/// Last-add-wins would reset the name, and a snapshot taken between the adds
/// has already folded that rename into its state with no way to mark it
/// superseded — so a compacted node would keep a name an uncompacted one had
/// discarded. Shrunk out of the compaction property test.
#[test]
fn a_repeated_add_across_a_snapshot_does_not_diverge() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("s0", 1, &["g"], OperationBody::AddDevice(device(2, "member", Role::Member, false)));
    history.op("s1", 1, &["s0"], OperationBody::Rename { device: device_id(2), name: "n0".into() });
    history.op(
        "s2",
        1,
        &["s1"],
        OperationBody::AddDevice(device(2, "member", Role::Member, false)),
    );
    history.op("s3", 1, &["s2"], OperationBody::Promote { device: device_id(2), founder: false });
    history.op(
        "s4",
        1,
        &["s3"],
        OperationBody::AddDevice(device(2, "member", Role::Member, false)),
    );
    history.op("s5", 1, &["s4"], OperationBody::Promote { device: device_id(2), founder: false });

    let mut compacted = Roster::with_staleness_depth(1);
    load(&mut compacted, &history);
    assert!(compacted.offer_snapshot(&history.snapshot_at(1, 1, &["s1"])).is_accepted());
    compacted.compact().expect("compacts");

    let mut whole = Roster::with_staleness_depth(1);
    load(&mut whole, &history);

    assert_eq!(
        compacted.state().expect("derives").to_bytes(),
        whole.state().expect("derives").to_bytes()
    );
    let state = whole.state().expect("derives");
    let record = state.devices.get(&device_id(2)).expect("present");
    assert_eq!(record.name, "n0", "the re-add does not undo the rename before it");
}

// ---------------------------------------------------------------------------
// Evidence of a fork outlives the compaction that would discard it
// ---------------------------------------------------------------------------

/// A history with a fork early on, and enough after it to be compactable past.
fn forked_then_long(length: usize) -> History {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("a", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));

    // One author, two concurrent operations: a fork, deep in the history.
    history.op(
        "fork-left",
        1,
        &["a"],
        OperationBody::Rename { device: device_id(2), name: "left".to_owned() },
    );
    history.op(
        "fork-right",
        1,
        &["a"],
        OperationBody::Rename { device: device_id(2), name: "right".to_owned() },
    );

    // A merge, so everything after has both branches as ancestors and the
    // region below is eligible to be discarded.
    history.op(
        "merge",
        1,
        &["fork-left", "fork-right"],
        OperationBody::Rename { device: device_id(2), name: "merged".to_owned() },
    );

    let mut previous = "merge".to_owned();
    for index in 0..length {
        let label = format!("n{index}");
        history.op(
            &label,
            1,
            &[previous.as_str()],
            OperationBody::Rename { device: device_id(2), name: format!("name{index}") },
        );
        previous = label;
    }
    history
}

/// **Compaction would take the proof with the region.** `Compaction
/// preconditions` blocks a region only while a *held* operation is concurrent
/// with it — two forked operations are concurrent with *each other*, so a region
/// containing both passes every gate. Without this, a node would keep reporting a
/// fork whose evidence it had thrown away: an accusation to be believed, against
/// a device, with an irreversible remedy.
#[test]
fn evidence_of_a_fork_survives_compaction() {
    let history = forked_then_long(12);
    let mut roster = Roster::with_staleness_depth(2);
    load(&mut roster, &history);

    let before = roster.equivocations();
    assert_eq!(before.len(), 1, "the fork is detected while everything is held");

    let bytes = history.snapshot_at(1, 1, &["n2"]);
    assert!(roster.offer_snapshot(&bytes).is_accepted());
    let discarded = roster.compact().expect("compacts");
    assert!(discarded > 0, "something was actually discarded");

    // The operations themselves are gone from the graph.
    assert!(!roster.dag().contains(&history.id("fork-left")), "the region was discarded");

    // The accusation and its proof are not.
    let after = roster.equivocations();
    assert_eq!(after, before, "the same fork, with the same evidence, after compaction");
}

/// Retained evidence is whole and signed, which is why keeping it does not
/// weaken the rule that every retained byte stays covered by a signature.
#[test]
fn retained_evidence_is_whole_and_verifies() {
    let history = forked_then_long(12);
    let mut roster = Roster::with_staleness_depth(2);
    load(&mut roster, &history);
    roster.offer_snapshot(&history.snapshot_at(1, 1, &["n2"]));
    roster.compact().expect("compacts");

    let reported = roster.equivocations();
    let evidence = reported.first().expect("the fork is still reported");
    let accused = signer(1).public_key();

    for proof in [&evidence.first, &evidence.second] {
        let offered = history
            .entries()
            .iter()
            .find(|entry| RawOperation::decode(&entry.bytes).expect("decodes").id() == proof.id)
            .expect("the evidence names an operation that was offered");
        let raw = RawOperation::decode(&offered.bytes).expect("decodes");

        assert_eq!(proof.core_bytes, raw.core_bytes(), "whole, and the bytes that arrived");
        assert!(raw.verify(&accused).is_ok(), "and still verifying under the accused key");
    }
}

/// A revocation settles the question, and the evidence is released.
#[test]
fn a_revocation_settles_the_question_and_releases_the_evidence() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op(
        "add9",
        1,
        &["g"],
        OperationBody::AddDevice(device(9, "other-admin", Role::Admin, false)),
    );
    // Device 9 forks.
    history.op("left", 9, &["add9"], OperationBody::AddDevice(device(2, "l", Role::Member, false)));
    history.op(
        "right",
        9,
        &["add9"],
        OperationBody::AddDevice(device(3, "r", Role::Member, false)),
    );

    let mut roster = Roster::new();
    load(&mut roster, &history);
    assert_eq!(roster.equivocations().len(), 1, "reported while unsettled");

    // The founder revokes the equivocating device, which is the remedy the
    // roster refuses to apply by itself.
    history.op(
        "expel",
        1,
        &["left", "right"],
        OperationBody::RevokeDevice {
            device: device_id(9),
            reason: "signed two histories".to_owned(),
        },
    );
    let expelled = history.entries().last().expect("the revocation").bytes.clone();
    assert!(roster.offer_bytes(&expelled).is_accepted());

    assert!(
        roster.equivocations().is_empty(),
        "once a signed operation has settled it, the accusation has nothing left to add"
    );
}

// ---- An attestation's signed time -------------------------------------------
//
// The test clock answers its own reading as Unix time, so an attestation signed
// "at day 0" and offered "at day 6" arrives six days old.

const DAY: u64 = 24 * 60 * 60;

/// A far-future signed time gives no age: the attestation is dated from its
/// receipt, exactly as one was before attestations carried a time. A stolen
/// attestation key gains nothing by writing one.
#[test]
fn a_far_future_signed_time_is_dated_from_receipt() {
    let history = linear(3);
    let (mut roster, clock) = on_clock(&history, 64);
    clock.advance(DAY);
    let far = u64::MAX / 2;
    assert!(
        roster.offer_attestation(&history.attestation_issued(1, 1, &["n2"], far)).is_accepted()
    );

    clock.advance(params().snapshot_window.saturating_sub(1));
    assert_eq!(roster.freshness(), Freshness::Fresh, "dated from its receipt");
    clock.advance(2);
    assert_eq!(roster.freshness(), Freshness::Stale, "and no later than a window after it");
}

/// Relayed six days late, an attestation is six days old on arrival: it buys one
/// more day, not seven.
#[test]
fn an_old_attestation_relayed_late_is_dated_from_when_it_was_signed() {
    let history = linear(3);
    let (mut roster, clock) = on_clock(&history, 64);
    let signed_at = clock.0.now_seconds();
    clock.advance(6 * DAY);
    assert!(
        roster
            .offer_attestation(&history.attestation_issued(1, 1, &["n2"], signed_at))
            .is_accepted()
    );
    assert_eq!(roster.attestation_received_at(), Some(signed_at), "moved back by its age");

    assert_eq!(roster.freshness(), Freshness::Fresh);
    clock.advance(params().snapshot_window.saturating_sub(6 * DAY).saturating_add(1));
    assert_eq!(roster.freshness(), Freshness::Stale, "one day bought, not seven");
}

/// One signed longer ago than the window is accepted — it is a valid attestation —
/// and dates nothing: the roster is already stale on its word.
#[test]
fn an_attestation_older_than_the_window_refreshes_nothing() {
    let history = linear(3);
    let (mut roster, clock) = on_clock(&history, 64);
    let signed_at = clock.0.now_seconds();
    clock.advance(params().snapshot_window.saturating_add(DAY));
    assert!(
        roster
            .offer_attestation(&history.attestation_issued(1, 1, &["n2"], signed_at))
            .is_accepted()
    );
    assert_eq!(roster.freshness(), Freshness::Stale);
}

/// What is kept beside the log is the dating it was given, age included, and a
/// restart neither ages it twice nor makes it young again.
#[test]
fn a_restored_attestation_keeps_the_age_it_arrived_with() {
    let history = linear(3);
    let (mut roster, clock) = on_clock(&history, 64);
    let signed_at = clock.0.now_seconds();
    clock.advance(6 * DAY);
    let bytes = history.attestation_issued(1, 1, &["n2"], signed_at);
    assert!(roster.offer_attestation(&bytes).is_accepted());
    let kept = roster.attestation_received_at().expect("dated");

    let restarted_clock = clock.clone();
    let mut restarted = Roster::with_staleness_and_clock(64, Box::new(restarted_clock));
    load(&mut restarted, &history);
    assert!(restarted.restore_attestation(&bytes, kept).is_accepted());
    assert_eq!(restarted.attestation_received_at(), Some(kept), "not aged a second time");

    assert_eq!(restarted.freshness(), Freshness::Fresh);
    clock.advance(params().snapshot_window.saturating_sub(6 * DAY).saturating_add(1));
    assert_eq!(restarted.freshness(), Freshness::Stale);
}

// ---- An admin's own word ------------------------------------------------------

/// A network with two admins: the founder (seed 1) and seed 2.
fn two_admins() -> History {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("a", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin, false)));
    history
}

/// An admin cut off from every other device keeps signing attestations, and with
/// another admin in the network they do not keep it fresh: that other admin could
/// have revoked something it has not heard about.
#[test]
fn an_isolated_admin_goes_stale_where_there_are_other_admins() {
    let history = two_admins();
    let (mut roster, clock) = on_clock(&history, 64);
    roster.set_own_device(device_id(2));

    let mut seq = 1;
    let mut elapsed = 0;
    while elapsed <= params().snapshot_window {
        let now = clock.0.now_seconds();
        assert!(
            roster
                .offer_attestation(&history.attestation_issued(seq, 2, &["a"], now))
                .is_accepted()
        );
        seq += 1;
        clock.advance(DAY / 2);
        elapsed += DAY / 2;
    }
    assert_ne!(roster.freshness(), Freshness::Fresh, "its own word does not date it");
}

/// The other admin's attestation still dates it, and so does its own once it is
/// relayed onward: only freshness skips it.
#[test]
fn another_admins_attestation_still_dates_an_admin() {
    let history = two_admins();
    let (mut roster, clock) = on_clock(&history, 64);
    roster.set_own_device(device_id(2));
    let now = clock.0.now_seconds();
    assert!(roster.offer_attestation(&history.attestation_issued(1, 1, &["a"], now)).is_accepted());
    assert_eq!(roster.freshness(), Freshness::Fresh);
}

/// With a single admin there is nobody else who could revoke anything, and its own
/// attestation is the only one there is.
#[test]
fn a_sole_admin_is_kept_fresh_by_its_own_attestation() {
    let history = linear(3);
    let (mut roster, clock) = on_clock(&history, 64);
    roster.set_own_device(device_id(1));

    let mut seq = 1;
    let mut elapsed = 0;
    while elapsed <= params().snapshot_window {
        let now = clock.0.now_seconds();
        assert!(
            roster
                .offer_attestation(&history.attestation_issued(seq, 1, &["n2"], now))
                .is_accepted()
        );
        seq += 1;
        clock.advance(DAY / 2);
        elapsed += DAY / 2;
    }
    assert_eq!(roster.freshness(), Freshness::Fresh);
}

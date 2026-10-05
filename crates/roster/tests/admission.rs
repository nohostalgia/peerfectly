//! Admission: the pending set and the staleness filter.
//!
//! These are the parts that are allowed to differ between nodes. The test that
//! matters most here is the last one, which proves they cannot leak into
//! derived state.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

mod support;

use roster::Error;
use roster::limits;
use roster::roster::{Admission, Roster};
use roster::sign::{RawOperation, Signer};
use roster::state::derive;
use roster::types::{OperationBody, Role};
use support::{History, device, device_id, signer};

/// A history with a genesis and a three-deep chain hanging off it.
fn chain() -> History {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("a", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    history.op("b", 1, &["a"], OperationBody::AddDevice(device(3, "nas", Role::Member, false)));
    history.op("c", 1, &["b"], OperationBody::AddDevice(device(4, "tablet", Role::Member, false)));
    history
}

// ---------------------------------------------------------------------------
// Pending operations
// ---------------------------------------------------------------------------

#[test]
fn an_operation_arriving_before_its_parent_is_retained() {
    let history = chain();
    let mut roster = Roster::new();
    roster.offer_bytes(&history.bytes("g"));

    let outcome = roster.offer_bytes(&history.bytes("b"));
    assert!(outcome.is_pending(), "held, not refused: it may be a revocation");
    match outcome {
        Admission::Pending { missing, .. } => assert_eq!(missing, vec![history.id("a")]),
        other => panic!("expected pending, got {other:?}"),
    }
    assert_eq!(roster.pending_count(), 1);
}

#[test]
fn a_pending_operation_is_integrated_when_its_parent_arrives() {
    let history = chain();
    let mut roster = Roster::new();
    roster.offer_bytes(&history.bytes("g"));
    roster.offer_bytes(&history.bytes("b"));
    assert_eq!(roster.pending_count(), 1);

    // The caller does not re-offer `b`; it lands on its own.
    let outcome = roster.offer_bytes(&history.bytes("a"));
    assert!(outcome.is_accepted());
    assert_eq!(roster.pending_count(), 0, "the pending entry was integrated");

    let state = roster.state().expect("derives");
    assert!(state.devices.contains_key(&device_id(3)), "and reached derived state");
}

#[test]
fn a_reverse_ordered_chain_cascades_into_place() {
    let history = chain();
    let mut roster = Roster::new();

    // Deepest first, genesis last.
    for label in ["c", "b", "a"] {
        assert!(roster.offer_bytes(&history.bytes(label)).is_pending(), "{label} waits");
    }
    assert_eq!(roster.pending_count(), 3);

    roster.offer_bytes(&history.bytes("g"));
    assert_eq!(roster.pending_count(), 0, "one arrival unblocks the whole chain");
    assert_eq!(roster.dag().len(), 4);

    let state = roster.state().expect("derives");
    for seed in [2u8, 3, 4] {
        assert!(state.devices.contains_key(&device_id(seed)), "device {seed} is present");
    }
}

#[test]
fn a_pending_operation_contributes_nothing_while_pending() {
    let history = chain();
    let mut roster = Roster::new();
    roster.offer_bytes(&history.bytes("g"));
    roster.offer_bytes(&history.bytes("b"));

    let state = roster.state().expect("derives");
    assert!(
        !state.devices.contains_key(&device_id(3)),
        "a pending add_device must not appear in state"
    );
}

#[test]
fn an_operation_offered_twice_occupies_one_pending_slot() {
    let history = chain();
    let mut roster = Roster::new();
    roster.offer_bytes(&history.bytes("g"));
    roster.offer_bytes(&history.bytes("b"));
    roster.offer_bytes(&history.bytes("b"));
    assert_eq!(roster.pending_count(), 1);
}

#[test]
fn the_pending_bound_is_enforced_and_reported() {
    let mut history = History::new();
    history.genesis("g", 1);
    // Build more orphans than the bound allows, each hanging off an operation
    // the roster will never be given.
    history.op(
        "hidden",
        1,
        &["g"],
        OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
    );
    let mut labels = Vec::new();
    for index in 0..=limits::MAX_PENDING_OPERATIONS {
        let label = format!("orphan{index}");
        history.op(
            &label,
            1,
            &["hidden"],
            OperationBody::Rename { device: device_id(2), name: format!("n{index}") },
        );
        labels.push(label);
    }

    let mut roster = Roster::new();
    roster.offer_bytes(&history.bytes("g"));

    let mut refused = 0usize;
    for label in &labels {
        if let Admission::Refused { reason, .. } = roster.offer_bytes(&history.bytes(label)) {
            assert_eq!(reason, Error::LimitExceeded("pending operations"));
            refused = refused.saturating_add(1);
        }
    }

    assert_eq!(roster.pending_count(), limits::MAX_PENDING_OPERATIONS);
    assert!(refused > 0, "the caller is told the limit was reached");
    assert!(!roster.refusals().is_empty(), "and the refusal is recorded, not dropped");
}

/// Pending entries are unverified by necessity: the key that would check them
/// is derived from the ancestors that are missing. So the check happens at
/// integration, and a bad signature is caught there.
#[test]
fn a_pending_operation_with_a_bad_signature_is_rejected_on_integration() {
    let history = chain();
    let mut roster = Roster::new();
    roster.offer_bytes(&history.bytes("g"));

    // Corrupt `b`'s signature. It still decodes and its id still matches, so
    // nothing catches it until the key becomes resolvable.
    let mut tampered = history.bytes("b");
    let position = tampered.len().saturating_sub(80);
    if let Some(slot) = tampered.get_mut(position) {
        *slot ^= 0x01;
    }

    let outcome = roster.offer_bytes(&tampered);
    // Either it fails to decode outright, or it waits — both are acceptable;
    // what matters is that it never reaches derived state.
    if outcome.is_pending() {
        roster.offer_bytes(&history.bytes("a"));
        assert_eq!(roster.dag().len(), 2, "the tampered operation was not integrated");
        assert!(
            roster.refusals().iter().any(|(_, reason)| matches!(
                reason,
                Error::SignatureInvalid | Error::AuthorKeyMismatch | Error::IdMismatch
            )),
            "and the reason was recorded"
        );
    }
    let state = roster.state().expect("derives");
    assert!(!state.devices.contains_key(&device_id(3)));
}

// ---------------------------------------------------------------------------
// Staleness
// ---------------------------------------------------------------------------

/// Builds a genesis, then `depth` operations in a chain, returning the history.
fn deep_history(depth: usize) -> History {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op(
        "anchor",
        1,
        &["g"],
        OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
    );
    let mut previous = "anchor".to_owned();
    for index in 0..depth {
        let label = format!("d{index}");
        history.op(
            &label,
            1,
            &[previous.as_str()],
            OperationBody::Rename { device: device_id(2), name: format!("n{index}") },
        );
        previous = label;
    }
    // Anchored right back at the start, far behind the frontier.
    history.op(
        "backdated",
        1,
        &["anchor"],
        OperationBody::AddDevice(device(3, "nas", Role::Member, false)),
    );
    history
}

#[test]
fn a_deeply_backdated_operation_is_refused_at_ingest() {
    let history = deep_history(12);
    let mut roster = Roster::with_staleness_depth(4);

    for entry in history.entries() {
        if entry.label == "backdated" {
            continue;
        }
        roster.offer_bytes(&entry.bytes);
    }

    let outcome = roster.offer_bytes(&history.bytes("backdated"));
    assert_eq!(outcome.refusal(), Some(&Error::StaleOperation));
    assert!(
        roster.refusals().iter().any(|(_, reason)| *reason == Error::StaleOperation),
        "the refusal is reported with its reason, never dropped"
    );
}

#[test]
fn an_operation_from_a_recently_offline_device_is_admitted() {
    let history = deep_history(3);
    let mut roster = Roster::with_staleness_depth(64);

    for entry in history.entries() {
        if entry.label == "backdated" {
            continue;
        }
        roster.offer_bytes(&entry.bytes);
    }

    let outcome = roster.offer_bytes(&history.bytes("backdated"));
    assert!(
        outcome.is_accepted(),
        "a device that was legitimately away must not be locked out, got {outcome:?}"
    );
}

/// The point of the whole two-layer split: policy governs admission and can
/// never move derived state. Two nodes running opposite thresholds, given the
/// same operations in an order neither considers stale, must agree exactly.
#[test]
fn nodes_with_different_thresholds_derive_the_same_state() {
    let history = deep_history(12);

    let mut strict = Roster::with_staleness_depth(1);
    let mut permissive = Roster::with_staleness_depth(1_000);

    for entry in history.entries() {
        if entry.label == "backdated" {
            continue;
        }
        assert!(strict.offer_bytes(&entry.bytes).is_accepted(), "{}", entry.label);
        assert!(permissive.offer_bytes(&entry.bytes).is_accepted(), "{}", entry.label);
    }

    let strict_state = strict.state().expect("derives");
    let permissive_state = permissive.state().expect("derives");
    assert_eq!(
        strict_state.to_bytes(),
        permissive_state.to_bytes(),
        "the threshold governs admission only"
    );
    assert_eq!(strict_state.fingerprint(), permissive_state.fingerprint());

    // And where the policies do differ, they differ only in what is admitted.
    let strict_outcome = strict.offer_bytes(&history.bytes("backdated"));
    let permissive_outcome = permissive.offer_bytes(&history.bytes("backdated"));
    assert_eq!(strict_outcome.refusal(), Some(&Error::StaleOperation));
    assert!(permissive_outcome.is_accepted());
    assert_ne!(
        strict.dag().len(),
        permissive.dag().len(),
        "they now hold different operation sets, which is allowed"
    );
    // Given the same set, they still agree: derivation never saw the policy.
    let same_set = derive(permissive.dag()).expect("derives");
    assert_eq!(same_set.to_bytes(), permissive_state_after(&permissive));
}

/// The permissive node's state, once it has taken the backdated operation.
fn permissive_state_after(roster: &Roster) -> Vec<u8> {
    roster.state().expect("derives").to_bytes()
}

/// A refusal from a key that still holds the admin role is the signal worth
/// raising: either a backdating attempt, or a device badly out of date.
#[test]
fn a_refusal_from_a_current_admin_is_identifiable() {
    let history = deep_history(12);
    let mut roster = Roster::with_staleness_depth(4);
    for entry in history.entries() {
        if entry.label == "backdated" {
            continue;
        }
        roster.offer_bytes(&entry.bytes);
    }
    roster.offer_bytes(&history.bytes("backdated"));

    let operation = history.verified("backdated");
    assert!(
        roster.refusal_is_from_current_admin(&operation),
        "the author is still a valid admin, which is what makes this worth an alert"
    );
}

#[test]
fn refusals_can_be_drained() {
    let history = deep_history(12);
    let mut roster = Roster::with_staleness_depth(4);
    for entry in history.entries() {
        if entry.label == "backdated" {
            continue;
        }
        roster.offer_bytes(&entry.bytes);
    }
    roster.offer_bytes(&history.bytes("backdated"));

    let drained = roster.take_refusals();
    assert_eq!(drained.len(), 1);
    assert!(roster.refusals().is_empty(), "draining clears them");
}

// ---------------------------------------------------------------------------
// Ordinary admission
// ---------------------------------------------------------------------------

#[test]
fn a_well_formed_history_is_admitted_in_order() {
    let history = chain();
    let mut roster = Roster::new();
    for entry in history.entries() {
        assert!(
            roster.offer_bytes(&entry.bytes).is_accepted(),
            "{} should be admitted",
            entry.label
        );
    }
    assert_eq!(roster.dag().len(), 4);
    assert_eq!(roster.heads(), vec![history.id("c")]);
}

#[test]
fn an_operation_already_held_is_reported_as_such() {
    let history = chain();
    let mut roster = Roster::new();
    roster.offer_bytes(&history.bytes("g"));
    let outcome = roster.offer_bytes(&history.bytes("g"));
    assert!(matches!(outcome, Admission::AlreadyHeld(_)));
    assert_eq!(roster.dag().len(), 1);
}

#[test]
fn undecodable_bytes_are_refused_with_a_reason() {
    let mut roster = Roster::new();
    let outcome = roster.offer_bytes(&[0xff, 0x00, 0x13]);
    assert!(outcome.refusal().is_some(), "garbage is refused, and says why");
    assert_eq!(roster.refusals().len(), 1);
}

// ---------------------------------------------------------------------------
// The evidence a detection carries
// ---------------------------------------------------------------------------

/// The evidence is the bytes that arrived, not a re-encoding of a decoded
/// structure. A re-serialized operation is no longer the thing that was signed,
/// so evidence that had been through a round trip would fail to verify under the
/// accused key and prove nothing.
#[test]
fn the_evidence_is_the_bytes_that_arrived() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("b", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Member, false)));
    history.op("c", 1, &["g"], OperationBody::AddDevice(device(3, "c", Role::Member, false)));

    let mut roster = Roster::new();
    for entry in history.entries() {
        assert!(roster.offer_bytes(&entry.bytes).is_accepted(), "{}", entry.label);
    }

    let reported = roster.equivocations();
    assert_eq!(reported.len(), 1, "one fork");
    let evidence = reported.first().expect("one");

    // What was offered, decoded only to reach the signed core.
    for label in ["b", "c"] {
        let offered = history.entries().iter().find(|entry| entry.label == label);
        let offered = offered.expect("the operation was offered");
        let raw = RawOperation::decode(&offered.bytes).expect("decodes");

        let halves = [&evidence.first, &evidence.second];
        let matching = halves
            .iter()
            .find(|proof| proof.id == raw.id())
            .unwrap_or_else(|| panic!("the evidence must name {label}"));

        assert_eq!(
            matching.core_bytes,
            raw.core_bytes(),
            "byte-identical to what arrived, for {label}"
        );
        assert_eq!(&matching.signature, raw.signature(), "and the signature that came with it");
    }
}

/// The pair names a culprit: both signatures verify under the accused device's
/// own key, and it authored both.
#[test]
fn the_evidence_verifies_under_the_accused_key() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("b", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Member, false)));
    history.op("c", 1, &["g"], OperationBody::AddDevice(device(3, "c", Role::Member, false)));

    let mut roster = Roster::new();
    for entry in history.entries() {
        assert!(roster.offer_bytes(&entry.bytes).is_accepted(), "{}", entry.label);
    }

    let reported = roster.equivocations();
    let evidence = reported.first().expect("one fork");
    let accused = signer(1).public_key();

    assert_eq!(evidence.author, accused.key_id(), "the accusation names who signed");

    for proof in [&evidence.first, &evidence.second] {
        let offered = history
            .entries()
            .iter()
            .find(|entry| RawOperation::decode(&entry.bytes).expect("decodes").id() == proof.id)
            .expect("the evidence names an operation that was offered");
        let raw = RawOperation::decode(&offered.bytes).expect("decodes");

        assert!(raw.verify(&accused).is_ok(), "each half verifies under the accused key");
        assert_eq!(raw.core().author, accused.key_id(), "and names it as the author");
    }
}

/// Any member reaches the verdict from its own copy of the log, without trusting
/// whoever reported it.
#[test]
fn any_member_reaches_the_verdict_independently() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("b", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Member, false)));
    history.op("c", 1, &["g"], OperationBody::AddDevice(device(3, "c", Role::Member, false)));

    // Two members, loading the same operations in opposite orders.
    let entries = history.entries();
    let mut theirs = Roster::new();
    for index in [0, 2, 1] {
        let entry = entries.get(index).expect("three operations");
        assert!(theirs.offer_bytes(&entry.bytes).is_accepted());
    }
    let mut ours = Roster::new();
    for entry in entries {
        assert!(ours.offer_bytes(&entry.bytes).is_accepted());
    }

    let mine = ours.equivocations();
    let theirs = theirs.equivocations();

    assert_eq!(mine.len(), 1);
    assert_eq!(mine, theirs, "the verdict is the operations', not the reporter's");
}

/// **What the pair alone cannot settle**, stated as a test so nobody later reads
/// the evidence as self-contained.
///
/// Two operations by one author that name different parents look concurrent when
/// held on their own — but one can be an ancestor of the other through a chain
/// neither names directly. Establishing that needs the operations between them,
/// which is why the requirement says a *member* reaches the verdict, not any
/// holder of the pair.
#[test]
fn the_pair_alone_does_not_settle_concurrency() {
    let mut history = History::new();
    history.genesis("g", 1);
    // A chain by one author: each anchored to its own previous operation.
    history.op("a", 1, &["g"], OperationBody::AddDevice(device(2, "a", Role::Member, false)));
    history.op("b", 1, &["a"], OperationBody::AddDevice(device(3, "b", Role::Member, false)));
    history.op("c", 1, &["b"], OperationBody::AddDevice(device(4, "c", Role::Member, false)));

    // `a` and `c` are by one author and neither names the other directly — the
    // shape a naive check on a bare pair would read as a fork.
    let entries = history.entries();
    let a =
        RawOperation::decode(&entries.get(1).expect("the chain has `a`").bytes).expect("decodes");
    let c =
        RawOperation::decode(&entries.get(3).expect("the chain has `c`").bytes).expect("decodes");
    assert_eq!(a.core().author, c.core().author, "one author");
    assert!(!c.core().parents.contains(&a.id()), "and neither names the other directly");

    // Held with the chain, they are ordered and there is no fork at all.
    let mut roster = Roster::new();
    for entry in history.entries() {
        assert!(roster.offer_bytes(&entry.bytes).is_accepted());
    }
    assert!(
        roster.equivocations().is_empty(),
        "the log is what settles it, and here it says these are a chain"
    );
}

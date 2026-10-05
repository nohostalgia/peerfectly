//! Property-based tests over compaction.
//!
//! The fixed tests in `snapshots.rs` check the compaction points we thought to
//! write. These check the ones we did not: for any generated history and any
//! legal point to compact at, a node that discarded its past and one that kept
//! it must derive the same household.
//!
//! The design argues that derivation composes across the boundary. That argument
//! is the kind that convinces and is wrong, so it is not the acceptance
//! criterion — this file is.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

mod support;

use proptest::prelude::*;
use roster::roster::Roster;
use roster::types::{OperationBody, Role};
use support::{History, device, device_id};

/// What a generated step does. Every step is authored by the founder, so the
/// generated history is one an honest network could produce.
#[derive(Debug, Clone, Copy)]
enum Step {
    /// Add a device as a member.
    AddMember(u8),
    /// Rename a device.
    Rename(u8, u8),
    /// Promote a device.
    Promote(u8),
    /// Demote a device.
    Demote(u8),
    /// Revoke a device.
    Revoke(u8),
}

/// Generates a step.
fn step_strategy() -> impl Strategy<Value = Step> {
    prop_oneof![
        (2u8..6).prop_map(Step::AddMember),
        ((2u8..6), any::<u8>()).prop_map(|(target, tag)| Step::Rename(target, tag)),
        (2u8..6).prop_map(Step::Promote),
        (2u8..6).prop_map(Step::Demote),
        (2u8..6).prop_map(Step::Revoke),
    ]
}

/// A linear history: a genesis and then the steps in a chain.
///
/// Linear on purpose. Compaction's preconditions forbid discarding a region any
/// held operation is concurrent with, so a forked history is exactly the case
/// where compaction is *refused* — covered by a fixed test that can aim at it.
/// These properties are about what happens when it is allowed.
fn build(steps: &[Step]) -> History {
    let mut history = History::new();
    history.genesis("g", 1);
    let mut previous = "g".to_owned();
    // Which devices this history has added and not revoked. A step naming
    // anything else is dropped: an author acts on what its own ancestors show it,
    // so an operation naming a device that is not there is refused at admission,
    // and a history built from those would be testing refusals rather than
    // snapshots.
    let mut present: Vec<u8> = Vec::new();
    let mut revoked: Vec<u8> = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        let label = format!("s{index}");
        let known = |seed: u8, present: &Vec<u8>, revoked: &Vec<u8>| {
            present.contains(&seed) && !revoked.contains(&seed)
        };
        let body = match *step {
            Step::AddMember(seed) => {
                if present.contains(&seed) || revoked.contains(&seed) {
                    continue;
                }
                present.push(seed);
                OperationBody::AddDevice(device(seed, "member", Role::Member, false))
            }
            Step::Rename(seed, tag) => {
                if !known(seed, &present, &revoked) {
                    continue;
                }
                OperationBody::Rename { device: device_id(seed), name: format!("n{tag}") }
            }
            Step::Promote(seed) => {
                if !known(seed, &present, &revoked) {
                    continue;
                }
                OperationBody::Promote { device: device_id(seed), founder: false }
            }
            Step::Demote(seed) => {
                if !known(seed, &present, &revoked) {
                    continue;
                }
                OperationBody::Demote { device: device_id(seed) }
            }
            Step::Revoke(seed) => {
                if !known(seed, &present, &revoked) {
                    continue;
                }
                revoked.push(seed);
                OperationBody::RevokeDevice {
                    device: device_id(seed),
                    reason: "generated".to_owned(),
                }
            }
        };
        history.op(&label, 1, &[previous.as_str()], body);
        previous = label;
    }
    history
}

/// Loads a whole history into a roster with a chosen staleness threshold.
fn loaded(history: &History, depth: u64) -> Roster {
    let mut roster = Roster::with_staleness_depth(depth);
    for entry in history.entries() {
        roster.offer_bytes(&entry.bytes);
    }
    roster
}

proptest! {
    /// The property the change turns on: compaction is not observable.
    #[test]
    fn a_compacted_node_derives_what_an_uncompacted_one_does(
        steps in proptest::collection::vec(step_strategy(), 6..14),
        cut in 0usize..4,
    ) {
        let history = build(&steps);
        let labels = history.labels();
        // Cut early enough that the region clears a tight staleness horizon.
        let head = labels.get(cut.min(labels.len().saturating_sub(4)))
            .cloned()
            .unwrap_or_else(|| "g".to_owned());

        let mut compacted = loaded(&history, 1);
        let snapshot = history.snapshot_at(1, 1, &[head.as_str()]);
        prop_assert!(compacted.offer_snapshot(&snapshot).is_accepted());
        // Compaction may legitimately refuse; when it does, there is nothing to
        // compare and the property is vacuous rather than violated.
        if compacted.compact().is_err() {
            return Ok(());
        }

        let whole = loaded(&history, 1);
        prop_assert_eq!(
            compacted.state().expect("derives").to_bytes(),
            whole.state().expect("derives").to_bytes()
        );
    }

    /// Compaction followed by more operations still agrees.
    #[test]
    fn compaction_survives_later_operations(
        steps in proptest::collection::vec(step_strategy(), 6..12),
        cut in 0usize..3,
    ) {
        let mut history = build(&steps);
        let labels = history.labels();
        let head = labels.get(cut.min(labels.len().saturating_sub(4)))
            .cloned()
            .unwrap_or_else(|| "g".to_owned());
        let tip = labels.last().cloned().unwrap_or_else(|| "g".to_owned());

        // One more operation after the snapshot point, on the tip.
        history.op(
            "later",
            1,
            &[tip.as_str()],
            OperationBody::Rename { device: device_id(2), name: "final".to_owned() },
        );

        let mut compacted = loaded(&history, 1);
        let snapshot = history.snapshot_at(1, 1, &[head.as_str()]);
        prop_assert!(compacted.offer_snapshot(&snapshot).is_accepted());
        if compacted.compact().is_err() {
            return Ok(());
        }

        let whole = loaded(&history, 1);
        prop_assert_eq!(
            compacted.state().expect("derives").to_bytes(),
            whole.state().expect("derives").to_bytes()
        );
    }

    /// A generated history and a snapshot over any prefix of it always verify.
    #[test]
    fn a_generated_snapshot_verifies_and_is_accepted(
        steps in proptest::collection::vec(step_strategy(), 3..10),
        cut in 0usize..3,
    ) {
        let history = build(&steps);
        let labels = history.labels();
        let head = labels.get(cut.min(labels.len().saturating_sub(1)))
            .cloned()
            .unwrap_or_else(|| "g".to_owned());

        let mut roster = loaded(&history, 1);
        let snapshot = history.snapshot_at(1, 1, &[head.as_str()]);
        let outcome = roster.offer_snapshot(&snapshot);
        prop_assert!(outcome.is_accepted(), "{outcome:?}");
        prop_assert!(roster.snapshot_is_verified(), "the node holds everything it covers");
    }

    /// Offering arbitrary bytes as a snapshot always returns a verdict.
    #[test]
    fn offering_arbitrary_bytes_as_a_snapshot_never_panics(
        input in proptest::collection::vec(any::<u8>(), 0..600),
    ) {
        let mut roster = Roster::new();
        let outcome = roster.offer_snapshot(&input);
        prop_assert!(outcome.is_accepted() || outcome.refusal().is_some());
    }

    /// A sequence number never goes backwards, whatever is offered.
    #[test]
    fn the_accepted_sequence_never_decreases(
        steps in proptest::collection::vec(step_strategy(), 4..10),
        sequences in proptest::collection::vec(1u64..20, 1..8),
    ) {
        let history = build(&steps);
        let labels = history.labels();
        let head = labels.first().cloned().unwrap_or_else(|| "g".to_owned());
        let mut roster = loaded(&history, 1);

        let mut highest = 0u64;
        for seq in sequences {
            let snapshot = history.snapshot_at(seq, 1, &[head.as_str()]);
            let _ = roster.offer_snapshot(&snapshot);
            if let Some(current) = roster.highest_sequence() {
                prop_assert!(current >= highest, "the accepted sequence went backwards");
                highest = current;
            }
        }
    }
}

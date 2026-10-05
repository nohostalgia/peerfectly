//! The room the ceiling keeps for revocations.
//!
//! A roster holds at most `MAX_OPERATIONS`, and compaction does not give that
//! back. The security review's finding F-02 turns on what happens at the
//! ceiling: with it reached, the founder's own revocation is refused, so the
//! device that filled the roster can never be expelled and the network is
//! finished. Refusing operations without authority is most of the answer; this
//! is the rest of it, for a network that fills up honestly.
//!
//! These tests build rosters of thousands of operations, so they use the graph
//! directly rather than signing each one: what is under test is the ceiling, not
//! admission, and signing four thousand operations takes far longer than the
//! rule being checked.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod support;

use roster::dag::Dag;
use roster::limits;
use roster::types::{OperationBody, Role};
use support::{History, device, device_id};

/// A graph holding `count` operations that are not revocations, and the history
/// that produced it, so a caller can keep adding to both.
fn filled_with_non_revocations(count: usize) -> (Dag, History) {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Member, false)));

    let mut parent = "add2".to_owned();
    // Two are already held: the genesis and the add.
    for step in 0..count.saturating_sub(2) {
        let label = format!("s{step}");
        history.op(
            &label,
            1,
            &[parent.as_str()],
            OperationBody::Rename { device: device_id(2), name: format!("n{step}") },
        );
        parent = label;
    }

    let operations: Vec<_> =
        history.entries().iter().map(|entry| history.verified(&entry.label)).collect();
    let dag = Dag::from_operations(operations).expect("the set places");
    assert_eq!(dag.len(), count);
    (dag, history)
}

/// The share for everything that is not a revocation is full, and a revocation
/// still finds room — which is the whole point of reserving it.
#[test]
fn a_revocation_is_admitted_when_the_rest_of_the_ceiling_is_full() {
    let (mut dag, mut history) = filled_with_non_revocations(limits::MAX_NON_REVOCATION_OPERATIONS);

    let parent = format!("s{}", limits::MAX_NON_REVOCATION_OPERATIONS - 3);
    history.op(
        "revoke",
        1,
        &[parent.as_str()],
        OperationBody::RevokeDevice { device: device_id(2), reason: "flooding".to_owned() },
    );

    dag.insert(history.verified("revoke")).expect("a revocation still fits");
    assert_eq!(dag.len(), limits::MAX_NON_REVOCATION_OPERATIONS.saturating_add(1));
}

/// And anything else is refused there, with the limit it reached, while the room
/// kept for revocations stays free.
#[test]
fn another_operation_is_refused_when_its_share_is_full() {
    let (mut dag, mut history) = filled_with_non_revocations(limits::MAX_NON_REVOCATION_OPERATIONS);

    let parent = format!("s{}", limits::MAX_NON_REVOCATION_OPERATIONS - 3);
    history.op(
        "another",
        1,
        &[parent.as_str()],
        OperationBody::AddDevice(device(9, "late", Role::Member, false)),
    );

    let refusal = dag.insert(history.verified("another")).expect_err("the share is full");
    assert_eq!(refusal.kind(), "limit_exceeded");
    assert!(
        format!("{refusal}").contains("reserve"),
        "the refusal says which bound was reached: {refusal}"
    );

    // The room it did not take is still there for a revocation.
    history.op(
        "revoke",
        1,
        &[parent.as_str()],
        OperationBody::RevokeDevice { device: device_id(2), reason: "flooding".to_owned() },
    );
    dag.insert(history.verified("revoke")).expect("the reserve is untouched");
}

/// The hard ceiling is unchanged, so the memory a roster can require is
/// unchanged: with it reached, everything is refused, revocations included.
#[test]
fn the_hard_ceiling_still_refuses_everything() {
    let (mut dag, mut history) = filled_with_non_revocations(limits::MAX_NON_REVOCATION_OPERATIONS);

    // Fill the reserve with revocations of devices that were really added, which
    // is what the reserve is for and the only thing that can fill it.
    let mut parent = format!("s{}", limits::MAX_NON_REVOCATION_OPERATIONS - 3);
    let reserve = limits::MAX_OPERATIONS.saturating_sub(limits::MAX_NON_REVOCATION_OPERATIONS);
    for step in 0..reserve {
        let label = format!("r{step}");
        history.op(
            &label,
            1,
            &[parent.as_str()],
            OperationBody::RevokeDevice { device: device_id(2), reason: format!("again {step}") },
        );
        dag.insert(history.verified(&label)).expect("inside the reserve");
        parent = label;
    }
    assert_eq!(dag.len(), limits::MAX_OPERATIONS);

    history.op(
        "over",
        1,
        &[parent.as_str()],
        OperationBody::RevokeDevice { device: device_id(2), reason: "one too many".to_owned() },
    );
    let refusal = dag.insert(history.verified("over")).expect_err("the ceiling is the ceiling");
    assert_eq!(refusal.kind(), "limit_exceeded");
    assert_eq!(dag.len(), limits::MAX_OPERATIONS, "and nothing was added");
}

//! IPv4 holdings read only what a snapshot keeps.
//!
//! Admission order is gone once a roster is compacted, so a rule that read it
//! would give a node fed a snapshot different addresses from a node fed the
//! whole history. This builds both nodes from one history, with collisions and
//! revocations on both sides of the snapshot, and compares.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

#[path = "../../roster/tests/support/mod.rs"]
mod support;

use roster::roster::Roster;
use roster::types::{OperationBody, Role};
use support::{History, device, device_id, params};
use tunnel::Ipv4Holdings;

/// A network in a range of fourteen assignable addresses, with more devices
/// than that, so collisions are certain; revocations before and after the
/// point a snapshot covers.
fn crowded() -> History {
    let mut history = History::new();
    history.genesis_with(
        "g",
        1,
        device(1, "phone", Role::Admin, true),
        params().in_ipv4_range("10.0.0.0/28".parse().expect("allowed")),
    );
    let mut previous = "g".to_owned();
    for seed in 2..=20u8 {
        let label = format!("add{seed}");
        history.op(
            &label,
            1,
            &[previous.as_str()],
            OperationBody::AddDevice(device(seed, &format!("d{seed}"), Role::Member, false)),
        );
        previous = label;
    }
    history.op(
        "rev3",
        1,
        &[previous.as_str()],
        OperationBody::RevokeDevice { device: device_id(3), reason: "sold".into() },
    );
    previous = "rev3".to_owned();
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
    history.op(
        "rev4",
        1,
        &[previous.as_str()],
        OperationBody::RevokeDevice { device: device_id(4), reason: "lost".into() },
    );
    history
}

fn loaded(history: &History) -> Roster {
    let mut roster = Roster::with_staleness_depth(2);
    for entry in history.entries() {
        let outcome = roster.offer_bytes(&entry.bytes);
        assert!(outcome.is_accepted(), "{} should be admitted: {outcome:?}", entry.label);
    }
    roster
}

#[test]
fn history_and_snapshot_give_identical_holdings() {
    let history = crowded();

    let whole = loaded(&history);
    let mut compacted = loaded(&history);
    assert!(compacted.offer_snapshot(&history.snapshot_at(1, 1, &["n2"])).is_accepted());
    let discarded = compacted.compact().expect("compacts");
    assert!(discarded > 0, "the fixture actually compacts");
    assert!(!compacted.dag().contains(&history.id("add2")), "admission order is gone");

    let from_history = Ipv4Holdings::of_state(&whole.state().expect("derives"));
    let from_snapshot = Ipv4Holdings::of_state(&compacted.state().expect("derives"));

    assert_eq!(from_history, from_snapshot);
    assert!(from_history.colliding().next().is_some(), "the fixture exercises collisions");
    assert!(from_history.held().next().is_some(), "and holdings");
    assert_eq!(from_history.of(&device_id(3)), None, "a revoked device holds nothing");
}

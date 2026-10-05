//! What no sequence of operations from a device without authority can do.
//!
//! The fixed tests in `authority.rs` aim at the shapes we thought of. These check
//! the two properties the change turns on, over sequences nobody chose: that a
//! member cannot make a node hold anything, and that what a node derives does not
//! depend on the order it was offered things — which is what a refusal must never
//! be allowed to break.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

mod support;

use proptest::prelude::*;
use roster::roster::Roster;
use roster::types::{OperationBody, Role};
use support::{History, device, device_id};

/// What a device without authority might try.
#[derive(Debug, Clone, Copy)]
enum Attempt {
    /// Admit a device of its own.
    AddDevice(u8),
    /// Promote itself.
    PromoteSelf,
    /// Demote the founder.
    DemoteFounder,
    /// Revoke the founder.
    RevokeFounder,
    /// Rename the founder.
    RenameFounder(u8),
    /// Rewrite the network's parameters.
    SetNetwork(u8),
}

fn attempt_strategy() -> impl Strategy<Value = Attempt> {
    prop_oneof![
        (3u8..9).prop_map(Attempt::AddDevice),
        Just(Attempt::PromoteSelf),
        Just(Attempt::DemoteFounder),
        Just(Attempt::RevokeFounder),
        any::<u8>().prop_map(Attempt::RenameFounder),
        any::<u8>().prop_map(Attempt::SetNetwork),
    ]
}

fn body(attempt: Attempt) -> OperationBody {
    match attempt {
        Attempt::AddDevice(seed) => {
            OperationBody::AddDevice(device(seed, "smuggled", Role::Member, false))
        }
        Attempt::PromoteSelf => OperationBody::Promote { device: device_id(2), founder: true },
        Attempt::DemoteFounder => OperationBody::Demote { device: device_id(1) },
        Attempt::RevokeFounder => {
            OperationBody::RevokeDevice { device: device_id(1), reason: "mine now".to_owned() }
        }
        Attempt::RenameFounder(tag) => {
            OperationBody::Rename { device: device_id(1), name: format!("n{tag}") }
        }
        Attempt::SetNetwork(tag) => OperationBody::SetNetwork(
            roster::types::NetworkParams::new(
                vec![0xfd, tag, 0, 0, 0, 0, 0, 0],
                "attacker.internal",
                2_592_000,
            )
            .expect("valid"),
        ),
    }
}

proptest! {
    /// No sequence of operations signed by a member changes how many operations
    /// a node holds, whatever they say and wherever they are anchored.
    ///
    /// This is F-02 as a property: the attack was not that the operations had
    /// effect — they never did — but that they occupied places in a bounded
    /// graph that revocations would need.
    #[test]
    fn no_sequence_from_a_member_changes_what_a_node_holds(
        attempts in proptest::collection::vec(attempt_strategy(), 1..12),
        anchor_at_head in proptest::collection::vec(any::<bool>(), 1..12),
    ) {
        let mut history = History::new();
        history.genesis("g", 1);
        history.op(
            "addB",
            1,
            &["g"],
            OperationBody::AddDevice(device(2, "b", Role::Member, false)),
        );

        let mut roster = Roster::new();
        for entry in history.entries() {
            prop_assert!(roster.offer_bytes(&entry.bytes).is_accepted(), "{}", entry.label);
        }
        let held = roster.dag().len();
        let before = roster.state().expect("derives").to_bytes();

        for (index, attempt) in attempts.iter().enumerate() {
            // Anchored either on the head or right back at the genesis, which is
            // the shape that used to walk past every check.
            let at_head = anchor_at_head.get(index).copied().unwrap_or(true);
            let parent = if at_head { "addB" } else { "g" };
            let label = format!("a{index}");
            history.op(&label, 2, &[parent], body(*attempt));
            roster.offer_bytes(&history.bytes(&label));
        }

        prop_assert_eq!(roster.dag().len(), held, "the graph did not grow");
        prop_assert_eq!(
            roster.state().expect("derives").to_bytes(),
            before,
            "and nothing it says changed"
        );
    }

    /// A node offered operations one at a time derives what a node given the
    /// same operations in another order derives.
    ///
    /// Refusing at admission is what puts this at risk: a refusal that depended
    /// on what a node happened to hold would leave the two with different
    /// graphs, and a refused operation's children can never be placed.
    #[test]
    fn arrival_order_does_not_change_what_is_derived(
        attempts in proptest::collection::vec(attempt_strategy(), 1..8),
    ) {
        let mut history = History::new();
        history.genesis("g", 1);
        history.op("addB", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Admin, false)));
        history.op("addC", 1, &["addB"], OperationBody::AddDevice(device(7, "c", Role::Member, false)));

        // A mixture: some authored by an admin, some by the member, anchored in
        // two places so the graph forks.
        for (index, attempt) in attempts.iter().enumerate() {
            let label = format!("a{index}");
            let parent = if index % 2 == 0 { "addC" } else { "addB" };
            let author = if index % 3 == 0 { 7 } else { 2 };
            history.op(&label, author, &[parent], body(*attempt));
        }

        let entries = history.entries();
        let forward: Vec<usize> = (0..entries.len()).collect();
        let backward: Vec<usize> = (0..entries.len()).rev().collect();

        let derive_in = |order: &[usize]| {
            let mut roster = Roster::new();
            for position in order {
                if let Some(entry) = entries.get(*position) {
                    roster.offer_bytes(&entry.bytes);
                }
            }
            roster.state().ok().map(|state| state.to_bytes())
        };

        prop_assert_eq!(
            derive_in(&forward),
            derive_in(&backward),
            "two nodes given the same operations in opposite orders disagree"
        );
    }
}

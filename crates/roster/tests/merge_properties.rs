//! Property-based tests over merging.
//!
//! The fixed tests in `graph.rs` check the cases we thought of. These check the
//! one property the whole change exists to guarantee: that the roster a node
//! derives depends on *which* operations it holds and never on *how* it came to
//! hold them.
//!
//! Histories are generated rather than written, because the interesting shapes
//! — a branch off a branch, a merge of two merges — are exactly the ones nobody
//! thinks to write by hand.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

mod support;

use proptest::prelude::*;
use roster::dag::Dag;
use roster::roster::Roster;
use roster::state::derive;
use roster::types::{OperationBody, Role};
use support::{History, device, device_id, params_with};

/// What a generated step does.
#[derive(Debug, Clone, Copy)]
enum Step {
    /// Add a new device as a member.
    AddMember(u8),
    /// Add a new device as an admin, so later steps can author from it.
    AddAdmin(u8),
    /// Rename an existing device.
    Rename(u8, u8),
    /// Promote a device.
    Promote(u8),
    /// Demote a device.
    Demote(u8),
    /// Revoke a device.
    Revoke(u8),
    /// Change the network parameters.
    SetNetwork(u8),
}

/// Generates a step.
fn step_strategy() -> impl Strategy<Value = Step> {
    prop_oneof![
        (2u8..8).prop_map(Step::AddMember),
        (2u8..8).prop_map(Step::AddAdmin),
        ((2u8..8), any::<u8>()).prop_map(|(target, tag)| Step::Rename(target, tag)),
        (2u8..8).prop_map(Step::Promote),
        (2u8..8).prop_map(Step::Demote),
        (2u8..8).prop_map(Step::Revoke),
        any::<u8>().prop_map(Step::SetNetwork),
    ]
}

/// What one branch of a generated history knows about.
///
/// An honest author acts on what it can see, which is exactly the state its own
/// parents imply — so a step naming a device that branch has not added, or has
/// already revoked, is not a history any node would produce. Since such an
/// operation is refused at admission, and a refused operation's children can
/// never be placed, generating one would test the pending set rather than
/// merging.
#[derive(Clone, Default)]
struct Known {
    /// Device seeds this branch has added and not revoked.
    present: Vec<u8>,
    /// Device seeds this branch has revoked.
    revoked: Vec<u8>,
}

impl Known {
    /// Whether a step naming this device is one this branch could author.
    fn can_act_on(&self, seed: u8) -> bool {
        self.present.contains(&seed) && !self.revoked.contains(&seed)
    }
}

/// A generated history: a genesis, then steps applied in a chain.
///
/// Every step is authored by the founder, which is always an admin, and every
/// step names a device the branch it sits on already has — so the generated
/// history is one an honest network could produce. A step that names anything
/// else is dropped rather than emitted. Adversarial shapes are covered by the
/// fixed tests, which can aim precisely.
fn build_history(steps: &[Step], branch_at: Option<usize>) -> History {
    let mut history = History::new();
    history.genesis("g", 1);

    let mut previous = "g".to_owned();
    let mut branch_point: Option<String> = None;
    let mut branch_previous: Option<String> = None;
    let mut known_main = Known::default();
    let mut known_branch: Option<Known> = None;
    // What the trunk knew where the branch forks, captured there rather than at
    // the branch's first step: the trunk keeps going meanwhile, and what it adds
    // after the fork is no ancestor of the branch.
    let mut known_at_fork: Option<Known> = None;

    for (index, step) in steps.iter().enumerate() {
        // Once past the branch point, alternate between the two branches so the
        // history genuinely diverges rather than staying a chain.
        let on_branch = branch_at.is_some_and(|at| index > at && index.wrapping_rem(2) == 1);
        // A branch starts knowing what the trunk knew where it forked, and the
        // two diverge from there, exactly as the operations do.
        if on_branch && known_branch.is_none() {
            known_branch = Some(known_at_fork.clone().unwrap_or_else(|| known_main.clone()));
            // **The fork is where the knowledge was taken.** When the step at
            // `branch_at` is dropped, no fork point was recorded, and the branch
            // used to attach to whatever the trunk's head was by the time it
            // first emitted — a head that may already have revoked a device the
            // branch still believed present. Its next step then named a device
            // its own ancestors had revoked, which the roster rightly refuses
            // (`unknown_target`), and this test failed on its own history.
            if branch_point.is_none() {
                branch_point = Some(previous.clone());
            }
        }
        let parent = if on_branch {
            branch_previous.clone().or_else(|| branch_point.clone()).unwrap_or(previous.clone())
        } else {
            previous.clone()
        };
        let known = if on_branch {
            known_branch.get_or_insert_with(Known::default)
        } else {
            &mut known_main
        };

        let label = format!("s{index}");
        let body = match *step {
            Step::AddMember(seed) => {
                if known.present.contains(&seed) || known.revoked.contains(&seed) {
                    continue;
                }
                known.present.push(seed);
                OperationBody::AddDevice(device(seed, "member", Role::Member, false))
            }
            Step::AddAdmin(seed) => {
                if known.present.contains(&seed) || known.revoked.contains(&seed) {
                    continue;
                }
                known.present.push(seed);
                OperationBody::AddDevice(device(seed, "admin", Role::Admin, false))
            }
            Step::Rename(seed, tag) => {
                if !known.can_act_on(seed) {
                    continue;
                }
                OperationBody::Rename { device: device_id(seed), name: format!("n{tag}") }
            }
            Step::Promote(seed) => {
                if !known.can_act_on(seed) {
                    continue;
                }
                OperationBody::Promote { device: device_id(seed), founder: false }
            }
            Step::Demote(seed) => {
                if !known.can_act_on(seed) {
                    continue;
                }
                OperationBody::Demote { device: device_id(seed) }
            }
            Step::Revoke(seed) => {
                if !known.can_act_on(seed) {
                    continue;
                }
                known.revoked.push(seed);
                OperationBody::RevokeDevice {
                    device: device_id(seed),
                    reason: "generated".to_owned(),
                }
            }
            Step::SetNetwork(tag) => {
                OperationBody::SetNetwork(params_with(&format!("n{tag}.internal")))
            }
        };

        history.op(&label, 1, &[parent.as_str()], body);

        if on_branch {
            branch_previous = Some(label);
        } else {
            previous = label.clone();
            if branch_at == Some(index) {
                branch_point = Some(label);
                known_at_fork = Some(known_main.clone());
            }
        }
    }
    history
}

/// Every ordering of a history that a DAG will accept.
///
/// A DAG only takes an operation once its parents are present, so an arbitrary
/// permutation is not directly loadable. Feeding it through a [`Roster`], whose
/// pending set holds what it cannot yet place, makes any order legal — which is
/// exactly the situation a node faces during a sync.
fn dag_from_any_order(history: &History, order: &[usize]) -> Dag {
    let mut roster = Roster::with_staleness_depth(u64::MAX);
    let entries = history.entries();
    for position in order {
        if let Some(entry) = entries.get(*position) {
            roster.offer_bytes(&entry.bytes);
        }
    }
    assert_eq!(
        roster.pending_count(),
        0,
        "every operation should have been placed; refused: {:?}",
        roster.refusals().iter().map(|(_, reason)| reason.kind()).collect::<Vec<_>>()
    );
    roster.dag().clone()
}

proptest! {
    /// The central property of the change: two nodes given divergent branches in
    /// opposite orders derive the same household.
    #[test]
    fn merging_branches_in_either_order_gives_one_state(
        steps in proptest::collection::vec(step_strategy(), 1..12),
        branch_at in 0usize..6,
    ) {
        let history = build_history(&steps, Some(branch_at.min(steps.len().saturating_sub(1))));
        let count = history.entries().len();

        let forward: Vec<usize> = (0..count).collect();
        let backward: Vec<usize> = (0..count).rev().collect();

        let one = derive(&dag_from_any_order(&history, &forward)).expect("derives");
        let other = derive(&dag_from_any_order(&history, &backward)).expect("derives");

        prop_assert_eq!(one.to_bytes(), other.to_bytes());
        prop_assert_eq!(one.fingerprint(), other.fingerprint());
    }

    /// Stronger than two-branch merging: any permutation at all.
    #[test]
    fn derivation_is_invariant_under_permutation(
        steps in proptest::collection::vec(step_strategy(), 1..10),
        branch_at in 0usize..5,
        seed in any::<u64>(),
    ) {
        let history = build_history(&steps, Some(branch_at.min(steps.len().saturating_sub(1))));
        let count = history.entries().len();

        let ordered: Vec<usize> = (0..count).collect();
        let baseline = derive(&dag_from_any_order(&history, &ordered)).expect("derives");

        // A deterministic shuffle driven by the generated seed.
        let mut shuffled = ordered.clone();
        let mut state = seed | 1;
        for index in (1..shuffled.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let span = u64::try_from(index).unwrap_or(0).saturating_add(1);
            let pick = usize::try_from(state.checked_rem(span).unwrap_or(0)).unwrap_or(0);
            shuffled.swap(index, pick);
        }

        let permuted = derive(&dag_from_any_order(&history, &shuffled)).expect("derives");
        prop_assert_eq!(baseline.to_bytes(), permuted.to_bytes());
    }

    /// Revocation is definitive, whatever order the operations arrive in.
    #[test]
    fn a_revoked_device_never_appears_in_derived_state(
        steps in proptest::collection::vec(step_strategy(), 1..12),
        branch_at in 0usize..6,
    ) {
        let history = build_history(&steps, Some(branch_at.min(steps.len().saturating_sub(1))));
        let count = history.entries().len();
        let order: Vec<usize> = (0..count).collect();
        let dag = dag_from_any_order(&history, &order);
        let state = derive(&dag).expect("derives");

        for device in &state.revoked {
            prop_assert!(
                !state.devices.contains_key(device),
                "a revoked device must not also be present"
            );
        }
    }

    /// Offering arbitrary bytes to a roster always terminates with a verdict.
    #[test]
    fn offering_arbitrary_bytes_always_returns_a_verdict(
        input in proptest::collection::vec(any::<u8>(), 0..600),
    ) {
        let mut roster = Roster::new();
        let outcome = roster.offer_bytes(&input);
        // Every arm is a verdict; the point is that none of them is a panic and
        // none of them is silence.
        prop_assert!(
            outcome.is_accepted() || outcome.is_pending() || outcome.refusal().is_some()
        );
    }

    /// A history offered in a scrambled order through a roster ends up holding
    /// exactly the operations it was given, with nothing stuck pending.
    #[test]
    fn scrambled_delivery_still_places_every_operation(
        steps in proptest::collection::vec(step_strategy(), 1..10),
        seed in any::<u64>(),
    ) {
        let history = build_history(&steps, None);
        let count = history.entries().len();

        let mut order: Vec<usize> = (0..count).collect();
        let mut rng = seed | 1;
        for index in (1..order.len()).rev() {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let span = u64::try_from(index).unwrap_or(0).saturating_add(1);
            let pick = usize::try_from(rng.checked_rem(span).unwrap_or(0)).unwrap_or(0);
            order.swap(index, pick);
        }

        let dag = dag_from_any_order(&history, &order);
        prop_assert_eq!(dag.len(), count);
    }

    /// Depth is a property of the operation set, never of delivery order.
    #[test]
    fn depth_is_invariant_under_delivery_order(
        steps in proptest::collection::vec(step_strategy(), 1..10),
        branch_at in 0usize..5,
    ) {
        let history = build_history(&steps, Some(branch_at.min(steps.len().saturating_sub(1))));
        let count = history.entries().len();

        let forward: Vec<usize> = (0..count).collect();
        let backward: Vec<usize> = (0..count).rev().collect();
        let a = dag_from_any_order(&history, &forward);
        let b = dag_from_any_order(&history, &backward);

        for entry in history.entries() {
            let depth_a = a.position(&entry.id).map(|index| a.depth(index));
            let depth_b = b.position(&entry.id).map(|index| b.depth(index));
            prop_assert_eq!(depth_a, depth_b, "depth of {}", entry.label);
        }
    }
}

/// A generated history always derives without error.
#[test]
fn generated_histories_derive() {
    let steps = [
        Step::AddAdmin(2),
        Step::AddMember(3),
        Step::Rename(3, 7),
        Step::Promote(3),
        Step::Demote(3),
        Step::Revoke(3),
        Step::SetNetwork(4),
    ];
    let history = build_history(&steps, Some(2));
    let order: Vec<usize> = (0..history.entries().len()).collect();
    let dag = dag_from_any_order(&history, &order);
    let state = derive(&dag).expect("a generated history derives");
    assert!(state.revoked.contains(&device_id(3)));
}

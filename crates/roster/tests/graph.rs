//! The graph and the derivation it implies.
//!
//! The negative cases here are all ways two nodes could end up seeing different
//! households from the same operations.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

mod support;

use roster::Error;
use roster::dag::Dag;
use roster::id::{NetworkId, OperationId};
use roster::roster::Roster;
use roster::state::{Invalidity, derive, derive_with_verdicts};
use roster::types::{OperationBody, Role};
use support::{History, device, device_id, params, params_with, signer};

use roster::sign::Signer;

// ---------------------------------------------------------------------------
// Genesis and network identity
// ---------------------------------------------------------------------------

#[test]
fn the_network_id_is_the_founding_operations_own_id() {
    let mut history = History::new();
    let genesis = history.genesis("g", 1);
    let dag = history.dag();

    assert_eq!(dag.network(), Some(NetworkId::from_bytes(*genesis.as_bytes())));
    let state = derive(&dag).expect("derives");
    assert_eq!(state.network, NetworkId::from_bytes(*genesis.as_bytes()));
}

/// The founding operation cannot name its own network id, because that field is
/// inside the bytes the id is computed over.
#[test]
fn a_founding_operation_naming_a_non_zero_network_is_rejected() {
    let mut history = History::new();
    history.genesis("g", 1);
    // Build a second founding operation that names a non-zero network.
    let mut other = History::new();
    other.genesis("g", 2);
    let bogus_network = other.network();

    let mut third = History::new();
    third.genesis("real", 3);
    let id = third.op_in(
        "fake_genesis",
        3,
        &[],
        OperationBody::CreateNetwork { device: device(3, "phone", Role::Admin), params: params() },
        bogus_network,
    );
    let _ = id;

    let mut dag = Dag::new();
    assert_eq!(dag.insert(third.verified("fake_genesis")), Err(Error::ForeignNetwork));
}

#[test]
fn a_second_create_network_is_rejected() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op(
        "second",
        1,
        &["g"],
        OperationBody::CreateNetwork { device: device(2, "other", Role::Admin), params: params() },
    );

    let mut dag = Dag::new();
    dag.insert(history.verified("g")).expect("genesis inserts");
    assert_eq!(dag.insert(history.verified("second")), Err(Error::DuplicateGenesis));
    // The first network stands.
    assert_eq!(dag.network(), Some(NetworkId::from_bytes(*history.id("g").as_bytes())));
}

#[test]
fn an_operation_from_another_network_is_rejected() {
    let mut history = History::new();
    history.genesis("g", 1);
    let foreign = NetworkId::from_bytes([0x99; 32]);
    history.op_in(
        "foreign",
        1,
        &["g"],
        OperationBody::AddDevice(device(2, "laptop", Role::Member)),
        foreign,
    );

    let mut dag = Dag::new();
    dag.insert(history.verified("g")).expect("genesis inserts");
    assert_eq!(dag.insert(history.verified("foreign")), Err(Error::ForeignNetwork));
}

#[test]
fn a_parentless_non_genesis_operation_is_rejected() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op_in(
        "orphan",
        1,
        &[],
        OperationBody::AddDevice(device(2, "laptop", Role::Member)),
        NetworkId::from_bytes([0; 32]),
    );

    let mut dag = Dag::new();
    dag.insert(history.verified("g")).expect("genesis inserts");
    assert_eq!(dag.insert(history.verified("orphan")), Err(Error::ParentlessOperation));
}

#[test]
fn a_genesis_whose_author_is_not_its_declared_admin_is_rejected() {
    let mut history = History::new();
    // Device 1's keys, but authored by signer 2.
    history.genesis_with("g", 2, device(1, "phone", Role::Admin), params());
    let dag = history.dag();
    assert!(matches!(derive(&dag), Err(Error::MissingGenesis)));
}

#[test]
fn a_genesis_declaring_a_member_is_rejected() {
    let mut history = History::new();
    history.genesis_with("g", 1, device(1, "phone", Role::Member), params());
    let dag = history.dag();
    assert!(matches!(derive(&dag), Err(Error::MissingGenesis)));
}

// ---------------------------------------------------------------------------
// Ancestry, depth, heads
// ---------------------------------------------------------------------------

/// Builds a genesis plus a fork: `b` and `c` both hang off `g`, `d` merges them.
fn forked_history() -> History {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("b", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member)));
    history.op("c", 1, &["g"], OperationBody::AddDevice(device(3, "nas", Role::Member)));
    history.op(
        "d",
        1,
        &["b", "c"],
        OperationBody::Rename { device: device_id(2), name: "work".into() },
    );
    history
}

#[test]
fn ancestry_is_transitive() {
    let mut history = History::new();
    history.genesis("a", 1);
    history.op("b", 1, &["a"], OperationBody::AddDevice(device(2, "laptop", Role::Member)));
    history.op("c", 1, &["b"], OperationBody::AddDevice(device(3, "nas", Role::Member)));
    let dag = history.dag();

    let (a, b, c) =
        (index(&dag, &history, "a"), index(&dag, &history, "b"), index(&dag, &history, "c"));
    assert!(dag.is_ancestor(a, c), "A precedes C through B");
    assert!(dag.is_ancestor(a, b));
    assert!(dag.is_ancestor(b, c));
    assert!(!dag.is_ancestor(c, a), "and the relation is not symmetric");
}

#[test]
fn divergent_branches_are_concurrent_and_both_are_heads() {
    let history = forked_history();
    let dag = history.dag_of(&["g", "b", "c"]);
    let (b, c) = (index(&dag, &history, "b"), index(&dag, &history, "c"));

    assert!(dag.concurrent(b, c));
    assert!(!dag.is_ancestor(b, c));
    assert!(!dag.is_ancestor(c, b));

    let mut heads = dag.heads();
    heads.sort_unstable();
    let mut expected = vec![history.id("b"), history.id("c")];
    expected.sort_unstable();
    assert_eq!(heads, expected);
}

#[test]
fn a_merge_has_both_branches_as_ancestors_and_is_the_only_head() {
    let history = forked_history();
    let dag = history.dag();
    let d = index(&dag, &history, "d");

    for label in ["g", "b", "c"] {
        assert!(dag.is_ancestor(index(&dag, &history, label), d), "{label} precedes the merge");
    }
    assert_eq!(dag.heads(), vec![history.id("d")]);
}

#[test]
fn an_operation_is_never_concurrent_with_itself() {
    let history = forked_history();
    let dag = history.dag();
    let b = index(&dag, &history, "b");
    assert!(!dag.concurrent(b, b));
}

#[test]
fn parents_always_precede_their_children_in_storage() {
    let history = forked_history();
    // Insert in an order that is legal but not creation order.
    let dag = history.dag_of(&["g", "c", "b", "d"]);
    for (index, operation) in dag.operations().iter().enumerate() {
        for parent in &operation.core().parents {
            let parent_index = dag.position(parent).expect("parent is held");
            assert!(parent_index < index, "a parent must occupy a lower index");
        }
    }
}

#[test]
fn depth_follows_the_longest_path() {
    let mut history = History::new();
    history.genesis("g", 1);
    // A short branch and a long one, then a merge.
    history.op("short", 1, &["g"], OperationBody::AddDevice(device(2, "a", Role::Member)));
    history.op("l1", 1, &["g"], OperationBody::AddDevice(device(3, "b", Role::Member)));
    history.op("l2", 1, &["l1"], OperationBody::Rename { device: device_id(3), name: "b2".into() });
    history.op("l3", 1, &["l2"], OperationBody::Rename { device: device_id(3), name: "b3".into() });
    history.op(
        "merge",
        1,
        &["short", "l3"],
        OperationBody::Rename { device: device_id(2), name: "a2".into() },
    );
    let dag = history.dag();

    assert_eq!(dag.depth(index(&dag, &history, "g")), 0);
    assert_eq!(dag.depth(index(&dag, &history, "short")), 1);
    assert_eq!(dag.depth(index(&dag, &history, "l3")), 3);
    assert_eq!(dag.depth(index(&dag, &history, "merge")), 4, "one past the deepest parent");
}

#[test]
fn depth_does_not_depend_on_insertion_order() {
    let history = forked_history();
    let first = history.dag_of(&["g", "b", "c", "d"]);
    let second = history.dag_of(&["g", "c", "b", "d"]);

    for label in ["g", "b", "c", "d"] {
        assert_eq!(
            first.depth(index(&first, &history, label)),
            second.depth(index(&second, &history, label)),
            "{label} must have one depth"
        );
    }
}

/// Timestamps are for display. A parent stamped later than its child changes
/// nothing about where either sits.
#[test]
fn depth_ignores_timestamps() {
    let history = forked_history();
    let dag = history.dag();
    let g = index(&dag, &history, "g");
    let b = index(&dag, &history, "b");
    assert_eq!(dag.depth(b), dag.depth(g).saturating_add(1));

    // The child is stamped later than its parent here, but nothing about depth
    // consulted the stamp: depth came from the parent link alone.
    let genesis_ts = dag.operation(g).expect("held").core().ts;
    let child_ts = dag.operation(b).expect("held").core().ts;
    assert_ne!(genesis_ts, child_ts, "the fixtures do carry different stamps");
    assert_eq!(dag.depth(g), 0, "and the genesis sits at zero regardless");
}

#[test]
fn a_linear_chain_has_exactly_one_head() {
    let mut history = History::new();
    history.genesis("a", 1);
    history.op("b", 1, &["a"], OperationBody::AddDevice(device(2, "laptop", Role::Member)));
    history.op("c", 1, &["b"], OperationBody::AddDevice(device(3, "nas", Role::Member)));
    let dag = history.dag();
    assert_eq!(dag.heads(), vec![history.id("c")]);
}

/// A genuine cycle cannot be constructed: an operation's id covers its parent
/// list, so two operations naming each other would each have to know the
/// other's hash before computing their own. The defence that matters is
/// therefore that an unplaceable set *terminates with an error* rather than
/// looping, which is what this checks.
#[test]
fn an_unplaceable_operation_set_terminates_with_an_error() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("b", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member)));
    history.op("c", 1, &["b"], OperationBody::AddDevice(device(3, "nas", Role::Member)));

    // Offer `c` without `b`: its parent is absent from the input entirely.
    let orphaned = vec![history.verified("g"), history.verified("c")];
    assert_eq!(Dag::from_operations(orphaned).map(|_| ()), Err(Error::MissingGenesis));
}

#[test]
fn from_operations_places_an_unordered_set() {
    let history = forked_history();
    let shuffled = vec![
        history.verified("d"),
        history.verified("c"),
        history.verified("g"),
        history.verified("b"),
    ];
    let dag = Dag::from_operations(shuffled).expect("places everything");
    assert_eq!(dag.len(), 4);
    assert_eq!(dag.heads(), vec![history.id("d")]);
}

#[test]
fn inserting_a_held_operation_again_changes_nothing() {
    let history = forked_history();
    let mut dag = history.dag();
    let before = derive(&dag).expect("derives");
    dag.insert(history.verified("b")).expect("idempotent");
    assert_eq!(dag.len(), 4, "not duplicated");
    assert_eq!(derive(&dag).expect("derives"), before);
}

// ---------------------------------------------------------------------------
// Order-independent derivation
// ---------------------------------------------------------------------------

#[test]
fn merging_two_branches_in_either_order_gives_one_state() {
    let history = forked_history();
    let one = derive(&history.dag_of(&["g", "b", "c", "d"])).expect("derives");
    let other = derive(&history.dag_of(&["g", "c", "b", "d"])).expect("derives");
    assert_eq!(one.to_bytes(), other.to_bytes(), "both orders, one household");
    assert_eq!(one.fingerprint(), other.fingerprint());
}

// ---------------------------------------------------------------------------
// Ancestor-relative validity
// ---------------------------------------------------------------------------

#[test]
fn work_done_while_an_admin_survives_that_admins_demotion() {
    let mut history = History::new();
    history.genesis("g", 1);
    // The founder promotes device 2 to admin.
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    // Device 2 adds device 3.
    history.op("add3", 2, &["add2"], OperationBody::AddDevice(device(3, "nas", Role::Member)));
    // The founder later demotes device 2, causally after the add.
    history.founder_op("demote2", &["add3"], OperationBody::Demote { device: device_id(2) });

    let state = derive(&history.dag()).expect("derives");
    assert!(state.devices.contains_key(&device_id(3)), "the added device stays");
    assert_eq!(
        state.devices.get(&device_id(2)).map(|record| record.role),
        Some(Role::Member),
        "and its author is now a member"
    );
}

#[test]
fn a_member_cannot_author_operations() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member)));
    // Device 2 is a member, and tries to add a device anyway.
    history.op("add3", 2, &["add2"], OperationBody::AddDevice(device(3, "nas", Role::Member)));

    let dag = history.dag();
    let (state, verdicts) = derive_with_verdicts(&dag).expect("derives");
    assert!(!state.devices.contains_key(&device_id(3)), "a member adds nothing");
    assert_eq!(
        verdicts.reason(index(&dag, &history, "add3")),
        Some(Invalidity::UnauthorizedAuthor)
    );
}

#[test]
fn an_operation_descended_from_its_authors_demotion_is_invalid() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    history.founder_op("demote2", &["add2"], OperationBody::Demote { device: device_id(2) });
    // Device 2 authors an operation that names its own demotion as an ancestor.
    history.op("late", 2, &["demote2"], OperationBody::AddDevice(device(3, "nas", Role::Member)));

    let dag = history.dag();
    let (state, verdicts) = derive_with_verdicts(&dag).expect("derives");
    assert!(!state.devices.contains_key(&device_id(3)));
    assert_eq!(
        verdicts.reason(index(&dag, &history, "late")),
        Some(Invalidity::UnauthorizedAuthor)
    );
}

// ---------------------------------------------------------------------------
// The causal authorship rule
// ---------------------------------------------------------------------------

/// The attack the rule exists for: an ex-admin anchors a new operation to
/// parents from before losing authority, where ancestor-derived state still
/// shows them as an admin.
#[test]
fn a_backdated_operation_from_a_demoted_admin_is_void() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    history.founder_op("demote2", &["add2"], OperationBody::Demote { device: device_id(2) });
    // Anchored to `add2`, not to the demotion: concurrent with it.
    history.op(
        "backdated",
        2,
        &["add2"],
        OperationBody::AddDevice(device(9, "backdoor", Role::Member)),
    );

    let dag = history.dag();
    let (state, verdicts) = derive_with_verdicts(&dag).expect("derives");

    let backdated = index(&dag, &history, "backdated");
    let demotion = index(&dag, &history, "demote2");
    assert!(dag.concurrent(backdated, demotion), "the two are indeed concurrent");
    assert_eq!(verdicts.reason(backdated), Some(Invalidity::ConcurrentWithAuthorRemoval));
    assert!(!state.devices.contains_key(&device_id(9)), "the backdoor device must not exist");
}

/// A node that admitted the forgery while unaware of the demotion must reach
/// the same conclusion once it syncs — without anyone revoking anything.
#[test]
fn a_lagging_node_self_heals_when_the_demotion_arrives() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    history.founder_op("demote2", &["add2"], OperationBody::Demote { device: device_id(2) });
    history.op(
        "backdated",
        2,
        &["add2"],
        OperationBody::AddDevice(device(9, "backdoor", Role::Member)),
    );

    // Before the demotion is known, the forgery looks entirely legitimate.
    let lagging = history.dag_of(&["g", "add2", "backdated"]);
    let before = derive(&lagging).expect("derives");
    assert!(before.devices.contains_key(&device_id(9)), "the lagging node is fooled");

    // After syncing, it disappears on its own.
    let synced = history.dag_of(&["g", "add2", "backdated", "demote2"]);
    let after = derive(&synced).expect("derives");
    assert!(!after.devices.contains_key(&device_id(9)), "and heals with no explicit revocation");
}

#[test]
fn legitimate_work_before_a_revocation_survives_it() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    history.op("add3", 2, &["add2"], OperationBody::AddDevice(device(3, "nas", Role::Member)));
    // The revocation has the add among its ancestors: the revoker saw it.
    history.founder_op(
        "revoke2",
        &["add3"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "stolen".into() },
    );

    let state = derive(&history.dag()).expect("derives");
    assert!(state.devices.contains_key(&device_id(3)), "work the revoker knew of stands");
    assert!(state.revoked.contains(&device_id(2)));
}

#[test]
fn an_in_flight_operation_concurrent_with_a_revocation_is_void() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    // Device 2's add never reached the founder, who revokes concurrently.
    history.op(
        "inflight",
        2,
        &["add2"],
        OperationBody::AddDevice(device(4, "tablet", Role::Member)),
    );
    history.founder_op(
        "revoke2",
        &["add2"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "stolen".into() },
    );

    let state = derive(&history.dag()).expect("derives");
    assert!(!state.devices.contains_key(&device_id(4)), "failing safe: the device is not added");
}

// ---------------------------------------------------------------------------
// Conflict rule 1: revocation always wins
// ---------------------------------------------------------------------------

#[test]
fn concurrent_promote_and_revoke_resolves_to_revoked() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member)));
    history.founder_op("promote", &["add2"], OperationBody::Promote { device: device_id(2) });
    history.op(
        "revoke",
        1,
        &["add2"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "stolen".into() },
    );

    for order in [["g", "add2", "promote", "revoke"], ["g", "add2", "revoke", "promote"]] {
        let state = derive(&history.dag_of(&order)).expect("derives");
        assert!(state.revoked.contains(&device_id(2)), "{order:?}");
        assert!(!state.devices.contains_key(&device_id(2)), "{order:?}");
    }
}

#[test]
fn a_causally_later_add_admits_a_revoked_device_again() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member)));
    history.op(
        "revoke",
        1,
        &["add2"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "stolen".into() },
    );
    // The same device id, added again after the revocation: a deliberate act.
    history.op(
        "readd",
        1,
        &["revoke"],
        OperationBody::AddDevice(device(2, "laptop-new", Role::Member)),
    );

    let state = derive(&history.dag()).expect("derives");
    assert!(!state.revoked.contains(&device_id(2)));
    assert_eq!(
        state.devices.get(&device_id(2)).map(|record| record.name.clone()).as_deref(),
        Some("laptop-new"),
        "the later admission stands, under the name it gives"
    );
}

/// An admission concurrent with a revocation of the same device loses to it,
/// in whichever order the two arrive.
#[test]
fn an_add_concurrent_with_a_revocation_loses_in_either_order() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("admin3", &["g"], OperationBody::AddDevice(device(3, "pc", Role::Admin)));
    history.op("add2", 1, &["admin3"], OperationBody::AddDevice(device(2, "laptop", Role::Member)));
    // Admin 1 revokes the laptop; admin 3, not having seen that, admits it again.
    history.op(
        "revoke",
        1,
        &["add2"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "stolen".into() },
    );
    history.op("readd", 3, &["add2"], OperationBody::AddDevice(device(2, "laptop", Role::Member)));

    let forward = derive(&history.dag()).expect("derives");
    assert!(!forward.devices.contains_key(&device_id(2)), "the revocation wins");
    assert!(forward.revoked.contains(&device_id(2)));

    let mut backward = roster::roster::Roster::new();
    for entry in history.entries().iter().rev() {
        let _ = backward.offer_bytes(&entry.bytes);
    }
    let backward = backward.state().expect("derives");
    assert_eq!(backward.to_bytes(), forward.to_bytes(), "the same in the other order");
    assert_eq!(backward.root(), forward.root());
}

#[test]
fn a_revoked_device_cannot_be_promoted() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member)));
    history.op(
        "revoke",
        1,
        &["add2"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "stolen".into() },
    );
    history.founder_op("promote", &["revoke"], OperationBody::Promote { device: device_id(2) });

    let state = derive(&history.dag()).expect("derives");
    assert!(!state.devices.contains_key(&device_id(2)));
    assert!(!state.is_admin(&device_id(2)));
}

// ---------------------------------------------------------------------------
// Conflict rule 2: demote beats promote among concurrent branches
// ---------------------------------------------------------------------------

#[test]
fn concurrent_promote_and_demote_by_the_founder_are_a_fork() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    // Only the founder key promotes or demotes, so the race this rule was about,
    // "an admin unaware of the demotion concurrently promotes it", can now only
    // be the founder signing two histories: a fork, and neither stands.
    history.founder_op("demote", &["add2"], OperationBody::Demote { device: device_id(2) });
    history.founder_op("promote", &["add2"], OperationBody::Promote { device: device_id(2) });

    for order in [["g", "add2", "demote", "promote"], ["g", "add2", "promote", "demote"]] {
        let state = derive(&history.dag_of(&order)).expect("derives");
        assert_eq!(
            state.devices.get(&device_id(2)).map(|record| record.role),
            Some(Role::Admin),
            "neither branch of the fork stands, in {order:?}"
        );
    }
}

#[test]
fn a_causally_later_promote_re_promotes() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    history.founder_op("demote", &["add2"], OperationBody::Demote { device: device_id(2) });
    // The promote descends from the demote: a deliberate re-promotion.
    history.founder_op("promote", &["demote"], OperationBody::Promote { device: device_id(2) });

    let state = derive(&history.dag()).expect("derives");
    assert_eq!(
        state.devices.get(&device_id(2)).map(|record| record.role),
        Some(Role::Admin),
        "demotion is reversible; revocation is not"
    );
}

// ---------------------------------------------------------------------------
// Conflict rule 3: last-writer-wins
// ---------------------------------------------------------------------------

#[test]
fn the_deeper_rename_wins() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member)));
    history.founder_op(
        "add9",
        &["add2"],
        OperationBody::AddDevice(device(9, "other-admin", Role::Admin)),
    );
    history.op(
        "shallow",
        1,
        &["add9"],
        OperationBody::Rename { device: device_id(2), name: "shallow".into() },
    );
    // The concurrent branch comes from a second admin. One admin writing both
    // would be a fork, and forks are judged before depth is consulted.
    history.op(
        "mid",
        9,
        &["add9"],
        OperationBody::Rename { device: device_id(2), name: "mid".into() },
    );
    history.op(
        "deep",
        9,
        &["mid"],
        OperationBody::Rename { device: device_id(2), name: "deep".into() },
    );

    let state = derive(&history.dag()).expect("derives");
    assert_eq!(state.devices.get(&device_id(2)).map(|r| r.name.clone()).as_deref(), Some("deep"));
}

#[test]
fn equal_depth_renames_are_broken_by_operation_id_and_agree_in_both_orders() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member)));
    history.founder_op(
        "add9",
        &["add2"],
        OperationBody::AddDevice(device(9, "other-admin", Role::Admin)),
    );
    // One rename from each admin: concurrent, equal depth, different authors.
    history.op(
        "left",
        1,
        &["add9"],
        OperationBody::Rename { device: device_id(2), name: "left".into() },
    );
    history.op(
        "right",
        9,
        &["add9"],
        OperationBody::Rename { device: device_id(2), name: "right".into() },
    );

    let expected = if history.id("left") > history.id("right") { "left" } else { "right" };
    for order in [["g", "add2", "add9", "left", "right"], ["g", "add2", "add9", "right", "left"]] {
        let state = derive(&history.dag_of(&order)).expect("derives");
        assert_eq!(
            state.devices.get(&device_id(2)).map(|r| r.name.clone()).as_deref(),
            Some(expected),
            "the greater id wins, in {order:?}"
        );
    }
}

#[test]
fn concurrent_network_parameter_changes_resolve_identically() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("left", 1, &["g"], OperationBody::SetNetwork(params_with("left.internal")));
    history.op("right", 1, &["g"], OperationBody::SetNetwork(params_with("right.internal")));

    let first = derive(&history.dag_of(&["g", "left", "right"])).expect("derives");
    let second = derive(&history.dag_of(&["g", "right", "left"])).expect("derives");
    assert_eq!(first.params, second.params);
    assert_eq!(first.to_bytes(), second.to_bytes());
}

// ---------------------------------------------------------------------------
// Only the founder key governs admins; admins govern members
// ---------------------------------------------------------------------------

#[test]
fn an_admins_revocation_of_another_admin_is_without_authority() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    history.op(
        "revoke1",
        2,
        &["add2"],
        OperationBody::RevokeDevice { device: device_id(1), reason: "stolen".into() },
    );

    let dag = history.dag();
    let (state, verdicts) = derive_with_verdicts(&dag).expect("derives");
    assert_eq!(
        verdicts.reason(index(&dag, &history, "revoke1")),
        Some(Invalidity::UnauthorizedAuthor)
    );
    assert!(state.is_admin(&device_id(1)), "the other admin keeps its role");
}

#[test]
fn the_founder_key_revokes_the_admin_that_founded_the_network() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    history.founder_op(
        "revoke1",
        &["add2"],
        OperationBody::RevokeDevice { device: device_id(1), reason: "stolen".into() },
    );

    let state = derive(&history.dag()).expect("derives");
    assert!(state.revoked.contains(&device_id(1)), "no admin is protected from the founder");
}

#[test]
fn an_admin_cannot_admit_an_admin_or_act_on_one() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    history.op("admit", 1, &["add2"], OperationBody::AddDevice(device(3, "pc", Role::Admin)));
    history.op(
        "rename",
        1,
        &["admit"],
        OperationBody::Rename { device: device_id(2), name: "mine".into() },
    );
    history.op("demote", 1, &["rename"], OperationBody::Demote { device: device_id(2) });

    let dag = history.dag();
    let (state, verdicts) = derive_with_verdicts(&dag).expect("derives");
    for act in ["admit", "rename", "demote"] {
        assert_eq!(
            verdicts.reason(index(&dag, &history, act)),
            Some(Invalidity::UnauthorizedAuthor),
            "{act}"
        );
    }
    assert!(!state.devices.contains_key(&device_id(3)));
    assert!(state.is_admin(&device_id(2)));
    assert_eq!(
        state.devices.get(&device_id(2)).map(|record| record.name.clone()).as_deref(),
        Some("laptop")
    );
}

#[test]
fn an_admin_governs_members() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("admit", 1, &["g"], OperationBody::AddDevice(device(3, "tv", Role::Member)));
    history.op(
        "rename",
        1,
        &["admit"],
        OperationBody::Rename { device: device_id(3), name: "telly".into() },
    );
    history.op(
        "revoke",
        1,
        &["rename"],
        OperationBody::RevokeDevice { device: device_id(3), reason: "sold".into() },
    );

    let dag = history.dag();
    let (state, verdicts) = derive_with_verdicts(&dag).expect("derives");
    for act in ["admit", "rename", "revoke"] {
        assert_eq!(verdicts.reason(index(&dag, &history, act)), None, "{act}");
    }
    assert!(state.revoked.contains(&device_id(3)));
}

#[test]
fn the_founder_key_demotes_the_admin_that_founded_the_network() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    history.founder_op("demote1", &["add2"], OperationBody::Demote { device: device_id(1) });

    let state = derive(&history.dag()).expect("derives");
    assert!(!state.is_admin(&device_id(1)));
    assert!(state.is_admin(&device_id(2)));
}

#[test]
fn an_admin_cannot_revoke_itself() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    history.op(
        "retire",
        1,
        &["add2"],
        OperationBody::RevokeDevice { device: device_id(1), reason: "handover".into() },
    );

    let dag = history.dag();
    let (state, verdicts) = derive_with_verdicts(&dag).expect("derives");
    assert_eq!(
        verdicts.reason(index(&dag, &history, "retire")),
        Some(Invalidity::UnauthorizedAuthor),
        "an admin governs members only; forgetting the network is how a device lets go"
    );
    assert!(state.is_admin(&device_id(1)));
}

/// What used to be a deadlock, two admins revoking each other at once, is now
/// two acts without authority: neither is an admin's to sign.
#[test]
fn two_admins_cannot_revoke_each_other() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    history.op(
        "a_revokes_b",
        1,
        &["add2"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "thief".into() },
    );
    history.op(
        "b_revokes_a",
        2,
        &["add2"],
        OperationBody::RevokeDevice { device: device_id(1), reason: "thief".into() },
    );

    let dag = history.dag();
    let (state, verdicts) = derive_with_verdicts(&dag).expect("derives");
    for act in ["a_revokes_b", "b_revokes_a"] {
        assert_eq!(
            verdicts.reason(index(&dag, &history, act)),
            Some(Invalidity::UnauthorizedAuthor),
            "{act}"
        );
    }
    assert!(state.is_admin(&device_id(1)) && state.is_admin(&device_id(2)));
    assert!(state.revoked.is_empty());
}

#[test]
fn the_founder_key_revokes_an_admin_whatever_that_admin_does_at_once() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "phone", Role::Member)));
    history.founder_op(
        "add3",
        &["add2"],
        OperationBody::AddDevice(device(3, "laptop", Role::Admin)),
    );
    // The stolen laptop revokes the phone; the founder, concurrently, revokes
    // the laptop.
    history.op(
        "laptop_revokes_phone",
        3,
        &["add3"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "mine".into() },
    );
    history.founder_op(
        "founder_revokes_laptop",
        &["add3"],
        OperationBody::RevokeDevice { device: device_id(3), reason: "stolen".into() },
    );

    let dag = history.dag();
    let (state, verdicts) = derive_with_verdicts(&dag).expect("derives");
    assert_eq!(verdicts.reason(index(&dag, &history, "founder_revokes_laptop")), None);
    assert_eq!(
        verdicts.reason(index(&dag, &history, "laptop_revokes_phone")),
        Some(Invalidity::ConcurrentWithAuthorRemoval)
    );
    assert!(state.revoked.contains(&device_id(3)), "the laptop is revoked");
    assert!(state.devices.contains_key(&device_id(2)), "and the phone is still a member");
}

/// The founder key is not a device, so no revocation of a device voids it.
#[test]
fn the_founder_keys_work_is_never_voided() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    history.op(
        "revoke1",
        2,
        &["add2"],
        OperationBody::RevokeDevice { device: device_id(1), reason: "x".into() },
    );
    history.founder_op(
        "founder_adds",
        &["add2"],
        OperationBody::AddDevice(device(4, "spare", Role::Admin)),
    );

    let state = derive(&history.dag()).expect("derives");
    assert!(state.is_admin(&device_id(4)), "the founder's admission stands");
}

#[test]
fn an_admin_cannot_change_the_founder_key() {
    let mut history = History::new();
    history.genesis("g", 1);
    let mut theirs = support::params_with("other.internal");
    theirs.founder = support::next_founder_keys();
    history.op("takeover", 1, &["g"], OperationBody::SetNetwork(theirs));

    let state = derive(&history.dag()).expect("derives");
    assert_eq!(state.params.founder, support::founder_keys(), "the founder's keys are unchanged");
    assert_eq!(state.params.suffix, "other.internal", "and the admin's other change stands");
}

#[test]
fn the_founder_key_replaces_itself() {
    let mut history = History::new();
    history.genesis("g", 1);
    let mut next = support::params();
    next.founder = support::next_founder_keys();
    history.founder_op("replace", &["g"], OperationBody::SetNetwork(next));
    history.signed_op(
        "new_key_acts",
        &support::next_founder_signer(),
        &["replace"],
        OperationBody::AddDevice(device(5, "new", Role::Member)),
    );
    history.founder_op(
        "old_key_acts",
        &["replace"],
        OperationBody::AddDevice(device(6, "old", Role::Member)),
    );

    let dag = history.dag();
    let (state, verdicts) = derive_with_verdicts(&dag).expect("derives");
    assert_eq!(state.params.founder, support::next_founder_keys());
    assert!(state.devices.contains_key(&device_id(5)), "the new key is the founder's");
    assert_eq!(
        verdicts.reason(index(&dag, &history, "old_key_acts")),
        Some(Invalidity::UnauthorizedAuthor),
        "the old key, after its replacement, is nobody's"
    );
}

#[test]
fn a_device_carrying_a_founder_key_is_refused() {
    let mut history = History::new();
    history.genesis("g", 1);
    let mut spec = device(7, "impostor", Role::Member);
    let founder = support::founder_keys();
    spec.keys.retain(|entry| entry.purpose != roster::types::KeyPurpose::Transport);
    spec.keys.push(
        roster::types::KeyEntry::new(
            roster::types::Algorithm::Ed25519,
            roster::types::KeyPurpose::Transport,
            founder.transport().to_vec(),
        )
        .expect("a key"),
    );
    spec.keys.sort_by_key(roster::types::KeyEntry::order_key);
    history.op("impostor", 1, &["g"], OperationBody::AddDevice(spec));

    let dag = history.dag();
    let (state, verdicts) = derive_with_verdicts(&dag).expect("derives");
    assert_eq!(
        verdicts.reason(index(&dag, &history, "impostor")),
        Some(Invalidity::FounderKeyReused)
    );
    assert!(!state.devices.contains_key(&device_id(7)));
}

/// The words used on two devices at once: neither branch takes effect, except a
/// revocation, which holds.
#[test]
fn a_founder_key_used_twice_at_once_keeps_only_its_revocations() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    history.founder_op("here", &["add2"], OperationBody::AddDevice(device(8, "mine", Role::Admin)));
    history.founder_op(
        "there",
        &["add2"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "theirs".into() },
    );

    let state = derive(&history.dag()).expect("derives");
    assert!(!state.devices.contains_key(&device_id(8)), "the equivocated admission is void");
    assert!(state.revoked.contains(&device_id(2)), "the revocation holds");
}

#[test]
fn revoked_devices_are_absent_and_survivors_keep_their_resolved_fields() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member)));
    history.op("add3", 1, &["add2"], OperationBody::AddDevice(device(3, "nas", Role::Member)));
    history.op(
        "rename3",
        1,
        &["add3"],
        OperationBody::Rename { device: device_id(3), name: "storage".into() },
    );
    history.founder_op("promote3", &["rename3"], OperationBody::Promote { device: device_id(3) });
    history.op(
        "revoke2",
        1,
        &["promote3"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "sold".into() },
    );

    let state = derive(&history.dag()).expect("derives");
    assert!(!state.devices.contains_key(&device_id(2)));
    assert!(state.revoked.contains(&device_id(2)));

    let nas = state.devices.get(&device_id(3)).expect("survives");
    assert_eq!(nas.name, "storage", "the rename applied");
    assert_eq!(nas.role, Role::Admin, "the promotion applied");
    assert_eq!(nas.id, device_id(3));
}

#[test]
fn an_author_key_resolves_to_its_device() {
    let mut history = History::new();
    history.genesis("g", 1);
    let state = derive(&history.dag()).expect("derives");
    let record = state.device_for_key(&signer(1).key_id()).expect("the founder is found");
    assert_eq!(record.id, device_id(1));
}

/// Two admins demoting each other at the same moment: both demotions are void
/// and both keep their roles, leaving a person to settle it deliberately.
///
/// Neither is a founder, so the two acts really are symmetric and each is one its
/// author was entitled to make. That is what makes them cancel: an authorised
/// removal voids the work concurrent with it, and here each is the other's.
#[test]
fn mutual_demotion_by_admins_is_without_authority() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("add2", &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Admin)));
    history.founder_op("add3", &["add2"], OperationBody::AddDevice(device(3, "nas", Role::Admin)));
    history.op("b_demotes_c", 2, &["add3"], OperationBody::Demote { device: device_id(3) });
    history.op("c_demotes_b", 3, &["add3"], OperationBody::Demote { device: device_id(2) });

    let dag = history.dag();
    let (state, verdicts) = derive_with_verdicts(&dag).expect("derives");
    for act in ["b_demotes_c", "c_demotes_b"] {
        assert_eq!(
            verdicts.reason(index(&dag, &history, act)),
            Some(Invalidity::UnauthorizedAuthor),
            "{act}: neither is an admin's to sign"
        );
    }
    assert!(state.is_admin(&device_id(2)), "neither demotion takes effect");
    assert!(state.is_admin(&device_id(3)));
}

/// An operation cannot act on a device that does not exist yet.
///
/// Without this the effect sits latent, applying if the device is added later.
/// A snapshot's state has nowhere to record a name or a role for a device it
/// does not contain, so a node that compacted would lose it and derive a
/// different roster from one that did not. Found by the compaction property
/// test in `snapshot_properties.rs`.
#[test]
fn an_operation_preceding_its_targets_add_has_no_effect() {
    let mut history = History::new();
    history.genesis("g", 1);
    // Rename and promote a device that does not exist yet.
    history.op(
        "early_rename",
        1,
        &["g"],
        OperationBody::Rename { device: device_id(2), name: "ghost".into() },
    );
    history.founder_op(
        "early_promote",
        &["early_rename"],
        OperationBody::Promote { device: device_id(2) },
    );
    // Only now is the device added.
    history.op(
        "add2",
        1,
        &["early_promote"],
        OperationBody::AddDevice(device(2, "laptop", Role::Member)),
    );

    let state = derive(&history.dag()).expect("derives");
    let record = state.devices.get(&device_id(2)).expect("the device is added");
    assert_eq!(record.name, "laptop", "the earlier rename does not apply retroactively");
    assert_eq!(record.role, Role::Member, "nor the earlier promotion");
}

/// The same operations, in the order that makes sense, do apply.
#[test]
fn an_operation_following_its_targets_add_applies_normally() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member)));
    history.op(
        "rename",
        1,
        &["add2"],
        OperationBody::Rename { device: device_id(2), name: "work".into() },
    );
    history.founder_op("promote", &["rename"], OperationBody::Promote { device: device_id(2) });

    let state = derive(&history.dag()).expect("derives");
    let record = state.devices.get(&device_id(2)).expect("present");
    assert_eq!(record.name, "work");
    assert_eq!(record.role, Role::Admin);
}

/// The index of a labelled operation in a graph.
fn index(dag: &Dag, history: &History, label: &str) -> usize {
    dag.position(&history.id(label)).unwrap_or_else(|| panic!("`{label}` is not in the graph"))
}

/// Silences the unused-import warning for `OperationId` in some builds.
#[allow(dead_code, reason = "type alias kept for readability of helper signatures")]
type _Id = OperationId;

/// A key resolves only for the purpose it declares. Without this, a signing key
/// could authenticate a transport session — the cross-protocol confusion the
/// key separation exists to prevent.
#[test]
fn a_key_resolves_only_for_its_declared_purpose() {
    let mut history = History::new();
    history.genesis("g", 1);
    let state = derive(&history.dag()).expect("derives");

    let record = state.devices.get(&device_id(1)).expect("the founder is present");
    let signing = record
        .keys
        .iter()
        .find(|entry| entry.purpose == roster::types::KeyPurpose::Signing)
        .expect("a signing key");
    let transport = record
        .keys
        .iter()
        .find(|entry| entry.purpose == roster::types::KeyPurpose::Transport)
        .expect("a transport key");

    // Each key resolves under its own purpose.
    assert!(
        state
            .device_for_key_of_purpose(&signing.key_id(), roster::types::KeyPurpose::Signing)
            .is_some()
    );
    assert!(
        state
            .device_for_key_of_purpose(&transport.key_id(), roster::types::KeyPurpose::Transport)
            .is_some()
    );

    // And under no other.
    assert!(
        state
            .device_for_key_of_purpose(&signing.key_id(), roster::types::KeyPurpose::Transport)
            .is_none(),
        "a signing key must not resolve as a transport key"
    );
    assert!(
        state
            .device_for_key_of_purpose(&transport.key_id(), roster::types::KeyPurpose::Signing)
            .is_none(),
        "nor a transport key as a signing key"
    );

    // The existing helper is the signing case.
    assert_eq!(state.device_for_key(&signing.key_id()).map(|r| r.id), Some(record.id));
    assert!(state.device_for_key(&transport.key_id()).is_none());
}

// ---------------------------------------------------------------------------
// Equivocation: one author, two histories
// ---------------------------------------------------------------------------

/// The signal, stated once: an honest device anchors each operation it writes to
/// its own previous one, because it knows what it last wrote. Two operations by
/// one author that are causally concurrent mean it signed two histories — or that
/// one identity is running in two places, which is the same evidence and the same
/// remedy.
#[test]
fn two_concurrent_operations_by_one_author_are_a_fork() {
    let mut history = History::new();
    history.genesis("g", 1);
    // One author, two operations, both anchored to the genesis and neither to
    // the other.
    history.op("b", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Member)));
    history.op("c", 1, &["g"], OperationBody::AddDevice(device(3, "c", Role::Member)));

    let dag = history.dag();
    let forks = dag.forks();

    assert_eq!(forks.len(), 1, "one fork, named once: {forks:?}");
    let fork = forks.first().expect("one fork");
    assert!(dag.concurrent(fork.first, fork.second), "the pair really is concurrent");
    assert!(dag.is_equivocated(fork.first));
    assert!(dag.is_equivocated(fork.second));
}

/// A device that writes a chain is behaving exactly as a device should, however
/// long the chain.
#[test]
fn a_chained_history_is_not_a_fork() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("a", 1, &["g"], OperationBody::AddDevice(device(2, "a", Role::Member)));
    history.op("b", 1, &["a"], OperationBody::AddDevice(device(3, "b", Role::Member)));
    history.op("c", 1, &["b"], OperationBody::AddDevice(device(4, "c", Role::Member)));

    assert!(history.dag().forks().is_empty(), "a chain is what an honest device writes");
}

/// Two admins acting at once is ordinary. The merge rules exist for it, and
/// reporting it would make the detection useless by crying wolf on every
/// legitimate concurrency.
#[test]
fn two_authors_writing_from_one_parent_is_not_a_fork() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.founder_op("promote", &["g"], OperationBody::AddDevice(device(2, "b", Role::Admin)));
    // Two different authors, both anchored to the same parent.
    history.op(
        "x",
        1,
        &["promote"],
        OperationBody::Rename { device: device_id(2), name: "one".to_owned() },
    );
    history.op(
        "y",
        2,
        &["promote"],
        OperationBody::Rename { device: device_id(2), name: "two".to_owned() },
    );

    let dag = history.dag();
    let x = dag.position(&history.id("x")).expect("placed");
    let y = dag.position(&history.id("y")).expect("placed");

    assert!(dag.concurrent(x, y), "they are concurrent, which is the point");
    assert!(dag.forks().is_empty(), "but concurrency between authors is not a fork");
}

/// The founding operation has no parents, so it is concurrent with nothing. Two
/// foundings by one author are two networks with different identifiers, which
/// nothing here joins.
#[test]
fn the_founding_operation_is_not_part_of_a_fork() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("b", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Member)));

    let dag = history.dag();
    let genesis = dag.genesis().expect("a genesis");

    assert!(!dag.is_equivocated(genesis));
    assert!(dag.forks().is_empty());
}

/// An author who merges their own branches afterwards has still signed two
/// histories. Both operations existed, both were signed, and an operation naming
/// them both as parents does not make them cease to be concurrent with each
/// other.
#[test]
fn a_later_merge_by_the_author_does_not_erase_the_fork() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("b", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Member)));
    history.op("c", 1, &["g"], OperationBody::AddDevice(device(3, "c", Role::Member)));
    history.op(
        "merge",
        1,
        &["b", "c"],
        OperationBody::Rename { device: device_id(2), name: "merged".to_owned() },
    );

    let dag = history.dag();
    assert_eq!(dag.forks().len(), 1, "the fork is still there after the merge");
}

/// The verdict is a function of the operation set, not of the order it arrived
/// in. Anything else would be gameable by the equivocator, who chooses delivery
/// order per peer — which is the attack itself.
#[test]
fn the_verdict_does_not_depend_on_arrival_order() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("b", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Member)));
    history.op("c", 1, &["g"], OperationBody::AddDevice(device(3, "c", Role::Member)));
    history.op(
        "d",
        2,
        &["b"],
        OperationBody::Rename { device: device_id(2), name: "d".to_owned() },
    );

    // Every order in which the parents precede their children.
    let orders: [&[usize]; 4] = [&[0, 1, 2, 3], &[0, 2, 1, 3], &[0, 1, 3, 2], &[0, 2, 1, 3]];
    let expected = history.dag_ordered(orders[0]).forks();
    assert_eq!(expected.len(), 1);

    // Compared by the operations named, not by position. Indices come from the
    // order operations arrived in, so comparing them would pass for two nodes
    // that disagree about which half of the pair is which — a real defect this
    // test missed in its first form, and the evidence tests caught instead.
    let named = |dag: &Dag, fork: &roster::dag::Fork| {
        (
            fork.author,
            dag.operation(fork.first).map(roster::sign::VerifiedOperation::id),
            dag.operation(fork.second).map(roster::sign::VerifiedOperation::id),
        )
    };
    let reference = history.dag_ordered(orders[0]);
    let mut wanted: Vec<_> = expected.iter().map(|fork| named(&reference, fork)).collect();
    wanted.sort();

    for order in orders {
        let dag = history.dag_ordered(order);
        let mut found: Vec<_> = dag.forks().iter().map(|fork| named(&dag, fork)).collect();
        found.sort();
        assert_eq!(
            found, wanted,
            "the same operations must give the same verdict, naming the same pair, whatever \
             order they arrived in: {order:?}"
        );
    }
}

/// A node that acted on one branch and receives the other later reaches the
/// verdict it would have reached had both arrived together.
#[test]
fn a_fork_found_later_is_found_just_the_same() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("b", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Member)));

    // One branch only: nothing to see.
    assert!(history.dag_of(&["g", "b"]).forks().is_empty());

    history.op("c", 1, &["g"], OperationBody::AddDevice(device(3, "c", Role::Member)));

    // The other arrives, and the fork is there.
    assert_eq!(history.dag_of(&["g", "b", "c"]).forks().len(), 1);
}

/// **The guard against the erase-history attack, written before the rule it
/// constrains.**
///
/// Voiding everything that descends from a forked operation is the intuitive
/// reading of "refuse the branch", and it is the dangerous one. An admin writes
/// B, a month of the network's work anchors to it, and the admin then signs C
/// concurrent with B. If descendants fell, that month would be invalidated — the
/// equivocator choosing when to fire, and firing backwards.
///
/// So: another author's operation anchored to a forked one keeps its validity and
/// its effect. This test exists before the code that could break it, and its job
/// is to fail if anybody ever widens the void.
#[test]
fn another_authors_work_anchored_to_a_fork_survives_it() {
    let mut history = History::new();
    history.genesis("g", 1);
    // A second admin, added before the fork, so its authority is not in question.
    history.founder_op("admin", &["g"], OperationBody::AddDevice(device(2, "b", Role::Admin)));

    // Author 1 forks: two concurrent operations of its own.
    history.op("x", 1, &["admin"], OperationBody::AddDevice(device(3, "x", Role::Member)));
    history.op("y", 1, &["admin"], OperationBody::AddDevice(device(4, "y", Role::Member)));

    // Author 2 builds on one branch — a month of work, in miniature.
    history.op("theirs", 2, &["x"], OperationBody::AddDevice(device(5, "theirs", Role::Member)));

    let dag = history.dag();
    assert_eq!(dag.forks().len(), 1, "author 1 forked");

    let state = derive(&dag).expect("derives");

    assert!(
        state.devices.contains_key(&device_id(5)),
        "the second author's device must survive a fork it merely anchored to: voiding it \
         would let an equivocator erase other people's work by signing one late sibling"
    );
}

// ---------------------------------------------------------------------------
// A founder revocation voids a stolen admin's acts from the one chosen
// ---------------------------------------------------------------------------

/// A network in which a stolen admin, `laptop`, signed one act still trusted
/// and then three that are not, with an honest admin's admission in between.
fn a_stolen_admins_evening() -> (History, Roster) {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("tv", 1, &["g"], OperationBody::AddDevice(device(3, "tv", Role::Member)));
    history.op("nas", 1, &["tv"], OperationBody::AddDevice(device(4, "nas", Role::Member)));
    history.founder_op(
        "thief",
        &["nas"],
        OperationBody::AddDevice(device(2, "laptop", Role::Admin)),
    );
    history.op(
        "before",
        2,
        &["thief"],
        OperationBody::AddDevice(device(6, "printer", Role::Member)),
    );
    history.op(
        "smuggled",
        2,
        &["before"],
        OperationBody::AddDevice(device(9, "smuggled", Role::Member)),
    );
    history.op(
        "phone",
        1,
        &["smuggled"],
        OperationBody::AddDevice(device(5, "phone", Role::Member)),
    );
    history.op(
        "out",
        2,
        &["phone"],
        OperationBody::RevokeDevice { device: device_id(3), reason: "mine".into() },
    );
    history.op(
        "renamed",
        2,
        &["out"],
        OperationBody::Rename { device: device_id(4), name: "mine".into() },
    );
    let mut roster = Roster::new();
    for entry in history.entries() {
        assert!(roster.offer_bytes(&entry.bytes).is_accepted(), "{}", entry.label);
    }
    (history, roster)
}

#[test]
fn a_founder_revocation_voids_a_stolen_admins_acts_from_the_chosen_one() {
    let (mut history, mut roster) = a_stolen_admins_evening();
    let anchor = roster.voiding_anchor(&device_id(2), &history.id("smuggled")).expect("an anchor");
    let mut voided: Vec<_> = anchor.voided.iter().map(|(id, _)| *id).collect();
    voided.sort_unstable();
    let mut expected = vec![history.id("smuggled"), history.id("out"), history.id("renamed")];
    expected.sort_unstable();
    assert_eq!(voided, expected, "the chosen act and every later one of the stolen admin");

    history.founder_op_on(
        "revoke",
        &anchor.heads,
        OperationBody::RevokeDevice { device: device_id(2), reason: "stolen".into() },
    );
    let revocation = history.entries().last().expect("the revocation").bytes.clone();
    assert!(roster.offer_bytes(&revocation).is_accepted());

    let state = roster.state().expect("derives");
    assert!(state.revoked.contains(&device_id(2)), "the stolen admin is out");
    assert!(!state.devices.contains_key(&device_id(9)), "what it admitted leaves");
    assert!(state.devices.contains_key(&device_id(3)), "what it revoked is back");
    assert_eq!(
        state.devices.get(&device_id(4)).map(|record| record.name.clone()).as_deref(),
        Some("nas"),
        "what it renamed has its name again"
    );
    assert!(state.devices.contains_key(&device_id(6)), "its act before the chosen one stands");
    assert!(state.devices.contains_key(&device_id(5)), "another admin's act in between stands");
}

/// A founder act resting on what would be voided would be concurrent with the
/// revocation, and the founder's two concurrent acts keep only revocations: the
/// anchor is refused, naming it, and a later act may be chosen instead.
#[test]
fn voiding_from_beneath_a_founder_act_is_refused() {
    let (mut history, _) = a_stolen_admins_evening();
    history.founder_op(
        "founders",
        &["renamed"],
        OperationBody::AddDevice(device(7, "pc", Role::Member)),
    );
    history.op(
        "after",
        2,
        &["founders"],
        OperationBody::AddDevice(device(8, "tablet", Role::Member)),
    );
    let mut roster = Roster::new();
    for entry in history.entries() {
        assert!(roster.offer_bytes(&entry.bytes).is_accepted(), "{}", entry.label);
    }
    assert_eq!(
        roster.voiding_anchor(&device_id(2), &history.id("smuggled")),
        Err(roster::roster::VoidingRefused::FounderRestsOn(history.id("founders")))
    );
    let later = roster.voiding_anchor(&device_id(2), &history.id("after")).expect("an anchor");
    assert_eq!(later.voided.len(), 1, "only the act after the founder's");
}

#[test]
fn voiding_from_another_devices_act_is_refused() {
    let (history, roster) = a_stolen_admins_evening();
    assert_eq!(
        roster.voiding_anchor(&device_id(2), &history.id("tv")),
        Err(roster::roster::VoidingRefused::NotItsAct)
    );
}

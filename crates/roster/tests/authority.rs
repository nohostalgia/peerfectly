//! Who may write to a network, judged where it has to be judged.
//!
//! Every test here is one device trying to act with authority it does not have.
//! The rule they all rest on is that an operation is judged against the state
//! **its own ancestors** imply — so the interesting attacks are not the obvious
//! "a member signs an operation", which was always refused, but the ones that
//! arrange for the ancestor state to be *missing something*.
//!
//! The sharpest of those is anchoring an operation **before the operation that
//! admitted its author**. In that ancestor state the author does not exist at
//! all, and a rule that answers "no role to check, then" rather than "no role,
//! so no authority" hands the network to whoever asks. That is what
//! `an_author_absent_from_its_own_ancestors_is_unauthorised` and the four after
//! it hold the line on, in derived state and not only at admission.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod support;

use roster::roster::Roster;
use roster::state::{RosterState, derive_with_verdicts};
use roster::types::{NetworkParams, OperationBody, Role};
use support::{History, device, device_id};

/// A network founded by device 1, which then admits device 2 as a **member**.
///
/// `attack` is authored by that member and anchored at the genesis, so the
/// operation that admitted it is not among its ancestors: in the state its own
/// ancestors imply, the author does not exist.
fn member_acting_from_before_its_own_admission(body: OperationBody) -> (Roster, RosterState) {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("addB", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Member, false)));
    history.op("attack", 2, &["g"], body);

    let mut roster = Roster::new();
    for entry in history.entries() {
        roster.offer_bytes(&entry.bytes);
    }
    let state = roster.state().expect("derives");
    (roster, state)
}

/// The founding device and the member it admitted, and nothing else, whatever
/// the member signed.
fn only_the_founder_and_the_member(state: &RosterState) {
    assert_eq!(state.devices.len(), 2, "no third device: {:?}", state.devices.keys());
    assert_eq!(
        state.devices.get(&device_id(2)).map(|record| record.role),
        Some(Role::Member),
        "the member is still a member"
    );
    assert!(state.revoked.is_empty(), "nobody was revoked");
}

#[test]
fn an_author_absent_from_its_own_ancestors_cannot_add_a_device() {
    let (_, state) = member_acting_from_before_its_own_admission(OperationBody::AddDevice(device(
        3,
        "smuggled",
        Role::Member,
        false,
    )));
    assert!(!state.devices.contains_key(&device_id(3)), "a device nobody with authority added");
    only_the_founder_and_the_member(&state);
}

#[test]
fn an_author_absent_from_its_own_ancestors_cannot_promote_itself() {
    let (_, state) = member_acting_from_before_its_own_admission(OperationBody::Promote {
        device: device_id(2),
        founder: true,
    });
    only_the_founder_and_the_member(&state);
    assert!(!state.is_founder(&device_id(2)), "and it did not make itself a founder on the way");
}

/// Founder protection sits *after* the authority check, so an author that slips
/// past the first check never meets the second. Anchoring earlier must not be a
/// way to reach it.
#[test]
fn an_author_absent_from_its_own_ancestors_cannot_revoke_the_founder() {
    let (_, state) = member_acting_from_before_its_own_admission(OperationBody::RevokeDevice {
        device: device_id(1),
        reason: "mine now".to_owned(),
    });
    assert!(!state.revoked.contains(&device_id(1)), "the founder is not revoked");
    only_the_founder_and_the_member(&state);
}

#[test]
fn an_author_absent_from_its_own_ancestors_cannot_rewrite_the_network() {
    let theirs = NetworkParams::new(
        vec![0xfd, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66],
        "attacker.internal",
        2_592_000,
    )
    .expect("valid");
    let (_, state) = member_acting_from_before_its_own_admission(OperationBody::SetNetwork(theirs));

    assert_eq!(state.params.suffix, "example.internal", "the suffix is the founder's");
    assert_eq!(state.params.ula, vec![0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    only_the_founder_and_the_member(&state);
}

/// The rule it all rests on, stated on its own: an operation whose author the
/// ancestor state does not name has no authority, whatever that author may be
/// elsewhere in the graph.
#[test]
fn an_author_absent_from_its_own_ancestors_is_unauthorised() {
    let (roster, _) = member_acting_from_before_its_own_admission(OperationBody::AddDevice(
        device(3, "smuggled", Role::Member, false),
    ));

    let (_, verdicts) = derive_with_verdicts(roster.dag()).expect("derives");
    let disregarded: Vec<String> = roster
        .dag()
        .operations()
        .iter()
        .enumerate()
        .filter_map(|(index, _)| verdicts.reason(index).map(|reason| reason.kind().to_owned()))
        .collect();

    assert!(
        disregarded.is_empty() || disregarded == vec!["unauthorized_author".to_owned()],
        "the only thing disregarded, if anything is held at all, is the unauthorised operation: \
         {disregarded:?}"
    );
}

/// The counterpart, so the rule is not simply "refuse everything": an admin's
/// work anchored where its own authority is visible stands.
#[test]
fn an_admin_acting_where_its_authority_is_visible_is_honoured() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("addB", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Admin, false)));
    history.op(
        "work",
        2,
        &["addB"],
        OperationBody::AddDevice(device(3, "laptop", Role::Member, false)),
    );

    let mut roster = Roster::new();
    for entry in history.entries() {
        let admission = roster.offer_bytes(&entry.bytes);
        assert!(admission.is_accepted(), "{} refused: {admission:?}", entry.label);
    }
    let state = roster.state().expect("derives");
    assert!(state.devices.contains_key(&device_id(3)), "an admin's own work stands");
}

/// The other door into the graph. An operation whose parents have not arrived
/// waits in the pending set, and is let in when they do — so the check has to be
/// made there too, or offering a child before its parent is a way to walk past
/// admission entirely.
#[test]
fn an_unauthorised_operation_offered_before_its_parents_is_refused_when_they_arrive() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("addB", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Member, false)));
    // Authored by the member, anchored on `addB` — so by the time it can be
    // judged, its author is present and is plainly a member.
    history.op(
        "attack",
        2,
        &["addB"],
        OperationBody::AddDevice(device(3, "smuggled", Role::Member, false)),
    );

    let entries = history.entries();
    let mut roster = Roster::new();
    // Offered last-first: the attack waits for parents it does not have yet.
    for index in [2, 1, 0] {
        let entry = entries.get(index).expect("three operations");
        roster.offer_bytes(&entry.bytes);
    }

    let state = roster.state().expect("derives");
    assert!(
        !state.devices.contains_key(&device_id(3)),
        "integration from the pending set must apply the same rule as admission"
    );
    assert_eq!(
        roster.dag().len(),
        2,
        "and the operation occupies nothing: {:?}",
        roster.dag().len()
    );
    assert_eq!(roster.pending_count(), 0, "nothing is left waiting");
}

// ---------------------------------------------------------------------------
// What may void somebody else's work
// ---------------------------------------------------------------------------

/// Derivation over a graph assembled directly, without going through admission.
///
/// Admission now refuses most of what follows, so a node running this build never
/// builds such a graph from a peer. It can still be handed one: a log written by
/// an older build, or a snapshot from a node that has not been updated. These
/// tests are about what derivation makes of it, which is the question admission
/// cannot answer for graphs it did not assemble.
fn derived(history: &History) -> (RosterState, Vec<(String, String)>) {
    let operations: Vec<_> =
        history.entries().iter().map(|entry| history.verified(&entry.label)).collect();
    let dag = roster::dag::Dag::from_operations(operations).expect("the set places");
    let (state, verdicts) = derive_with_verdicts(&dag).expect("derives");

    let disregarded = history
        .entries()
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            verdicts.reason(index).map(|reason| (entry.label.clone(), reason.kind().to_owned()))
        })
        .collect();
    (state, disregarded)
}

/// An operation nobody was entitled to write removes nothing — including the
/// work of the device it names. Before this rule, a member's revocation of the
/// founder was void *and* took the founder's concurrent operations with it, so a
/// member who could not revoke anybody could still erase what they did.
#[test]
fn a_revocation_from_a_member_voids_nothing_but_itself() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("addB", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Member, false)));
    history.op(
        "attack",
        2,
        &["g"],
        OperationBody::RevokeDevice { device: device_id(1), reason: "mine now".to_owned() },
    );

    let (state, disregarded) = derived(&history);

    assert_eq!(
        disregarded,
        vec![("attack".to_owned(), "unauthorized_author".to_owned())],
        "only the member's own operation is disregarded"
    );
    assert!(state.devices.contains_key(&device_id(2)), "the founder's `addB` stands");
    assert!(!state.revoked.contains(&device_id(1)), "and the founder is not revoked");
}

/// The same rule where the author *is* an admin: a revocation refused by founder
/// protection is still no removal, so the founder's concurrent work stands.
#[test]
fn a_revocation_refused_by_founder_protection_voids_nothing_but_itself() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("addB", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Admin, false)));
    // Concurrent: both hang off `addB`.
    history.op(
        "work",
        1,
        &["addB"],
        OperationBody::AddDevice(device(3, "laptop", Role::Member, false)),
    );
    history.op(
        "retire",
        2,
        &["addB"],
        OperationBody::RevokeDevice { device: device_id(1), reason: "retiring you".to_owned() },
    );

    let (state, disregarded) = derived(&history);

    assert_eq!(
        disregarded,
        vec![("retire".to_owned(), "founder_protected".to_owned())],
        "the refused revocation, and nothing else"
    );
    assert!(
        state.devices.contains_key(&device_id(3)),
        "the founder's concurrent work stands: it was not removed by anything"
    );
    assert!(!state.revoked.contains(&device_id(1)));
}

/// And the case the rule is actually for, unchanged: a removal somebody *was*
/// entitled to make still voids the work concurrent with it.
#[test]
fn an_authorised_removal_still_voids_the_work_concurrent_with_it() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("addB", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Admin, false)));
    // The founder demotes B; B, not having seen it, adds a device concurrently.
    history.op("demoteB", 1, &["addB"], OperationBody::Demote { device: device_id(2) });
    history.op(
        "backdated",
        2,
        &["addB"],
        OperationBody::AddDevice(device(9, "backdoor", Role::Admin, false)),
    );

    let (state, disregarded) = derived(&history);

    assert_eq!(
        disregarded,
        vec![("backdated".to_owned(), "concurrent_with_author_removal".to_owned())],
        "the backdating rule still holds"
    );
    assert!(!state.devices.contains_key(&device_id(9)), "no backdoor device");
}

// ---------------------------------------------------------------------------
// Losing authority, and what survives it
// ---------------------------------------------------------------------------

/// Admission judges an operation against its own ancestors, so a node that
/// already holds a demotion still **admits** work anchored before it. Refusing
/// on the strength of what the node happens to hold would make admission depend
/// on the order a sync delivered things, and two nodes would end up holding
/// different graphs.
///
/// Whether that work then has effect is derivation's question, and a different
/// one: here it does not, because it is concurrent with the demotion, which is
/// the backdating rule doing its job. Admission is the more permissive of the
/// two on purpose.
#[test]
fn work_anchored_before_a_demotion_is_admitted_by_a_node_that_holds_the_demotion() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("addB", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Admin, false)));
    history.op("demoteB", 1, &["addB"], OperationBody::Demote { device: device_id(2) });
    // B, not having seen the demotion, keeps working from where it was.
    history.op(
        "work",
        2,
        &["addB"],
        OperationBody::AddDevice(device(3, "laptop", Role::Member, false)),
    );

    let entries = history.entries();
    let mut roster = Roster::new();
    // The demotion arrives first; the work it did not see arrives after.
    for index in [0, 1, 2, 3] {
        let entry = entries.get(index).expect("four operations");
        let admission = roster.offer_bytes(&entry.bytes);
        assert!(admission.is_accepted(), "{} must be admitted, got {admission:?}", entry.label);
    }
    assert_eq!(roster.dag().len(), 4, "all four are held");

    let state = roster.state().expect("derives");
    assert!(!state.is_admin(&device_id(2)), "the demotion took effect");
    assert!(
        !state.devices.contains_key(&device_id(3)),
        "and the concurrent work is void by the causal authorship rule, not by admission"
    );
}

/// The mirror: an operation that names the demotion among its ancestors is
/// refused, because in the state those ancestors imply its author is a member.
#[test]
fn work_descended_from_its_authors_demotion_is_refused() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("addB", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Admin, false)));
    history.op("demoteB", 1, &["addB"], OperationBody::Demote { device: device_id(2) });
    history.op(
        "after",
        2,
        &["demoteB"],
        OperationBody::AddDevice(device(3, "laptop", Role::Member, false)),
    );

    let mut roster = Roster::new();
    let mut refused = None;
    for entry in history.entries() {
        let admission = roster.offer_bytes(&entry.bytes);
        if entry.label == "after" {
            refused = admission.refusal().map(roster::error::Error::kind);
        }
    }

    assert_eq!(refused, Some("unauthorized_author"));
    assert_eq!(roster.dag().len(), 3, "and it occupies nothing");
}

// ---------------------------------------------------------------------------
// The proof of concept, reversed
// ---------------------------------------------------------------------------

/// The security review's finding F-02, as a test that now asserts the opposite.
///
/// The assessment ran this against the build of the time: four hundred
/// operations from a plain member were **all admitted**, in 1.65 s, and the cost
/// grew with the cube — about twenty-four minutes for a full roster, on every
/// node that received them. At the ceiling the founder's own revocation was
/// refused, and the network could never admit or revoke anybody again.
///
/// Now every one of them is refused, the graph does not grow, and the revocation
/// that mattered still fits.
#[test]
fn four_hundred_operations_from_a_member_fill_nothing() {
    const ATTEMPTS: usize = 400;

    let mut history = History::new();
    history.genesis("g", 1);
    history.op("addB", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Member, false)));

    let mut roster = Roster::new();
    for entry in history.entries() {
        assert!(roster.offer_bytes(&entry.bytes).is_accepted(), "{}", entry.label);
    }
    let held = roster.dag().len();

    // The member signs, and keeps signing. Each operation is well formed,
    // correctly signed, and anchored on the current head — everything an honest
    // client would do, from a device with no authority to do it.
    let mut parent = "addB".to_owned();
    for attempt in 0..ATTEMPTS {
        let label = format!("flood{attempt}");
        history.op(
            &label,
            2,
            &[parent.as_str()],
            OperationBody::Rename { device: device_id(2), name: format!("n{attempt}") },
        );
        let bytes = history.bytes(&label);
        let admission = roster.offer_bytes(&bytes);
        assert!(!admission.is_accepted(), "attempt {attempt} was admitted: {admission:?}");
        parent = label;
    }

    assert_eq!(roster.dag().len(), held, "the graph did not grow");

    // And the operation the attack was trying to make impossible still lands.
    history.op(
        "revoke",
        1,
        &["addB"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "flooding".to_owned() },
    );
    let admission = roster.offer_bytes(&history.bytes("revoke"));
    assert!(admission.is_accepted(), "the admin's revocation must still fit: {admission:?}");
    assert!(roster.state().expect("derives").revoked.contains(&device_id(2)));
}

/// An attacker chooses where to anchor. Refusing must not cost more when it
/// anchors somewhere awkward: a device never granted admin anywhere in the graph
/// is refused without any state being resolved for it, whatever parents it
/// names.
#[test]
fn a_member_is_refused_whatever_parents_it_names() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("addB", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Member, false)));
    for step in 0..6 {
        let label = format!("s{step}");
        let parent = if step == 0 { "addB".to_owned() } else { format!("s{}", step - 1) };
        history.op(
            &label,
            1,
            &[parent.as_str()],
            OperationBody::AddDevice(device(10 + step, "device", Role::Member, false)),
        );
    }

    let mut roster = Roster::new();
    for entry in history.entries() {
        assert!(roster.offer_bytes(&entry.bytes).is_accepted(), "{}", entry.label);
    }
    let held = roster.dag().len();

    // Anchored on the head, on the middle of the chain, and on the genesis:
    // every one is refused, and none of them grows the graph.
    for (attempt, parent) in ["s5", "s2", "addB", "g"].iter().enumerate() {
        let label = format!("attack{attempt}");
        history.op(
            &label,
            2,
            &[parent],
            OperationBody::AddDevice(device(
                30 + u8::try_from(attempt).expect("small"),
                "x",
                Role::Member,
                false,
            )),
        );
        let admission = roster.offer_bytes(&history.bytes(&label));
        assert_eq!(
            admission.refusal().map(roster::error::Error::kind),
            Some("unauthorized_author"),
            "anchored at {parent}: {admission:?}"
        );
    }
    assert_eq!(roster.dag().len(), held, "the graph did not grow");
}

// ---------------------------------------------------------------------------
// The kept state is only ever what derivation would say
// ---------------------------------------------------------------------------

/// The roster keeps the state at its heads instead of deriving it for every
/// operation offered. Kept state that drifted from derived state would be a
/// second answer to what the network is, so it is checked after **every**
/// admission, over a history that uses every operation type.
#[test]
fn the_kept_state_equals_derivation_after_every_admission() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Admin, false)));
    history.op("add3", 1, &["add2"], OperationBody::AddDevice(device(3, "c", Role::Member, false)));
    history.op(
        "rename3",
        2,
        &["add3"],
        OperationBody::Rename { device: device_id(3), name: "renamed".to_owned() },
    );
    history.op(
        "promote3",
        1,
        &["rename3"],
        OperationBody::Promote { device: device_id(3), founder: false },
    );
    history.op("demote3", 2, &["promote3"], OperationBody::Demote { device: device_id(3) });
    history.op(
        "params",
        1,
        &["demote3"],
        OperationBody::SetNetwork(
            roster::types::NetworkParams::new(
                vec![0xfd, 0x09, 0, 0, 0, 0, 0, 0],
                "altro.internal",
                2_592_000,
            )
            .expect("valid"),
        ),
    );
    history.op(
        "revoke3",
        1,
        &["params"],
        OperationBody::RevokeDevice { device: device_id(3), reason: "sold".to_owned() },
    );
    // A re-add of a revoked device, which must change nothing.
    history.op(
        "readd3",
        1,
        &["revoke3"],
        OperationBody::AddDevice(device(3, "c", Role::Member, false)),
    );

    let mut roster = Roster::new();
    for entry in history.entries() {
        let admission = roster.offer_bytes(&entry.bytes);
        assert!(admission.is_accepted() || admission.refusal().is_some(), "{:?}", admission);
        assert_eq!(
            roster.state().ok().map(|state| state.to_bytes()),
            roster.derived_state().ok().map(|state| state.to_bytes()),
            "after {}, the kept state is not what derivation says",
            entry.label
        );
    }

    let state = roster.state().expect("derives");
    assert_eq!(state.params.suffix, "altro.internal");
    assert!(state.revoked.contains(&device_id(3)));
    assert!(!state.devices.contains_key(&device_id(3)), "a revoked device does not come back");
}

/// The same, where the graph is not a chain: a merge, and an operation offered
/// before its parents. Neither can be followed by applying one operation, so the
/// roster must derive — and the result must still match.
#[test]
fn the_kept_state_equals_derivation_when_the_graph_is_not_a_chain() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Admin, false)));
    history.op("left", 1, &["add2"], OperationBody::AddDevice(device(4, "l", Role::Member, false)));
    history.op(
        "right",
        2,
        &["add2"],
        OperationBody::AddDevice(device(5, "r", Role::Member, false)),
    );
    history.op(
        "merge",
        1,
        &["left", "right"],
        OperationBody::AddDevice(device(6, "m", Role::Member, false)),
    );

    // Offered out of order, so the pending set holds some of it.
    let entries = history.entries();
    let mut roster = Roster::new();
    for index in [4, 2, 0, 3, 1] {
        let entry = entries.get(index).expect("five operations");
        roster.offer_bytes(&entry.bytes);
        assert_eq!(
            roster.state().ok().map(|state| state.to_bytes()),
            roster.derived_state().ok().map(|state| state.to_bytes()),
            "after offering {}, the kept state is not what derivation says",
            entry.label
        );
    }
    assert_eq!(roster.pending_count(), 0, "everything was placed");
    assert_eq!(roster.dag().len(), 5);
}

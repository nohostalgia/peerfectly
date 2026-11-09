//! A light member: what it holds, what it learns, and what it forgets.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod support;

use roster::member::{DEFAULT_BUDGET, LightMember};
use roster::roster::Roster;
use roster::sign::Signer as _;
use roster::snapshot::{Covering, Snapshot, sign_snapshot};
use roster::state::RosterState;
use roster::types::{OperationBody, Role};
use support::{History, device, device_id, signer};

/// A network of the founder and three members.
fn history() -> History {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op(
        "two",
        1,
        &["g"],
        OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
    );
    history.op(
        "three",
        1,
        &["two"],
        OperationBody::AddDevice(device(3, "phone", Role::Member, false)),
    );
    history.op(
        "four",
        1,
        &["three"],
        OperationBody::AddDevice(device(4, "sensor", Role::Member, false)),
    );
    history
}

fn loaded(history: &History) -> Roster {
    let mut roster = Roster::new();
    for entry in history.entries() {
        let _ = roster.offer_bytes(&entry.bytes);
    }
    roster
}

/// A root over what `roster` holds, signed by the founder, following
/// `previous` where given.
fn root_of(roster: &Roster, previous: Option<(&Snapshot, &RosterState)>) -> (Vec<u8>, Snapshot) {
    let state = roster.state().unwrap();
    let heads = roster.heads();
    let depths =
        heads.iter().map(|head| roster.dag().depth(roster.dag().position(head).unwrap())).collect();
    let body =
        Snapshot::over(&state, Covering { heads, depths }, signer(1).key_id(), previous).unwrap();
    (sign_snapshot(&body, &signer(1)).unwrap(), body)
}

/// The full member's roster holding the first root, and that root.
fn rooted(history: &History) -> (Roster, Vec<u8>, Snapshot) {
    let mut roster = loaded(history);
    let (bytes, body) = root_of(&roster, None);
    assert!(roster.offer_snapshot(&bytes).is_accepted());
    (roster, bytes, body)
}

#[test]
fn a_light_member_knows_itself_and_the_peers_it_checked_and_keeps_them() {
    let history = history();
    let (full, _, _) = rooted(&history);
    let mut member = LightMember::new(
        full.evidence_for(&device_id(2)).unwrap(),
        full.state().unwrap().params,
        DEFAULT_BUDGET,
    )
    .unwrap();
    assert_eq!(member.contact(), device_id(1), "the admin whose root it holds");
    assert_eq!(member.state().devices.len(), 2, "itself and its contact, nobody else yet");
    assert!(!member.needs_renewal());

    let peer = full.evidence_for(&device_id(3)).unwrap().to_bytes();
    assert_eq!(member.learn(&peer).unwrap(), device_id(3));
    let state = member.state();
    assert!(state.devices.contains_key(&device_id(3)));
    assert!(!state.devices.contains_key(&device_id(4)), "only what it checked");

    let kept = LightMember::from_bytes(&member.to_bytes()).unwrap();
    assert_eq!(kept, member, "it reads back as it was");
}

#[test]
fn a_root_revoking_a_peer_makes_the_member_forget_it() {
    let mut history = history();
    let (full, first, first_body) = rooted(&history);
    let first_state = full.state().unwrap();
    let mut member = LightMember::new(
        full.evidence_for(&device_id(2)).unwrap(),
        first_state.params.clone(),
        DEFAULT_BUDGET,
    )
    .unwrap();
    member.learn(&full.evidence_for(&device_id(3)).unwrap().to_bytes()).unwrap();
    let _ = first;

    history.op(
        "revoke",
        1,
        &["four"],
        OperationBody::RevokeDevice { device: device_id(3), reason: "stolen".into() },
    );
    let later = loaded(&history);
    let (second, _) = root_of(&later, Some((&first_body, &first_state)));

    assert_eq!(member.offer_root(&second).unwrap(), roster::light::RootOutcome::Adopted);
    assert!(!member.state().devices.contains_key(&device_id(3)), "the revoked peer is forgotten");
    assert!(!member.needs_renewal(), "its own proof still stands: the delta does not name it");

    // And its old evidence is not taken again.
    assert!(member.learn(&full.evidence_for(&device_id(3)).unwrap().to_bytes()).is_err());
}

#[test]
fn a_member_named_in_a_delta_must_renew() {
    let mut history = history();
    let (full, _, first_body) = rooted(&history);
    let first_state = full.state().unwrap();
    let mut member = LightMember::new(
        full.evidence_for(&device_id(2)).unwrap(),
        first_state.params.clone(),
        DEFAULT_BUDGET,
    )
    .unwrap();
    history.op(
        "rename",
        1,
        &["four"],
        OperationBody::Rename { device: device_id(2), name: "renamed".into() },
    );
    let mut later = loaded(&history);
    let (second, _) = root_of(&later, Some((&first_body, &first_state)));
    member.offer_root(&second).unwrap();
    assert!(member.needs_renewal(), "a delta names it");

    assert!(later.offer_snapshot(&second).is_accepted());
    member.renew(later.evidence_for(&device_id(2)).unwrap()).unwrap();
    assert!(!member.needs_renewal());
    assert_eq!(member.state().devices.get(&device_id(2)).unwrap().name, "renamed");
}

#[test]
fn a_member_that_missed_roots_takes_the_chain_and_then_the_root() {
    let mut history = history();
    let (mut full, _, first_body) = rooted(&history);
    let first_state = full.state().unwrap();
    let mut member = LightMember::new(
        full.evidence_for(&device_id(2)).unwrap(),
        first_state.params.clone(),
        DEFAULT_BUDGET,
    )
    .unwrap();

    // Two roots the member does not see, the full member takes both.
    history.op(
        "r1",
        1,
        &["four"],
        OperationBody::Rename { device: device_id(4), name: "a".into() },
    );
    let second_roster = loaded(&history);
    let second_state = second_roster.state().unwrap();
    let (second, second_body) = root_of(&second_roster, Some((&first_body, &first_state)));
    history.op("r2", 1, &["r1"], OperationBody::Rename { device: device_id(4), name: "b".into() });
    let third_roster = loaded(&history);
    let (third, _) = root_of(&third_roster, Some((&second_body, &second_state)));
    let mut full_later = loaded(&history);
    assert!(full_later.offer_snapshot(&full.snapshot().unwrap().to_bytes()).is_accepted());
    assert!(full_later.offer_snapshot(&second).is_accepted());
    assert!(full_later.offer_snapshot(&third).is_accepted());
    let _ = &mut full;

    assert_eq!(member.offer_root(&third).unwrap(), roster::light::RootOutcome::NeedsChain);
    let chain = full_later.roots_after(&member.current().unwrap());
    assert_eq!(chain.len(), 2, "what it missed, and the current one");
    for root in &chain {
        let _ = member.offer_root(root).unwrap();
    }
    assert_eq!(
        member.current(),
        Some(roster::snapshot::RawSnapshot::decode(&third).unwrap().body().root)
    );
}

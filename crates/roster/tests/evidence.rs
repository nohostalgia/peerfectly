//! What a member shows a peer as a session opens, and what that peer can
//! conclude from it.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod support;

use roster::membership::Evidence;
use roster::roster::Roster;
use roster::types::{KeyPurpose, OperationBody, Role};
use support::{History, device, device_id};

/// A network of three with a root over all of it: the roster holding it.
fn rooted() -> Roster {
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
    let mut roster = Roster::new();
    for entry in history.entries() {
        assert!(roster.offer_bytes(&entry.bytes).is_accepted());
    }
    assert!(roster.offer_snapshot(&history.snapshot_at(1, 1, &["three"])).is_accepted());
    roster
}

fn transport_key_of(seed: u8) -> roster::id::KeyId {
    device(seed, "x", Role::Member, false)
        .keys
        .iter()
        .find(|entry| entry.purpose == KeyPurpose::Transport)
        .unwrap()
        .key_id()
}

#[test]
fn a_members_evidence_shows_it_and_round_trips() {
    let roster = rooted();
    let evidence = roster.evidence_for(&device_id(2)).expect("a member under the held root");
    assert_eq!(Evidence::from_bytes(&evidence.to_bytes()).unwrap(), evidence);
    let (shown, root) = evidence.shows(&transport_key_of(2)).unwrap();
    assert_eq!(shown, device_id(2));
    assert_eq!(root.body().root, roster.snapshot().unwrap().body().root);
}

#[test]
fn a_proof_of_another_devices_leaf_is_refused() {
    let roster = rooted();
    let theirs = roster.evidence_for(&device_id(3)).unwrap();
    assert!(theirs.shows(&transport_key_of(2)).is_err(), "device 2 presenting device 3's leaf");
}

#[test]
fn evidence_against_another_root_does_not_prove() {
    let roster = rooted();
    let mut evidence = roster.evidence_for(&device_id(2)).unwrap();
    let mut history = History::new();
    history.genesis("g", 9);
    let mut other = Roster::new();
    for entry in history.entries() {
        let _ = other.offer_bytes(&entry.bytes);
    }
    evidence.root = history.snapshot_at(1, 9, &["g"]);
    assert!(evidence.shows(&transport_key_of(2)).is_err());
}

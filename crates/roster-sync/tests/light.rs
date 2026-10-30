//! A light member's session: roots and answers cross it, operations never do.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod common;

use common::Fixture;
use roster::id::DeviceId;
use roster::leaf::{Mode, SettingsChange};
use roster_sync::error::Error;
use roster_sync::message::{Message, Offer};

/// A network with a phone admitted and then made light, and a laptop left
/// full: the fixture and the two devices.
fn with_a_light_member() -> (Fixture, DeviceId, DeviceId) {
    let mut fixture = Fixture::found();
    let phone = fixture.add_member("phone").device_id();
    let laptop = fixture.add_member("laptop").device_id();
    fixture
        .set_device(phone, SettingsChange { mode: Some(Mode::Light), ..SettingsChange::default() });
    (fixture, phone, laptop)
}

#[test]
fn a_light_member_is_sent_roots_and_never_operations() {
    let (fixture, phone, laptop) = with_a_light_member();
    let node = fixture.syncer_with_snapshot(1);
    assert!(node.is_light(&phone));
    assert!(!node.is_light(&laptop));

    let transfer = Message::Transfer(vec![fixture.last().to_vec()]);
    assert_eq!(node.for_peer(&phone, transfer.clone()), None, "no operation");
    assert_eq!(node.for_peer(&phone, Message::Pieces(vec![vec![1]])), None, "no piece");
    assert_eq!(node.for_peer(&phone, Message::Offer(node.offer())), None, "no offer");
    assert_eq!(
        node.for_peer(&phone, node.greeting()),
        None,
        "no greeting: the root is in the evidence shown as the session opened"
    );
    let root = Message::Snapshot(vec![9]);
    assert_eq!(node.for_peer(&phone, root.clone()), Some(root), "a root taken later still goes");
    let attestation = Message::Attestation(vec![7]);
    assert_eq!(node.for_peer(&phone, attestation.clone()), Some(attestation));

    // A full member is sent all of it, as before.
    assert_eq!(node.for_peer(&laptop, transfer.clone()), Some(transfer));
    assert!(matches!(node.for_peer(&laptop, node.greeting()), Some(Message::Digest(_))));
}

#[test]
fn operations_from_a_light_member_are_refused_unread() {
    let (fixture, phone, _) = with_a_light_member();
    let mut node = fixture.syncer_through(fixture.operations.len());
    let before = node.roster().dag().len();

    let offered = node.receive(
        phone,
        &Message::Offer(Offer { ids: Vec::new(), snapshot: None, root: None, partial: Vec::new() })
            .encode(),
    );
    assert!(offered.replies.is_empty(), "nothing is sent for its offer");
    assert!(matches!(
        offered.refusals.first().map(|refusal| &refusal.reason),
        Some(Error::FromLightMember { .. })
    ));

    let branch = fixture.branch(fixture.head(), 1, "renamed");
    let sent = node.receive(phone, &Message::Transfer(vec![branch]).encode());
    assert!(sent.admitted.is_empty() && sent.forward.is_none());
    assert_eq!(node.roster().dag().len(), before, "and nothing enters the graph");
}

#[test]
fn a_light_members_digest_is_answered_with_the_root() {
    let (fixture, phone, _) = with_a_light_member();
    let mut node = fixture.syncer_with_snapshot(1);
    let greeting = node.greeting();
    let answered = node.receive(phone, &greeting.encode());
    assert_eq!(answered.replies.len(), 1);
    assert!(matches!(answered.replies.first(), Some(Message::Snapshot(_))));
    assert!(answered.refusals.is_empty());
}

#[test]
fn a_root_adopted_from_a_peer_is_passed_on_once() {
    let (fixture, _, laptop) = with_a_light_member();
    let held = fixture.roster();
    let root = fixture.snapshot_bytes(&held, 1);
    let mut node = fixture.syncer();

    let first = node.receive(laptop, &Message::Snapshot(root.clone()).encode());
    assert_eq!(first.forward, Some(Message::Snapshot(root.clone())), "to every other session");
    let again = node.receive(laptop, &Message::Snapshot(root).encode());
    assert_eq!(again.forward, None, "and not a second time");
}

#[test]
fn sibling_roots_of_one_generation_converge_on_the_heavier() {
    let (fixture, _, laptop) = with_a_light_member();
    let founder = fixture.founder.device_id();
    // Two roots of generation 1, over the state at two different moments, as
    // two admins acting at once would publish them.
    let earlier = fixture.snapshot_bytes(&fixture.roster_through(2), 1);
    let later = fixture.snapshot_bytes(&fixture.roster(), 1);
    let mut left = roster_sync::Syncer::new(fixture.roster());
    let mut right = roster_sync::Syncer::new(fixture.roster());
    assert!(left.roster_mut().offer_snapshot(&earlier).is_accepted());
    assert!(right.roster_mut().offer_snapshot(&later).is_accepted());
    assert_ne!(left.digest(), right.digest(), "the same operations, different roots");

    let mut to_left = vec![right.greeting()];
    let mut to_right = vec![left.greeting()];
    for _ in 0..6 {
        let next_right: Vec<Message> = to_left
            .drain(..)
            .flat_map(|message| left.receive(laptop, &message.encode()).replies)
            .collect();
        let next_left: Vec<Message> = to_right
            .drain(..)
            .flat_map(|message| right.receive(founder, &message.encode()).replies)
            .collect();
        to_left = next_left;
        to_right = next_right;
    }
    let held = |node: &roster_sync::Syncer| node.roster().snapshot().map(|root| root.body().root);
    assert_eq!(held(&left), held(&right), "both hold the heavier");
}

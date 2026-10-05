//! The pending set, divided fairly.
//!
//! `roster`'s `FORMAT.md` §19 names the attack these tests exist for: pending
//! entries are unverified by necessity, the set is bounded, and one peer that
//! can fill it can stop the `revoke_device` that names that peer from ever
//! finding somewhere to wait. Reserving space for revocations does not help —
//! an attacker labels junk as one.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod common;

use common::{Fixture, held, orphans};
use roster::id::DeviceId;
use roster_sync::Error;
use roster_sync::limits::PENDING_PER_PEER;
use roster_sync::message::Message;

fn attacker() -> DeviceId {
    DeviceId::from_bytes([0x66; 32])
}

fn honest() -> DeviceId {
    DeviceId::from_bytes([0x11; 32])
}

/// Feeds orphans from one peer until it is refused, and reports how many landed.
fn flood(node: &mut roster_sync::Syncer, peer: DeviceId, count: usize) -> usize {
    let mut refused = 0usize;
    for bytes in orphans(count) {
        let outcome = node.receive(peer, &Message::Transfer(vec![bytes]).encode());
        refused = refused.saturating_add(outcome.refusals.len());
    }
    refused
}

#[test]
fn one_peer_cannot_fill_the_pending_set() {
    let mut fixture = Fixture::found();
    fixture.extend(2);
    let mut node = fixture.syncer();

    let refused = flood(&mut node, attacker(), PENDING_PER_PEER * 3);

    assert_eq!(
        node.charged_to(&attacker()),
        PENDING_PER_PEER,
        "a peer's pending entries stop at its share"
    );
    assert!(refused > 0, "everything past the share is refused");
}

#[test]
fn a_refusal_past_the_quota_names_the_bound() {
    let mut fixture = Fixture::found();
    fixture.extend(2);
    let mut node = fixture.syncer();

    flood(&mut node, attacker(), PENDING_PER_PEER);

    let one_more = orphans(PENDING_PER_PEER + 1).pop().expect("an orphan");
    let outcome = node.receive(attacker(), &Message::Transfer(vec![one_more]).encode());

    match &outcome.refusals.first().expect("a refusal").reason {
        Error::OverQuota { peer, limit } => {
            assert_eq!(*peer, attacker());
            assert_eq!(*limit, PENDING_PER_PEER);
        }
        other => panic!("expected a quota refusal naming the bound, got {other:?}"),
    }
}

/// The central case. A peer floods the pending set to its share; a revocation
/// arriving from a different peer, with its parent momentarily absent, must
/// still find somewhere to wait — and must integrate when the parent lands.
#[test]
fn a_flood_from_one_peer_does_not_block_a_revocation_from_another() {
    let mut fixture = Fixture::found();
    let laptop = fixture.add_member("laptop");
    fixture.extend(4);
    let parent_index = fixture.operations.len();
    fixture.extend(1);
    fixture.revoke(laptop.device_id());

    // The node is behind by two: it lacks the revocation and the operation
    // before it.
    let mut node = fixture.syncer_through(parent_index);
    let parent = fixture.operation(parent_index).to_vec();
    let revocation = fixture.last().to_vec();

    // The attacker takes its entire share.
    flood(&mut node, attacker(), PENDING_PER_PEER * 2);
    assert_eq!(node.charged_to(&attacker()), PENDING_PER_PEER);

    // The revocation arrives from an honest peer, out of order.
    let held_out_of_order = node.receive(honest(), &Message::Transfer(vec![revocation]).encode());
    assert!(
        held_out_of_order.is_clean(),
        "the revocation must be held, not refused: {:?}",
        held_out_of_order.refusals
    );
    assert_eq!(node.charged_to(&honest()), 1, "it is waiting, charged to the honest peer");

    // Its parent follows, and it integrates.
    node.receive(honest(), &Message::Transfer(vec![parent]).encode());

    let state = node.roster().state().expect("derives");
    assert!(
        state.revoked.contains(&laptop.device_id()),
        "a flood must never stop a revocation from landing"
    );
}

#[test]
fn nothing_already_pending_is_evicted() {
    let mut fixture = Fixture::found();
    fixture.extend(2);
    let mut node = fixture.syncer();

    // Fill from several peers so the roster's overall bound is what binds.
    let peers: Vec<DeviceId> = (0u8..10).map(|tag| DeviceId::from_bytes([tag; 32])).collect();
    for peer in &peers {
        flood(&mut node, *peer, PENDING_PER_PEER);
    }

    let before: Vec<_> = node.roster().pending_ids();
    assert!(!before.is_empty(), "there is something pending to protect");

    // One more offer, from a fresh peer, at the overall bound.
    let extra = DeviceId::from_bytes([0xee; 32]);
    let one_more = orphans(1).pop().expect("an orphan");
    node.receive(extra, &Message::Transfer(vec![one_more]).encode());

    let after: Vec<_> = node.roster().pending_ids();
    for id in &before {
        assert!(
            after.contains(id),
            "every entry pending before the offer must still be pending after it"
        );
    }
}

#[test]
fn reconnecting_does_not_renew_a_quota() {
    let mut fixture = Fixture::found();
    fixture.extend(2);
    let mut node = fixture.syncer();

    flood(&mut node, attacker(), PENDING_PER_PEER);
    assert_eq!(node.charged_to(&attacker()), PENDING_PER_PEER);

    // A new session is, to the syncer, simply the same device again: the quota
    // is keyed on the authenticated device, never on the session. There is
    // nowhere for a per-session counter to live, which is what makes this hold.
    let greeting = node.greeting().encode();
    node.receive(attacker(), &greeting);

    let one_more = orphans(2).pop().expect("an orphan");
    let outcome = node.receive(attacker(), &Message::Transfer(vec![one_more]).encode());

    assert!(
        matches!(
            outcome.refusals.first().map(|refusal| &refusal.reason),
            Some(Error::OverQuota { .. })
        ),
        "the quota survives a reconnect: {:?}",
        outcome.refusals
    );
    assert_eq!(node.charged_to(&attacker()), PENDING_PER_PEER);
}

#[test]
fn supplying_the_missing_parents_frees_the_quota() {
    let mut fixture = Fixture::found();
    fixture.extend(6);

    // The node lacks the last two operations, and is sent them backwards so the
    // later one waits.
    let mut node = fixture.syncer_through(fixture.operations.len() - 2);
    let parent = fixture.operation(fixture.operations.len() - 2).to_vec();
    let child = fixture.last().to_vec();

    node.receive(honest(), &Message::Transfer(vec![child]).encode());
    assert_eq!(node.charged_to(&honest()), 1, "the child waits");

    node.receive(honest(), &Message::Transfer(vec![parent]).encode());

    assert_eq!(node.charged_to(&honest()), 0, "supplying the parent frees the charge");
    assert_eq!(held(node.roster()).len(), fixture.operations.len(), "both landed");
}

#[test]
fn a_quota_refusal_is_distinguishable_from_a_rejection() {
    let mut fixture = Fixture::found();
    fixture.extend(3);

    let mut node = fixture.syncer_through(1);
    flood(&mut node, attacker(), PENDING_PER_PEER);

    // Over quota: says nothing about the operation.
    let orphan = orphans(2).pop().expect("an orphan");
    let throttled = node.receive(attacker(), &Message::Transfer(vec![orphan]).encode());
    let throttle_reason = &throttled.refusals.first().expect("a refusal").reason;
    assert!(throttle_reason.is_about_the_sender());
    assert!(!throttle_reason.is_about_the_content());

    // Forged: says everything about the operation, and nothing about who sent
    // it — an honest peer may be relaying someone else's forgery.
    let mut forged = fixture.operation(1).to_vec();
    let last = forged.len().saturating_sub(1);
    if let Some(byte) = forged.get_mut(last) {
        *byte ^= 0xff;
    }
    let rejected = node.receive(honest(), &Message::Transfer(vec![forged]).encode());
    let reject_reason = &rejected.refusals.first().expect("a refusal").reason;
    assert!(reject_reason.is_about_the_content());
    assert!(!reject_reason.is_about_the_sender());
}

#[test]
fn a_quota_refusal_never_ends_a_session() {
    let mut fixture = Fixture::found();
    fixture.extend(2);
    let mut node = fixture.syncer();

    flood(&mut node, attacker(), PENDING_PER_PEER * 2);

    let orphan = orphans(3).pop().expect("an orphan");
    let outcome = node.receive(attacker(), &Message::Transfer(vec![orphan]).encode());

    assert!(
        !outcome.refusals.iter().any(|refusal| refusal.reason.is_session_over()),
        "throttling is not disconnection"
    );

    // And the peer is still heard for anything valid.
    let mut fresh = Fixture::found();
    fresh.extend(1);
    let mut other = fresh.syncer_through(1);
    flood(&mut other, attacker(), PENDING_PER_PEER * 2);
    let accepted =
        other.receive(attacker(), &Message::Transfer(vec![fresh.operation(1).to_vec()]).encode());
    assert_eq!(accepted.admitted.len(), 1, "a throttled peer is still heard");
}

#[test]
fn a_peer_is_charged_once_for_the_same_operation() {
    let mut fixture = Fixture::found();
    fixture.extend(2);
    let mut node = fixture.syncer();

    let orphan = orphans(1).pop().expect("an orphan");
    for _ in 0..5 {
        node.receive(attacker(), &Message::Transfer(vec![orphan.clone()]).encode());
    }

    assert_eq!(
        node.charged_to(&attacker()),
        1,
        "re-offering something already pending must not be billed again"
    );
}

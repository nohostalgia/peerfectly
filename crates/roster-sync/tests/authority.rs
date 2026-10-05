//! What a peer gains by offering operations it has no authority to write.
//!
//! Nothing, is the answer this pins. `roster` refuses such an operation before it
//! reaches the graph, and this is the sync layer's side of it: the refusal is
//! reported against the peer that sent it, the graph does not grow, and what the
//! node forwards to everybody else is unchanged — which is what stopped the
//! attack of the security review's finding F-02 from spreading node to node.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod common;

use common::Fixture;
use roster::types::{OperationBody, OperationCore};
use roster_sync::message::Message;

/// A member of the network offers operations it may not write.
#[test]
fn a_member_offering_operations_fills_nothing() {
    const ATTEMPTS: usize = 20;

    let mut fixture = Fixture::found();
    let member = fixture.add_member("laptop");
    let mut node = fixture.syncer();

    let before = node.roster().dag().len();
    let peer = member.device_id();
    // Every attempt anchored on the node's real head, which is what does the
    // most damage: an operation anchored on a refused one merely waits for a
    // parent that will never arrive.
    let head = fixture.head();
    let mut refusals = 0usize;

    for attempt in 0..ATTEMPTS {
        let core = OperationCore::new(
            1_000 + attempt as u64,
            member.signing_key().algorithm(),
            OperationBody::Rename { device: member.device_id(), name: format!("mine-{attempt}") },
            vec![head],
            member.signing_key().key_id(),
            fixture.network,
        )
        .expect("well-formed");
        let bytes = member.sign_operation(&core).expect("signs");

        let outcome = node.receive(peer, &Message::Transfer(vec![bytes]).encode());
        refusals = refusals.saturating_add(outcome.refusals.len());
    }

    assert_eq!(refusals, ATTEMPTS, "every one is refused, and every refusal is reported");
    assert_eq!(node.roster().dag().len(), before, "and the node holds what it held before");
    assert_eq!(
        node.charged_to(&peer),
        0,
        "nothing is waiting for parents, so nothing is charged against the peer's share"
    );
}

/// The refusal carries the roster's own reason, so an operator can tell a peer
/// sending junk from a peer that is merely behind.
#[test]
fn the_refusal_says_the_author_had_no_authority() {
    let mut fixture = Fixture::found();
    let member = fixture.add_member("laptop");
    let mut node = fixture.syncer();

    let core = OperationCore::new(
        1_000,
        member.signing_key().algorithm(),
        OperationBody::Rename { device: member.device_id(), name: "mine".to_owned() },
        vec![fixture.head()],
        member.signing_key().key_id(),
        fixture.network,
    )
    .expect("well-formed");
    let bytes = member.sign_operation(&core).expect("signs");

    let outcome = node.receive(member.device_id(), &Message::Transfer(vec![bytes]).encode());
    let refusal = outcome.refusals.first().expect("one refusal");
    assert_eq!(refusal.peer, member.device_id(), "charged to the peer that sent it");
    assert!(
        format!("{:?}", refusal.reason).contains("UnauthorizedAuthor"),
        "the roster's reason survives: {:?}",
        refusal.reason
    );
}

/// The other shape: each attempt anchored on the last one, so only the first is
/// judged and the rest wait for a parent that will never arrive. They wait
/// inside the sender's own share of the pending set, which is what bounds this.
#[test]
fn a_chain_of_unauthorised_operations_waits_inside_its_senders_share() {
    let mut fixture = Fixture::found();
    let member = fixture.add_member("laptop");
    let mut node = fixture.syncer();

    let before = node.roster().dag().len();
    let peer = member.device_id();
    let mut head = fixture.head();

    for attempt in 0..(roster_sync::limits::PENDING_PER_PEER * 2) {
        let core = OperationCore::new(
            1_000 + attempt as u64,
            member.signing_key().algorithm(),
            OperationBody::Rename { device: member.device_id(), name: format!("mine-{attempt}") },
            vec![head],
            member.signing_key().key_id(),
            fixture.network,
        )
        .expect("well-formed");
        head = core.id();
        let bytes = member.sign_operation(&core).expect("signs");
        node.receive(peer, &Message::Transfer(vec![bytes]).encode());
    }

    assert_eq!(node.roster().dag().len(), before, "the graph never grew");
    assert!(
        node.charged_to(&peer) <= roster_sync::limits::PENDING_PER_PEER,
        "waiting costs the sender its own share and no more: {}",
        node.charged_to(&peer)
    );
}

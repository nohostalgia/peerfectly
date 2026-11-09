//! A full member that holds nothing, joining a network whose peers have
//! compacted: it is given the root, asks for the state behind it, and rests on
//! it.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod common;

use common::{Fixture, membership};
use roster::id::DeviceId;
use roster::roster::Roster;
use roster_sync::Syncer;
use roster_sync::message::Message;

/// A node of a long-lived network that compacted beneath its first root: the
/// fixture, and the node.
fn compacted() -> (Fixture, Syncer) {
    let mut fixture = Fixture::found();
    fixture.add_member("phone");
    fixture.add_member("laptop");
    fixture.add_member("printer");
    let root = fixture.snapshot_bytes(&fixture.roster_through(4), 1);
    fixture.extend(12);

    let mut node = Roster::with_staleness_depth(2);
    for bytes in &fixture.operations {
        assert!(node.offer_bytes(bytes).is_accepted());
    }
    assert!(node.offer_snapshot(&root).is_accepted());
    let discarded = node.compact().unwrap();
    assert!(discarded > 0, "the history beneath the root is gone");
    (fixture, Syncer::new(node))
}

/// Delivers every message to `to` as from `from_id`, and returns its replies
/// and what it reported.
fn deliver(
    to: &mut Syncer,
    from_id: DeviceId,
    messages: Vec<Message>,
) -> (Vec<Message>, Vec<roster_sync::syncer::Reception>) {
    let mut replies = Vec::new();
    let mut receptions = Vec::new();
    for message in messages {
        let reception = to.receive(from_id, &message.encode());
        replies.extend(reception.replies.clone());
        receptions.push(reception);
    }
    (replies, receptions)
}

#[test]
fn a_new_full_member_rests_on_the_state_behind_the_root() {
    let (_fixture, mut old) = compacted();
    let mut new = Syncer::new(Roster::new());
    let (old_id, new_id) = (DeviceId::from_bytes([0xa1; 32]), DeviceId::from_bytes([0xb2; 32]));
    let root = old.roster().snapshot().unwrap().to_bytes();

    // Given the root, it asks for the state.
    let (asked, _) = deliver(&mut new, old_id, vec![Message::Snapshot(root)]);
    assert!(matches!(asked.as_slice(), [Message::StateRequest(_)]), "{asked:?}");

    // The heads it covers, then the state in pieces.
    let (answer, _) = deliver(&mut old, new_id, asked);
    assert!(matches!(answer.first(), Some(Message::Transfer(_))));
    assert!(answer.iter().any(|message| matches!(message, Message::State(state) if state.last)));
    let (_, receptions) = deliver(&mut new, old_id, answer);
    let based = receptions.iter().find_map(|reception| reception.base.clone());
    let (_, state) = based.expect("it rests on a base, and says so for keeping");
    assert_eq!(state.root(), old.roster().dag().base_state().unwrap().root());
    assert!(
        receptions.iter().any(|reception| !reception.accepted.is_empty()),
        "the heads are kept"
    );

    // The rest is ordinary reconciliation.
    let mut to_new = vec![old.greeting()];
    let mut to_old = vec![new.greeting()];
    for _ in 0..6 {
        let (next_old, _) = deliver(&mut new, old_id, std::mem::take(&mut to_new));
        let (next_new, _) = deliver(&mut old, new_id, std::mem::take(&mut to_old));
        to_old = next_old;
        to_new = next_new;
    }
    assert_eq!(new.digest(), old.digest(), "it holds what the old member holds");
    assert_eq!(membership(new.roster()), membership(old.roster()));
    assert_eq!(new.roster().state().unwrap().root(), old.roster().state().unwrap().root());
}

#[test]
fn a_state_that_does_not_make_the_root_is_refused() {
    let (fixture, mut old) = compacted();
    let mut new = Syncer::new(Roster::new());
    let (old_id, new_id) = (DeviceId::from_bytes([0xa1; 32]), DeviceId::from_bytes([0xb2; 32]));
    let root = old.roster().snapshot().unwrap().to_bytes();
    let (asked, _) = deliver(&mut new, old_id, vec![Message::Snapshot(root)]);
    let (answer, _) = deliver(&mut old, new_id, asked);

    // The pieces of another state, labelled with the root asked for.
    let other = roster::transfer::pieces_of(&fixture.roster().state().unwrap());
    let forged: Vec<Message> = answer
        .into_iter()
        .map(|message| match message {
            Message::State(mut state) => {
                state.pieces = other.clone();
                Message::State(state)
            }
            other => other,
        })
        .collect();
    let (_, receptions) = deliver(&mut new, old_id, forged);
    assert!(receptions.iter().all(|reception| reception.base.is_none()));
    assert!(receptions.iter().any(|reception| !reception.refusals.is_empty()));
    assert!(new.roster().dag().is_empty(), "nothing is taken");
}

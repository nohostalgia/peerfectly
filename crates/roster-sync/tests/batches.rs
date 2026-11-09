//! Batches crossing a sync: what a node does while it holds a header and not
//! yet every piece.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod common;

use common::{Fixture, membership};
use identity::NodeIdentity;
use roster::batch::{BatchEntry, BatchHeader, pieces_of};
use roster::id::{DeviceId, OperationId};
use roster::leaf::Mode;
use roster::roster::Roster;
use roster::types::{OperationBody, Role};
use roster_sync::Syncer;
use roster_sync::message::Message;

/// Pieces delivered to each side over one exchange.
#[derive(Debug, Default)]
struct Delivered {
    to_left: usize,
    to_right: usize,
}

/// Both sides greet, and replies are delivered until neither has more to say.
/// Pieces are delivered only where `carry_pieces` says, so a test can stand
/// for a node still waiting on them.
fn reconcile(
    left: &mut Syncer,
    left_id: DeviceId,
    right: &mut Syncer,
    right_id: DeviceId,
    carry_pieces: bool,
) -> Delivered {
    let mut delivered = Delivered::default();
    let count = |message: &Message| match message {
        Message::Pieces(pieces) => pieces.len(),
        _ => 0,
    };
    let carried = |message: &Message| carry_pieces || !matches!(message, Message::Pieces(_));
    let mut to_left = vec![right.greeting()];
    let mut to_right = vec![left.greeting()];
    for _ in 0..8 {
        if to_left.is_empty() && to_right.is_empty() {
            return delivered;
        }
        let mut next_left = Vec::new();
        let mut next_right = Vec::new();
        for message in to_left.drain(..).filter(|message| carried(message)) {
            delivered.to_left = delivered.to_left.saturating_add(count(&message));
            next_right.extend(left.receive(right_id, &message.encode()).replies);
        }
        for message in to_right.drain(..).filter(|message| carried(message)) {
            delivered.to_right = delivered.to_right.saturating_add(count(&message));
            next_left.extend(right.receive(left_id, &message.encode()).replies);
        }
        to_left = next_left;
        to_right = next_right;
    }
    panic!("reconciliation did not settle");
}

fn ids() -> (DeviceId, DeviceId) {
    (DeviceId::from_bytes([0xa1; 32]), DeviceId::from_bytes([0xb2; 32]))
}

/// A network with a member, then a batch the founder signed: the fixture, the
/// batch, its entries and pieces, and how many operations came before it.
fn with_batch(count: usize) -> (Fixture, OperationId, Vec<BatchEntry>, Vec<Vec<u8>>, usize) {
    let mut fixture = Fixture::found();
    fixture.add_member("laptop");
    let before = fixture.operations.len();
    let (entries, header) = lot(count);
    let batch = fixture.admit_batch(header);
    let pieces = pieces_of(&batch, &entries).unwrap();
    (fixture, batch, entries, pieces, before)
}

/// A syncer holding every operation of the fixture and the pieces given.
fn holding(fixture: &Fixture, pieces: &[Vec<u8>]) -> Syncer {
    let mut roster = Roster::new();
    for bytes in &fixture.operations {
        let _ = roster.offer_bytes(bytes);
    }
    for piece in pieces {
        let _ = roster.offer_piece(piece);
    }
    Syncer::new(roster)
}

/// A batch of `count` boards, by their public keys.
fn lot(count: usize) -> (Vec<BatchEntry>, BatchHeader) {
    let entries: Vec<BatchEntry> = (0..count)
        .map(|index| {
            let board = NodeIdentity::generate().expect("generates");
            let spec = board.device_spec("board", Role::Member, false, vec![]).expect("spec");
            BatchEntry {
                keys: spec.keys,
                name: format!("board-{index}"),
                serial: Vec::new(),
                ipv4: None,
            }
        })
        .collect();
    let header = BatchHeader::for_entries(&entries, Mode::Light, Vec::new(), None, "lot").unwrap();
    (entries, header)
}

#[test]
fn a_revocation_passes_a_batch_whose_pieces_have_not_arrived() {
    let mut fixture = Fixture::found();
    let laptop = fixture.add_member("laptop").device_id();
    let before_batch = fixture.operations.len();
    let (entries, header) = lot(200);
    let batch = fixture.admit_batch(header);

    // The admin's node holds the batch whole, and revokes the laptop a moment
    // later, anchored as an urgent act is.
    let mut admin = Roster::new();
    for bytes in &fixture.operations {
        let _ = admin.offer_bytes(bytes);
    }
    for piece in pieces_of(&batch, &entries).unwrap() {
        let _ = admin.offer_piece(&piece);
    }
    let now = 1_000;
    let anchor = admin.urgent_anchor(&laptop, now);
    assert!(!anchor.heads.contains(&batch));
    let revocation = fixture.sign_on(
        OperationBody::RevokeDevice { device: laptop, reason: "stolen".to_owned() },
        anchor.heads,
        now,
    );
    assert!(admin.offer_bytes(&revocation).is_accepted());
    let mut admin = Syncer::new(admin);

    // Another node had everything before the batch, and gets the header and the
    // revocation now, but not one piece.
    let mut other = fixture.syncer_through(before_batch);
    let (admin_id, other_id) = ids();
    reconcile(&mut admin, admin_id, &mut other, other_id, false);

    assert_eq!(other.roster().awaiting_pieces(), vec![batch], "the batch is still incomplete");
    assert!(!membership(other.roster()).contains(&laptop), "and the laptop is out regardless");
}

#[test]
fn a_behind_node_gets_a_batch_whole_through_sync() {
    let (fixture, batch, entries, pieces, before) = with_batch(300);
    assert!(pieces.len() > 3);
    let mut admin = holding(&fixture, &pieces);
    let mut behind = fixture.syncer_through(before);
    let (admin_id, behind_id) = ids();

    let delivered = reconcile(&mut admin, admin_id, &mut behind, behind_id, true);

    assert_eq!(delivered.to_right, pieces.len(), "each piece once");
    assert!(behind.roster().awaiting_pieces().is_empty());
    assert!(behind.roster().dag().contains(&batch));
    let members = membership(behind.roster());
    assert!(entries.iter().all(|entry| members.contains(&entry.device_id().unwrap())));
    assert_eq!(behind.digest(), admin.digest(), "and the two now agree");
}

#[test]
fn a_piece_is_passed_on_before_its_batch_is_whole() {
    let (fixture, batch, _, pieces, before) = with_batch(300);
    let mut middle = fixture.syncer_through(before);
    let header = fixture.operations.last().unwrap().clone();
    let peer = DeviceId::from_bytes([0xc3; 32]);

    let header_taken = middle.receive(peer, &Message::Transfer(vec![header.clone()]).encode());
    assert_eq!(
        header_taken.forward,
        Some(Message::Transfer(vec![header.clone()])),
        "the header goes on"
    );
    assert_eq!(header_taken.accepted, vec![header], "and is kept");

    let first = pieces.first().unwrap().clone();
    let taken = middle.receive(peer, &Message::Pieces(vec![first.clone()]).encode());
    assert_eq!(
        taken.forward,
        Some(Message::Pieces(vec![first.clone()])),
        "the piece goes on at once"
    );
    assert_eq!(taken.pieces, vec![first.clone()], "and is kept");
    assert_eq!(middle.roster().awaiting_pieces(), vec![batch], "though the batch is not whole");

    // A third node reconciling with it gets the header and that piece.
    let mut last = fixture.syncer_through(before);
    let (middle_id, last_id) = ids();
    let delivered = reconcile(&mut middle, middle_id, &mut last, last_id, true);
    assert_eq!(delivered.to_right, 1);
    let partial = last.roster().partial_batches();
    assert_eq!(partial.first().map(|partial| partial.held.clone()), Some(vec![0]));

    // Seen again, it is not passed on again.
    let again = middle.receive(peer, &Message::Pieces(vec![first]).encode());
    assert_eq!(again.forward, None);
}

#[test]
fn only_the_missing_pieces_are_fetched() {
    let (fixture, batch, _, pieces, _) = with_batch(600);
    let half = pieces.len() / 2;
    assert!(half > 2);
    let mut whole = holding(&fixture, &pieces);
    let some: Vec<Vec<u8>> = pieces.iter().step_by(2).cloned().collect();
    let mut partly = holding(&fixture, &some);
    assert_eq!(partly.roster().awaiting_pieces(), vec![batch]);
    let (whole_id, partly_id) = ids();

    let delivered = reconcile(&mut whole, whole_id, &mut partly, partly_id, true);

    assert_eq!(delivered.to_right, pieces.len() - some.len(), "the missing ones, and no more");
    assert_eq!(delivered.to_left, 0);
    assert!(partly.roster().dag().contains(&batch), "and the batch is whole");
}

#[test]
fn two_nodes_holding_different_halves_complete_each_other() {
    let (fixture, batch, _, pieces, _) = with_batch(400);
    let evens: Vec<Vec<u8>> = pieces.iter().step_by(2).cloned().collect();
    let odds: Vec<Vec<u8>> = pieces.iter().skip(1).step_by(2).cloned().collect();
    let mut left = holding(&fixture, &evens);
    let mut right = holding(&fixture, &odds);
    let (left_id, right_id) = ids();

    let delivered = reconcile(&mut left, left_id, &mut right, right_id, true);

    assert_eq!(delivered.to_left, odds.len());
    assert_eq!(delivered.to_right, evens.len());
    assert!(left.roster().dag().contains(&batch) && right.roster().dag().contains(&batch));
}

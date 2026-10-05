//! Reconciliation, snapshots, push and the misbehaviour policy.
//!
//! These drive [`Syncer`] directly, in a chosen order. That is what makes
//! partition, interleaving and interruption expressible as tests rather than as
//! races — and it is why the syncer owns no runtime.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod common;

use common::{Fixture, held, membership, orphan};
use roster::id::DeviceId;
use roster_sync::message::Message;
use roster_sync::syncer::{Reception, Syncer};

/// One full exchange: both sides offer, both sides answer.
///
/// Symmetric by construction — neither call is privileged, and swapping the two
/// lines changes nothing.
fn reconcile(a: (&mut Syncer, DeviceId), b: (&mut Syncer, DeviceId)) {
    let (left, left_id) = a;
    let (right, right_id) = b;

    let left_offer = left.greeting().encode();
    let right_offer = right.greeting().encode();

    let left_answer = left.receive(right_id, &right_offer);
    let right_answer = right.receive(left_id, &left_offer);

    for message in left_answer.replies {
        right.receive(left_id, &message.encode());
    }
    for message in right_answer.replies {
        left.receive(right_id, &message.encode());
    }
}

fn ids() -> (DeviceId, DeviceId) {
    (DeviceId::from_bytes([0xa1; 32]), DeviceId::from_bytes([0xb2; 32]))
}

// ---------------------------------------------------------------------------
// Reconciliation when a session is established
// ---------------------------------------------------------------------------

#[test]
fn a_node_behind_learns_what_it_missed() {
    let mut fixture = Fixture::found();
    fixture.add_member("phone");
    fixture.extend(18);

    let mut behind = fixture.syncer_through(1);
    let mut ahead = fixture.syncer();
    let (behind_id, ahead_id) = ids();

    reconcile((&mut behind, behind_id), (&mut ahead, ahead_id));

    assert_eq!(held(behind.roster()), held(ahead.roster()));
    assert_eq!(membership(behind.roster()), membership(ahead.roster()));
}

#[test]
fn a_node_ahead_teaches_without_being_asked() {
    let mut fixture = Fixture::found();
    fixture.extend(20);

    let mut ahead = fixture.syncer();
    let behind = fixture.syncer_through(1);
    let (ahead_id, behind_id) = ids();

    // The answer to the behind node's offer carries the operations, with no
    // request of any kind in between.
    let answer = ahead.receive(behind_id, &behind.greeting().encode());
    let _ = ahead_id;

    let transferred: usize = answer
        .replies
        .iter()
        .map(|message| match message {
            Message::Transfer(operations) => operations.len(),
            _ => 0,
        })
        .sum();
    assert_eq!(transferred, 20, "everything the offer did not name");
}

#[test]
fn two_nodes_that_already_agree_exchange_nothing() {
    let mut fixture = Fixture::found();
    fixture.extend(5);

    let mut left = fixture.syncer();
    let right = fixture.syncer();
    let (left_id, right_id) = ids();
    let _ = left_id;

    let answer = left.receive(right_id, &right.greeting().encode());
    assert!(answer.replies.is_empty(), "nothing to send: {:?}", answer.replies);
    assert!(answer.is_clean());
}

#[test]
fn a_node_a_month_behind_catches_up_from_any_member() {
    let mut fixture = Fixture::found();
    let phone = fixture.add_member("phone");
    let laptop = fixture.add_member("laptop");
    fixture.extend(10);
    // The laptop is revoked while the phone is off.
    fixture.revoke(laptop.device_id());

    // The catching-up node syncs with the phone, which is a plain member and no
    // admin. Contagion must not depend on reaching an admin.
    let mut stale = fixture.syncer_through(2);
    let mut member = fixture.syncer();
    let (stale_id, member_id) = ids();

    reconcile((&mut stale, stale_id), (&mut member, member_id));

    let state = stale.roster().state().expect("derives");
    assert!(
        state.revoked.contains(&laptop.device_id()),
        "a revocation issued while the node was off must be in its state"
    );
    assert!(state.devices.contains_key(&phone.device_id()));
}

#[test]
fn an_operation_offered_during_reconciliation_is_still_verified() {
    let mut fixture = Fixture::found();
    fixture.extend(2);

    let mut node = fixture.syncer_through(1);
    let (peer, _) = ids();

    // Flip a byte in the signature. The bytes still decode; the signature does
    // not verify.
    let mut forged = fixture.operation(1).to_vec();
    let last = forged.len().saturating_sub(1);
    if let Some(byte) = forged.get_mut(last) {
        *byte ^= 0xff;
    }

    let outcome = node.receive(peer, &Message::Transfer(vec![forged]).encode());

    assert!(!outcome.is_clean(), "a forged operation must be refused");
    assert_eq!(outcome.admitted, Vec::new());
    assert_eq!(held(node.roster()).len(), 1, "it must not reach the verified set");
    let reason = &outcome.refusals.first().expect("a refusal").reason;
    assert!(reason.is_about_the_content(), "{reason:?}");
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

#[test]
fn a_snapshot_is_sent_before_the_operations_that_build_on_it() {
    let mut fixture = Fixture::found();
    fixture.extend(12);

    let mut ahead = fixture.syncer_with_snapshot(1);
    assert!(ahead.roster().snapshot().is_some(), "the node holds a snapshot");

    let behind = fixture.syncer_through(1);
    let (_, behind_id) = ids();

    let answer = ahead.receive(behind_id, &behind.greeting().encode());
    let kinds: Vec<&str> = answer.replies.iter().map(kind_of).collect();

    assert_eq!(
        kinds.first().copied(),
        Some("snapshot"),
        "a node far behind cannot place what builds on a foundation it lacks: {kinds:?}"
    );
}

#[test]
fn a_snapshot_that_would_regress_is_refused() {
    let mut fixture = Fixture::found();
    fixture.extend(12);

    let earlier = fixture.snapshot_bytes(&fixture.roster(), 1);
    let mut node = fixture.syncer_with_snapshot(4);
    let before = node.roster().snapshot().map(|snapshot| snapshot.body().seq);
    assert_eq!(before, Some(4));

    let (peer, _) = ids();
    let outcome = node.receive(peer, &Message::Snapshot(earlier).encode());

    assert!(!outcome.is_clean(), "a regression must be refused");
    assert_eq!(
        node.roster().snapshot().map(|snapshot| snapshot.body().seq),
        before,
        "the held snapshot is unchanged"
    );
}

#[test]
fn no_snapshot_is_transferred_when_the_peer_is_already_ahead() {
    let mut fixture = Fixture::found();
    fixture.extend(12);

    let mut behind = fixture.syncer_with_snapshot(1);
    let ahead = fixture.syncer_with_snapshot(4);
    let (peer, _) = ids();

    // Seen in the offer alone: the peer's sequence is higher, so this node's
    // snapshot would regress it. No snapshot bytes are sent for it.
    let answer = behind.receive(peer, &ahead.greeting().encode());

    assert!(
        !answer.replies.iter().any(|message| matches!(message, Message::Snapshot(_))),
        "no snapshot payload may be transferred: {:?}",
        answer.replies.iter().map(kind_of).collect::<Vec<_>>()
    );
}

#[test]
fn operations_outside_a_snapshot_survive_it() {
    let mut fixture = Fixture::found();
    fixture.extend(8);

    // A snapshot over the history as it stands, covering everything so far.
    let snapshot = fixture.snapshot_bytes(&fixture.roster(), 1);

    // Then one operation more, which the snapshot does not cover.
    let phone = fixture.add_member("phone");
    let mut node = Syncer::new(fixture.roster());
    let before = held(node.roster()).len();

    let (peer, _) = ids();
    let outcome = node.receive(peer, &Message::Snapshot(snapshot).encode());
    assert!(outcome.is_clean(), "the snapshot is accepted: {:?}", outcome.refusals);

    assert_eq!(
        held(node.roster()).len(),
        before,
        "a snapshot is not authoritative over what a node already holds"
    );
    assert!(
        node.roster().state().expect("derives").devices.contains_key(&phone.device_id()),
        "an operation outside the snapshot's coverage still contributes to state"
    );
}

#[test]
fn a_snapshot_from_a_non_admin_is_refused() {
    let mut fixture = Fixture::found();
    fixture.extend(6);

    // Signed by a second network's founder: a real signature, by a key this
    // roster does not name as an admin.
    let mut stranger = Fixture::found();
    stranger.extend(6);
    let forged = stranger.snapshot_bytes(&stranger.roster(), 1);

    let mut node = fixture.syncer();
    let (peer, _) = ids();
    let outcome = node.receive(peer, &Message::Snapshot(forged).encode());

    assert!(!outcome.is_clean(), "a snapshot from a stranger must be refused");
    assert!(node.roster().snapshot().is_none(), "and must not be adopted");
    let reason = &outcome.refusals.first().expect("a refusal").reason;
    assert!(reason.is_about_the_content(), "{reason:?}");
}

/// Names a message kind, for assertions that care about order.
fn kind_of(message: &Message) -> &'static str {
    match message {
        Message::Snapshot(_) => "snapshot",
        Message::Transfer(_) => "transfer",
        Message::Offer(_) => "offer",
        Message::Attestation(_) => "attestation",
    }
}

// ---------------------------------------------------------------------------
// Push on local admission
// ---------------------------------------------------------------------------

#[test]
fn a_revocation_reaches_an_already_connected_node() {
    let mut fixture = Fixture::found();
    let laptop = fixture.add_member("laptop");
    fixture.extend(3);

    let mut admin = fixture.syncer();
    let mut peer_one = fixture.syncer();
    let mut peer_two = fixture.syncer();
    let (admin_id, _) = ids();

    // The admin authors a revocation while both sessions are open.
    let mut authoring = fixture;
    authoring.revoke(laptop.device_id());
    let revocation = authoring.last().to_vec();

    let forward = admin.admit_local(&revocation).expect("admits").expect("something to forward");

    for peer in [&mut peer_one, &mut peer_two] {
        peer.receive(admin_id, &forward.encode());
        let state = peer.roster().state().expect("derives");
        assert!(
            state.revoked.contains(&laptop.device_id()),
            "the revocation must reach an already-connected node without a reconnect"
        );
    }
}

#[test]
fn an_operation_is_not_returned_to_the_peer_it_came_from() {
    let mut fixture = Fixture::found();
    fixture.extend(2);

    let mut node = fixture.syncer_through(1);
    let (source, _) = ids();

    let outcome =
        node.receive(source, &Message::Transfer(vec![fixture.operation(1).to_vec()]).encode());

    assert_eq!(outcome.admitted.len(), 1);
    assert!(outcome.forward.is_some(), "it is forwarded to others");
    assert!(outcome.replies.is_empty(), "nothing goes back to the sender: {:?}", outcome.replies);
}

#[test]
fn propagation_converges_rather_than_echoing() {
    let mut fixture = Fixture::found();
    fixture.extend(2);
    let operation = fixture.operation(1).to_vec();

    // Three nodes in a cycle: a -> b -> c -> a.
    let mut a = fixture.syncer_through(1);
    let mut b = fixture.syncer_through(1);
    let mut c = fixture.syncer_through(1);
    let (a_id, b_id) = ids();
    let c_id = DeviceId::from_bytes([0xc3; 32]);

    let mut queue: Vec<(DeviceId, Message)> = Vec::new();
    let first = a.admit_local(&operation).expect("admits").expect("forwards");
    queue.push((a_id, first));

    let mut deliveries = 0usize;
    let mut rounds = 0usize;
    while let Some((from, message)) = queue.pop() {
        rounds = rounds.saturating_add(1);
        assert!(rounds < 50, "propagation did not terminate");

        let targets: Vec<&mut Syncer> = if from == a_id {
            vec![&mut b]
        } else if from == b_id {
            vec![&mut c]
        } else {
            vec![&mut a]
        };
        let next_from = if from == a_id {
            b_id
        } else if from == b_id {
            c_id
        } else {
            a_id
        };

        for target in targets {
            deliveries = deliveries.saturating_add(1);
            let outcome = target.receive(from, &message.encode());
            if let Some(forward) = outcome.forward {
                queue.push((next_from, forward));
            }
        }
    }

    for node in [&a, &b, &c] {
        assert_eq!(held(node.roster()).len(), 2, "every node holds it");
    }
    assert!(deliveries <= 3, "each node receives it a bounded number of times: {deliveries}");
}

#[test]
fn a_node_with_no_open_sessions_still_admits() {
    let mut fixture = Fixture::found();
    fixture.extend(1);
    let mut node = fixture.syncer_through(1);

    let forward = node.admit_local(fixture.operation(1)).expect("admits");

    assert!(forward.is_some(), "there is something to send when a session next opens");
    assert_eq!(held(node.roster()).len(), 2, "the admission succeeded regardless");
}

#[test]
fn a_pending_operation_is_not_forwarded() {
    let mut fixture = Fixture::found();
    fixture.extend(1);
    let mut node = fixture.syncer_through(1);
    let (peer, _) = ids();

    let outcome = node.receive(peer, &Message::Transfer(vec![orphan(1)]).encode());

    assert!(outcome.admitted.is_empty(), "an orphan enters nothing");
    assert!(outcome.forward.is_none(), "and is never relayed");
    // It is held rather than discarded — the one you cannot place may be a
    // revocation.
    assert_eq!(node.charged_to(&peer), 1, "it is held, and charged to its sender");
}

#[test]
fn only_the_verified_set_is_offered() {
    let mut fixture = Fixture::found();
    fixture.extend(1);
    let mut node = fixture.syncer_through(1);
    let (peer, _) = ids();

    node.receive(peer, &Message::Transfer(vec![orphan(2)]).encode());

    let offer = node.offer();
    assert_eq!(offer.ids.len(), 1, "the pending orphan is not offered: {offer:?}");
}

// ---------------------------------------------------------------------------
// Misbehaviour: throttle, never disconnect
// ---------------------------------------------------------------------------

#[test]
fn a_peer_sending_an_invalid_operation_is_still_heard() {
    let mut fixture = Fixture::found();
    fixture.extend(2);
    let mut node = fixture.syncer_through(1);
    let (peer, _) = ids();

    let mut forged = fixture.operation(1).to_vec();
    let last = forged.len().saturating_sub(1);
    if let Some(byte) = forged.get_mut(last) {
        *byte ^= 0xff;
    }
    let refused = node.receive(peer, &Message::Transfer(vec![forged]).encode());
    assert!(!refused.is_clean());
    assert!(
        !refused.refusals.iter().any(|refusal| refusal.reason.is_session_over()),
        "a refusal must never end a session"
    );

    // The very next valid operation from the same peer is accepted.
    let accepted =
        node.receive(peer, &Message::Transfer(vec![fixture.operation(1).to_vec()]).encode());
    assert_eq!(accepted.admitted.len(), 1, "the peer is still heard");
}

#[test]
fn repeated_refusals_do_not_escalate() {
    let mut fixture = Fixture::found();
    fixture.extend(1);
    let mut node = fixture.syncer_through(1);
    let (peer, _) = ids();

    for round in 0..20u8 {
        let outcome = node.receive(peer, &[0xff, 0x00, round]);
        assert!(!outcome.is_clean(), "round {round} should refuse");
        assert!(
            !outcome.refusals.iter().any(|refusal| refusal.reason.is_session_over()),
            "round {round} must not end the session"
        );
    }

    let accepted =
        node.receive(peer, &Message::Transfer(vec![fixture.operation(1).to_vec()]).encode());
    assert_eq!(accepted.admitted.len(), 1, "still heard after twenty refusals");
}

#[test]
fn every_refusal_is_reported() {
    let mut fixture = Fixture::found();
    fixture.extend(1);
    let mut node = fixture.syncer_through(1);
    let (peer, _) = ids();

    let outcome: Reception = node.receive(peer, b"not a message at all");

    assert_eq!(outcome.refusals.len(), 1, "nothing is swallowed");
    assert_eq!(outcome.refusals.first().expect("a refusal").peer, peer);
}

// ---------------------------------------------------------------------------
// Interruption
// ---------------------------------------------------------------------------

#[test]
fn an_interrupted_reconciliation_loses_nothing() {
    let mut fixture = Fixture::found();
    fixture.extend(12);

    let mut behind = fixture.syncer_through(4);
    let mut ahead = fixture.syncer();
    let (behind_id, ahead_id) = ids();

    let before = held(behind.roster());

    // The session dies after the offers cross but before the answer is
    // delivered: the answer is computed and thrown away.
    let _abandoned = ahead.receive(behind_id, &behind.greeting().encode());
    assert_eq!(held(behind.roster()), before, "nothing was lost");

    // Reconciling again completes what was left.
    reconcile((&mut behind, behind_id), (&mut ahead, ahead_id));
    assert_eq!(held(behind.roster()), held(ahead.roster()));
}

#[test]
fn convergence_does_not_depend_on_who_dialled() {
    let mut fixture = Fixture::found();
    fixture.add_member("phone");
    fixture.extend(9);

    let (left_id, right_id) = ids();

    let mut a1 = fixture.syncer_through(3);
    let mut b1 = fixture.syncer();
    reconcile((&mut a1, left_id), (&mut b1, right_id));

    let mut a2 = fixture.syncer_through(3);
    let mut b2 = fixture.syncer();
    reconcile((&mut b2, right_id), (&mut a2, left_id));

    assert_eq!(held(a1.roster()), held(a2.roster()));
    assert_eq!(held(b1.roster()), held(b2.roster()));
}

/// Transitive punishment, named explicitly.
///
/// The relaying peer did not author the forgery — it passed on something it was
/// given. Sync cannot tell the two apart from the operation alone, which is
/// exactly why it must not act on the difference: an attacker who could get an
/// honest node blamed for relaying would remove nodes from the network by
/// forging one operation, with no key and no membership.
#[test]
fn a_peer_relaying_someone_elses_forgery_is_not_blamed() {
    let mut fixture = Fixture::found();
    fixture.extend(3);

    let mut node = fixture.syncer_through(1);
    let relayer = DeviceId::from_bytes([0x7e; 32]);

    // A stranger's operation, corrupted in flight. The relayer is a member in
    // good standing that received this and passed it on.
    let mut stranger = Fixture::found();
    stranger.extend(2);
    let mut forged = stranger.operation(1).to_vec();
    let last = forged.len().saturating_sub(1);
    if let Some(byte) = forged.get_mut(last) {
        *byte ^= 0xff;
    }

    let refused = node.receive(relayer, &Message::Transfer(vec![forged]).encode());
    assert!(!refused.is_clean(), "the forgery is refused");
    assert!(
        !refused.refusals.iter().any(|refusal| refusal.reason.is_session_over()),
        "but the relayer is not disconnected for it"
    );

    // And it may still relay valid operations afterwards, with nothing held
    // against it.
    let accepted =
        node.receive(relayer, &Message::Transfer(vec![fixture.operation(1).to_vec()]).encode());
    assert_eq!(accepted.admitted.len(), 1, "the relayer is not penalised");
    assert_eq!(node.charged_to(&relayer), 0, "and carries no charge for someone else's forgery");
}

// ---------------------------------------------------------------------------
// A reconciliation says which operations the peer already holds
// ---------------------------------------------------------------------------

#[test]
fn a_reception_names_what_the_peer_already_had() {
    let mut fixture = Fixture::found();
    fixture.extend(5);

    let mut ahead = fixture.syncer();
    let behind = fixture.syncer_through(3);
    let (_, behind_id) = ids();

    let reception = ahead.receive(behind_id, &behind.greeting().encode());

    let held = reception.held.expect("an offer reports what the peer holds");
    assert_eq!(held.peer, behind_id, "attributed to the peer that offered");

    let theirs = held.ids;
    for index in 0..3 {
        assert!(theirs.contains(&fixture.id_at(index)), "an operation the peer named is reported");
    }
    for index in 3..fixture.operations.len() {
        assert!(
            !theirs.contains(&fixture.id_at(index)),
            "an operation the offer omitted is not reported as held"
        );
    }
}

#[test]
fn what_one_peer_holds_is_not_attributed_to_another() {
    let mut fixture = Fixture::found();
    fixture.extend(4);

    let mut ahead = fixture.syncer();
    let informed = fixture.syncer_through(4);
    let ignorant = fixture.syncer_through(1);
    let (informed_id, ignorant_id) = ids();

    let from_informed = ahead
        .receive(informed_id, &informed.greeting().encode())
        .held
        .expect("an offer reports what the peer holds");
    let from_ignorant = ahead
        .receive(ignorant_id, &ignorant.greeting().encode())
        .held
        .expect("an offer reports what the peer holds");

    let recent = fixture.id_at(3);
    assert_eq!(from_informed.peer, informed_id);
    assert_eq!(from_ignorant.peer, ignorant_id);
    assert!(from_informed.ids.contains(&recent), "the peer that named it holds it");
    assert!(
        !from_ignorant.ids.contains(&recent),
        "and the other peer is not credited with what its own offer never named"
    );
}

/// The evidence is the peer's own statement, never this node's optimism.
#[test]
fn sending_is_not_evidence_of_holding() {
    let mut fixture = Fixture::found();
    fixture.extend(3);

    let mut ahead = fixture.syncer();
    let (_, behind_id) = ids();

    // The operations the peer lacks are handed over — the send half of the
    // exchange, from this side indistinguishable from one the far end read.
    let behind = fixture.syncer_through(1);
    let first = ahead.receive(behind_id, &behind.greeting().encode());
    assert!(
        first.replies.iter().any(|message| matches!(message, Message::Transfer(_))),
        "what the peer lacked was sent"
    );

    // The peer's next offer still does not name them: it never read what was
    // sent, or read it and discarded it. Either way nothing is evidence yet.
    let second = ahead.receive(behind_id, &behind.greeting().encode());
    let held = second.held.expect("an offer reports what the peer holds");
    for index in 1..fixture.operations.len() {
        assert!(
            !held.ids.contains(&fixture.id_at(index)),
            "an operation that was transmitted but never named is still not held"
        );
    }
}

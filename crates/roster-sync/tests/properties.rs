//! Convergence, stated over generated inputs rather than chosen ones.
//!
//! §4.7's claim is that two nodes that have exchanged agree. Until this change
//! that had been demonstrated only on merges the roster performed on itself,
//! with the operations handed over by a function call. These drive it through
//! the protocol.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod common;

use common::{Fixture, held, orphans};
use proptest::prelude::*;
use roster::id::DeviceId;
use roster_sync::Syncer;
use roster_sync::limits::PENDING_PER_PEER;
use roster_sync::message::Message;

fn left() -> DeviceId {
    DeviceId::from_bytes([0x0a; 32])
}

fn right() -> DeviceId {
    DeviceId::from_bytes([0x0b; 32])
}

/// One full exchange: both sides greet, and every reply is delivered until
/// neither side has anything left to say.
fn reconcile(a: &mut Syncer, b: &mut Syncer) {
    let mut to_a = vec![b.greeting()];
    let mut to_b = vec![a.greeting()];
    for _ in 0..8 {
        if to_a.is_empty() && to_b.is_empty() {
            return;
        }
        let mut next_a = Vec::new();
        let mut next_b = Vec::new();
        for message in to_a.drain(..) {
            next_b.extend(a.receive(right(), &message.encode()).replies);
        }
        for message in to_b.drain(..) {
            next_a.extend(b.receive(left(), &message.encode()).replies);
        }
        to_a = next_a;
        to_b = next_b;
    }
    panic!("reconciliation did not settle");
}

/// Derived state, as bytes, for comparing two nodes exactly.
fn state_bytes(node: &Syncer) -> Vec<u8> {
    node.roster().state().expect("derives").to_bytes()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Two nodes that have reconciled derive the same state, whatever each
    /// started with.
    #[test]
    fn reconciled_nodes_converge(total in 3usize..14, behind in 1usize..3) {
        let mut fixture = Fixture::found();
        fixture.add_member("phone");
        fixture.extend(total);

        let held_by_a = behind.min(fixture.operations.len());
        let mut a = fixture.syncer_through(held_by_a);
        let mut b = fixture.syncer();

        reconcile(&mut a, &mut b);

        prop_assert_eq!(held(a.roster()), held(b.roster()));
        prop_assert_eq!(state_bytes(&a), state_bytes(&b));
    }

    /// A partition heals without loss: each side keeps what it admitted alone,
    /// and both end up with everything.
    #[test]
    fn a_partition_heals_without_loss(shared in 2usize..8, branches in 1usize..4) {
        let mut fixture = Fixture::found();
        fixture.extend(shared);
        let fork = fixture.id_at(fixture.operations.len().saturating_sub(1));

        let mut a = fixture.syncer();
        let mut b = fixture.syncer();

        // Each side admits operations the other cannot see. They name the same
        // parent, so they are genuinely concurrent rather than merely later.
        let mut mine = Vec::new();
        let mut theirs = Vec::new();
        for index in 0..branches {
            let a_side = fixture.branch(fork, index as u64, &format!("a-{index}"));
            let b_side = fixture.branch(fork, (index as u64).wrapping_add(500), &format!("b-{index}"));
            a.admit_local(&a_side).expect("admits");
            b.admit_local(&b_side).expect("admits");
            mine.push(a_side);
            theirs.push(b_side);
        }

        let a_before = held(a.roster()).len();
        let b_before = held(b.roster()).len();
        prop_assert!(a_before > shared, "each side really did diverge");

        reconcile(&mut a, &mut b);

        prop_assert_eq!(held(a.roster()), held(b.roster()), "they converge");
        prop_assert_eq!(state_bytes(&a), state_bytes(&b));
        prop_assert!(
            held(a.roster()).len() >= a_before.max(b_before),
            "neither lost what it admitted while apart"
        );
    }

    /// Which side dialled changes nothing.
    #[test]
    fn convergence_does_not_depend_on_who_dialled(total in 3usize..12) {
        let mut fixture = Fixture::found();
        fixture.extend(total);

        let mut a1 = fixture.syncer_through(2);
        let mut b1 = fixture.syncer();
        reconcile(&mut a1, &mut b1);

        let mut a2 = fixture.syncer_through(2);
        let mut b2 = fixture.syncer();
        reconcile(&mut b2, &mut a2);

        prop_assert_eq!(state_bytes(&a1), state_bytes(&a2));
        prop_assert_eq!(state_bytes(&b1), state_bytes(&b2));
    }

    /// No sequence of offers from one peer, however hostile, prevents a second
    /// peer's operation from being admitted. The quota guarantee, stated over
    /// arbitrary traffic rather than one chosen flood.
    #[test]
    fn a_hostile_peer_cannot_starve_an_honest_one(
        flood in 1usize..(PENDING_PER_PEER * 3),
        interleave in any::<bool>(),
    ) {
        let mut fixture = Fixture::found();
        let laptop = fixture.add_member("laptop");
        fixture.extend(3);
        let parent_index = fixture.operations.len();
        fixture.extend(1);
        fixture.revoke(laptop.device_id());

        let mut node = fixture.syncer_through(parent_index);
        let parent = fixture.operation(parent_index).to_vec();
        let revocation = fixture.last().to_vec();

        let junk = orphans(flood);
        let attacker = DeviceId::from_bytes([0x66; 32]);
        let honest = DeviceId::from_bytes([0x11; 32]);

        if interleave {
            // The revocation arrives partway through the flood rather than after
            // it, so the property does not depend on ordering.
            let half = junk.len() / 2;
            for bytes in junk.iter().take(half) {
                node.receive(attacker, &Message::Transfer(vec![bytes.clone()]).encode());
            }
            node.receive(honest, &Message::Transfer(vec![revocation.clone()]).encode());
            for bytes in junk.iter().skip(half) {
                node.receive(attacker, &Message::Transfer(vec![bytes.clone()]).encode());
            }
        } else {
            for bytes in &junk {
                node.receive(attacker, &Message::Transfer(vec![bytes.clone()]).encode());
            }
            node.receive(honest, &Message::Transfer(vec![revocation.clone()]).encode());
        }

        prop_assert!(
            node.charged_to(&attacker) <= PENDING_PER_PEER,
            "the attacker never exceeds its share"
        );

        // The parent arrives and the revocation lands, whatever the flood did.
        node.receive(honest, &Message::Transfer(vec![parent]).encode());
        let state = node.roster().state().expect("derives");
        prop_assert!(
            state.revoked.contains(&laptop.device_id()),
            "a flood must never stop a revocation from landing"
        );
    }

    /// Push terminates on a ring of nodes, with each receiving an operation a
    /// bounded number of times.
    #[test]
    fn push_terminates_on_a_ring(nodes in 2usize..7) {
        let mut fixture = Fixture::found();
        fixture.extend(2);
        let operation = fixture.operation(1).to_vec();

        let mut ring: Vec<Syncer> = (0..nodes).map(|_| fixture.syncer_through(1)).collect();
        let ids: Vec<DeviceId> =
            (0..nodes).map(|index| DeviceId::from_bytes([index as u8; 32])).collect();

        // The first node admits it, and the message walks the ring.
        let mut carried = ring
            .first_mut()
            .expect("a ring")
            .admit_local(&operation)
            .expect("admits");

        let mut deliveries = 0usize;
        let mut position = 0usize;
        let mut steps = 0usize;
        while let Some(message) = carried.take() {
            steps = steps.saturating_add(1);
            prop_assert!(steps <= nodes.saturating_mul(2), "propagation did not terminate");

            let from = *ids.get(position).expect("an id");
            position = position.saturating_add(1).checked_rem(nodes).unwrap_or(0);
            let target = ring.get_mut(position).expect("a node");

            deliveries = deliveries.saturating_add(1);
            carried = target.receive(from, &message.encode()).forward;
        }

        prop_assert!(deliveries <= nodes, "each node receives it a bounded number of times");
        for node in &ring {
            prop_assert_eq!(held(node.roster()).len(), 2, "every node ends up holding it");
        }
    }
}

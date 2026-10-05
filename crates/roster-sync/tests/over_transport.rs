//! The syncer driven over real authenticated sessions.
//!
//! Run against both of `transport`'s implementations. They are behaviourally
//! interchangeable by construction — one suite, two independent internals — so a
//! reconciliation that works over both works over anything satisfying that
//! suite, which `transport-iroh` must.
//!
//! The loop here is the *caller's*, which is the point of the syncer owning no
//! runtime: `windows-daemon` will write a different one, knowing things this crate
//! does not.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{Fixture, held};
use roster_sync::Syncer;
use roster_sync::message::Message;
use transport::session::{Session, Transport};
use transport::{DirectFabric, DirectTransport, MemoryFabric, MemoryTransport};

/// Drives one side until it has nothing left to say.
///
/// Bounded: a reconciliation that did not terminate would hang here, and a test
/// that hangs is a test that reports nothing.
async fn drain(session: &dyn Session, syncer: &mut Syncer, rounds: usize) {
    let peer = session.peer();
    for _ in 0..rounds {
        let Ok(Ok(payload)) =
            tokio::time::timeout(Duration::from_millis(120), session.recv()).await
        else {
            return;
        };
        let outcome = syncer.receive(peer, &payload);
        for reply in outcome.replies {
            if session.send(&reply.encode()).await.is_err() {
                return;
            }
        }
    }
}

/// A full reconciliation over a pair of sessions.
async fn reconcile_over(left: (&dyn Session, &mut Syncer), right: (&dyn Session, &mut Syncer)) {
    let (left_session, left_syncer) = left;
    let (right_session, right_syncer) = right;

    // Both greet immediately, without waiting to be asked. Neither side is the
    // server.
    left_session.send(&left_syncer.greeting().encode()).await.expect("sends");
    right_session.send(&right_syncer.greeting().encode()).await.expect("sends");

    drain(right_session, right_syncer, 4).await;
    drain(left_session, left_syncer, 4).await;
    drain(right_session, right_syncer, 4).await;
    drain(left_session, left_syncer, 4).await;
}

/// Builds a fixture, a pair of connected sessions, and a pair of syncers.
struct Pair {
    behind: Box<dyn Session>,
    ahead: Box<dyn Session>,
    behind_syncer: Syncer,
    ahead_syncer: Syncer,
    total: usize,
}

async fn memory_pair() -> Pair {
    let mut fixture = Fixture::found();
    let phone = fixture.add_member("phone");
    fixture.extend(12);
    let state = fixture.roster().state().expect("derives");
    let founder = Arc::clone(&fixture.founder);

    let fabric = MemoryFabric::new();
    let dialler = MemoryTransport::join(&fabric, founder, state.clone()).await;
    let acceptor = MemoryTransport::join(&fabric, phone, state).await;

    let key = acceptor.transport_key();
    let (dialled, accepted) = tokio::join!(dialler.connect(&key), acceptor.accept());

    Pair {
        behind: dialled.expect("establishes"),
        ahead: accepted.expect("establishes"),
        behind_syncer: fixture.syncer_through(2),
        ahead_syncer: fixture.syncer(),
        total: fixture.operations.len(),
    }
}

async fn direct_pair() -> Pair {
    let mut fixture = Fixture::found();
    let phone = fixture.add_member("phone");
    fixture.extend(12);
    let state = fixture.roster().state().expect("derives");
    let founder = Arc::clone(&fixture.founder);

    let fabric = DirectFabric::new();
    let dialler = DirectTransport::join(&fabric, founder, state.clone()).await;
    let acceptor = DirectTransport::join(&fabric, phone, state).await;

    let key = acceptor.transport_key();
    let (dialled, accepted) = tokio::join!(dialler.connect(&key), acceptor.accept());

    Pair {
        behind: dialled.expect("establishes"),
        ahead: accepted.expect("establishes"),
        behind_syncer: fixture.syncer_through(2),
        ahead_syncer: fixture.syncer(),
        total: fixture.operations.len(),
    }
}

async fn a_behind_node_catches_up(mut pair: Pair) {
    assert_eq!(held(pair.behind_syncer.roster()).len(), 2, "it starts behind");

    reconcile_over(
        (pair.behind.as_ref(), &mut pair.behind_syncer),
        (pair.ahead.as_ref(), &mut pair.ahead_syncer),
    )
    .await;

    assert_eq!(
        held(pair.behind_syncer.roster()).len(),
        pair.total,
        "it caught up over a real session"
    );
    assert_eq!(held(pair.behind_syncer.roster()), held(pair.ahead_syncer.roster()));
}

async fn a_push_crosses_a_session(mut pair: Pair) {
    reconcile_over(
        (pair.behind.as_ref(), &mut pair.behind_syncer),
        (pair.ahead.as_ref(), &mut pair.ahead_syncer),
    )
    .await;

    // A payload sent as one message arrives as one message, which is what lets
    // an operation be framed at all.
    let message = Message::Transfer(vec![vec![7; 64]]).encode();
    pair.ahead.send(&message).await.expect("sends");
    let received = pair.behind.recv().await.expect("receives");
    assert_eq!(received, message, "boundaries and contents intact");
}

async fn the_quota_is_keyed_on_the_authenticated_peer(mut pair: Pair) {
    // Whatever the sender puts in the message, the charge lands on the device
    // the transport authenticated. That identity is the whole reason the quota
    // can exist here and could not exist in `roster` alone.
    let authenticated = pair.behind.peer();
    let someone_else = roster::id::DeviceId::from_bytes([0xcd; 32]);

    let orphan = common::orphans(1).pop().expect("an orphan");
    pair.ahead.send(&Message::Transfer(vec![orphan]).encode()).await.expect("sends");
    let payload = pair.behind.recv().await.expect("receives");
    pair.behind_syncer.receive(authenticated, &payload);

    assert_eq!(
        pair.behind_syncer.charged_to(&authenticated),
        1,
        "the orphan is charged to the peer the session authenticated"
    );
    assert_eq!(pair.behind_syncer.charged_to(&someone_else), 0, "and to nobody else");
}

macro_rules! both {
    ($name:ident, $body:ident) => {
        mod $name {
            #[tokio::test]
            async fn over_memory() {
                super::$body(super::memory_pair().await).await;
            }

            #[tokio::test]
            async fn over_direct() {
                super::$body(super::direct_pair().await).await;
            }
        }
    };
}

both!(catching_up, a_behind_node_catches_up);
both!(pushing, a_push_crosses_a_session);
both!(peer_identity, the_quota_is_keyed_on_the_authenticated_peer);

/// Losing membership ends a session — and it is the transport that ends it, not
/// a sync decision. Sync adding a second ground for closing would mean two
/// components deciding who a node talks to.
#[tokio::test]
async fn membership_loss_closes_the_session_and_sync_does_not() {
    let mut fixture = Fixture::found();
    let phone = fixture.add_member("phone");
    fixture.extend(4);
    let state = fixture.roster().state().expect("derives");
    let founder = Arc::clone(&fixture.founder);

    let fabric = MemoryFabric::new();
    let dialler = MemoryTransport::join(&fabric, founder, state.clone()).await;
    let acceptor = MemoryTransport::join(&fabric, Arc::clone(&phone), state).await;

    let key = acceptor.transport_key();
    let (dialled, accepted) = tokio::join!(dialler.connect(&key), acceptor.accept());
    let dialled = dialled.expect("establishes");
    let _accepted = accepted.expect("establishes");

    // The phone is revoked, and the newer state reaches the transport.
    fixture.revoke(phone.device_id());
    let after = fixture.roster().state().expect("derives");
    dialler.update_state(after).await;

    let outcome = dialled.send(b"anything").await;
    assert!(
        outcome.as_ref().err().is_some_and(transport::Error::is_closed),
        "the session ends on membership loss: {outcome:?}"
    );
    assert_eq!(
        outcome.err(),
        Some(transport::Error::ClosedOnMembershipLoss),
        "and the reason names membership, distinctly from a hang-up"
    );
}

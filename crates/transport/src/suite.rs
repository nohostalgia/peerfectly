//! One behavioural suite, run against every implementation.
//!
//! Written against [`Transport`] and [`Session`], never against a concrete type.
//! That is what stops the interface drifting into describing whichever
//! implementation happens to exist: a behaviour only one of them has fails the
//! moment a second appears, and `transport-iroh` inherits a check of its
//! semantics rather than having to invent one.
//!
//! A harness supplies a pair of connected nodes and a way to change the roster
//! state they see. Everything else here is written in terms of the interface.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "this module is a test suite; a failed expectation is reported by panicking"
)]

use std::sync::Arc;

use identity::NodeIdentity;
use roster::id::DeviceId;
use roster::sign::PublicKey;
use roster::state::RosterState;

use crate::error::Error;
use crate::session::{Session, Transport};

/// What a suite run needs from an implementation.
///
/// Deliberately small: two nodes that can reach each other, the keys to dial
/// with, and a way to hand both of them newer roster state. An implementation
/// that needs more than this to be tested is probably doing more than the
/// interface says.
#[async_trait::async_trait]
pub trait Harness: Send + Sync {
    /// The dialling node.
    fn dialler(&self) -> &dyn Transport;

    /// The accepting node.
    fn acceptor(&self) -> &dyn Transport;

    /// The acceptor's transport key, to dial it by.
    fn acceptor_key(&self) -> PublicKey;

    /// A transport key belonging to nobody reachable.
    fn unreachable_key(&self) -> PublicKey;

    /// The device ids of the two nodes.
    fn dialler_device(&self) -> DeviceId;

    /// The acceptor's device id.
    fn acceptor_device(&self) -> DeviceId;

    /// Hands both nodes newer roster state.
    async fn set_state(&self, state: RosterState);

    /// The roster state both nodes currently see.
    async fn state(&self) -> RosterState;
}

/// Establishes a session from both ends at once.
///
/// `connect` and `accept` must run concurrently or each waits for the other.
async fn establish(harness: &dyn Harness) -> (Box<dyn Session>, Box<dyn Session>) {
    let key = harness.acceptor_key();
    let (dialled, accepted) =
        tokio::join!(harness.dialler().connect(&key), harness.acceptor().accept());
    (dialled.expect("the dialler establishes"), accepted.expect("the acceptor establishes"))
}

/// Runs every behaviour the specification requires.
///
/// One entry point, so adding a requirement here reaches every implementation.
pub async fn run_all(harness: Arc<dyn Harness>) {
    a_member_establishes_a_session(harness.as_ref()).await;
    a_session_reports_a_stable_peer(harness.as_ref()).await;
    payloads_arrive_unchanged(harness.as_ref()).await;
    payload_boundaries_are_preserved(harness.as_ref()).await;
    an_oversized_payload_is_refused_at_the_sender(harness.as_ref()).await;
    sending_on_a_closed_session_fails(harness.as_ref()).await;
    receiving_on_a_closed_session_reports_the_close(harness.as_ref()).await;
    an_unreachable_peer_is_reported_as_unreachable(harness.as_ref()).await;
    packets_arrive_whole(harness.as_ref()).await;
    packets_and_payloads_are_received_apart(harness.as_ref()).await;
    an_oversized_packet_is_refused_at_the_sender(harness.as_ref()).await;
    sending_a_packet_on_a_closed_session_fails(harness.as_ref()).await;
    receiving_a_packet_on_a_closed_session_reports_the_close(harness.as_ref()).await;
    // Last: these two revoke a peer, and nothing after them could establish.
    revoking_a_peer_closes_its_session(harness.as_ref()).await;
    a_revoked_peer_cannot_reconnect(harness.as_ref()).await;
}

/// How long a receive may take before a behaviour calls it lost.
const PATIENCE: std::time::Duration = std::time::Duration::from_secs(10);

/// Receives one packet, or fails the behaviour.
async fn next_packet(session: &dyn Session) -> Vec<u8> {
    tokio::time::timeout(PATIENCE, session.recv_packet())
        .await
        .expect("a packet arrives on a path that loses nothing")
        .expect("receives a packet")
}

/// Packets of every size up to the bound arrive as the packets that were sent.
///
/// Compared as a set: a packet channel promises no order.
pub async fn packets_arrive_whole(harness: &dyn Harness) {
    let (dialled, accepted) = establish(harness).await;
    let sizes = [1_usize, 100, 1_200, 1_280, crate::limits::MAX_PACKET];
    let mut sent: Vec<Vec<u8>> = sizes
        .iter()
        .enumerate()
        .map(|(index, size)| {
            (0..*size).map(|at| u8::try_from((at ^ index) & 0xff).unwrap_or(0)).collect()
        })
        .collect();
    for packet in &sent {
        dialled.send_packet(packet).await.expect("sends a packet");
    }
    let mut received = Vec::new();
    for _ in &sent {
        received.push(next_packet(accepted.as_ref()).await);
    }
    sent.sort();
    received.sort();
    assert_eq!(received, sent, "each packet arrives whole, one per packet sent");

    // And in the other direction.
    accepted.send_packet(b"back").await.expect("sends a packet");
    assert_eq!(next_packet(dialled.as_ref()).await, b"back".to_vec());
}

/// A payload arrives as a payload and a packet as a packet.
pub async fn packets_and_payloads_are_received_apart(harness: &dyn Harness) {
    let (dialled, accepted) = establish(harness).await;
    dialled.send(b"a payload").await.expect("sends");
    dialled.send_packet(b"a packet").await.expect("sends a packet");

    assert_eq!(next_packet(accepted.as_ref()).await, b"a packet".to_vec());
    assert_eq!(
        tokio::time::timeout(PATIENCE, accepted.recv()).await.expect("arrives").expect("receives"),
        b"a payload".to_vec()
    );
}

/// An oversized packet is refused whole, naming the bound.
pub async fn an_oversized_packet_is_refused_at_the_sender(harness: &dyn Harness) {
    let (dialled, accepted) = establish(harness).await;
    let oversized = vec![7u8; crate::limits::MAX_PACKET.saturating_add(1)];

    match dialled.send_packet(&oversized).await {
        Err(Error::PacketTooLarge { len, limit }) => {
            assert_eq!(len, oversized.len());
            assert_eq!(limit, crate::limits::MAX_PACKET);
        }
        other => panic!("expected a refusal naming the packet bound, got {other:?}"),
    }

    dialled.send_packet(b"after").await.expect("sends a packet");
    assert_eq!(next_packet(accepted.as_ref()).await, b"after".to_vec(), "nothing partial arrived");
}

/// A packet sent after close fails rather than appearing to succeed.
pub async fn sending_a_packet_on_a_closed_session_fails(harness: &dyn Harness) {
    let (dialled, _accepted) = establish(harness).await;
    dialled.close().await.expect("closes");
    let outcome = dialled.send_packet(b"too late").await;
    assert!(
        matches!(outcome, Err(error) if error.is_closed()),
        "a packet sent on a closed session must fail"
    );
}

/// A packet receive after close reports it rather than waiting forever.
pub async fn receiving_a_packet_on_a_closed_session_reports_the_close(harness: &dyn Harness) {
    let (dialled, _accepted) = establish(harness).await;
    dialled.close().await.expect("closes");
    let outcome =
        tokio::time::timeout(std::time::Duration::from_secs(2), dialled.recv_packet()).await;
    match outcome {
        Ok(Err(error)) => assert!(error.is_closed(), "the close is reported: {error:?}"),
        Ok(Ok(_)) => panic!("a closed session must not yield a packet"),
        Err(_) => panic!("a packet receive on a closed session must not block indefinitely"),
    }
}

/// A peer the roster names gets a session, carrying its device id.
pub async fn a_member_establishes_a_session(harness: &dyn Harness) {
    let (dialled, accepted) = establish(harness).await;
    assert_eq!(dialled.peer(), harness.acceptor_device(), "the dialler sees the acceptor");
    assert_eq!(accepted.peer(), harness.dialler_device(), "and the acceptor sees the dialler");
}

/// The peer identity is settled at establishment and does not move.
pub async fn a_session_reports_a_stable_peer(harness: &dyn Harness) {
    let (dialled, _accepted) = establish(harness).await;
    let first = dialled.peer();
    dialled.send(b"anything").await.expect("sends");
    assert_eq!(dialled.peer(), first, "the peer does not change with use");
}

/// Bytes arrive as they were sent.
pub async fn payloads_arrive_unchanged(harness: &dyn Harness) {
    let (dialled, accepted) = establish(harness).await;
    let payload = b"the exact bytes".to_vec();
    dialled.send(&payload).await.expect("sends");
    assert_eq!(accepted.recv().await.expect("receives"), payload);

    // And in the other direction.
    let back = b"and back again".to_vec();
    accepted.send(&back).await.expect("sends");
    assert_eq!(dialled.recv().await.expect("receives"), back);
}

/// Two payloads arrive as two, neither joined nor split.
pub async fn payload_boundaries_are_preserved(harness: &dyn Harness) {
    let (dialled, accepted) = establish(harness).await;
    dialled.send(b"first").await.expect("sends");
    dialled.send(b"second").await.expect("sends");

    assert_eq!(accepted.recv().await.expect("receives"), b"first".to_vec());
    assert_eq!(
        accepted.recv().await.expect("receives"),
        b"second".to_vec(),
        "two payloads, not one joined payload nor three fragments"
    );
}

/// An oversized payload is refused whole, not truncated.
pub async fn an_oversized_payload_is_refused_at_the_sender(harness: &dyn Harness) {
    let (dialled, accepted) = establish(harness).await;
    let oversized = vec![0u8; crate::limits::MAX_PAYLOAD.saturating_add(1)];

    match dialled.send(&oversized).await {
        Err(Error::PayloadTooLarge { len, limit }) => {
            assert_eq!(len, oversized.len());
            assert_eq!(limit, crate::limits::MAX_PAYLOAD);
        }
        other => panic!("expected a refusal naming the bound, got {other:?}"),
    }

    // Nothing partial reached the peer: a following payload is the first thing
    // it sees.
    dialled.send(b"after").await.expect("sends");
    assert_eq!(accepted.recv().await.expect("receives"), b"after".to_vec());
}

/// A send after close fails rather than appearing to succeed.
pub async fn sending_on_a_closed_session_fails(harness: &dyn Harness) {
    let (dialled, _accepted) = establish(harness).await;
    dialled.close().await.expect("closes");
    let outcome = dialled.send(b"too late").await;
    assert!(
        matches!(outcome, Err(error) if error.is_closed()),
        "a send on a closed session must fail"
    );
}

/// A receive after close reports it rather than waiting forever.
pub async fn receiving_on_a_closed_session_reports_the_close(harness: &dyn Harness) {
    let (dialled, _accepted) = establish(harness).await;
    dialled.close().await.expect("closes");
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), dialled.recv()).await;
    match outcome {
        Ok(Err(error)) => assert!(error.is_closed(), "the close is reported: {error:?}"),
        Ok(Ok(_)) => panic!("a closed session must not yield a payload"),
        Err(_) => panic!("a receive on a closed session must not block indefinitely"),
    }
}

/// A peer nobody can reach is reported as unreachable, not as a refusal.
pub async fn an_unreachable_peer_is_reported_as_unreachable(harness: &dyn Harness) {
    let outcome = harness.dialler().connect(&harness.unreachable_key()).await;
    match outcome {
        Err(error) => {
            assert!(matches!(error, Error::PeerUnreachable { .. }), "{error}");
            assert!(
                !error.is_membership_refusal(),
                "unreachable is a connectivity answer, not a membership one"
            );
        }
        Ok(_) => panic!("a session must not be established with an unreachable peer"),
    }
}

/// Revoking a peer closes the session it already had.
pub async fn revoking_a_peer_closes_its_session(harness: &dyn Harness) {
    let (dialled, _accepted) = establish(harness).await;
    assert!(dialled.send(b"while a member").await.is_ok());

    let mut state = harness.state().await;
    let peer = dialled.peer();
    state.devices.remove(&peer);
    state.revoked.insert(peer);
    harness.set_state(state).await;

    let outcome = dialled.send(b"after revocation").await;
    match outcome {
        Err(Error::ClosedOnMembershipLoss) => {}
        other => panic!("expected a close on membership loss, got {other:?}"),
    }
}

/// And it cannot come back.
pub async fn a_revoked_peer_cannot_reconnect(harness: &dyn Harness) {
    let mut state = harness.state().await;
    let peer = harness.acceptor_device();
    state.devices.remove(&peer);
    state.revoked.insert(peer);
    harness.set_state(state).await;

    let key = harness.acceptor_key();
    let (dialled, _accepted) =
        tokio::join!(harness.dialler().connect(&key), harness.acceptor().accept());
    match dialled {
        Err(error) => assert!(
            error.is_membership_refusal(),
            "a revoked peer is refused on membership grounds, got {error:?}"
        ),
        Ok(_) => panic!("a revoked peer must not establish a session"),
    }
}

/// A harness needs two identities; this makes them so the suite reads clearly.
#[must_use]
pub fn two_identities() -> (Arc<NodeIdentity>, Arc<NodeIdentity>) {
    (
        Arc::new(NodeIdentity::generate().expect("generates")),
        Arc::new(NodeIdentity::generate().expect("generates")),
    )
}

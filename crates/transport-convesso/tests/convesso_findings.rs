//! What the binding relies on convesso doing, checked on convesso alone, with
//! none of this crate's code in the way.
//!
//! Each test began as a finding: something convesso did that broke the
//! binding, reproduced here before it was reported. Once convesso was fixed the
//! test stayed, so a convesso that regresses fails here, where the cause is
//! plain, rather than somewhere in the shared suite.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::time::Duration;

use convesso_core::identity::Identity;
use convesso_tokio::{
    Config, Context, ContextEvent, ContextEvents, ContextOptions, Node, NodeEvent, RelayLocation,
};
use transport_convesso::fixture::TestRelay;

/// A node registered on `relay`, serving one context open to everyone.
async fn node(seed: u8, relay: &TestRelay) -> (Node, Context, ContextEvents) {
    let identity = Identity::from_ed25519_seed(&[seed; 32]).unwrap();
    let address = convesso_core::identity::Address::parse(relay.key).unwrap();
    let (node, mut events) = convesso_tokio::start(
        identity,
        Config {
            relay: Some(RelayLocation { address, host: relay.host.clone(), tls: false }),
            ..Config::default()
        },
    )
    .await
    .unwrap();
    let (context, context_events) =
        node.context(b"finding", ContextOptions::default()).await.unwrap();
    node.set_reachable(true).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = events.next().await {
            if event == NodeEvent::RelayAvailable {
                return;
            }
        }
    })
    .await
    .unwrap();
    // The node's own events are not read past this point; it does not wait on
    // them (`DESIGN.md §5`).
    drop(events);
    (node, context, context_events)
}

/// The next message from anyone, or `None` within the patience given.
async fn message(events: &mut ContextEvents, patience: Duration) -> Option<Vec<u8>> {
    tokio::time::timeout(patience, async {
        while let Some(event) = events.next().await {
            if let ContextEvent::Message { data, .. } = event {
                return Some(data);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

/// The next datagram from anyone, or `None` within the patience given.
async fn datagram(events: &mut ContextEvents, patience: Duration) -> Option<Vec<u8>> {
    tokio::time::timeout(patience, async {
        while let Some(event) = events.next().await {
            if let ContextEvent::Datagram { data, .. } = event {
                return Some(data);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

/// After `close_peer`, a reliable message to the same peer arrives, as a
/// datagram does. Before convesso `82f4f6c` it was lost, and nothing said so:
/// the binding closes a revoked peer's session this way, and the peer's next
/// dial never arrived.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_after_close_peer_arrives() {
    let relay = TestRelay::start().await;
    let (_a_node, a, _a_events) = node(1, &relay).await;
    let (b_node, _b, mut b_events) = node(2, &relay).await;

    a.send_message(b_node.address(), b"before".to_vec()).await.unwrap();
    assert_eq!(message(&mut b_events, Duration::from_secs(10)).await, Some(b"before".to_vec()));

    _a_node.close_peer(b_node.address().peer_id(), 0x0101).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;

    a.send(b_node.address(), b"datagram after".to_vec()).await.unwrap();
    assert_eq!(
        datagram(&mut b_events, Duration::from_secs(10)).await,
        Some(b"datagram after".to_vec()),
        "a datagram after close_peer arrives"
    );

    a.send_message(b_node.address(), b"message after".to_vec()).await.unwrap();
    assert_eq!(
        message(&mut b_events, Duration::from_secs(15)).await,
        Some(b"message after".to_vec()),
        "a message after close_peer arrives"
    );
}

/// The same after `close`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_after_close_arrives() {
    let relay = TestRelay::start().await;
    let (_a_node, a, _a_events) = node(1, &relay).await;
    let (b_node, _b, mut b_events) = node(2, &relay).await;

    a.send_message(b_node.address(), b"before".to_vec()).await.unwrap();
    assert_eq!(message(&mut b_events, Duration::from_secs(10)).await, Some(b"before".to_vec()));

    a.close(b_node.address().peer_id(), 0x0101).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;

    a.send(b_node.address(), b"datagram after".to_vec()).await.unwrap();
    assert_eq!(
        datagram(&mut b_events, Duration::from_secs(10)).await,
        Some(b"datagram after".to_vec()),
        "a datagram after close arrives"
    );

    a.send_message(b_node.address(), b"message after".to_vec()).await.unwrap();
    assert_eq!(
        message(&mut b_events, Duration::from_secs(15)).await,
        Some(b"message after".to_vec()),
        "a message after close arrives"
    );
}

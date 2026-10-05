//! Two endpoints, a relay in this process, and real QUIC between them.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod common;

use common::Fixture;
use transport::session::Transport;
use transport_iroh::IrohTransport;

#[tokio::test]
async fn two_members_establish_a_session_over_a_relay() {
    let (_map, url, _server) =
        iroh::test_utils::run_relay_server().await.expect("a relay in this process");
    let fixture = Fixture::found(Some(url.as_str()));

    let dialler =
        IrohTransport::bind_trusting_any_relay_certificate(&fixture.founder, fixture.state.clone())
            .await
            .expect("binds");
    let acceptor =
        IrohTransport::bind_trusting_any_relay_certificate(&fixture.joiner, fixture.state.clone())
            .await
            .expect("binds");

    // Both endpoints must have reached their relay before either can be found
    // through it. Waiting here is test setup, not something the binding hides.
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::join!(dialler.endpoint().online(), acceptor.endpoint().online())
    })
    .await
    .expect("both endpoints reach the relay");

    let key = acceptor.transport_key();
    // Bounded: a hang here is a result, and a test that blocks reports nothing.
    let (dialled, accepted) = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::join!(dialler.connect(&key), acceptor.accept())
    })
    .await
    .expect("the pair connects within thirty seconds");

    let dialled = dialled.expect("establishes");
    let accepted = accepted.expect("establishes");

    assert_eq!(dialled.peer(), fixture.joiner.device_id());
    assert_eq!(accepted.peer(), fixture.founder.device_id());

    dialled.send(b"hello").await.expect("sends");
    assert_eq!(accepted.recv().await.expect("receives"), b"hello");
}

/// A session is usable before hole punching resolves.
///
/// §2.9 requires the relay to open in parallel with the direct attempt, and
/// §2.6b budgets 500 ms from activation to a useful session. Serialising —
/// try direct, fall back — would put a NAT timeout in front of every first
/// connection, and a timeout is the worst case of the slowest step.
///
/// This asserts the property the container matrix demonstrates at scale: every
/// case there establishes in about a second and carries traffic while the path
/// is still relayed.
#[tokio::test]
async fn a_session_is_usable_before_a_direct_path_exists() {
    let (_map, url, _server) =
        iroh::test_utils::run_relay_server().await.expect("a relay in this process");
    let fixture = Fixture::found(Some(url.as_str()));

    let dialler =
        IrohTransport::bind_trusting_any_relay_certificate(&fixture.founder, fixture.state.clone())
            .await
            .expect("binds");
    let acceptor =
        IrohTransport::bind_trusting_any_relay_certificate(&fixture.joiner, fixture.state.clone())
            .await
            .expect("binds");

    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::join!(dialler.endpoint().online(), acceptor.endpoint().online())
    })
    .await
    .expect("both endpoints reach the relay");

    let key = acceptor.transport_key();
    let started = std::time::Instant::now();
    let (dialled, accepted) = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::join!(dialler.connect(&key), acceptor.accept())
    })
    .await
    .expect("the pair connects");
    let elapsed = started.elapsed();

    let dialled = dialled.expect("establishes");
    let accepted = accepted.expect("establishes");

    // Usable: it carries bytes now, not once some later attempt resolves.
    dialled.send(b"before any direct path").await.expect("sends");
    assert_eq!(accepted.recv().await.expect("receives"), b"before any direct path");

    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "a session must not wait on hole punching to become usable, took {elapsed:?}"
    );
}

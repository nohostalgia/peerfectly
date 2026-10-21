//! The relay container's program, asked the way a founding device asks it.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::net::SocketAddr;

use relay_server::{Running, Settings};

fn settings(data: &std::path::Path, public_port: Option<u16>) -> Settings {
    Settings {
        data: data.to_path_buf(),
        relay: SocketAddr::from(([127, 0, 0, 1], 0)),
        key: SocketAddr::from(([127, 0, 0, 1], 0)),
        public_port,
        extra: None,
    }
}

/// Starts it and serves it in the background, answering what `start` said.
async fn serving(settings: &Settings) -> (String, u16, u16) {
    let running: Running = relay_server::start(settings).await.unwrap();
    let key = running.key.clone();
    let relay_port = running.relay_udp.port();
    let key_port = running.key_at.port();
    tokio::spawn(running.serve());
    (key, relay_port, key_port)
}

/// What the daemon makes of the answer, asked over the loopback.
async fn asked(key_port: u16) -> String {
    tokio::task::spawn_blocking(move || daemon::relay::ask("127.0.0.1", "relay.example", key_port))
        .await
        .unwrap()
        .unwrap()
}

/// A fresh data directory answers the key the relay started with, and its port.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fresh_relay_answers_its_own_key() {
    let data = tempfile::tempdir().unwrap();
    let (key, relay_port, key_port) = serving(&settings(data.path(), None)).await;

    let relay = asked(key_port).await;
    assert_eq!(relay, format!("{key}@relay.example:{relay_port}"), "its key, at its port");
}

/// A restart on the same data keeps the key and the certificate: what a person
/// confirmed once is what the relay is afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_keeps_the_key_and_the_certificate() {
    let data = tempfile::tempdir().unwrap();
    let first = relay_server::start(&settings(data.path(), None)).await.unwrap();
    assert!(first.created, "made on first start");
    let key = first.key.clone();
    let certificate = std::fs::read(data.path().join("https.crt")).unwrap();
    drop(first);

    let second = relay_server::start(&settings(data.path(), None)).await.unwrap();
    assert!(!second.created, "kept, not made again");
    assert_eq!(key, second.key);
    assert_eq!(certificate, std::fs::read(data.path().join("https.crt")).unwrap());
}

/// A host that publishes the relay on another port says so once, and the
/// answer carries it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_public_port_is_the_port_answered() {
    let data = tempfile::tempdir().unwrap();
    let (key, _relay_port, key_port) = serving(&settings(data.path(), Some(9443))).await;
    assert_eq!(asked(key_port).await, format!("{key}@relay.example:9443"));
}

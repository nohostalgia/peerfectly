//! The program's library against the real client, over TLS on a loopback port.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::path::PathBuf;

use identity::PrivateKey;
use rendezvous::error::Limit;
use rendezvous::{Client, Error};
use roster::id::NetworkId;
use roster::types::Algorithm;

/// A running server, the certificate it presents, and where it is.
struct Running {
    base: String,
    certificate: Vec<u8>,
    _scratch: tempfile::TempDir,
}

/// A self-signed certificate for the loopback address, written as PEM.
fn issued(scratch: &tempfile::TempDir) -> (PathBuf, PathBuf, Vec<u8>) {
    let issued = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let cert = scratch.path().join("relay.crt");
    let key = scratch.path().join("relay.key");
    std::fs::write(&cert, issued.cert.pem()).unwrap();
    std::fs::write(&key, issued.signing_key.serialize_pem()).unwrap();
    (cert, key, issued.cert.der().to_vec())
}

async fn start() -> Running {
    let scratch = tempfile::tempdir().unwrap();
    let (cert, key, certificate) = issued(&scratch);
    let tls = rendezvous_server::tls(&cert, &key).expect("a TLS server");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(rendezvous_server::serve(listener, tls));
    Running { base: format!("https://127.0.0.1:{port}"), certificate, _scratch: scratch }
}

fn network() -> NetworkId {
    NetworkId::from_bytes([4; 32])
}

fn device() -> PrivateKey {
    PrivateKey::generate(Algorithm::Ed25519).unwrap()
}

async fn publish(client: &Client, device: &PrivateKey) -> Result<(), Error> {
    client
        .publish(1, vec!["ip:203.0.113.7:51820".to_owned()], device.signer(), device.public_key())
        .await
}

/// **A record is published and fetched over TLS**, by a client pinning the
/// server's certificate and trusting nothing else.
#[tokio::test]
async fn a_record_round_trips_over_tls() {
    let server = start().await;
    let client = Client::pinned(&server.base, network(), &server.certificate).expect("a client");
    let device = device();

    publish(&client, &device).await.expect("published");
    let fetched = client.fetch(&device.key_id(), None).await.expect("fetched").expect("present");
    assert_eq!(fetched.addresses, vec!["ip:203.0.113.7:51820".to_owned()]);
}

/// **Plain HTTP reaches nothing.** The connection never completes a handshake,
/// so the service never sees it.
#[tokio::test]
async fn plain_http_gets_no_record() {
    let server = start().await;
    let plain = server.base.replacen("https://", "http://", 1);
    let device = device();

    let asked = reqwest::Client::new()
        .get(format!("{plain}/r/{}", roster::hex::encode(device.key_id().as_bytes())))
        .send()
        .await;
    assert!(asked.is_err(), "a plain request was answered: {asked:?}");
}

/// **The per-source limit sees each client's own address.** Past the limit of
/// keys one address may hold, the next is refused — which only happens if the
/// address reached the service through TLS.
#[tokio::test]
async fn the_per_source_limit_sees_the_clients_address() {
    let server = start().await;
    let client = Client::pinned(&server.base, network(), &server.certificate).expect("a client");

    for _ in 0..rendezvous::limits::MAX_KEYS_PER_SOURCE {
        publish(&client, &device()).await.expect("within the limit");
    }
    let refused = publish(&client, &device()).await;
    assert!(
        matches!(refused, Err(Error::Limit(Limit::KeysPerSource { .. }))),
        "one address past its keys: {refused:?}"
    );
}

/// **Another certificate on that host is refused**: nothing is published to
/// it, nothing read from it.
#[tokio::test]
async fn another_certificate_is_refused() {
    let server = start().await;
    let elsewhere = tempfile::tempdir().unwrap();
    let (_, _, other) = issued(&elsewhere);
    let client = Client::pinned(&server.base, network(), &other).expect("a client");
    let device = device();

    assert!(publish(&client, &device).await.is_err(), "published to a server it does not pin");
    assert!(client.fetch(&device.key_id(), None).await.is_err(), "and read from it");
}

/// **A pinned client never speaks in clear**, even pointed at `http://`.
#[tokio::test]
async fn a_pinned_client_refuses_plain_http() {
    let server = start().await;
    let plain = server.base.replacen("https://", "http://", 1);
    let client = Client::pinned(&plain, network(), &server.certificate).expect("a client");

    assert!(publish(&client, &device()).await.is_err());
}

/// A certificate that is not one gives no client, never one on the public roots.
#[test]
fn an_unusable_certificate_gives_no_client() {
    assert!(Client::pinned("https://127.0.0.1:1", network(), b"not a certificate").is_none());
}

/// The certificate's paths are one setting: the variables, then the defaults.
#[test]
fn the_certificate_follows_the_variables() {
    let none = rendezvous_server::Asked::from_words(Vec::<String>::new(), |_| None).unwrap();
    assert_eq!(PathBuf::from(rendezvous_server::CERT_DEFAULT), none.cert);
    assert_eq!(PathBuf::from(rendezvous_server::KEY_DEFAULT), none.key);

    let set = rendezvous_server::Asked::from_words(Vec::<String>::new(), |name| {
        Some(format!("/certs/{name}.pem"))
    })
    .unwrap();
    assert_eq!(PathBuf::from("/certs/PEERFECTLY_CERT.pem"), set.cert);
    assert_eq!(PathBuf::from("/certs/PEERFECTLY_KEY.pem"), set.key);

    let told =
        rendezvous_server::Asked::from_words(["--cert".to_owned(), "/a.pem".to_owned()], |name| {
            Some(format!("/certs/{name}.pem"))
        })
        .unwrap();
    assert_eq!(PathBuf::from("/a.pem"), told.cert, "an argument wins over the variable");
}

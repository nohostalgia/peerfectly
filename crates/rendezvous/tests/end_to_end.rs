//! The real client against the real service, over a loopback port.
//!
//! No network beyond the loopback interface: this is not NAT traversal, and
//! `DESIGN.md` §0's rule about real-world NAT tests governs hole punching, which
//! this change does not do.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::net::SocketAddr;
use std::time::Duration;

use identity::PrivateKey;
use rendezvous::error::Limit;
use rendezvous::record::{Record, SignedRecord};
use rendezvous::{Client, Error};
use roster::id::NetworkId;
use roster::types::Algorithm;

/// A running service, and where to reach it.
struct Service {
    base: String,
}

/// Starts the service on an ephemeral loopback port.
async fn start() -> Service {
    let store = rendezvous::service::shared_store();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("binds");
    let address = listener.local_addr().expect("has an address");

    let app = rendezvous::service::router(store);
    tokio::spawn(async move {
        let _ =
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await;
    });

    // Give the accept loop a moment to be listening.
    tokio::time::sleep(Duration::from_millis(50)).await;
    Service { base: format!("http://{address}") }
}

fn network() -> NetworkId {
    NetworkId::from_bytes([4; 32])
}

fn device() -> PrivateKey {
    PrivateKey::generate(Algorithm::Ed25519).expect("generates")
}

/// Publishes through the client, which signs on the caller's behalf.
async fn publish(
    client: &Client,
    device: &PrivateKey,
    sequence: u64,
    addresses: &[&str],
) -> Result<(), Error> {
    client
        .publish(
            sequence,
            addresses.iter().map(|a| (*a).to_owned()).collect(),
            device.signer(),
            device.public_key(),
        )
        .await
}

#[tokio::test]
async fn a_record_round_trips() {
    let service = start().await;
    let client = Client::new(&service.base, network());
    let device = device();

    publish(&client, &device, 1, &["ip:203.0.113.7:51820"]).await.expect("published");

    let fetched = client.fetch(&device.key_id(), None).await.expect("fetched").expect("present");
    assert_eq!(fetched.addresses, vec!["ip:203.0.113.7:51820".to_owned()]);
    assert_eq!(fetched.sequence, 1);
}

#[tokio::test]
async fn an_unknown_key_is_absent_rather_than_an_error() {
    let service = start().await;
    let client = Client::new(&service.base, network());

    let outcome = client.fetch(&device().key_id(), None).await.expect("no error");
    assert_eq!(outcome, None, "a key nobody published is absent, not a failure");
}

#[tokio::test]
async fn a_later_record_replaces_an_earlier_one() {
    let service = start().await;
    let client = Client::new(&service.base, network());
    let device = device();

    publish(&client, &device, 1, &["ip:a"]).await.expect("published");
    // The service enforces a minimum interval between publications.
    tokio::time::sleep(Duration::from_secs(rendezvous::limits::MIN_PUBLISH_INTERVAL_SECS)).await;
    publish(&client, &device, 2, &["ip:b"]).await.expect("published");

    let fetched = client.fetch(&device.key_id(), None).await.expect("fetched").expect("present");
    assert_eq!(fetched.addresses, vec!["ip:b".to_owned()]);
    assert_eq!(fetched.sequence, 2);
}

#[tokio::test]
async fn an_earlier_record_is_refused_over_the_wire() {
    let service = start().await;
    let client = Client::new(&service.base, network());
    let device = device();

    publish(&client, &device, 5, &["ip:a"]).await.expect("published");
    tokio::time::sleep(Duration::from_secs(rendezvous::limits::MIN_PUBLISH_INTERVAL_SECS)).await;

    let refused = publish(&client, &device, 4, &["ip:b"]).await;
    assert!(refused.is_err(), "a lower sequence must not be accepted");

    let fetched = client.fetch(&device.key_id(), None).await.expect("fetched").expect("present");
    assert_eq!(fetched.addresses, vec!["ip:a".to_owned()], "and nothing changed");
}

/// The client's own rule, which is what protects it when the service is
/// compromised or has restarted with an empty store.
#[tokio::test]
async fn a_client_refuses_a_record_no_newer_than_one_it_has_seen() {
    let service = start().await;
    let client = Client::new(&service.base, network());
    let device = device();

    publish(&client, &device, 3, &["ip:a"]).await.expect("published");

    match client.fetch(&device.key_id(), Some(3)).await {
        Err(Error::SequenceNotNewer { offered, held }) => {
            assert_eq!(offered, 3);
            assert_eq!(held, 3);
        }
        other => panic!("expected the client's own sequence refusal, got {other:?}"),
    }
}

/// A record filed under someone else's key must be refused, or a device could
/// publish its own perfectly valid record where another device's belongs.
#[tokio::test]
async fn a_record_cannot_be_filed_under_another_key() {
    let service = start().await;
    let mine = device();
    let other = device();

    let record = Record::new(mine.public_key(), network(), 1, vec!["ip:a".to_owned()])
        .expect("within bounds");
    let signed = SignedRecord::sign(record, mine.signer()).expect("signs");

    // Filed by hand under the *other* device's key. The signature verifies; the
    // key it names does not match where it is being stored.
    let url = format!("{}/r/{}", service.base, roster::hex::encode(other.key_id().as_bytes()));
    let response = reqwest::Client::new()
        .put(url)
        .body(signed.to_bytes())
        .send()
        .await
        .expect("reaches the service");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let client = Client::new(&service.base, network());
    assert_eq!(client.fetch(&other.key_id(), None).await.expect("no error"), None);
}

#[tokio::test]
async fn an_altered_record_no_longer_verifies() {
    let service = start().await;
    let device = device();
    let record = Record::new(device.public_key(), network(), 1, vec!["ip:a".to_owned()])
        .expect("within bounds");
    let signed = SignedRecord::sign(record, device.signer()).expect("signs");

    let mut tampered = signed.to_bytes();
    // Flip a byte inside the signed body, not the signature.
    if let Some(byte) = tampered.first_mut() {
        *byte ^= 0x01;
    }

    let url = format!("{}/r/{}", service.base, roster::hex::encode(device.key_id().as_bytes()));
    let response =
        reqwest::Client::new().put(url).body(tampered).send().await.expect("reaches the service");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}

/// A device's *signing* key must not sign a record: the key that says "I am
/// here" has to be the key that will prove "I am me" when the session opens.
#[tokio::test]
async fn a_signing_key_does_not_sign_a_record() {
    let service = start().await;
    let signing = PrivateKey::generate(Algorithm::Ed25519).expect("generates");
    let transport = PrivateKey::generate(Algorithm::Ed25519).expect("generates");

    // A record naming the transport key, but signed with the signing key.
    let record = Record::new(transport.public_key(), network(), 1, vec!["ip:a".to_owned()])
        .expect("within bounds");
    let signed = SignedRecord::sign(record, signing.signer()).expect("signs");

    let url = format!("{}/r/{}", service.base, roster::hex::encode(transport.key_id().as_bytes()));
    let response = reqwest::Client::new()
        .put(url)
        .body(signed.to_bytes())
        .send()
        .await
        .expect("reaches the service");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_record_from_another_network_is_refused_by_the_client() {
    let service = start().await;
    let device = device();

    // Published for one network...
    let elsewhere = NetworkId::from_bytes([77; 32]);
    let publisher = Client::new(&service.base, elsewhere);
    publish(&publisher, &device, 1, &["ip:a"]).await.expect("published");

    // ...and fetched by a client that belongs to another.
    let ours = Client::new(&service.base, network());
    assert_eq!(ours.fetch(&device.key_id(), None).await, Err(Error::ForeignNetwork));
}

#[tokio::test]
async fn publishing_too_soon_is_refused_and_says_to_wait() {
    let service = start().await;
    let client = Client::new(&service.base, network());
    let device = device();

    publish(&client, &device, 1, &["ip:a"]).await.expect("published");
    let refused = publish(&client, &device, 2, &["ip:b"]).await;

    match refused {
        Err(reason) => {
            assert!(reason.is_retryable(), "waiting must be the advice: {reason:?}");
            assert!(reason.is_about_the_publisher());
            assert!(!reason.is_about_the_record());
        }
        Ok(()) => panic!("a second publication inside the interval must be refused"),
    }
}

#[tokio::test]
async fn an_oversized_record_is_refused() {
    let service = start().await;
    let device = device();

    let url = format!("{}/r/{}", service.base, roster::hex::encode(device.key_id().as_bytes()));
    let response = reqwest::Client::new()
        .put(url)
        .body(vec![0u8; rendezvous::limits::MAX_RECORD_SIZE * 4])
        .send()
        .await
        .expect("reaches the service");

    assert!(
        !response.status().is_success(),
        "a body past the bound must not be accepted: {}",
        response.status()
    );
}

#[tokio::test]
async fn too_many_addresses_are_refused_before_signing() {
    let service = start().await;
    let client = Client::new(&service.base, network());
    let device = device();

    let many: Vec<String> =
        (0..=rendezvous::limits::MAX_ADDRESSES).map(|i| format!("ip:{i}")).collect();
    let outcome = client.publish(1, many, device.signer(), device.public_key()).await;

    match outcome {
        Err(Error::Limit(Limit::AddressCount { limit, .. })) => {
            assert_eq!(limit, rendezvous::limits::MAX_ADDRESSES);
        }
        other => panic!("expected a bound refusal naming the count, got {other:?}"),
    }
}

/// The bytes served are the bytes the device signed. A service that re-encoded
/// would be serving what it understood rather than what was signed.
#[tokio::test]
async fn the_service_serves_back_the_signed_bytes() {
    let service = start().await;
    let device = device();
    let record = Record::new(device.public_key(), network(), 1, vec!["ip:a".to_owned()])
        .expect("within bounds");
    let signed = SignedRecord::sign(record, device.signer()).expect("signs");
    let sent = signed.to_bytes();

    let url = format!("{}/r/{}", service.base, roster::hex::encode(device.key_id().as_bytes()));
    let http = reqwest::Client::new();
    http.put(&url).body(sent.clone()).send().await.expect("published");

    let served = http.get(&url).send().await.expect("fetched").bytes().await.expect("body");
    assert_eq!(served.as_ref(), sent.as_slice());
}

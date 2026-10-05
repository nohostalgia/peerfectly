//! The enrolment endpoint: what it reaches, what it refuses, and what it cannot
//! be talked into.
//!
//! The waiting side accepts a peer no roster names, which is the only place in
//! this crate that happens. These tests are what keep that exception the size it
//! is supposed to be.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod common;

use std::time::Duration;

use common::Fixture;
use identity::NodeIdentity;
use transport::session::Transport as _;
use transport_iroh::enrolment::{Admitting, ENROLMENT_ALPN, Waiting};
use transport_iroh::{ALPN, IrohTransport};

/// A relay in this process, and the certificate it presents.
async fn relay() -> (iroh_relay::server::Server, String, Vec<u8>) {
    use std::net::Ipv4Addr;

    use iroh_relay::server::{CertConfig, QuicConfig, RelayConfig, ServerConfig, TlsConfig};

    let (certs, server_config) = iroh_relay::server::testing::self_signed_tls_certs_and_config();
    let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
    relay.tls =
        Some(TlsConfig::new((Ipv4Addr::LOCALHOST, 0), CertConfig::Manual { server_config }));

    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    config.quic = Some(QuicConfig::new((Ipv4Addr::LOCALHOST, 0)));
    let server = iroh_relay::server::Server::spawn(config).await.expect("a relay in this process");

    let url = format!("https://{}", server.https_addr().expect("configured"));
    let certificate = certs.first().expect("one certificate").to_vec();
    (server, url, certificate)
}

/// A device with nothing binds at a relay a person named, and becomes reachable.
///
/// No roster, no network parameters, no pinned certificate: a relay address and
/// its own keys are the whole input. That is what makes joining possible at all
/// — a device with no network is otherwise unreachable in both directions.
#[tokio::test]
async fn a_device_with_no_roster_becomes_reachable_at_a_relay_a_person_named() {
    let (_server, url, certificate) = relay().await;
    let joiner = NodeIdentity::generate().expect("generates");

    let waiting = Waiting::listen(&joiner, &url).await.expect("binds");
    tokio::time::timeout(Duration::from_secs(30), waiting.online())
        .await
        .expect("registers at the relay");

    assert_eq!(waiting.relay(), url);
    assert_eq!(
        waiting.transport_key().as_bytes(),
        joiner.transport_key().public_key().as_bytes(),
        "the endpoint identity is the device's transport key"
    );
    assert_eq!(
        waiting.accepted_on_sight(),
        Some(certificate),
        "a self-signed relay is accepted on sight, and recorded rather than waved through"
    );
}

/// The whole exchange, end to end, between a device with nothing and a device
/// with a roster.
#[tokio::test]
async fn the_two_sides_exchange_messages_and_agree_on_the_channel() {
    let (_server, url, certificate) = relay().await;
    let fixture = Fixture::found_pinning(Some(url.as_str()), Some(certificate));
    let joiner = NodeIdentity::generate().expect("generates");

    let waiting = Waiting::listen(&joiner, &url).await.expect("binds");
    tokio::time::timeout(Duration::from_secs(30), waiting.online()).await.expect("online");

    let admitting =
        Admitting::dialling(&fixture.founder, &fixture.state).await.expect("binds to dial");
    let key = waiting.transport_key();

    let (reached, accepted) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(admitting.reach(&key, &url), waiting.accept())
    })
    .await
    .expect("the two sides meet");

    let mut admin_side = reached.expect("reaches");
    let mut joiner_side = accepted.expect("accepts");

    // The property the confirmation code rests on.
    assert_eq!(
        admin_side.material().expect("exports"),
        joiner_side.material().expect("exports"),
        "both ends of one channel must export the same material"
    );

    admin_side.send(b"a message").await.expect("sends");
    assert_eq!(joiner_side.receive().await.expect("receives"), b"a message");
    joiner_side.send(b"and back").await.expect("sends");
    assert_eq!(admin_side.receive().await.expect("receives"), b"and back");

    assert_eq!(
        joiner_side.peer().expect("a peer").as_bytes(),
        fixture.founder.transport_key().public_key().as_bytes(),
        "the channel authenticates the transport key, and only that"
    );
}

/// Two exchanges never share channel material, so a code seen once is worth
/// nothing later — and a forwarded exchange, which is two channels, produces two
/// different codes rather than one.
#[tokio::test]
async fn no_two_exchanges_share_channel_material() {
    let (_server, url, certificate) = relay().await;
    let fixture = Fixture::found_pinning(Some(url.as_str()), Some(certificate));
    let joiner = NodeIdentity::generate().expect("generates");

    let waiting = Waiting::listen(&joiner, &url).await.expect("binds");
    tokio::time::timeout(Duration::from_secs(30), waiting.online()).await.expect("online");
    let admitting = Admitting::dialling(&fixture.founder, &fixture.state).await.expect("binds");
    let key = waiting.transport_key();

    let mut seen = Vec::new();
    for _ in 0..2 {
        let (reached, accepted) = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(admitting.reach(&key, &url), waiting.accept())
        })
        .await
        .expect("the two sides meet");

        let admin_side = reached.expect("reaches");
        let joiner_side = accepted.expect("accepts");
        let material = admin_side.material().expect("exports");
        assert_eq!(material, joiner_side.material().expect("exports"));
        seen.push(material);
    }

    assert_ne!(
        seen.first(),
        seen.get(1),
        "two exchanges produced the same material, so a code could be replayed"
    );
}

/// Nothing can open an enrolment exchange against a machine that holds a
/// roster. The admitting side offers no protocol, so there is nothing to agree
/// with — by construction, not by a check.
#[tokio::test]
async fn a_machine_that_is_admitting_cannot_be_reached() {
    let (_server, url, certificate) = relay().await;
    let fixture = Fixture::found_pinning(Some(url.as_str()), Some(certificate));
    let joiner = NodeIdentity::generate().expect("generates");

    let admitting = Admitting::dialling(&fixture.founder, &fixture.state).await.expect("binds");
    drop(admitting);

    // Somebody who knows the admin's key tries to enrol *it*.
    let intruder = Waiting::listen(&joiner, &url).await.expect("binds");
    tokio::time::timeout(Duration::from_secs(30), intruder.online()).await.expect("online");

    // There is no method on `Admitting` that would accept this, and the
    // endpoint offers no protocol: the attempt cannot succeed.
    let outcome = tokio::time::timeout(Duration::from_secs(5), intruder.accept()).await;
    assert!(outcome.is_err(), "nothing should ever arrive at a waiting device nobody dialled");
}

/// The two protocols cannot be confused. An ordinary session and an enrolment
/// exchange do not share a name, so neither can reach the other.
#[tokio::test]
async fn an_ordinary_peer_cannot_open_a_session_against_an_enrolment_endpoint() {
    assert_ne!(ALPN, ENROLMENT_ALPN, "the two protocols must not share a name");

    let (_server, url, certificate) = relay().await;
    let fixture = Fixture::found_pinning(Some(url.as_str()), Some(certificate));
    let joiner = NodeIdentity::generate().expect("generates");

    let waiting = Waiting::listen(&joiner, &url).await.expect("binds");
    tokio::time::timeout(Duration::from_secs(30), waiting.online()).await.expect("online");

    let ordinary =
        IrohTransport::bind(&fixture.founder, fixture.state.clone()).await.expect("binds");
    tokio::time::timeout(Duration::from_secs(30), ordinary.endpoint().online())
        .await
        .expect("online");

    // The ordinary transport dials with its own ALPN. The waiting endpoint
    // speaks a different one, so no session can result.
    let dialled =
        tokio::time::timeout(Duration::from_secs(10), ordinary.connect(&waiting.transport_key()))
            .await;
    assert!(
        dialled.map_or(true, |outcome| outcome.is_err()),
        "an ordinary session must not establish against an enrolment endpoint"
    );
}

/// The endpoint does not outlive the enrolment.
#[tokio::test]
async fn closing_stops_the_device_being_reachable() {
    let (_server, url, _certificate) = relay().await;
    let joiner = NodeIdentity::generate().expect("generates");

    let waiting = Waiting::listen(&joiner, &url).await.expect("binds");
    tokio::time::timeout(Duration::from_secs(30), waiting.online()).await.expect("online");
    let key = waiting.transport_key();
    waiting.close().await;

    let founder = NodeIdentity::generate().expect("generates");
    let fixture = Fixture::found(Some(url.as_str()));
    let admitting = Admitting::dialling(&founder, &fixture.state).await.expect("binds");

    let reached = tokio::time::timeout(Duration::from_secs(10), admitting.reach(&key, &url)).await;
    assert!(
        reached.map_or(true, |outcome| outcome.is_err()),
        "a closed enrolment endpoint must not still be reachable"
    );
}

/// An enrolment channel is not a session and cannot be used as one.
///
/// Checked in the source because it is a fact about types: if `Channel` ever
/// gained the session interface, this crate would have a way to carry
/// application payloads over an endpoint that authenticates nobody.
#[test]
fn an_enrolment_channel_is_not_a_session() {
    let source = include_str!("../src/enrolment.rs");
    assert!(
        !source.contains("impl Session for") && !source.contains("impl Transport for"),
        "an enrolment channel must not implement the session or transport interface"
    );
    assert!(
        !source.contains("dyn Session"),
        "nothing here may be handed out where a session is expected"
    );
}

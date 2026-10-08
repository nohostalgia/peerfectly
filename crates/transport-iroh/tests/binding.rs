//! What this binding must get right beyond the shared suite: the endpoint
//! identity, the framing, the path it took, and the boundaries it must not
//! cross.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod common;

use std::net::Ipv4Addr;
use std::time::Duration;

use common::Fixture;
use identity::NodeIdentity;
use roster::types::Algorithm;
use transport::session::{Session, Transport};
use transport_iroh::{ALPN, BuildError, IrohTransport};

/// A bound pair on a relay running in this process.
async fn pair(fixture: &Fixture) -> (IrohTransport, IrohTransport) {
    let dialler =
        IrohTransport::bind_trusting_any_relay_certificate(&fixture.founder, fixture.state.clone())
            .await
            .expect("binds");
    let acceptor =
        IrohTransport::bind_trusting_any_relay_certificate(&fixture.joiner, fixture.state.clone())
            .await
            .expect("binds");
    tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(dialler.endpoint().online(), acceptor.endpoint().online())
    })
    .await
    .expect("both endpoints reach the relay");
    (dialler, acceptor)
}

/// A relay in this process, its address, and the certificate it presents.
///
/// Configured here rather than by `iroh::test_utils::run_relay_server`, which
/// discards the certificate it generated. A test about pinning needs the bytes
/// the relay will actually present.
async fn relay_and_its_certificate() -> (iroh_relay::server::Server, String, Vec<u8>) {
    use iroh_relay::server::{CertConfig, QuicConfig, RelayConfig, ServerConfig, TlsConfig};

    let (certs, server_config) = iroh_relay::server::testing::self_signed_tls_certs_and_config();
    let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
    relay.tls =
        Some(TlsConfig::new((Ipv4Addr::LOCALHOST, 0), CertConfig::Manual { server_config }));

    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    config.quic = Some(QuicConfig::new((Ipv4Addr::LOCALHOST, 0)));
    let server = iroh_relay::server::Server::spawn(config).await.expect("a relay in this process");

    // The certificate names `127.0.0.1`, so the address has to be that and not
    // `localhost`: a pin does not excuse a node from checking that the
    // certificate belongs to the address it dialled.
    let url = format!("https://{}", server.https_addr().expect("configured"));
    let certificate = certs.first().expect("one certificate").to_vec();
    (server, url, certificate)
}

/// Establishes one session, from both ends at once.
async fn establish(
    dialler: &IrohTransport,
    acceptor: &IrohTransport,
) -> (Box<dyn Session>, Box<dyn Session>) {
    let key = acceptor.transport_key();
    let (dialled, accepted) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(dialler.connect(&key), acceptor.accept())
    })
    .await
    .expect("the pair connects");
    (dialled.expect("establishes"), accepted.expect("establishes"))
}

// ---------------------------------------------------------------------------
// The endpoint identity
// ---------------------------------------------------------------------------

/// The thing being dialled and the thing being authorised are the same bytes.
/// Any other arrangement needs a device-to-endpoint mapping, and that mapping
/// would be a second answer to "who is this peer", kept outside the signed log.
#[tokio::test]
async fn the_endpoint_identity_is_the_devices_transport_key() {
    let (_map, url, _server) =
        iroh::test_utils::run_relay_server().await.expect("a relay in this process");
    let fixture = Fixture::found(Some(url.as_str()));
    let (dialler, acceptor) = pair(&fixture).await;

    assert_eq!(
        dialler.transport_key().as_bytes(),
        fixture.founder.transport_key().public_key().as_bytes(),
        "the endpoint presents the device's transport key, byte for byte"
    );
    assert_eq!(
        acceptor.transport_key().as_bytes(),
        fixture.joiner.transport_key().public_key().as_bytes()
    );
    assert_eq!(dialler.transport_key().algorithm(), Algorithm::Ed25519);
}

/// A node on a quiet relay connection pings its relay once a minute, not every
/// fifteen seconds: what it spends at rest is set here, not left to iroh.
#[tokio::test]
async fn a_quiet_node_does_not_ping_its_relay_every_fifteen_seconds() {
    let (_map, url, server) =
        iroh::test_utils::run_relay_server().await.expect("a relay in this process");
    let fixture = Fixture::found(Some(url.as_str()));
    let node =
        IrohTransport::bind_trusting_any_relay_certificate(&fixture.founder, fixture.state.clone())
            .await
            .expect("binds");
    tokio::time::timeout(Duration::from_secs(30), node.endpoint().online())
        .await
        .expect("reaches the relay");

    // The first ping goes out as the connection opens, whatever the interval.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let before = server.metrics().server.got_ping.get();
    tokio::time::sleep(Duration::from_secs(16)).await;
    assert_eq!(
        server.metrics().server.got_ping.get(),
        before,
        "no ping within sixteen seconds: iroh's default would have sent one"
    );
}

/// A key this layer cannot represent must fail when the endpoint is built, not
/// silently at the first connection — which would be diagnosed on a bad day, far
/// from the misconfiguration that caused it.
#[tokio::test]
async fn a_non_ed25519_transport_key_is_refused_when_the_endpoint_is_built() {
    // A device whose *transport* key is P-256. DESIGN.md §2.3 says this should
    // not happen; the point is that if it does, it is said plainly.
    let signing = identity::PrivateKey::generate(Algorithm::Ed25519).expect("generates");
    let transport = identity::PrivateKey::generate(Algorithm::P256).expect("generates");
    let attestation = identity::PrivateKey::generate(Algorithm::Ed25519).expect("generates");
    let odd = NodeIdentity::assemble(signing, transport, attestation).expect("assembles");

    let fixture = Fixture::found(None);
    match IrohTransport::bind(&odd, fixture.state).await {
        Err(BuildError::NotEd25519 { algorithm }) => assert_eq!(algorithm, Algorithm::P256),
        Err(other) => panic!("expected a refusal naming the algorithm, got {other:?}"),
        Ok(_) => panic!("a transport key this layer cannot represent must be refused"),
    }
}

// ---------------------------------------------------------------------------
// Addresses learned from somewhere else
// ---------------------------------------------------------------------------

/// §2.9's first path: two devices on one network, no relay, no internet.
///
/// The network here has no relay at all, so the only way to reach the acceptor
/// is an address somebody else supplied — which is what local discovery and the
/// rendezvous exist to supply. Without the hint the dial has nowhere to go; with
/// it the session establishes and carries bytes.
#[tokio::test]
async fn a_peer_with_no_relay_is_reached_only_because_its_address_was_learned() {
    let fixture = Fixture::found(None);
    let dialler =
        IrohTransport::bind(&fixture.founder, fixture.state.clone()).await.expect("binds");
    let acceptor =
        IrohTransport::bind(&fixture.joiner, fixture.state.clone()).await.expect("binds");
    let key = acceptor.transport_key();

    // Nothing has been learned yet, and there is no relay: the dial cannot
    // reach anybody. Short, because the point is that it does not succeed.
    let blind = tokio::time::timeout(Duration::from_secs(3), dialler.connect(&key)).await;
    assert!(
        blind.map_or(true, |outcome| outcome.is_err()),
        "with no relay and no address there is nowhere to dial"
    );

    let addresses = acceptor.addresses();
    assert!(!addresses.is_empty(), "an endpoint must be able to say where it is");

    // Loopback, built from the port the endpoint reported.
    //
    // What it reports is its interface addresses — here `192.168.x` — and both
    // endpoints are in this one process, so dialling those would send a packet
    // out to the host's own LAN address and back through the Windows firewall.
    // Whether that is allowed is a property of the machine, not of this code,
    // and it made this test pass and fail on alternate runs. One socket is bound
    // to `0.0.0.0:port`, so loopback reaches the same endpoint and reaches it
    // deterministically.
    let port = addresses
        .first()
        .and_then(|address| address.rsplit(':').next())
        .and_then(|port| port.parse::<u16>().ok())
        .expect("a reported address carries a port");
    let learned = vec![format!("127.0.0.1:{port}")];
    dialler.learned(&key, &learned);

    let (dialled, accepted) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(dialler.connect(&key), acceptor.accept())
    })
    .await
    .expect("the pair connects over a learned address");

    let dialled = dialled.expect("establishes");
    let accepted = accepted.expect("establishes");
    dialled.send(b"over the local network").await.expect("sends");
    assert_eq!(accepted.recv().await.expect("receives"), b"over the local network");
}

/// A hint is a hint. Nothing about an address decides who a peer is — the
/// session is authorised from the roster once it exists — so rubbish is dropped
/// rather than reported, and what it does not do is displace what works.
#[tokio::test]
async fn addresses_that_are_not_addresses_are_ignored() {
    let (_map, url, _server) =
        iroh::test_utils::run_relay_server().await.expect("a relay in this process");
    let fixture = Fixture::found(Some(url.as_str()));
    let (dialler, acceptor) = pair(&fixture).await;
    let key = acceptor.transport_key();

    dialler.learned(&key, &["not an address".to_owned(), "999.999.999.999:1".to_owned()]);

    // The relay still reaches it, exactly as it did before the hint.
    let (dialled, accepted) = establish(&dialler, &acceptor).await;
    dialled.send(b"unharmed").await.expect("sends");
    assert_eq!(accepted.recv().await.expect("receives"), b"unharmed");
}

// ---------------------------------------------------------------------------
// The relay's certificate
// ---------------------------------------------------------------------------

/// The production path, against a relay with a certificate no public authority
/// signed. Nothing here enables `insecure-test-relay`.
///
/// This is the arrangement §2.8 asks for — a relay the network runs itself —
/// and without the pin it cannot work at all: a strict client refuses the
/// self-signed certificate, no endpoint registers a home relay, and every dial
/// times out with nothing in the log about certificates.
#[tokio::test]
async fn a_pinned_relay_is_reached_without_trusting_any_certificate_authority() {
    let (_server, url, certificate) = relay_and_its_certificate().await;
    let fixture = Fixture::found_pinning(Some(url.as_str()), Some(certificate));

    let dialler =
        IrohTransport::bind(&fixture.founder, fixture.state.clone()).await.expect("binds");
    let acceptor =
        IrohTransport::bind(&fixture.joiner, fixture.state.clone()).await.expect("binds");
    tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(dialler.endpoint().online(), acceptor.endpoint().online())
    })
    .await
    .expect("both endpoints reach the pinned relay");

    let (dialled, accepted) = establish(&dialler, &acceptor).await;
    dialled.send(b"through the pinned relay").await.expect("sends");
    assert_eq!(accepted.recv().await.expect("receives"), b"through the pinned relay");
}

/// The same relay, unpinned. Left as evidence that the pin is what makes the
/// test above pass, rather than the relay being reachable anyway.
#[tokio::test]
async fn the_same_relay_is_unreachable_when_the_network_pins_nothing() {
    let (_server, url, _certificate) = relay_and_its_certificate().await;
    let fixture = Fixture::found(Some(url.as_str()));

    let node = IrohTransport::bind(&fixture.founder, fixture.state).await.expect("binds");
    // Binding succeeds — the failure is in the TLS handshake with the relay,
    // which happens afterwards and forever. `online` never resolves.
    let reached = tokio::time::timeout(Duration::from_secs(5), node.endpoint().online()).await;
    assert!(reached.is_err(), "an unpinned self-signed relay must not be trusted");
}

/// A pin that is not a certificate leaves the trust store empty, and an empty
/// trust store rejects the real relay exactly as it would an impostor. Said at
/// bind, where the parameters are, rather than at every dial.
#[tokio::test]
async fn a_pin_that_is_not_a_certificate_is_refused_when_the_endpoint_is_built() {
    let fixture = Fixture::found_pinning(
        Some("https://relay.example:443"),
        Some(b"not a certificate".to_vec()),
    );

    match IrohTransport::bind(&fixture.founder, fixture.state).await {
        Err(BuildError::UnusableRelayCertificate { reason }) => assert!(!reason.is_empty()),
        Err(other) => panic!("expected a refusal naming the certificate, got {other:?}"),
        Ok(_) => panic!("a pin that cannot be a trust anchor must be refused"),
    }
}

/// The signing key is not an endpoint identity, and dialling it reaches nobody.
#[tokio::test]
async fn a_signing_key_is_not_an_endpoint_identity() {
    let (_map, url, _server) =
        iroh::test_utils::run_relay_server().await.expect("a relay in this process");
    let fixture = Fixture::found(Some(url.as_str()));
    let (dialler, _acceptor) = pair(&fixture).await;

    let signing = fixture.joiner.signing_key().public_key();
    let outcome = tokio::time::timeout(Duration::from_secs(10), dialler.connect(&signing)).await;

    // Either it cannot be dialled at all, or nothing answers. What must never
    // happen is a session.
    // Either it cannot be dialled at all, or nothing answers within the bound.
    assert!(!matches!(outcome, Ok(Ok(_))), "a signing key must never open a session");
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn payloads_of_every_size_keep_their_boundaries() {
    let (_map, url, _server) =
        iroh::test_utils::run_relay_server().await.expect("a relay in this process");
    let fixture = Fixture::found(Some(url.as_str()));
    let (dialler, acceptor) = pair(&fixture).await;
    let (dialled, accepted) = establish(&dialler, &acceptor).await;

    // Empty, tiny, and larger than any single QUIC packet, so the framing is
    // doing real work rather than coinciding with packet boundaries.
    let payloads: Vec<Vec<u8>> =
        vec![Vec::new(), vec![1], vec![2; 1500], vec![3; 60_000], vec![4; 5]];

    for payload in &payloads {
        dialled.send(payload).await.expect("sends");
    }
    for expected in &payloads {
        let received = tokio::time::timeout(Duration::from_secs(20), accepted.recv())
            .await
            .expect("arrives")
            .expect("receives");
        assert_eq!(&received, expected, "a payload changed in flight or ran into its neighbour");
    }
}

#[tokio::test]
async fn a_payload_at_the_limit_is_carried_and_one_past_it_is_refused() {
    let (_map, url, _server) =
        iroh::test_utils::run_relay_server().await.expect("a relay in this process");
    let fixture = Fixture::found(Some(url.as_str()));
    let (dialler, acceptor) = pair(&fixture).await;
    let (dialled, accepted) = establish(&dialler, &acceptor).await;

    let exact = vec![7u8; transport::limits::MAX_PAYLOAD];
    dialled.send(&exact).await.expect("the bound is inclusive");
    let received = tokio::time::timeout(Duration::from_secs(30), accepted.recv())
        .await
        .expect("arrives")
        .expect("receives");
    assert_eq!(received.len(), transport::limits::MAX_PAYLOAD);

    let too_big = vec![7u8; transport::limits::MAX_PAYLOAD + 1];
    match dialled.send(&too_big).await {
        Err(transport::Error::PayloadTooLarge { len, limit }) => {
            assert_eq!(len, transport::limits::MAX_PAYLOAD + 1);
            assert_eq!(limit, transport::limits::MAX_PAYLOAD);
        }
        other => panic!("expected a refusal naming the bound, got {other:?}"),
    }

    // Refused at the sender, whole: the session still works afterwards, so
    // nothing partial was written to the stream.
    dialled.send(b"still here").await.expect("sends");
    let after = tokio::time::timeout(Duration::from_secs(20), accepted.recv())
        .await
        .expect("arrives")
        .expect("receives");
    assert_eq!(after, b"still here", "an oversized payload put nothing on the wire");
}

// ---------------------------------------------------------------------------
// The path
// ---------------------------------------------------------------------------

/// Both the §10.4 measurement and an operator asking why a session is slow need
/// this. Without it "it connected" is the only thing anyone can report, and that
/// was never the question.
#[tokio::test]
async fn whether_a_session_is_direct_is_observable() {
    let (_map, url, _server) =
        iroh::test_utils::run_relay_server().await.expect("a relay in this process");
    let fixture = Fixture::found(Some(url.as_str()));
    let (dialler, acceptor) = pair(&fixture).await;
    let (_dialled, _accepted) = establish(&dialler, &acceptor).await;

    // Asked through the interface: the in-memory implementations answer that they
    // cannot tell, and this one answers from the connection.
    let observed = dialler.path_to(&fixture.joiner.device_id()).await;
    assert!(observed.is_some(), "the path of an open session can be inspected");

    assert_eq!(
        dialler.path_to(&fixture.founder.device_id()).await,
        None,
        "and a device with no session reports nothing rather than guessing"
    );
}

// ---------------------------------------------------------------------------
// Boundaries
// ---------------------------------------------------------------------------

/// `DESIGN.md` §0 forbids iroh types outside the transport layer, and the scan in
/// `transport` asserts that crate is free of them. This one asserts the binding
/// did not smuggle a relay address into the code, where no `set_network`
/// operation could ever change it.
#[test]
fn no_relay_address_is_compiled_in() {
    let node = include_str!("../src/node.rs");
    for smell in ["https://", "http://", "relay.iroh", "n0.computer"] {
        assert!(
            !node.contains(smell),
            "`{smell}` looks like a compiled-in relay address; the relay is a signed \
             network parameter so that changing it costs one operation"
        );
    }
    assert!(node.contains("presets::Minimal"), "and no third-party defaults are pulled in");
}

/// The binding holds no membership list. One that disagreed with the signed log
/// would be the thing actually deciding who is in the network.
#[test]
fn the_binding_keeps_no_membership_list_of_its_own() {
    let node = include_str!("../src/node.rs");
    assert!(node.contains("auth::authorize"), "membership comes from the roster");
    for forbidden in ["allowed_devices", "known_members", "permitted", "trusted_keys"] {
        assert!(!node.contains(forbidden), "`{forbidden}` would be a second answer");
    }
}

/// The ALPN is specific to this protocol, so an unrelated application on the
/// same connectivity layer cannot open a session here by accident.
#[test]
fn the_protocol_has_its_own_alpn() {
    assert_eq!(ALPN, b"peerfectly/transport/2");
    assert!(!ALPN.is_empty(), "an empty ALPN would accept anything");
}

/// A peer speaking a different protocol on the same connectivity layer must not
/// get a session here. The ALPN is what keeps two unrelated applications sharing
/// an endpoint from finding each other.
#[tokio::test]
async fn a_peer_offering_a_different_alpn_is_not_accepted() {
    let (map, url, _server) =
        iroh::test_utils::run_relay_server().await.expect("a relay in this process");
    let fixture = Fixture::found(Some(url.as_str()));
    let (_dialler, acceptor) = pair(&fixture).await;

    // A stranger's endpoint speaking something else entirely.
    let outsider = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::endpoint::RelayMode::Custom(map))
        .alpns(vec![b"someone/else/1".to_vec()])
        .ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify())
        .bind()
        .await
        .expect("binds");
    tokio::time::timeout(Duration::from_secs(30), outsider.online())
        .await
        .expect("reaches the relay");

    let target: [u8; 32] = acceptor.transport_key().as_bytes().try_into().expect("an ed25519 key");
    let id = iroh::PublicKey::from_bytes(&target).expect("a valid identity");
    let address = iroh::EndpointAddr::new(id).with_relay_url(url);

    let outcome =
        tokio::time::timeout(Duration::from_secs(15), outsider.connect(address, b"someone/else/1"))
            .await;

    assert!(!matches!(outcome, Ok(Ok(_))), "a different protocol must not open a session here");
}

/// A device of the first version offers `peerfectly/transport/1`. Reaching it is
/// not "could not be reached" but "update one of them", because that is what a
/// person has to do.
#[tokio::test]
async fn a_device_of_another_version_is_told_apart() {
    let (map, url, _server) =
        iroh::test_utils::run_relay_server().await.expect("a relay in this process");
    let fixture = Fixture::found(Some(url.as_str()));
    let dialler =
        IrohTransport::bind_trusting_any_relay_certificate(&fixture.founder, fixture.state.clone())
            .await
            .expect("binds");

    let first_version = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::endpoint::RelayMode::Custom(map))
        .alpns(vec![b"peerfectly/transport/1".to_vec()])
        .ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify())
        .bind()
        .await
        .expect("binds");
    tokio::time::timeout(Duration::from_secs(30), first_version.online())
        .await
        .expect("reaches the relay");
    let listening = first_version.clone();
    tokio::spawn(async move {
        while let Some(incoming) = listening.accept().await {
            let _refused = incoming.await;
        }
    });

    let key = roster::sign::PublicKey::new(
        roster::types::Algorithm::Ed25519,
        first_version.id().as_bytes().to_vec(),
    )
    .expect("an ed25519 key");
    let outcome = tokio::time::timeout(Duration::from_secs(20), dialler.connect(&key))
        .await
        .expect("answers within the bound");
    assert!(
        matches!(outcome, Err(transport::Error::IncompatibleVersion)),
        "a version mismatch is named as one: {:?}",
        outcome.map(|_| ())
    );
}

/// The suite this binding runs is the one the in-memory implementations run.
/// A private copy would let this implementation quietly negotiate its own
/// semantics, which is the failure the two-implementation rule exists to catch.
#[test]
fn the_suite_is_the_shared_one() {
    let ours = include_str!("suite.rs");
    assert!(
        ours.contains("transport::suite") && ours.contains("run_all"),
        "the shared entry point is what runs"
    );
    assert!(
        !ours.contains("async fn a_member_establishes_a_session"),
        "the behaviours must come from the shared suite, not be restated here"
    );
}

/// The README covers the requirements this change adds, and records the two
/// facts a reader most needs: that possession comes from TLS here, and that the
/// container matrix is not the gate.
#[test]
fn the_readme_covers_what_it_must() {
    // Line endings normalised: a checkout on Windows with git's default
    // `autocrlf` writes this file with CRLF, and markers span lines.
    let readme = include_str!("../README.md").replace("\r\n", "\n");
    for (topic, marker) in [
        ("the endpoint identity", "endpoint identity"),
        ("possession from the handshake", "bound to that channel"),
        ("the framing", "big-endian length"),
        ("the relay's source", "signed network parameters"),
        ("the shared suite", "passes unmodified"),
        ("the vocabulary change", "EndpointId"),
        ("moving a relay", "keep the old"),
        ("pinning the relay's certificate", "custom_roots"),
        ("addresses learned elsewhere", "learned"),
        ("the enrolment endpoint", "accepts a stranger"),
        ("why admitting never listens", "has no listener at all"),
        (
            "what binds the confirmation code",
            "does not
exist until the channel does",
        ),
    ] {
        assert!(readme.contains(marker), "the README must cover {topic}");
    }
    assert!(
        readme.contains("Not run") || readme.contains("not run"),
        "and must say plainly that the real-world measurement has not been taken"
    );
}

/// Every deferral names where it went. "Later" is not a destination.
#[test]
fn every_deferral_names_its_destination() {
    let readme = include_str!("../README.md");
    for destination in ["rendezvous-service", "local-discovery", "tunnel", "windows-daemon"] {
        assert!(readme.contains(destination), "a deferral must name `{destination}`");
    }
}

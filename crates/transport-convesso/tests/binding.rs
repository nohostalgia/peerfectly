//! What the convesso binding promises beyond the shared suite.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use convesso_core::identity::{Address, Identity};
use convesso_tokio::{
    Config, Context, ContextEvent, ContextEvents, ContextOptions, Node, RelayLocation,
};
use identity::NodeIdentity;
use roster::types::Algorithm;
use transport::error::Error;
use transport::session::{Path, Session, Transport};
use transport_convesso::fixture::{Network, TestRelay};
use transport_convesso::frame::{Frame, Reason};
use transport_convesso::{BuildError, ConvessoTransport};

const PATIENCE: Duration = Duration::from_secs(20);

/// A network on an in-process relay, with both devices' nodes reachable.
async fn pair() -> (TestRelay, Network, ConvessoTransport, ConvessoTransport) {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let founder = ConvessoTransport::bind(&network.founder, network.state.clone()).await.unwrap();
    let joiner = ConvessoTransport::bind(&network.joiner, network.state.clone()).await.unwrap();
    tokio::time::timeout(PATIENCE, async { tokio::join!(founder.online(), joiner.online()) })
        .await
        .expect("both nodes reach the relay");
    (relay, network, founder, joiner)
}

/// A session from `dialler` to `acceptor`, both ends.
async fn session(
    dialler: &ConvessoTransport,
    acceptor: &ConvessoTransport,
) -> (Box<dyn Session>, Box<dyn Session>) {
    let key = acceptor.transport_key();
    let (dialled, accepted) = tokio::time::timeout(PATIENCE, async {
        tokio::join!(dialler.connect(&key), acceptor.accept())
    })
    .await
    .expect("establishment finishes");
    (dialled.expect("dials"), accepted.expect("accepts"))
}

// ---------------------------------------------------------------------------
// Building a node
// ---------------------------------------------------------------------------

/// A key convesso cannot represent fails when the node is built.
#[tokio::test]
async fn a_non_ed25519_transport_key_is_refused_at_build() {
    let signing = identity::PrivateKey::generate(Algorithm::Ed25519).unwrap();
    let transport = identity::PrivateKey::generate(Algorithm::P256).unwrap();
    let attestation = identity::PrivateKey::generate(Algorithm::Ed25519).unwrap();
    let odd = NodeIdentity::assemble(signing, transport, attestation).unwrap();

    let network = Network::found(None);
    match ConvessoTransport::bind(&odd, network.state).await {
        Err(BuildError::NotEd25519 { algorithm }) => assert_eq!(algorithm, Algorithm::P256),
        Err(other) => panic!("expected a refusal naming the algorithm, got {other:?}"),
        Ok(_) => panic!("a key convesso cannot represent must be refused"),
    }
}

/// A relay that is not `key@host:port`, an `https://` one or one without its
/// key, is refused at build.
#[tokio::test]
async fn a_relay_that_is_not_a_convesso_relay_is_refused_at_build() {
    let network = Network::found(Some("https://relay.example:443"));
    match ConvessoTransport::bind(&network.founder, network.state).await {
        Err(BuildError::UnusableRelay { .. }) => {}
        Err(other) => panic!("expected an unusable relay, got {other:?}"),
        Ok(_) => panic!("a relay without its key must be refused"),
    }

    let keyless = Network::found(Some("relay.example:7400"));
    assert!(matches!(
        ConvessoTransport::bind(&keyless.founder, keyless.state).await,
        Err(BuildError::UnusableRelay { .. })
    ));
}

/// A network with no relay has none, and its node is online at once.
#[tokio::test]
async fn a_network_without_a_relay_builds_a_node_without_one() {
    let network = Network::found(None);
    let node = ConvessoTransport::bind(&network.founder, network.state).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), node.online()).await.expect("nothing to wait for");
    let ports = node.own_ports();
    assert!(matches!(ports.as_slice(), [port] if *port != 0), "the port it sends from: {ports:?}");
}

/// **A node knows its addresses once it is built**, so the first announcement
/// on the LAN carries them. Learned a moment later, that announcement was
/// skipped and the next went out five seconds on: with no relay, a device
/// that had just come up took that long to be found (`convesso-reach` 5.4).
#[tokio::test]
async fn a_node_knows_its_addresses_once_built() {
    let network = Network::found(None);
    let node = ConvessoTransport::bind(&network.founder, network.state).await.unwrap();
    assert!(!node.addresses().is_empty(), "the addresses it can be reached at");
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

/// A session dropped without a close, and another opened after it, both
/// establish; the older one ends as closed by the peer, and what follows is
/// delivered on the newer one only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_newer_session_replaces_an_older_one() {
    let (_relay, _network, founder, joiner) = pair().await;
    let (first_dialled, first_accepted) = session(&founder, &joiner).await;
    drop(first_dialled);
    let (second_dialled, second_accepted) = session(&founder, &joiner).await;

    match tokio::time::timeout(PATIENCE, first_accepted.recv()).await.expect("ends") {
        Err(Error::ClosedByPeer) => {}
        other => panic!("the replaced session ends as closed by the peer, got {other:?}"),
    }
    second_dialled.send(b"to the newer one").await.unwrap();
    let received = tokio::time::timeout(PATIENCE, second_accepted.recv()).await.unwrap().unwrap();
    assert_eq!(received, b"to the newer one".to_vec());
}

/// **A session replaced where it was accepted ends where it was dialled.**
/// Two dials from one device in flight at once both open; the accepting side
/// keeps the newer, and the dialler must not go on holding the older as open.
/// Held, it was chosen over every session the peer opened afterwards, and the
/// two devices stayed apart (`convesso-reach` 5.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_replaced_where_it_was_accepted_ends_where_it_was_dialled() {
    let (_relay, _network, founder, joiner) = pair().await;
    let (first_dialled, _first_accepted) = session(&founder, &joiner).await;
    let (second_dialled, second_accepted) = session(&founder, &joiner).await;

    match tokio::time::timeout(PATIENCE, first_dialled.recv()).await.expect("ends") {
        Err(Error::ClosedByPeer) => {}
        other => panic!("the replaced session ends as closed by the peer, got {other:?}"),
    }
    second_dialled.send(b"to the newer one").await.unwrap();
    let received = tokio::time::timeout(PATIENCE, second_accepted.recv()).await.unwrap().unwrap();
    assert_eq!(received, b"to the newer one".to_vec());
}

/// A key no device holds is refused in the handshake, with the accepting
/// side's reason, and the accepting side yields nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranger_is_refused_in_the_handshake() {
    let (_relay, network, founder, _joiner) = pair().await;
    let stranger = NodeIdentity::generate().unwrap();
    let outsider = ConvessoTransport::bind(&stranger, network.state.clone()).await.unwrap();
    tokio::time::timeout(PATIENCE, outsider.online()).await.unwrap();

    let dial = tokio::time::timeout(PATIENCE, outsider.connect(&founder.transport_key()))
        .await
        .expect("the dial finishes");
    match dial {
        Err(Error::NotAMember) => {}
        Err(other) => panic!("expected the accepting side's refusal, got {other:?}"),
        Ok(_) => panic!("a stranger must not establish"),
    }
    assert!(
        tokio::time::timeout(Duration::from_secs(1), founder.accept()).await.is_err(),
        "the accepting side yields no session"
    );
}

/// A key nobody holds is unreachability, never a membership refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_nobody_holds_is_unreachable() {
    let (_relay, _network, founder, _joiner) = pair().await;
    let nobody = NodeIdentity::generate().unwrap();
    let dial = tokio::time::timeout(
        Duration::from_secs(30),
        founder.connect(&nobody.transport_key().public_key()),
    )
    .await
    .expect("the dial finishes");
    match dial {
        Err(error @ Error::PeerUnreachable { cause: Some(_) }) => {
            assert!(!error.is_membership_refusal());
        }
        other => panic!("expected unreachability with convesso's reason, got {:?}", other.err()),
    }
}

/// A raw convesso node under a member's key, serving this binding's context.
async fn raw_member(network: &Network, relay: &TestRelay) -> (Node, Context, ContextEvents) {
    let seed = network.joiner.transport_key().material().expose();
    let identity = Identity::from_ed25519_seed(seed).unwrap();
    let (node, _events) =
        convesso_tokio::start_with_stream::<transport_convesso::frame::Stream, _>(
            identity,
            Config {
                relay: Some(RelayLocation {
                    address: Address::parse(relay.key).unwrap(),
                    host: relay.host.clone(),
                    tls: false,
                }),
                ..Config::default()
            },
            convesso_tokio::entropy::OsEntropy,
        )
        .await
        .unwrap();
    let (context, events) =
        node.context(transport_convesso::node::CONTEXT, ContextOptions::default()).await.unwrap();
    (node, context, events)
}

/// An `OPEN` of another version is refused as such, so the dialler can say
/// "update a device" rather than "unreachable".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_version_is_refused_as_such() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let founder = ConvessoTransport::bind(&network.founder, network.state.clone()).await.unwrap();
    tokio::time::timeout(PATIENCE, founder.online()).await.unwrap();
    let (_raw_node, raw, mut events) = raw_member(&network, &relay).await;

    let founder_key: [u8; 32] = founder.transport_key().as_bytes().try_into().unwrap();
    let open = Frame::Open { version: 99, id: 42, evidence: Vec::new() }.encode();
    raw.send_message(Address::parse(founder_key).unwrap(), open).await.unwrap();

    let answer = tokio::time::timeout(PATIENCE, async {
        while let Some(event) = events.next().await {
            if let ContextEvent::Message { data, .. } = event {
                return Frame::decode(&data);
            }
        }
        None
    })
    .await
    .expect("an answer comes");
    assert_eq!(answer, Some(Frame::Refuse { id: 42, reason: Reason::Version }));
}

/// The next frame `events` delivers as a message.
async fn next_frame(events: &mut ContextEvents) -> Option<Frame> {
    tokio::time::timeout(PATIENCE, async {
        while let Some(event) = events.next().await {
            if let ContextEvent::Message { data, .. } = event {
                return Frame::decode(&data);
            }
        }
        None
    })
    .await
    .expect("a frame comes")
}

/// **A session outlives convesso's.** Past its keys' life convesso tells the
/// session idle and forgets it, and each side ends its reader so that the
/// channel is forgotten too. The next payload, from either side, opens a new
/// convesso session and arrives on the same session of this binding.
///
/// Waits out the keys' life on the real clock: run by hand.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "waits three minutes: cargo test -p transport-convesso --test binding -- --ignored"]
async fn a_session_carries_on_after_convesso_forgets_its_own() {
    let (_relay, _network, founder, joiner) = pair().await;
    let (dialled, accepted) = session(&founder, &joiner).await;
    dialled.send(b"before").await.unwrap();
    assert_eq!(accepted.recv().await.unwrap(), b"before".to_vec());

    tokio::time::sleep(Duration::from_secs(200)).await;

    dialled.send(b"after, one way").await.unwrap();
    let got = tokio::time::timeout(PATIENCE, accepted.recv()).await.expect("arrives").unwrap();
    assert_eq!(got, b"after, one way".to_vec());

    tokio::time::sleep(Duration::from_secs(200)).await;

    accepted.send(b"after, the other").await.unwrap();
    let got = tokio::time::timeout(PATIENCE, dialled.recv()).await.expect("arrives").unwrap();
    assert_eq!(got, b"after, the other".to_vec());
}

/// **A payload for a session this node does not hold is answered with a
/// `CLOSE`, once.** What a peer that crashed and came back looks like from
/// the other side: convesso starts its new session's channels anew without a
/// reset, so the frames of a session it kept arrive for a session id nobody
/// holds. Told, the sender ends that session rather than send into nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_payload_for_a_session_nobody_holds_is_answered_with_a_close() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let founder = ConvessoTransport::bind(&network.founder, network.state.clone()).await.unwrap();
    tokio::time::timeout(PATIENCE, founder.online()).await.unwrap();
    let (_raw_node, raw, mut events) = raw_member(&network, &relay).await;
    let founder_key: [u8; 32] = founder.transport_key().as_bytes().try_into().unwrap();
    let to_founder = Address::parse(founder_key).unwrap();

    for _ in 0..2 {
        let stale = Frame::Payload { id: 77, bytes: b"into nothing".to_vec() }.encode();
        raw.send_message(to_founder, stale).await.unwrap();
    }
    assert_eq!(
        next_frame(&mut events).await,
        Some(Frame::Close { id: 77, reason: Reason::Ordinary })
    );

    // Once: the second stale payload brings no second close.
    let more = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(event) = events.next().await {
            if let ContextEvent::Message { data, .. } = event {
                return Frame::decode(&data);
            }
        }
        None
    })
    .await;
    assert!(more.is_err(), "told once: {more:?}");
}

/// **An `ACCEPT` for a dial given up on is answered with a `CLOSE`.** The far
/// end took the session and holds it as open; nobody here will read it, and
/// the far end is told rather than left holding it (`convesso-reach` 5.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_accept_for_a_dial_given_up_on_is_closed() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let founder =
        Arc::new(ConvessoTransport::bind(&network.founder, network.state.clone()).await.unwrap());
    tokio::time::timeout(PATIENCE, founder.online()).await.unwrap();
    let (_raw_node, raw, mut events) = raw_member(&network, &relay).await;
    let founder_key: [u8; 32] = founder.transport_key().as_bytes().try_into().unwrap();
    let to_founder = Address::parse(founder_key).unwrap();
    // The raw node opens the channel, so the dial finds it there: a `CLOSE` of a
    // session nobody has is ignored.
    raw.send_message(to_founder, Frame::Close { id: 0, reason: Reason::Ordinary }.encode())
        .await
        .unwrap();
    tokio::time::timeout(PATIENCE, async {
        while let Some(event) = events.next().await {
            if matches!(event, ContextEvent::Connected { .. }) {
                return;
            }
        }
    })
    .await
    .expect("the channel opens");

    let dialling = {
        let founder = Arc::clone(&founder);
        let key = network.joiner.transport_key().public_key();
        tokio::spawn(async move { founder.connect(&key).await.map(|_| ()) })
    };
    let Some(Frame::Open { id, .. }) = next_frame(&mut events).await else {
        panic!("the dial arrives as an OPEN");
    };
    dialling.abort();
    let _ = dialling.await;

    raw.send_message(to_founder, Frame::Accept { id, evidence: Vec::new() }.encode())
        .await
        .unwrap();
    assert_eq!(next_frame(&mut events).await, Some(Frame::Close { id, reason: Reason::Ordinary }));
}

// ---------------------------------------------------------------------------
// Payloads and packets
// ---------------------------------------------------------------------------

/// A payload of exactly the interface's largest size crosses whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_payload_of_exactly_the_bound_crosses() {
    let (_relay, _network, founder, joiner) = pair().await;
    let (dialled, accepted) = session(&founder, &joiner).await;
    let payload: Vec<u8> =
        (0..transport::limits::MAX_PAYLOAD).map(|at| u8::try_from(at % 251).unwrap()).collect();
    dialled.send(&payload).await.unwrap();
    let received = tokio::time::timeout(PATIENCE, accepted.recv()).await.unwrap().unwrap();
    assert_eq!(received.len(), payload.len());
    assert_eq!(received, payload);
}

/// A tunnel-sized packet is one fragment on every path, a full-size one two.
#[test]
fn a_tunnel_sized_packet_is_one_datagram() {
    let room = transport_convesso::session::FRAGMENT_ROOM;
    assert_eq!(transport::fragment::split(1, &[0; 1_280], room).unwrap().len(), 1);
    assert_eq!(
        transport::fragment::split(2, &[0; transport::limits::MAX_PACKET], room).unwrap().len(),
        2
    );
    assert!(room + transport_convesso::frame::PACKET_HEADER <= 1_380 - 31, "fits the relay");
}

/// Every address there is, as ranges a tunnel might serve.
fn everywhere() -> Vec<transport::Range> {
    [
        (IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1),
        (IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1),
        (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1),
        (IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)), 1),
    ]
    .into_iter()
    .map(|(address, prefix)| transport::Range::new(address, prefix).unwrap())
    .collect()
}

/// With every direct address avoided, the session stays on the relay, says
/// so, and still carries a full-size packet whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_size_packet_crosses_the_relay_whole() {
    let (_relay, network, founder, joiner) = pair().await;
    founder.avoid(&everywhere());
    joiner.avoid(&everywhere());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(founder.path_to(&network.joiner.device_id()).await, None, "no session yet");

    let (dialled, accepted) = session(&founder, &joiner).await;
    let packet: Vec<u8> =
        (0..transport::limits::MAX_PACKET).map(|at| u8::try_from(at % 253).unwrap()).collect();
    for _ in 0..3 {
        dialled.send_packet(&packet).await.unwrap();
    }
    let received = tokio::time::timeout(PATIENCE, accepted.recv_packet()).await.unwrap().unwrap();
    assert_eq!(received, packet);

    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        founder.path_to(&network.joiner.device_id()).await,
        Some(Path::Relay),
        "no direct path inside an avoided range"
    );
}

// ---------------------------------------------------------------------------
// Membership changes
// ---------------------------------------------------------------------------

/// Revoking a device closes its session as a loss of membership, and the
/// handshake then refuses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_device_is_closed_and_then_refused_in_the_handshake() {
    let (_relay, network, founder, joiner) = pair().await;
    let (dialled, _accepted) = session(&founder, &joiner).await;

    let mut state = network.state.clone();
    let revoked = network.joiner.device_id();
    state.devices.remove(&revoked);
    state.revoked.insert(revoked);
    founder.update_state(state).await;

    match dialled.send(b"after").await {
        Err(Error::ClosedOnMembershipLoss) => {}
        other => panic!("expected a close on loss of membership, got {other:?}"),
    }

    // The revoked device still holds the old state, so it dials as a member
    // would: the founder's handshake is what refuses it. A dial made at once
    // may meet the old channel being reset instead, and fail as unreachable:
    // with signatures fast, as in a release build, it does. It never
    // establishes, and once the old channel is gone it is refused as what it
    // is.
    let refused = tokio::time::timeout(PATIENCE, async {
        loop {
            match joiner.connect(&founder.transport_key()).await {
                Ok(_) => panic!("a revoked device must not establish"),
                Err(error) if error.is_membership_refusal() => return error,
                Err(Error::PeerUnreachable { .. }) => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(other) => panic!("neither a refusal nor the old channel: {other:?}"),
            }
        }
    })
    .await
    .expect("refused within patience");
    assert!(refused.is_membership_refusal(), "{refused:?}");
}

// ---------------------------------------------------------------------------
// The relay, as the roster names it
// ---------------------------------------------------------------------------

/// The state on another relay: `relay` and its key, and no move.
fn on_relay(state: &roster::state::RosterState, relay: &TestRelay) -> roster::state::RosterState {
    let mut moved = state.clone();
    moved.params.relay = Some(relay.written());
    moved.params.leaving = None;
    moved
}

// ---------------------------------------------------------------------------
// A relay whose name resolves late
// ---------------------------------------------------------------------------

/// A resolver standing in for the system's: a host under `late.test` does not
/// resolve the first `failures` times it is asked, then answers `at`; any other
/// host is an address and answers itself. Counts what it was asked for under
/// `late.test`.
fn late_resolver(
    failures: usize,
    at: SocketAddr,
    asked: Arc<AtomicUsize>,
) -> convesso_tokio::Resolver {
    Arc::new(move |host: String| {
        let asked = Arc::clone(&asked);
        Box::pin(async move {
            if !host.starts_with("late.test:") {
                return host.parse().map(|address| vec![address]).map_err(std::io::Error::other);
            }
            if asked.fetch_add(1, Ordering::SeqCst) < failures {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not yet"))
            } else {
                Ok(vec![at])
            }
        })
    })
}

/// `relay`'s key, at `late.test` on its port.
fn named_late(relay: &TestRelay) -> String {
    let port = relay.host.rsplit_once(':').map(|(_, port)| port).unwrap();
    transport_convesso::relay::written(&relay.key, &format!("late.test:{port}"), false)
}

/// **A relay whose name does not resolve stops nothing.** The node starts with
/// the name unanswered, and reaches the relay once it answers, with nothing
/// restarted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_whose_name_resolves_late_is_reached_when_it_does() {
    let relay = TestRelay::start().await;
    let network = Network::found(Some(&named_late(&relay)));
    let asked = Arc::new(AtomicUsize::new(0));
    let at: SocketAddr = relay.host.parse().unwrap();

    let node = ConvessoTransport::bind_resolving(
        &network.founder,
        network.state.clone(),
        late_resolver(2, at, Arc::clone(&asked)),
    )
    .await
    .expect("the node starts though its relay's name does not resolve");

    tokio::time::timeout(PATIENCE, node.online()).await.expect("and reaches it once it does");
    assert!(asked.load(Ordering::SeqCst) >= 3, "the name was asked again until it answered");
}

/// A relay change to a name that does not resolve yet is followed once it does:
/// a peer on the new relay is reached through it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_change_to_a_name_that_resolves_late_is_followed() {
    let first = TestRelay::start().await;
    let second = TestRelay::start().await;
    let network = Network::on(&first);
    let asked = Arc::new(AtomicUsize::new(0));
    let at: SocketAddr = second.host.parse().unwrap();

    let founder = ConvessoTransport::bind_resolving(
        &network.founder,
        network.state.clone(),
        late_resolver(2, at, Arc::clone(&asked)),
    )
    .await
    .unwrap();
    let joiner =
        ConvessoTransport::bind(&network.joiner, on_relay(&network.state, &second)).await.unwrap();
    tokio::time::timeout(PATIENCE, async { tokio::join!(founder.online(), joiner.online()) })
        .await
        .expect("each on its relay");

    let mut moved = network.state.clone();
    moved.params.relay = Some(named_late(&second));
    moved.params.leaving = None;
    founder.update_state(moved).await;
    assert_eq!(
        founder.relay().map(|relay| relay.host),
        Some(named_late(&second).split('@').nth(1).unwrap().to_owned())
    );

    tokio::time::timeout(PATIENCE, async {
        while asked.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the new name is asked until it answers");
    // Registered there, which a change of relay waits for: dialled before, the
    // relay has nobody to hand the dial to.
    tokio::time::timeout(PATIENCE, founder.online()).await.expect("on the new relay");

    // Only the relay is left as a path, so a session is proof of registration.
    founder.avoid(&everywhere());
    joiner.avoid(&everywhere());
    let (dialled, accepted) = session(&joiner, &founder).await;
    dialled.send(b"through the relay named late").await.unwrap();
    let received = tokio::time::timeout(PATIENCE, accepted.recv()).await.unwrap().unwrap();
    assert_eq!(received, b"through the relay named late".to_vec());
}

/// **A peer's address learned while a dial is under way is used by it**, with
/// the relay's name not resolving: the case of two devices on a LAN whose
/// internet is down, where one dials before it has heard the other announce.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_address_learned_during_a_dial_is_used_with_no_relay_to_be_had() {
    let relay = TestRelay::start().await;
    let network = Network::found(Some(&named_late(&relay)));
    let at: SocketAddr = relay.host.parse().unwrap();
    let never = || late_resolver(usize::MAX, at, Arc::new(AtomicUsize::new(0)));
    let founder = Arc::new(
        ConvessoTransport::bind_resolving(&network.founder, network.state.clone(), never())
            .await
            .unwrap(),
    );
    let joiner = Arc::new(
        ConvessoTransport::bind_resolving(&network.joiner, network.state.clone(), never())
            .await
            .unwrap(),
    );
    let port = joiner.own_ports().first().copied().unwrap();
    let key = joiner.transport_key();

    let accepting = {
        let joiner = Arc::clone(&joiner);
        tokio::spawn(async move { joiner.accept().await })
    };
    let dialling = {
        let founder = Arc::clone(&founder);
        let key = key.clone();
        tokio::spawn(async move { founder.connect(&key).await })
    };
    // Heard on the LAN two seconds into the dial.
    tokio::time::sleep(Duration::from_secs(2)).await;
    founder.learned(&key, &[format!("127.0.0.1:{port}")]);

    let dialled = tokio::time::timeout(Duration::from_secs(8), dialling)
        .await
        .expect("the dial ends within seconds of the address arriving")
        .unwrap();
    assert!(dialled.is_ok(), "{:?}", dialled.err());
    assert!(accepting.await.unwrap().is_ok());
}

/// **Two nodes that dial each other at the same moment both get a session,
/// and a payload crosses on it**, with no relay to be had: what two devices
/// coming up together on a LAN do. Repeated, because a crossing is a race.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crossing_dials_leave_both_with_a_working_session() {
    let relay = TestRelay::start().await;
    let at: SocketAddr = relay.host.parse().unwrap();
    for round in 0..20 {
        let network = Network::found(Some(&named_late(&relay)));
        let never = || late_resolver(usize::MAX, at, Arc::new(AtomicUsize::new(0)));
        let founder = Arc::new(
            ConvessoTransport::bind_resolving(&network.founder, network.state.clone(), never())
                .await
                .unwrap(),
        );
        let joiner = Arc::new(
            ConvessoTransport::bind_resolving(&network.joiner, network.state.clone(), never())
                .await
                .unwrap(),
        );
        let to_joiner = joiner.transport_key();
        let to_founder = founder.transport_key();
        let joiner_port = joiner.own_ports().first().copied().unwrap();
        let founder_port = founder.own_ports().first().copied().unwrap();
        founder.learned(&to_joiner, &[format!("127.0.0.1:{joiner_port}")]);
        joiner.learned(&to_founder, &[format!("127.0.0.1:{founder_port}")]);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let accepts = {
            let (founder, joiner) = (Arc::clone(&founder), Arc::clone(&joiner));
            tokio::spawn(async move { tokio::join!(founder.accept(), joiner.accept()) })
        };
        let (one, other) = tokio::time::timeout(Duration::from_secs(25), async {
            tokio::join!(founder.connect(&to_joiner), joiner.connect(&to_founder))
        })
        .await
        .unwrap_or_else(|_| panic!("round {round}: the dials end"));
        let (founder_accepted, joiner_accepted) =
            tokio::time::timeout(Duration::from_secs(5), accepts)
                .await
                .unwrap_or_else(|_| panic!("round {round}: both accept"))
                .unwrap();
        let dialled =
            one.unwrap_or_else(|error| panic!("round {round}: founder's dial: {error:?}"));
        let accepted = joiner_accepted
            .unwrap_or_else(|error| panic!("round {round}: joiner's accept: {error:?}"));
        dialled.send(b"across").await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
            .await
            .unwrap_or_else(|_| panic!("round {round}: the payload arrives"));
        assert_eq!(got.unwrap(), b"across".to_vec(), "round {round}");
        let _ = (other, founder_accepted);
    }
}

/// Milliseconds since the epoch.
fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(),
    )
    .unwrap()
}

/// A relay changed in newer state is followed at once, without restarting the
/// node and without closing its sessions; new sessions go through it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_change_is_followed_without_closing_sessions() {
    let (_first, network, founder, joiner) = pair().await;
    let (dialled, accepted) = session(&founder, &joiner).await;

    let second = TestRelay::start().await;
    let moved = on_relay(&network.state, &second);
    founder.update_state(moved.clone()).await;
    joiner.update_state(moved).await;
    assert_eq!(founder.relay().map(|relay| relay.host), Some(second.host.clone()));
    tokio::time::timeout(PATIENCE, async { tokio::join!(founder.online(), joiner.online()) })
        .await
        .expect("both register on the new relay");

    dialled.send(b"across the change").await.unwrap();
    let received = tokio::time::timeout(PATIENCE, accepted.recv()).await.unwrap().unwrap();
    assert_eq!(received, b"across the change".to_vec(), "the session went on");

    founder.avoid(&everywhere());
    joiner.avoid(&everywhere());
    let (fresh, fresh_accepted) = session(&joiner, &founder).await;
    fresh.send(b"through the new relay").await.unwrap();
    let received = tokio::time::timeout(PATIENCE, fresh_accepted.recv()).await.unwrap().unwrap();
    assert_eq!(received, b"through the new relay".to_vec());
}

/// During a move, a node stays on the relay being left, and moves to the new
/// one when the move ends, with nothing else signed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_move_keeps_the_relay_being_left_until_its_end() {
    let (first, network, founder, _joiner) = pair().await;
    let second = TestRelay::start().await;

    let mut moving = on_relay(&network.state, &second);
    moving.params.leaving =
        Some(roster::types::Leaving { relay: first.written(), until: now_ms() + 1_500 });
    founder.update_state(moving).await;
    assert_eq!(founder.relay().map(|relay| relay.host), Some(first.host.clone()), "until the end");

    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert_eq!(founder.relay().map(|relay| relay.host), Some(second.host.clone()), "after it");
    tokio::time::timeout(PATIENCE, founder.online()).await.expect("registered on the new relay");
}

/// A relay written as `tls://` is reached over a TLS-wrapped link, and works
/// as any other: the pinned key, not the certificate, is what is trusted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_behind_tls_carries_sessions() {
    let relay = TestRelay::start_tls().await;
    let network = Network::on(&relay);
    let founder = ConvessoTransport::bind(&network.founder, network.state.clone()).await.unwrap();
    let joiner = ConvessoTransport::bind(&network.joiner, network.state.clone()).await.unwrap();
    assert!(founder.relay().is_some_and(|relay| relay.tls), "the link is wrapped");
    tokio::time::timeout(PATIENCE, async { tokio::join!(founder.online(), joiner.online()) })
        .await
        .expect("both reach the relay over TLS");

    founder.avoid(&everywhere());
    joiner.avoid(&everywhere());
    let (dialled, accepted) = session(&founder, &joiner).await;
    dialled.send(b"over tls").await.unwrap();
    let received = tokio::time::timeout(PATIENCE, accepted.recv()).await.unwrap().unwrap();
    assert_eq!(received, b"over tls".to_vec());
}

// ---------------------------------------------------------------------------
// A reader that stops
// ---------------------------------------------------------------------------

/// A session nobody reads holds back its own peer's sender, and no other peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_nobody_reads_holds_back_its_peer_alone() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let founder = ConvessoTransport::bind(&network.founder, network.state.clone()).await.unwrap();
    let joiner = ConvessoTransport::bind(&network.joiner, network.state.clone()).await.unwrap();
    let third = ConvessoTransport::bind(&network.third, network.state.clone()).await.unwrap();
    tokio::time::timeout(PATIENCE, async {
        tokio::join!(founder.online(), joiner.online(), third.online())
    })
    .await
    .expect("all three reach the relay");

    // The joiner's session with the founder is never read on the founder's side.
    let (flooding, _unread) = session(&joiner, &founder).await;
    let flood = tokio::spawn(async move {
        let chunk = vec![1u8; 16 * 1024];
        for _ in 0..400 {
            if flooding.send(&chunk).await.is_err() {
                return;
            }
        }
    });
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!flood.is_finished(), "the unread session holds its sender back");

    let (talking, listening) = session(&third, &founder).await;
    talking.send(b"from another peer").await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(5), listening.recv())
        .await
        .expect("another peer is not held back")
        .unwrap();
    assert_eq!(received, b"from another peer".to_vec());
    flood.abort();
}

// ---------------------------------------------------------------------------
// A node holding no roster
// ---------------------------------------------------------------------------

/// A judge believing only the network's root.
fn believing(network: &Network) -> transport_convesso::node::Judge {
    let root = roster::snapshot::RawSnapshot::decode(&network.root).unwrap().body().root;
    Arc::new(move |shown: &roster::membership::Shown| shown.against == root)
}

/// The joiner as a light member, on `relay`, showing `evidence`.
async fn light(network: &Network, evidence: Vec<u8>) -> ConvessoTransport {
    ConvessoTransport::bind_light(
        &network.joiner,
        network.state.network,
        network.state.params.clone(),
        evidence,
        believing(network),
    )
    .await
    .unwrap()
}

/// A full member that shows its evidence, as a daemon holding a root does.
async fn full_showing(network: &Network, who: &Arc<NodeIdentity>) -> ConvessoTransport {
    let node = ConvessoTransport::bind(who, network.state.clone()).await.unwrap();
    node.update_evidence(network.evidence.get(&who.device_id()).unwrap().clone());
    node
}

#[tokio::test]
async fn a_light_member_and_a_full_one_authenticate_each_other_both_ways() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let full = full_showing(&network, &network.founder).await;
    let joiner =
        light(&network, network.evidence.get(&network.joiner.device_id()).unwrap().clone()).await;
    tokio::time::timeout(PATIENCE, async { tokio::join!(full.online(), joiner.online()) })
        .await
        .unwrap();

    let (dialled, accepted) = session(&joiner, &full).await;
    assert_eq!(dialled.peer(), network.founder.device_id(), "the light one learns who it reached");
    assert_eq!(accepted.peer(), network.joiner.device_id(), "the full one knows it by its state");

    let (dialled, accepted) = session(&full, &joiner).await;
    assert_eq!(dialled.peer(), network.joiner.device_id());
    assert_eq!(accepted.peer(), network.founder.device_id(), "known by its evidence");
}

/// A light member holds no roster, so it knows nobody it has not met: a member
/// admitted a moment ago, dialling it first, is still read, and judged by what
/// it shows.
#[tokio::test]
async fn a_light_member_is_reached_by_a_full_one_it_never_met() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let full = full_showing(&network, &network.founder).await;
    let joiner =
        light(&network, network.evidence.get(&network.joiner.device_id()).unwrap().clone()).await;
    tokio::time::timeout(PATIENCE, async { tokio::join!(full.online(), joiner.online()) })
        .await
        .unwrap();

    let (dialled, accepted) = session(&full, &joiner).await;
    assert_eq!(dialled.peer(), network.joiner.device_id());
    assert_eq!(accepted.peer(), network.founder.device_id(), "known by its evidence");
}

#[tokio::test]
async fn a_light_member_refuses_a_proof_of_another_devices_leaf() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    // The third device shows the founder's evidence: valid, and not its own.
    let impostor = ConvessoTransport::bind(&network.third, network.state.clone()).await.unwrap();
    impostor.update_evidence(network.evidence.get(&network.founder.device_id()).unwrap().clone());
    let joiner =
        light(&network, network.evidence.get(&network.joiner.device_id()).unwrap().clone()).await;
    tokio::time::timeout(PATIENCE, async { tokio::join!(impostor.online(), joiner.online()) })
        .await
        .unwrap();

    let key = impostor.transport_key();
    let dialled = tokio::time::timeout(PATIENCE, joiner.connect(&key)).await.unwrap();
    assert!(
        matches!(dialled, Err(ref error) if error.is_membership_refusal()),
        "{:?}",
        dialled.as_ref().err()
    );

    // And dialled by it, it refuses the same way.
    let key = joiner.transport_key();
    let (dialled, _) = tokio::time::timeout(PATIENCE, async {
        tokio::join!(
            impostor.connect(&key),
            tokio::time::timeout(Duration::from_secs(3), joiner.accept())
        )
    })
    .await
    .unwrap();
    assert!(dialled.is_err(), "a light member takes no session on another's proof");
}

#[tokio::test]
async fn a_light_member_refuses_a_peer_showing_nothing() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let silent = ConvessoTransport::bind(&network.founder, network.state.clone()).await.unwrap();
    let joiner =
        light(&network, network.evidence.get(&network.joiner.device_id()).unwrap().clone()).await;
    tokio::time::timeout(PATIENCE, async { tokio::join!(silent.online(), joiner.online()) })
        .await
        .unwrap();
    let key = silent.transport_key();
    let dialled = tokio::time::timeout(PATIENCE, joiner.connect(&key)).await.unwrap();
    assert!(dialled.is_err());
}

#[tokio::test]
async fn a_light_member_cuts_off_a_peer_its_view_no_longer_believes() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let full = full_showing(&network, &network.founder).await;
    // A view that believes the founder until told it was invalidated.
    let invalidated = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let root = roster::snapshot::RawSnapshot::decode(&network.root).unwrap().body().root;
    let judge: transport_convesso::node::Judge = {
        let invalidated = Arc::clone(&invalidated);
        Arc::new(move |shown: &roster::membership::Shown| {
            shown.against == root
                && !(invalidated.load(Ordering::SeqCst) && shown.leaf.record.name == "founder")
        })
    };
    let joiner = ConvessoTransport::bind_light(
        &network.joiner,
        network.state.network,
        network.state.params.clone(),
        network.evidence.get(&network.joiner.device_id()).unwrap().clone(),
        judge,
    )
    .await
    .unwrap();
    tokio::time::timeout(PATIENCE, async { tokio::join!(full.online(), joiner.online()) })
        .await
        .unwrap();
    let (dialled, _accepted) = session(&joiner, &full).await;

    joiner.reconsider();
    assert!(dialled.send(b"still").await.is_ok(), "nothing changed, nothing closes");

    invalidated.store(true, Ordering::SeqCst);
    joiner.reconsider();
    assert!(
        matches!(dialled.send(b"gone").await, Err(Error::ClosedOnMembershipLoss)),
        "a peer the view stopped believing is cut off"
    );
}

/// A light member that believes the full one only once it has taken the
/// chain `chain`, asking after `held`: the judge, and how it catches up.
fn catching_up_on(
    network: &Network,
    held: [u8; 32],
    chain: &'static [u8],
) -> (transport_convesso::node::Judge, transport::session::CatchingUp, Arc<AtomicUsize>) {
    let caught_up = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let asked = Arc::new(AtomicUsize::new(0));
    let root = roster::snapshot::RawSnapshot::decode(&network.root).unwrap().body().root;
    let judge: transport_convesso::node::Judge = {
        let caught_up = Arc::clone(&caught_up);
        Arc::new(move |shown: &roster::membership::Shown| {
            shown.against == root && caught_up.load(Ordering::SeqCst)
        })
    };
    let behind = {
        let caught_up = Arc::clone(&caught_up);
        let asked = Arc::clone(&asked);
        Arc::new(move |_: &[u8]| {
            if caught_up.load(Ordering::SeqCst) {
                return None;
            }
            asked.fetch_add(1, Ordering::SeqCst);
            Some(held)
        })
    };
    let take = Arc::new(move |_: &[u8], roots: &[u8]| {
        let taken = roots == chain;
        if taken {
            caught_up.store(true, Ordering::SeqCst);
        }
        taken
    });
    (judge, transport::session::CatchingUp { behind, take }, asked)
}

/// Roots served for `held` alone: `chain`.
fn serving(held: [u8; 32], chain: &'static [u8]) -> transport::session::RootsAfter {
    Arc::new(move |since: [u8; 32]| {
        Box::pin(async move { if since == held { chain.to_vec() } else { Vec::new() } })
    })
}

/// A light member shown evidence on a root it cannot place asks the peer for
/// the roots after its own, takes them, and believes the peer: dialling, and
/// dialled. Before, it refused every member holding roots it had missed, and
/// had nobody left to ask (testbed, 18.1).
#[tokio::test]
async fn a_light_member_catches_up_while_a_session_opens() {
    const HELD: [u8; 32] = [7; 32];
    const CHAIN: &[u8] = b"the roots after seven";
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let full = full_showing(&network, &network.founder).await;
    full.serve_roots(serving(HELD, CHAIN));

    for light_dials in [true, false] {
        let (judge, catching, asked) = catching_up_on(&network, HELD, CHAIN);
        let joiner = ConvessoTransport::bind_light(
            &network.joiner,
            network.state.network,
            network.state.params.clone(),
            network.evidence.get(&network.joiner.device_id()).unwrap().clone(),
            judge,
        )
        .await
        .unwrap();
        joiner.catch_up_by(catching);
        tokio::time::timeout(PATIENCE, async { tokio::join!(full.online(), joiner.online()) })
            .await
            .unwrap();

        let (dialled, accepted) =
            if light_dials { session(&joiner, &full).await } else { session(&full, &joiner).await };
        let (light_side, full_side) =
            if light_dials { (dialled, accepted) } else { (accepted, dialled) };
        assert_eq!(light_side.peer(), network.founder.device_id(), "dialling: {light_dials}");
        assert_eq!(full_side.peer(), network.joiner.device_id());
        assert_eq!(asked.load(Ordering::SeqCst), 1, "asked once");
        light_side.send(b"through").await.unwrap();
        assert_eq!(full_side.recv().await.unwrap(), b"through".to_vec());
    }
}

/// A peer with nothing to answer is refused as before, within the dial's
/// patience.
#[tokio::test]
async fn a_light_member_still_refuses_a_peer_with_no_roots_to_give() {
    const HELD: [u8; 32] = [7; 32];
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let full = full_showing(&network, &network.founder).await;
    let (judge, catching, _) = catching_up_on(&network, HELD, b"never sent");
    let joiner = ConvessoTransport::bind_light(
        &network.joiner,
        network.state.network,
        network.state.params.clone(),
        network.evidence.get(&network.joiner.device_id()).unwrap().clone(),
        judge,
    )
    .await
    .unwrap();
    joiner.catch_up_by(catching);
    tokio::time::timeout(PATIENCE, async { tokio::join!(full.online(), joiner.online()) })
        .await
        .unwrap();

    let dialled = tokio::time::timeout(PATIENCE, joiner.connect(&full.transport_key()))
        .await
        .expect("answered within patience");
    assert!(
        matches!(dialled, Err(ref error) if error.is_membership_refusal()),
        "{:?}",
        dialled.as_ref().err()
    );
}

#[tokio::test]
async fn a_rotated_transport_key_ends_the_session_it_authenticated() {
    let (_relay, network, founder, joiner) = pair().await;
    let (dialled, _accepted) = session(&founder, &joiner).await;

    // The same device, under a new transport key: the record the state holds
    // for it no longer names the key this session authenticated.
    let mut rotated = network.state.clone();
    let fresh = NodeIdentity::generate().unwrap();
    rotated.devices.modify(&network.joiner.device_id(), |record| {
        for entry in &mut record.keys {
            if entry.purpose == roster::types::KeyPurpose::Transport {
                *entry = roster::types::KeyEntry::new(
                    Algorithm::Ed25519,
                    roster::types::KeyPurpose::Transport,
                    fresh.transport_key().public_key().as_bytes().to_vec(),
                )
                .unwrap();
            }
        }
    });
    founder.update_state(rotated).await;
    assert!(
        matches!(dialled.send(b"old key").await, Err(Error::ClosedOnMembershipLoss)),
        "the session under the old key is closed"
    );
}

// ---------------------------------------------------------------------------
// Access groups
// ---------------------------------------------------------------------------

/// The fixture's state with the founder a controller, the other two sensors,
/// and, where `policy` says so, sensors allowed to reach controllers only.
fn grouped(network: &Network, policy: bool) -> roster::state::RosterState {
    let group = |name: &str| roster::leaf::Group::new(name).unwrap();
    let mut state = network.state.clone();
    let in_group = |name: &str| {
        roster::leaf::DeviceSettings::new(roster::leaf::Mode::Full, vec![group(name)], None, None)
            .unwrap()
    };
    state.set_settings(network.founder.device_id(), in_group("controller"));
    state.set_settings(network.joiner.device_id(), in_group("sensori"));
    state.set_settings(network.third.device_id(), in_group("sensori"));
    if policy {
        state.params.policy =
            vec![roster::parameters::Rule { from: group("sensori"), to: group("controller") }];
    }
    state
}

/// The three devices' nodes, each holding `state`.
async fn three(
    relay: &TestRelay,
    network: &Network,
    state: &roster::state::RosterState,
) -> (ConvessoTransport, ConvessoTransport, ConvessoTransport) {
    let _ = relay;
    let founder = ConvessoTransport::bind(&network.founder, state.clone()).await.unwrap();
    let joiner = ConvessoTransport::bind(&network.joiner, state.clone()).await.unwrap();
    let third = ConvessoTransport::bind(&network.third, state.clone()).await.unwrap();
    tokio::time::timeout(PATIENCE, async {
        tokio::join!(founder.online(), joiner.online(), third.online())
    })
    .await
    .unwrap();
    (founder, joiner, third)
}

#[tokio::test]
async fn a_sensor_may_reach_its_controller_and_nothing_else() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let state = grouped(&network, true);
    let (controller, sensor, other) = three(&relay, &network, &state).await;

    let (dialled, accepted) = session(&sensor, &controller).await;
    assert_eq!(accepted.peer(), network.joiner.device_id(), "the controller accepts");
    drop((dialled, accepted));

    let key = other.transport_key();
    let refused = tokio::time::timeout(PATIENCE, sensor.connect(&key)).await.unwrap();
    assert!(matches!(refused, Err(Error::NotAllowed)), "{:?}", refused.as_ref().err());
}

#[tokio::test]
async fn a_changed_policy_closes_what_it_no_longer_allows() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let open = grouped(&network, false);
    let (_controller, sensor, other) = three(&relay, &network, &open).await;
    let (_dialled, accepted) = session(&sensor, &other).await;

    other.update_state(grouped(&network, true)).await;
    assert!(
        matches!(accepted.send(b"after").await, Err(Error::NotAllowed)),
        "the receiver closes the session the new policy does not allow"
    );
}

//! The full inbound path, over a real authenticated session.
//!
//! A session established through the transport, a packet judged against the
//! device that session resolved to, and the packet handed to a device. No
//! privileges, no TUN, no network — which is the point of the split: the rule
//! §2.5 cares about most is the part that gets the most testing.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::net::Ipv6Addr;
use std::sync::Arc;

use identity::NodeIdentity;
use roster::id::{DeviceId, NetworkId};
use roster::roster::Roster;
use roster::sign::sign_operation;
use roster::state::RosterState;
use roster::types::{NetworkParams, OperationBody, OperationCore, Role};
use transport::session::{Session, Transport};
use transport::{MemoryFabric, MemoryTransport};
use tunnel::{Inbound, MemoryDevice, Packets, Prefix, Tunnel};

/// The ULA prefix the fixture network carries.
const ULA: &[u8] = &[0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

/// A two-device network, and the identities that own it.
struct Fixture {
    founder: Arc<NodeIdentity>,
    joiner: Arc<NodeIdentity>,
    state: RosterState,
}

impl Fixture {
    fn found() -> Self {
        let founder = Arc::new(NodeIdentity::generate().expect("generates"));
        let joiner = Arc::new(NodeIdentity::generate().expect("generates"));
        let params =
            NetworkParams::new(ULA.to_vec(), "example.internal", 2_592_000).expect("valid");

        let genesis = OperationCore::new(
            1,
            founder.signing_key().algorithm(),
            OperationBody::CreateNetwork {
                device: founder.device_spec("founder", Role::Admin, true, vec![]).expect("spec"),
                params,
            },
            vec![],
            founder.signing_key().key_id(),
            NetworkId::from_bytes([0; 32]),
        )
        .expect("well-formed");
        let genesis_bytes = sign_operation(&genesis, founder.signer()).expect("signs");
        let network = NetworkId::from_bytes(*genesis.id().as_bytes());

        let add = OperationCore::new(
            2,
            founder.signing_key().algorithm(),
            OperationBody::AddDevice(
                joiner.device_spec("joiner", Role::Member, false, vec![]).expect("spec"),
            ),
            vec![genesis.id()],
            founder.signing_key().key_id(),
            network,
        )
        .expect("well-formed");
        let add_bytes = sign_operation(&add, founder.signer()).expect("signs");

        let mut node = Roster::new();
        assert!(node.offer_bytes(&genesis_bytes).is_accepted());
        assert!(node.offer_bytes(&add_bytes).is_accepted());

        Self { founder, joiner, state: node.state().expect("derives") }
    }

    /// The tunnel this network's parameters describe, for one of its devices.
    ///
    /// One tunnel belongs to one device: it judges a packet's destination
    /// against the addresses that device holds, so a fixture shared between two
    /// of them would be a fixture that is neither.
    fn tunnel(&self, own: &DeviceId) -> Tunnel {
        Tunnel::new(Prefix::from_parameter(&self.state.params.ula).expect("a usable prefix"), *own)
    }

    /// The founder's tunnel, which most of these tests judge from.
    fn founders_tunnel(&self) -> Tunnel {
        self.tunnel(&self.founder.device_id())
    }
}

/// An IPv6 header carrying the given addresses.
fn packet(source: Ipv6Addr, destination: Ipv6Addr) -> Vec<u8> {
    let mut out = vec![0u8; 40];
    if let Some(first) = out.first_mut() {
        *first = 0x60;
    }
    out.splice(8..24, source.octets().iter().copied());
    out.splice(24..40, destination.octets().iter().copied());
    out
}

/// A connected pair, on the transport's own in-process fabric.
async fn session_pair(fixture: &Fixture) -> (Box<dyn Session>, Box<dyn Session>) {
    let fabric = MemoryFabric::new();
    let dialler =
        MemoryTransport::join(&fabric, Arc::clone(&fixture.founder), fixture.state.clone()).await;
    let acceptor =
        MemoryTransport::join(&fabric, Arc::clone(&fixture.joiner), fixture.state.clone()).await;

    let key = acceptor.transport_key();
    let (dialled, accepted) = tokio::join!(dialler.connect(&key), acceptor.accept());
    (dialled.expect("establishes"), accepted.expect("establishes"))
}

/// The whole path: a real session, a packet from the device it resolved to, and
/// delivery.
#[tokio::test]
async fn a_packet_from_the_sessions_device_reaches_the_host() {
    let fixture = Fixture::found();
    let tunnel = fixture.founders_tunnel();
    let (dialled, _accepted) = session_pair(&fixture).await;

    // The transport already resolved a key to a device; that is the whole input.
    let peer = dialled.peer();
    assert_eq!(peer, fixture.joiner.device_id());

    let theirs = tunnel.address_of(&peer);
    let mine = tunnel.address_of(&fixture.founder.device_id());
    let inbound = packet(theirs, mine);

    assert_eq!(tunnel.inbound(peer, &inbound), Inbound::Accepted);

    let device = MemoryDevice::new();
    device.deliver(&inbound).await.expect("delivers");
    assert_eq!(device.delivered().await, vec![inbound], "unchanged, and one packet");
}

/// The case §2.5 exists for, over a real session: a member claiming another
/// member's address inside its own legitimate session.
#[tokio::test]
async fn a_member_spoofing_another_member_is_stopped_and_named() {
    let fixture = Fixture::found();
    let tunnel = fixture.founders_tunnel();
    let (dialled, _accepted) = session_pair(&fixture).await;

    let peer = dialled.peer();
    // The joiner's session, carrying the founder's source address.
    let not_theirs = tunnel.address_of(&fixture.founder.device_id());
    // Addressed here, so the source is the only thing wrong with it.
    let spoofed = packet(not_theirs, tunnel.own_address());

    let outcome = tunnel.inbound(peer, &spoofed);

    assert!(outcome.is_spoofed_source(), "a member must not claim another's address");
    assert_eq!(outcome.session(), Some(peer), "and the drop names which member did it");

    // Nothing reaches the host.
    let device = MemoryDevice::new();
    if outcome.is_accepted() {
        device.deliver(&spoofed).await.expect("delivers");
    }
    assert!(device.delivered().await.is_empty(), "a spoofed packet reaches nothing");
}

/// The session identity is the only input. Two sessions with different peers
/// accept different addresses, with no roster consulted at packet time.
#[tokio::test]
async fn each_session_accepts_only_its_own_peers_address() {
    let fixture = Fixture::found();
    let (dialled, accepted) = session_pair(&fixture).await;

    let joiner = dialled.peer();
    let founder = accepted.peer();
    assert_ne!(joiner, founder);

    // Each device judges with its own tunnel, which is what each device has.
    let here = fixture.tunnel(&founder);
    let there = fixture.tunnel(&joiner);
    let joiner_address = here.address_of(&joiner);
    let founder_address = here.address_of(&founder);

    // Each accepts its peer's traffic, addressed to itself.
    assert_eq!(here.inbound(joiner, &packet(joiner_address, founder_address)), Inbound::Accepted);
    assert_eq!(there.inbound(founder, &packet(founder_address, joiner_address)), Inbound::Accepted);

    // And neither accepts its peer's address as a source.
    assert!(here.inbound(joiner, &packet(founder_address, founder_address)).is_spoofed_source());
    assert!(there.inbound(founder, &packet(joiner_address, joiner_address)).is_spoofed_source());

    // Nor a packet addressed to the other device, honest source and all: that is
    // the other half of the rule, over a real session.
    let elsewhere = here.inbound(joiner, &packet(joiner_address, joiner_address));
    assert!(elsewhere.is_misdirected(), "{elsewhere:?}");
    assert_eq!(elsewhere.session(), Some(joiner), "and it names who sent it");
}

/// §2.6: a packet for the wider internet does not leave through the tunnel.
#[tokio::test]
async fn a_packet_for_the_internet_does_not_leave_through_the_tunnel() {
    let fixture = Fixture::found();
    let tunnel = fixture.founders_tunnel();

    let elsewhere: Ipv6Addr = "2001:db8::1".parse().expect("valid");
    let outbound = tunnel.outbound(&packet(Ipv6Addr::UNSPECIFIED, elsewhere));

    assert!(!outbound.is_carried());
    assert!(outbound.to_string().contains("not on this network"), "{outbound}");
}

/// Addresses come from the roster's own parameters, so two nodes reading the
/// same signed network agree without coordinating.
#[tokio::test]
async fn addresses_follow_the_signed_parameters() {
    let fixture = Fixture::found();

    let one = fixture.founders_tunnel();
    let two = Tunnel::new(
        Prefix::from_parameter(&fixture.state.params.ula).expect("valid"),
        fixture.founder.device_id(),
    );

    for device in [fixture.founder.device_id(), fixture.joiner.device_id()] {
        assert_eq!(one.address_of(&device), two.address_of(&device));
        assert!(one.prefix().contains(one.address_of(&device)));
    }
}

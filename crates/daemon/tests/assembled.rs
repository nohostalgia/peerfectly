//! The whole node, running.
//!
//! Two assembled nodes over the in-process transport: a packet crossing between
//! them through the real gateway, a roster change propagating without either
//! being restarted, and a subsystem failing without taking the rest down.
//!
//! No network, no adapter, no privileges — which is the point of the split. The
//! parts that decide things are exercised here; the parts that call Windows are
//! covered by `VERIFICATION.md` and by nothing else, and are not pretended
//! otherwise.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use daemon::gateway::{Departure, Gateway};
use daemon::node::Node;
use daemon::router::Router;
use daemon::schedule::Schedule;
use daemon::state::Log;
use identity::NodeIdentity;
use roster::id::NetworkId;
use roster::roster::Roster;
use roster::sign::sign_operation;
use roster::state::RosterState;
use roster::types::{NetworkParams, OperationBody, OperationCore, Role};
use roster_sync::Syncer;
use tokio::sync::Mutex;
use transport::session::{Session, Transport};
use transport::{MemoryFabric, MemoryTransport};
use tunnel::{Ipv4Holdings, MemoryDevice, Packets, Prefix, Tunnel};

/// The prefix the fixture network carries.
const ULA: &[u8] = &[0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

/// A founded network and the identities that own it.
struct Fixture {
    founder: Arc<NodeIdentity>,
    joiner: Arc<NodeIdentity>,
    genesis: Vec<u8>,
    add: Vec<u8>,
    network: NetworkId,
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

        Self {
            founder,
            joiner,
            genesis: genesis_bytes,
            add: add_bytes,
            network,
            state: node.state().expect("derives"),
        }
    }

    /// A roster holding what the network already agrees on.
    fn roster(&self) -> Roster {
        let mut roster = Roster::new();
        assert!(roster.offer_bytes(&self.genesis).is_accepted());
        assert!(roster.offer_bytes(&self.add).is_accepted());
        roster
    }

    /// An operation adding a third device, signed by the founder.
    fn add_a_third(&self) -> Vec<u8> {
        let third = NodeIdentity::generate().expect("generates");
        let core = OperationCore::new(
            3,
            self.founder.signing_key().algorithm(),
            OperationBody::AddDevice(
                third.device_spec("printer", Role::Member, false, vec![]).expect("spec"),
            ),
            self.roster().heads(),
            self.founder.signing_key().key_id(),
            self.network,
        )
        .expect("well-formed");
        sign_operation(&core, self.founder.signer()).expect("signs")
    }

    /// An operation revoking a device, signed by the founder.
    fn revoke(&self, device: roster::id::DeviceId) -> Vec<u8> {
        let core = OperationCore::new(
            3,
            self.founder.signing_key().algorithm(),
            OperationBody::RevokeDevice { device, reason: "verification".to_owned() },
            self.roster().heads(),
            self.founder.signing_key().key_id(),
            self.network,
        )
        .expect("well-formed");
        sign_operation(&core, self.founder.signer()).expect("signs")
    }

    fn prefix(&self) -> Prefix {
        Prefix::from_parameter(&self.state.params.ula).expect("usable")
    }
}

/// One assembled node, plus the machine behind its tunnel.
struct Assembled {
    node: Arc<Node>,
    machine: Arc<MemoryDevice>,
    /// Where this node keeps its network, for a test that reads what was written
    /// beside the log rather than asking the node what it thinks it holds.
    paths: daemon::state::Paths,
    /// Kept alive so the temporary directory outlives the log.
    _scratch: tempfile::TempDir,
}

async fn assemble(
    fixture: &Fixture,
    identity: &Arc<NodeIdentity>,
    transport: Arc<dyn Transport>,
) -> Assembled {
    assemble_holding(fixture, fixture.roster(), identity, transport).await
}

/// As [`assemble`], with a roster of the caller's choosing.
async fn assemble_holding(
    fixture: &Fixture,
    roster: Roster,
    identity: &Arc<NodeIdentity>,
    transport: Arc<dyn Transport>,
) -> Assembled {
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let paths = daemon::state::Paths::under(scratch.path());
    let machine = Arc::new(MemoryDevice::new());
    let gateway = Arc::new(Gateway::new(Tunnel::new(fixture.prefix(), identity.device_id())));

    // The tunnel is up in these tests, so the device and the transport are both
    // attached — the same order the service brings them up in.
    gateway.attach(Arc::clone(&machine) as Arc<dyn Packets>).await;

    let node = Arc::new(Node::new(
        Arc::clone(identity),
        Syncer::new(roster),
        gateway,
        Router::new(fixture.prefix()),
        Log::at(scratch.path().join("roster.log")),
        Schedule::provisional(),
    ));
    node.started(transport).await;

    Assembled { node, machine, paths, _scratch: scratch }
}

/// Moves everything waiting on one session into the node that owns the far end.
///
/// Stands in for the per-session task the daemon runs, so the test drives the
/// same code the daemon does rather than a simplified version of it.
async fn pump(from: &Arc<dyn Session>, into: &Arc<Node>, peer: roster::id::DeviceId, times: usize) {
    for _ in 0..times {
        match tokio::time::timeout(std::time::Duration::from_millis(50), from.recv()).await {
            Ok(Ok(payload)) => into.received(peer, &payload).await,
            _ => return,
        }
    }
}

/// Moves every packet waiting on one session into the node that owns the far end,
/// as the daemon's per-session packet loop does.
async fn pump_packets(
    from: &Arc<dyn Session>,
    into: &Arc<Node>,
    peer: roster::id::DeviceId,
    times: usize,
) {
    for _ in 0..times {
        match tokio::time::timeout(std::time::Duration::from_millis(200), from.recv_packet()).await
        {
            Ok(Ok(packet)) => into.received_packet(peer, &packet).await,
            _ => return,
        }
    }
}

/// An IPv6 header carrying these addresses.
fn packet(source: Ipv6Addr, destination: Ipv6Addr) -> Vec<u8> {
    let mut out = vec![0u8; 40];
    if let Some(first) = out.first_mut() {
        *first = 0x60;
    }
    out.splice(8..24, source.octets().iter().copied());
    out.splice(24..40, destination.octets().iter().copied());
    out
}

/// Two assembled nodes with a session between them, ready to be pumped.
async fn pair() -> (Fixture, Assembled, Assembled, Arc<dyn Session>, Arc<dyn Session>) {
    let fixture = Fixture::found();
    let fabric = MemoryFabric::new();

    let founder_transport = Arc::new(
        MemoryTransport::join(&fabric, Arc::clone(&fixture.founder), fixture.state.clone()).await,
    );
    let joiner_transport = Arc::new(
        MemoryTransport::join(&fabric, Arc::clone(&fixture.joiner), fixture.state.clone()).await,
    );

    let key = joiner_transport.transport_key();
    let (dialled, accepted) =
        tokio::join!(founder_transport.connect(&key), joiner_transport.accept());
    let dialled: Arc<dyn Session> = Arc::from(dialled.expect("establishes"));
    let accepted: Arc<dyn Session> = Arc::from(accepted.expect("establishes"));

    let founder =
        assemble(&fixture, &fixture.founder, founder_transport as Arc<dyn Transport>).await;
    let joiner = assemble(&fixture, &fixture.joiner, joiner_transport as Arc<dyn Transport>).await;

    (fixture, founder, joiner, dialled, accepted)
}

/// An IPv4 header carrying these addresses.
fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
    let mut out = vec![0x45, 0, 0, 28];
    out.resize(12, 0);
    out.extend_from_slice(&source.octets());
    out.extend_from_slice(&destination.octets());
    out.resize(28, 0);
    out
}

/// A device admitted while the tunnel is up becomes routable at its IPv4
/// address without a restart, and stops being so when it is revoked.
///
/// The founder's node starts from the genesis alone, with a session to the
/// joiner already open, so the only thing that can make the joiner's IPv4
/// address routable is the admission reaching `enforce_roster`.
#[tokio::test]
async fn an_admission_while_up_makes_ipv4_routable_and_a_revocation_refuses_it() {
    let fixture = Fixture::found();
    let fabric = MemoryFabric::new();
    let founder_transport = Arc::new(
        MemoryTransport::join(&fabric, Arc::clone(&fixture.founder), fixture.state.clone()).await,
    );
    let joiner_transport = Arc::new(
        MemoryTransport::join(&fabric, Arc::clone(&fixture.joiner), fixture.state.clone()).await,
    );
    let key = joiner_transport.transport_key();
    let (dialled, _accepted) =
        tokio::join!(founder_transport.connect(&key), joiner_transport.accept());
    let dialled: Arc<dyn Session> = Arc::from(dialled.expect("establishes"));

    let mut genesis_only = Roster::new();
    assert!(genesis_only.offer_bytes(&fixture.genesis).is_accepted());
    let founder = assemble_holding(
        &fixture,
        genesis_only,
        &fixture.founder,
        founder_transport as Arc<dyn Transport>,
    )
    .await;
    register(&founder, &dialled).await;

    let joiner = fixture.joiner.device_id();
    let address = Ipv4Holdings::of_state(&fixture.state).of(&joiner).expect("the joiner holds one");
    let mine =
        Ipv4Holdings::of_state(&fixture.state).of(&fixture.founder.device_id()).expect("held");
    let mut watched = founder.node.ipv4_holdings();
    assert_eq!(watched.borrow().of(&joiner), None, "not admitted yet");

    founder.machine.queue(ipv4_packet(mine, address)).await;
    match founder.node.carry_one().await.expect("takes") {
        Departure::Refused(tunnel::Outbound::DestinationHeldByNobody { destination }) => {
            assert_eq!(destination, address);
        }
        other => panic!("nobody holds it before the admission, got {other:?}"),
    }

    founder.node.admit_without_activating(&fixture.add).await.expect("the founder may add");
    assert!(watched.has_changed().expect("the node is alive"), "the change is signalled");
    assert_eq!(watched.borrow_and_update().of(&joiner), Some(address));

    let outgoing = ipv4_packet(mine, address);
    founder.machine.queue(outgoing.clone()).await;
    match founder.node.carry_one().await.expect("takes") {
        Departure::To { device, packet } => {
            assert_eq!(device, joiner);
            assert_eq!(packet, outgoing);
        }
        other => panic!("the admitted device is routable without a restart, got {other:?}"),
    }

    founder
        .node
        .admit_without_activating(&fixture.revoke(joiner))
        .await
        .expect("the founder may revoke");
    assert!(watched.has_changed().expect("the node is alive"));
    assert_eq!(watched.borrow_and_update().of(&joiner), None);

    founder.machine.queue(ipv4_packet(mine, address)).await;
    assert!(
        matches!(
            founder.node.carry_one().await.expect("takes"),
            Departure::Refused(tunnel::Outbound::DestinationHeldByNobody { .. })
        ),
        "a revoked device is refused at once"
    );
}

/// A session cannot be registered twice under different owners, so each node is
/// handed its own half.
async fn register(assembled: &Assembled, session: &Arc<dyn Session>) {
    struct Shared(Arc<dyn Session>);

    #[async_trait::async_trait]
    impl Session for Shared {
        fn peer(&self) -> roster::id::DeviceId {
            self.0.peer()
        }
        async fn send(&self, payload: &[u8]) -> transport::Result<()> {
            self.0.send(payload).await
        }
        async fn recv(&self) -> transport::Result<Vec<u8>> {
            self.0.recv().await
        }
        async fn send_packet(&self, packet: &[u8]) -> transport::Result<()> {
            self.0.send_packet(packet).await
        }
        async fn recv_packet(&self) -> transport::Result<Vec<u8>> {
            self.0.recv_packet().await
        }
        async fn close(&self) -> transport::Result<()> {
            self.0.close().await
        }
    }

    assembled.node.opened(Box::new(Shared(Arc::clone(session)))).await;
}

/// A device is dated the moment it can talk to an admin, which is what makes it
/// right that the admission does not carry an attestation.
///
/// **This is the obligation the enrolment test used to state and no longer can.**
/// A device that has just joined holds a roster and a snapshot and has never been
/// attested — honestly, because §2.6b leaves its network off until a person turns
/// it on, and nothing has dated it. What must then be true is that meeting an
/// admin dates it at once, rather than at that admin's next period, which could
/// be twelve hours away.
///
/// Found on two real devices before it was written here: the desktop joined a
/// network founded on the phone and held no attestation at all until this was
/// added.
#[tokio::test]
async fn a_session_opening_dates_the_peer() {
    let (fixture, founder, joiner, dialled, accepted) = pair().await;

    // The founder is the admin and has attested; the joiner has not.
    founder.node.attest_change().await;
    assert!(
        daemon::state::read_attestation(&founder.paths).is_some(),
        "the admin holds one to send"
    );
    assert!(
        daemon::state::read_attestation(&joiner.paths).is_none(),
        "and the joiner has never had one"
    );

    // The sessions open, as they do when a person turns the network on.
    register(&founder, &dialled).await;
    register(&joiner, &accepted).await;
    pump(&accepted, &joiner.node, fixture.founder.device_id(), 4).await;

    let dated = daemon::state::read_attestation(&joiner.paths);
    assert!(dated.is_some(), "the admin dated it on the session, without being asked");

    // And it is the admin's own bytes, not a re-encoding.
    let (theirs, _) = daemon::state::read_attestation(&founder.paths).expect("held");
    let (ours, _) = dated.expect("held");
    assert_eq!(theirs, ours, "what was signed is what arrived");
}

/// And a member's node dates nobody: it has nothing the roster would accept, and
/// reaching for a key twice a day to produce it is the failure this avoids
/// rather than reports.
#[tokio::test]
async fn a_member_dates_nobody_when_a_session_opens() {
    let (fixture, founder, joiner, dialled, accepted) = pair().await;

    // The joiner is a member. Nothing it does produces an attestation.
    joiner.node.attest_change().await;
    assert!(
        daemon::state::read_attestation(&joiner.paths).is_none(),
        "a member attests to nothing"
    );

    register(&joiner, &accepted).await;
    register(&founder, &dialled).await;
    pump(&dialled, &founder.node, fixture.joiner.device_id(), 4).await;

    // The founder is an admin and has never attested here, so nothing arrived
    // from the member either.
    assert!(
        daemon::state::read_attestation(&founder.paths).is_none(),
        "and sends the admin nothing"
    );
}

/// The whole path, over a real authenticated session: a packet leaves one node's
/// machine and arrives on the other's.
#[tokio::test]
async fn a_packet_crosses_between_two_assembled_nodes() {
    let (fixture, founder, joiner, dialled, accepted) = pair().await;
    register(&founder, &dialled).await;
    register(&joiner, &accepted).await;

    // Clear the greetings each node sent on establishment.
    pump(&accepted, &joiner.node, fixture.founder.device_id(), 2).await;
    pump(&dialled, &founder.node, fixture.joiner.device_id(), 2).await;

    let to_joiner = Tunnel::new(fixture.prefix(), fixture.founder.device_id())
        .address_of(&fixture.joiner.device_id());
    let from_founder = Tunnel::new(fixture.prefix(), fixture.founder.device_id())
        .address_of(&fixture.founder.device_id());
    let outgoing = packet(from_founder, to_joiner);

    founder.machine.queue(outgoing.clone()).await;
    let departure = founder.node.carry_one().await.expect("takes");
    assert!(departure.is_carried(), "{departure:?}");

    // On the packet channel, not among the payloads.
    pump(&accepted, &joiner.node, fixture.founder.device_id(), 2).await;
    assert!(joiner.machine.delivered().await.is_empty(), "no packet travels as a payload");
    pump_packets(&accepted, &joiner.node, fixture.founder.device_id(), 1).await;

    assert_eq!(
        joiner.machine.delivered().await,
        vec![outgoing],
        "the packet arrived on the other machine, unchanged"
    );
}

/// A node serving a session delivers packets while its payload receive is
/// waiting for something that has not come. Before packets had their own channel
/// they queued behind payloads on one stream; now nothing a payload does can hold
/// one up.
#[tokio::test]
async fn a_waiting_payload_receive_does_not_hold_up_packets() {
    let (fixture, founder, joiner, dialled, accepted) = pair().await;
    register(&founder, &dialled).await;

    // The joiner serves its end the way the daemon does: a payload loop and a
    // packet loop. Nothing is sent as a payload, so its payload receive waits.
    struct Owned(Arc<dyn Session>);
    #[async_trait::async_trait]
    impl Session for Owned {
        fn peer(&self) -> roster::id::DeviceId {
            self.0.peer()
        }
        async fn send(&self, payload: &[u8]) -> transport::Result<()> {
            self.0.send(payload).await
        }
        async fn recv(&self) -> transport::Result<Vec<u8>> {
            self.0.recv().await
        }
        async fn send_packet(&self, packet: &[u8]) -> transport::Result<()> {
            self.0.send_packet(packet).await
        }
        async fn recv_packet(&self) -> transport::Result<Vec<u8>> {
            self.0.recv_packet().await
        }
        async fn close(&self) -> transport::Result<()> {
            self.0.close().await
        }
    }
    let serving = tokio::spawn(Arc::clone(&joiner.node).serve(Box::new(Owned(accepted))));

    let to_joiner = Tunnel::new(fixture.prefix(), fixture.founder.device_id())
        .address_of(&fixture.joiner.device_id());
    let from_founder = Tunnel::new(fixture.prefix(), fixture.founder.device_id())
        .address_of(&fixture.founder.device_id());
    let outgoing = packet(from_founder, to_joiner);
    dialled.send_packet(&outgoing).await.expect("sends a packet");

    let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let delivered = joiner.machine.delivered().await;
            if !delivered.is_empty() {
                return delivered;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the packet is delivered while the payload receive waits");
    assert_eq!(delivered, vec![outgoing]);
    serving.abort();
}

/// A member spoofing another member is stopped on the way in, and the drop is
/// recorded rather than swallowed.
#[tokio::test]
async fn a_spoofed_packet_is_stopped_and_recorded() {
    let (fixture, founder, joiner, dialled, accepted) = pair().await;
    register(&founder, &dialled).await;
    register(&joiner, &accepted).await;
    pump(&accepted, &joiner.node, fixture.founder.device_id(), 2).await;

    // The founder's session, carrying the joiner's source address.
    let not_theirs = Tunnel::new(fixture.prefix(), fixture.founder.device_id())
        .address_of(&fixture.joiner.device_id());
    let spoofed = packet(not_theirs, not_theirs);

    joiner.node.received_packet(fixture.founder.device_id(), &spoofed).await;

    assert!(joiner.machine.delivered().await.is_empty(), "nothing reached the machine");
    let fault = joiner.node.fault().await;
    assert!(
        fault.as_ref().is_some_and(|fault| fault.subsystem == "tunnel"),
        "a spoofed packet must be reported, not silently dropped: {fault:?}"
    );
}

/// A packet addressed somewhere other than this device is stopped on the way in,
/// and recorded — no exemption, unlike the machine's own outbound chatter.
///
/// The assessment asked for a silent count here. It is reported instead, and
/// this is the test that says so: to arrive at all, such a packet had to pass
/// the sender's own outbound rule, so it is not ordinary noise — it is a peer
/// running something other than this product, or an attack.
#[tokio::test]
async fn a_packet_addressed_elsewhere_is_stopped_and_recorded() {
    let (fixture, founder, joiner, dialled, accepted) = pair().await;
    register(&founder, &dialled).await;
    register(&joiner, &accepted).await;
    pump(&accepted, &joiner.node, fixture.founder.device_id(), 2).await;

    // The founder's session, an honest founder source — and addressed at the
    // founder rather than at the joiner receiving it.
    let addresses = Tunnel::new(fixture.prefix(), fixture.founder.device_id());
    let theirs = addresses.address_of(&fixture.founder.device_id());
    let elsewhere = packet(theirs, theirs);

    joiner.node.received_packet(fixture.founder.device_id(), &elsewhere).await;

    assert!(joiner.machine.delivered().await.is_empty(), "nothing reached the machine");
    let fault = joiner.node.fault().await;
    let said = fault
        .filter(|fault| fault.subsystem == "tunnel")
        .map(|fault| fault.cause)
        .unwrap_or_default();
    assert!(said.contains("sent a packet to"), "and say the destination was the fault: {said}");
    assert!(!said.contains("source"), "and not read as a spoofed source: {said}");
}

/// §4.7 in the roster's terms: a change made on one node reaches the other with
/// neither being restarted.
#[tokio::test]
async fn a_roster_change_reaches_the_other_node() {
    let (fixture, founder, joiner, dialled, accepted) = pair().await;
    register(&founder, &dialled).await;
    register(&joiner, &accepted).await;
    pump(&accepted, &joiner.node, fixture.founder.device_id(), 2).await;
    pump(&dialled, &founder.node, fixture.joiner.device_id(), 2).await;

    let before = joiner.node.state().await.expect("derives").devices.len();

    founder
        .node
        .admit_without_activating(&fixture.add_a_third())
        .await
        .expect("the founder may add a device");
    pump(&accepted, &joiner.node, fixture.founder.device_id(), 4).await;

    let after = joiner.node.state().await.expect("derives").devices.len();
    assert_eq!(after, before + 1, "the change propagated without a restart");
}

/// **A packet for a device that is not connected is an event, never a
/// problem.** An application on the machine that keeps trying a device that is
/// off would otherwise keep the network shown as wrong for as long as it tried.
#[tokio::test]
async fn a_packet_for_a_device_not_connected_is_not_a_problem() {
    let (fixture, founder, _joiner, _dialled, _accepted) = pair().await;

    let to_joiner = Tunnel::new(fixture.prefix(), fixture.founder.device_id())
        .address_of(&fixture.joiner.device_id());
    let from_founder = Tunnel::new(fixture.prefix(), fixture.founder.device_id())
        .address_of(&fixture.founder.device_id());
    founder.machine.queue(packet(from_founder, to_joiner)).await;
    let _ = founder.node.carry_one().await;

    let event = founder.node.event().await;
    assert!(
        event.as_ref().is_some_and(|event| event.cause.contains("no session for")),
        "it is logged: {event:?}"
    );
    assert_eq!(None, founder.node.fault().await, "and it is not the network's problem");
}

/// A failure in one part is recorded and the rest keeps working. A node that
/// stopped carrying packets because the rendezvous was unreachable would be
/// least available exactly when a person most wanted it.
#[tokio::test]
async fn one_subsystem_failing_does_not_stop_the_others() {
    let (fixture, founder, joiner, dialled, accepted) = pair().await;
    register(&founder, &dialled).await;
    register(&joiner, &accepted).await;
    pump(&accepted, &joiner.node, fixture.founder.device_id(), 2).await;

    founder
        .node
        .record(daemon::node::Severity::Problem, "rendezvous", "unreachable on this network")
        .await;

    // Packets still cross.
    let to_joiner = Tunnel::new(fixture.prefix(), fixture.founder.device_id())
        .address_of(&fixture.joiner.device_id());
    let from_founder = Tunnel::new(fixture.prefix(), fixture.founder.device_id())
        .address_of(&fixture.founder.device_id());
    founder.machine.queue(packet(from_founder, to_joiner)).await;

    assert!(founder.node.carry_one().await.expect("takes").is_carried());

    let fault = founder.node.fault().await;
    assert!(
        fault.as_ref().is_some_and(|fault| fault.subsystem == "rendezvous"),
        "the failure is visible rather than swallowed: {fault:?}"
    );
}

/// A payload naming a channel this build does not know is dropped and reported,
/// never guessed at.
#[tokio::test]
async fn an_unknown_channel_is_reported_and_dropped() {
    let (fixture, founder, joiner, dialled, accepted) = pair().await;
    register(&founder, &dialled).await;
    register(&joiner, &accepted).await;

    joiner.node.received(fixture.founder.device_id(), &[99, 1, 2, 3]).await;

    assert!(joiner.machine.delivered().await.is_empty());
    assert!(
        joiner.node.event().await.is_some_and(|event| event.subsystem == "session"),
        "an unknown channel is logged, as an event of one peer's"
    );
}

/// A tunnel packet framed as a payload — the way a build from before packets had
/// their own channel sent one — is refused and recorded, never delivered.
#[tokio::test]
async fn a_packet_framed_on_the_payload_channel_is_refused() {
    let (fixture, founder, joiner, dialled, accepted) = pair().await;
    register(&founder, &dialled).await;
    register(&joiner, &accepted).await;

    let to_joiner = Tunnel::new(fixture.prefix(), fixture.founder.device_id())
        .address_of(&fixture.joiner.device_id());
    let from_founder = Tunnel::new(fixture.prefix(), fixture.founder.device_id())
        .address_of(&fixture.founder.device_id());
    let mut framed = vec![2_u8];
    framed.extend(packet(from_founder, to_joiner));

    joiner.node.received(fixture.founder.device_id(), &framed).await;

    assert!(joiner.machine.delivered().await.is_empty(), "nothing reached the machine");
    assert!(
        joiner.node.event().await.is_some_and(|event| event.cause.contains("no known channel")),
        "the refusal is logged, as an event of one peer's: {:?}",
        joiner.node.event().await
    );
}

/// §2.6c, at the level the assembly can show it: a node with no transport reaches
/// nothing, and there is nothing to reach with rather than a check to remember.
#[tokio::test]
async fn a_stopped_node_has_nothing_to_reach_infrastructure_with() {
    let (fixture, founder, _joiner, dialled, _accepted) = pair().await;
    register(&founder, &dialled).await;

    assert!(founder.node.is_reachable().await, "up while the tunnel is up");
    assert_eq!(founder.node.session_count().await, 1);

    founder.node.stopped().await;

    assert!(!founder.node.is_reachable().await, "and nothing at all once stopped");
    assert_eq!(founder.node.session_count().await, 0, "every session closed with it");

    // Nothing can be dialled, because there is nothing to dial with.
    let key = fixture.joiner.transport_key().public_key();
    assert!(founder.node.connect(&key).await.is_err());
}

/// The roster survives a restart because the bytes that arrived were kept.
#[tokio::test]
async fn the_roster_is_rebuilt_from_what_arrived() {
    let fixture = Fixture::found();
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let log = Log::at(scratch.path().join("roster.log"));

    log.append(&fixture.genesis).expect("appends");
    log.append(&fixture.add).expect("appends");

    let mut rebuilt = Roster::new();
    for operation in log.read().expect("reads") {
        assert!(rebuilt.offer_bytes(&operation).is_accepted(), "replay runs the same validation");
    }

    assert_eq!(
        rebuilt.state().expect("derives").devices.len(),
        fixture.state.devices.len(),
        "the same network came back"
    );

    let _ = Mutex::new(());
}

/// A revocation stops the session it revokes, on the sessions that already
/// exist and with no restart.
///
/// The transport checks membership when a session is *established*. A session
/// established before a revocation was never checked against it, so without
/// this the revoked device would stay connected until it happened to reconnect —
/// which is exactly the window a revocation exists to close.
#[tokio::test]
async fn a_revocation_closes_the_session_it_revokes() {
    let (fixture, founder, joiner, dialled, accepted) = pair().await;
    register(&founder, &dialled).await;
    register(&joiner, &accepted).await;
    pump(&accepted, &joiner.node, fixture.founder.device_id(), 2).await;
    pump(&dialled, &founder.node, fixture.joiner.device_id(), 2).await;

    assert_eq!(founder.node.session_count().await, 1, "connected to begin with");

    founder
        .node
        .admit_without_activating(&fixture.revoke(fixture.joiner.device_id()))
        .await
        .expect("the founder may revoke");

    assert_eq!(
        founder.node.session_count().await,
        0,
        "the revoked device's session is closed, not left until it reconnects"
    );
    assert!(
        founder.node.event().await.is_some_and(|event| event.subsystem == "roster"),
        "and the closure is logged rather than silent — as an event: it is the peer's standing"
    );
}

/// A revocation arriving *from a peer* takes effect the same way. A node that
/// only enforced its own revocations would keep a device its network had removed.
#[tokio::test]
async fn a_revocation_that_arrives_from_a_peer_also_closes_the_session() {
    let (fixture, founder, joiner, dialled, accepted) = pair().await;
    register(&founder, &dialled).await;
    register(&joiner, &accepted).await;
    pump(&accepted, &joiner.node, fixture.founder.device_id(), 2).await;
    pump(&dialled, &founder.node, fixture.joiner.device_id(), 2).await;

    // The founder revokes the joiner; the joiner learns of it over the session.
    founder
        .node
        .admit_without_activating(&fixture.revoke(fixture.joiner.device_id()))
        .await
        .expect("the founder may revoke");
    pump(&accepted, &joiner.node, fixture.founder.device_id(), 4).await;

    assert!(
        !joiner
            .node
            .state()
            .await
            .expect("derives")
            .devices
            .contains_key(&fixture.joiner.device_id()),
        "the joiner learned it is out"
    );
    assert_eq!(
        joiner.node.session_count().await,
        0,
        "and dropped the session rather than keeping it open to a network it has left"
    );
}

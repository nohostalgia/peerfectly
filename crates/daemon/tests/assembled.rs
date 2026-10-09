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

        let mut node = Roster::with_clock(Box::new(daemon::state::WallClock));
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
        let mut roster = Roster::with_clock(Box::new(daemon::state::WallClock));
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

    /// An operation admitting `device`, signed by the founder.
    fn admit(&self, device: &NodeIdentity) -> Vec<u8> {
        let core = OperationCore::new(
            3,
            self.founder.signing_key().algorithm(),
            OperationBody::AddDevice(
                device.device_spec("newcomer", Role::Member, false, vec![]).expect("spec"),
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

    /// `count` renames of the joiner, each on the one before, as an admin's
    /// daemon writes them. Concurrent ones by one author would be an
    /// equivocation, which the roster rightly does not trust; and renames add no
    /// member, so the network stays small enough that everyone is a neighbour.
    fn a_chain_of_renames(&self, count: usize) -> Vec<Vec<u8>> {
        let mut parents = self.roster().heads();
        let mut out = Vec::new();
        for index in 0..count {
            let core = OperationCore::new(
                u64::try_from(index).expect("small").saturating_add(4),
                self.founder.signing_key().algorithm(),
                OperationBody::Rename {
                    device: self.joiner.device_id(),
                    name: format!("laptop-{index}"),
                },
                parents.clone(),
                self.founder.signing_key().key_id(),
                self.network,
            )
            .expect("well-formed");
            parents = vec![core.id()];
            out.push(sign_operation(&core, self.founder.signer()).expect("signs"));
        }
        out
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

    let mut genesis_only = Roster::with_clock(Box::new(daemon::state::WallClock));
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

/// A session that says whether it was closed, and carries nothing.
struct Watched {
    peer: roster::id::DeviceId,
    closed: std::sync::atomic::AtomicBool,
}

impl Watched {
    fn to(peer: roster::id::DeviceId) -> Arc<Self> {
        Arc::new(Self { peer, closed: std::sync::atomic::AtomicBool::new(false) })
    }

    fn closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// A handle on a `Watched`, which the node can own while the test keeps watching.
struct WatchedHandle(Arc<Watched>);

#[async_trait::async_trait]
impl Session for WatchedHandle {
    fn peer(&self) -> roster::id::DeviceId {
        self.0.peer
    }
    async fn send(&self, _payload: &[u8]) -> transport::Result<()> {
        Ok(())
    }
    async fn recv(&self) -> transport::Result<Vec<u8>> {
        std::future::pending().await
    }
    async fn send_packet(&self, _packet: &[u8]) -> transport::Result<()> {
        Ok(())
    }
    async fn recv_packet(&self) -> transport::Result<Vec<u8>> {
        std::future::pending().await
    }
    async fn close(&self) -> transport::Result<()> {
        self.0.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// A session that replaces another to the same device closes the one it replaces.
///
/// Two devices that dial each other at the same moment open two connections, and
/// each side keeps whichever it registered last. Where both kept the same one, the
/// other was dropped from both tables and closed by neither: its own reader kept it
/// alive in the transport, both paths and the net report with it, at rest and for
/// good. Found in the testbed, in two runs out of six (Linux `VERIFICATION.md`,
/// step 35).
#[tokio::test]
async fn a_session_replaced_by_another_to_the_same_device_is_closed() {
    let (_fixture, founder, _joiner, dialled, _accepted) = pair().await;
    let peer = dialled.peer();
    let first = Watched::to(peer);
    let second = Watched::to(peer);

    founder.node.opened(Box::new(WatchedHandle(Arc::clone(&first)))).await;
    founder.node.opened(Box::new(WatchedHandle(Arc::clone(&second)))).await;

    assert!(first.closed(), "the session replaced is closed");
    assert!(!second.closed(), "the session that replaced it is kept");
    assert_eq!(founder.node.session_count().await, 1);
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

/// **A packet for a device that is switched off is an event, never a
/// problem.** The packet opens a session; the device does not answer; what was
/// waiting is dropped and that is recorded. An application on the machine that
/// keeps trying a device that is off would otherwise keep the network shown as
/// wrong for as long as it tried.
#[tokio::test]
async fn a_packet_for_a_device_not_connected_is_not_a_problem() {
    let fixture = Fixture::found();
    let fabric = MemoryFabric::new();
    let founder_transport = Arc::new(
        MemoryTransport::join(&fabric, Arc::clone(&fixture.founder), fixture.state.clone()).await,
    );
    let founder =
        assemble(&fixture, &fixture.founder, founder_transport as Arc<dyn Transport>).await;

    let to_joiner = Tunnel::new(fixture.prefix(), fixture.founder.device_id())
        .address_of(&fixture.joiner.device_id());
    let from_founder = Tunnel::new(fixture.prefix(), fixture.founder.device_id())
        .address_of(&fixture.founder.device_id());
    founder.machine.queue(packet(from_founder, to_joiner)).await;
    let _ = founder.node.carry_one().await;

    let mut event = None;
    for _ in 0..100 {
        event = founder.node.event().await;
        if event.as_ref().is_some_and(|event| event.cause.contains("were dropped")) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        event.as_ref().is_some_and(|event| event.cause.contains("were dropped")),
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

    let mut rebuilt = Roster::with_clock(Box::new(daemon::state::WallClock));
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

// ---- A session opened by the packet that needs it -----------------------------

/// Two assembled nodes on one fabric with no session between them. The joiner
/// is not accepting yet: a test starts it when it wants the session to open.
async fn apart() -> (Fixture, Assembled, Assembled) {
    let (fixture, founder, joiner, _fabric) = apart_on_fabric().await;
    (fixture, founder, joiner)
}

/// As [`apart`], with the fabric, for a test that brings a third party onto it.
async fn apart_on_fabric() -> (Fixture, Assembled, Assembled, MemoryFabric) {
    let fixture = Fixture::found();
    let fabric = MemoryFabric::new();
    let founder_transport = Arc::new(
        MemoryTransport::join(&fabric, Arc::clone(&fixture.founder), fixture.state.clone()).await,
    );
    let joiner_transport = Arc::new(
        MemoryTransport::join(&fabric, Arc::clone(&fixture.joiner), fixture.state.clone()).await,
    );
    let founder =
        assemble(&fixture, &fixture.founder, founder_transport as Arc<dyn Transport>).await;
    let joiner = assemble(&fixture, &fixture.joiner, joiner_transport as Arc<dyn Transport>).await;
    // As an admin's daemon does on its way up: without it the founder has never
    // dated its roster, and carries traffic only to administrators.
    founder.node.attest_change().await;
    (fixture, founder, joiner, fabric)
}

/// A packet from the founder's machine to the joiner's, marked so that a burst's
/// order can be read back.
fn marked(fixture: &Fixture, mark: u8) -> Vec<u8> {
    let tunnel = Tunnel::new(fixture.prefix(), fixture.founder.device_id());
    let mut out = packet(
        tunnel.address_of(&fixture.founder.device_id()),
        tunnel.address_of(&fixture.joiner.device_id()),
    );
    out.push(mark);
    out
}

/// What the machine has been handed, once `count` have arrived or the bound
/// has passed.
async fn delivered(machine: &MemoryDevice, count: usize) -> Vec<Vec<u8>> {
    for _ in 0..100 {
        let got = machine.delivered().await;
        if got.len() >= count {
            return got;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    machine.delivered().await
}

#[tokio::test]
async fn the_first_packet_opens_the_session_and_arrives() {
    let (fixture, founder, joiner) = apart().await;
    tokio::spawn(Arc::clone(&joiner.node).accept_forever());

    let first = marked(&fixture, 1);
    founder.machine.queue(first.clone()).await;
    let departure = founder.node.carry_one().await.expect("takes");
    assert!(matches!(departure, Departure::Unreachable { .. }), "no session yet: {departure:?}");

    assert_eq!(delivered(&joiner.machine, 1).await, vec![first], "late, but not lost");
}

#[tokio::test]
async fn a_burst_while_the_session_opens_arrives_in_order() {
    let (fixture, founder, joiner) = apart().await;

    let burst: Vec<Vec<u8>> = (1..=5).map(|mark| marked(&fixture, mark)).collect();
    for packet in &burst {
        founder.machine.queue(packet.clone()).await;
        let _ = founder.node.carry_one().await.expect("takes");
    }
    // Only now does the other side answer: everything above waited.
    tokio::spawn(Arc::clone(&joiner.node).accept_forever());

    assert_eq!(delivered(&joiner.machine, burst.len()).await, burst);
}

#[tokio::test]
async fn the_waiting_queue_is_bounded() {
    let (fixture, founder, joiner) = apart().await;

    let over = daemon::limits::MAX_WAITING_PACKETS + 8;
    for mark in 0..over {
        founder.machine.queue(marked(&fixture, u8::try_from(mark).expect("small"))).await;
        let _ = founder.node.carry_one().await.expect("takes");
    }
    tokio::spawn(Arc::clone(&joiner.node).accept_forever());

    let got = delivered(&joiner.machine, daemon::limits::MAX_WAITING_PACKETS).await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        joiner.machine.delivered().await.len(),
        daemon::limits::MAX_WAITING_PACKETS,
        "the bound, and not one more: {}",
        got.len()
    );
}

#[tokio::test]
async fn an_unreachable_member_costs_one_recorded_failure() {
    let fixture = Fixture::found();
    let fabric = MemoryFabric::new();
    // Only the founder is on the fabric: the joiner is switched off.
    let founder_transport = Arc::new(
        MemoryTransport::join(&fabric, Arc::clone(&fixture.founder), fixture.state.clone()).await,
    );
    let founder =
        assemble(&fixture, &fixture.founder, founder_transport as Arc<dyn Transport>).await;

    founder.machine.queue(marked(&fixture, 1)).await;
    let _ = founder.node.carry_one().await.expect("takes");

    let mut said = None;
    for _ in 0..100 {
        said = founder.node.event().await;
        if said.as_ref().is_some_and(|event| event.cause.contains("were dropped")) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let said = said.expect("the failure is recorded");
    assert!(said.cause.contains("1 packets"), "once, for the attempt: {}", said.cause);
}

// ---- An idle session is closed ---------------------------------------------------

const IDLE: std::time::Duration = std::time::Duration::from_secs(10 * 60);

#[tokio::test(start_paused = true)]
async fn an_unused_session_is_closed_without_a_fault() {
    let (fixture, founder, _joiner, dialled, _accepted) = pair().await;
    register(&founder, &dialled).await;
    assert!(founder.node.has_session(&fixture.joiner.device_id()).await);

    tokio::time::advance(IDLE + std::time::Duration::from_secs(1)).await;
    founder.node.close_idle(IDLE).await;

    assert!(!founder.node.has_session(&fixture.joiner.device_id()).await, "closed");
    assert_eq!(None, founder.node.fault().await, "and nothing went wrong");
}

#[tokio::test(start_paused = true)]
async fn a_session_in_use_is_kept() {
    let (fixture, founder, joiner, dialled, accepted) = pair().await;
    register(&founder, &dialled).await;
    register(&joiner, &accepted).await;

    // Halfway through the idle period, a packet crosses.
    tokio::time::advance(IDLE / 2).await;
    founder.machine.queue(marked(&fixture, 1)).await;
    assert!(founder.node.carry_one().await.expect("takes").is_carried());

    tokio::time::advance(IDLE / 2 + std::time::Duration::from_secs(1)).await;
    founder.node.close_idle(IDLE).await;
    assert!(
        founder.node.has_session(&fixture.joiner.device_id()).await,
        "used five minutes ago: still open"
    );
}

#[tokio::test]
async fn a_closed_session_reopens_on_the_next_packet() {
    let (fixture, founder, joiner) = apart().await;
    tokio::spawn(Arc::clone(&joiner.node).accept_forever());

    founder.machine.queue(marked(&fixture, 1)).await;
    let _ = founder.node.carry_one().await.expect("takes");
    assert_eq!(delivered(&joiner.machine, 1).await.len(), 1);

    // Idle for "ever": closed at once.
    founder.node.close_idle(std::time::Duration::ZERO).await;
    assert!(!founder.node.has_session(&fixture.joiner.device_id()).await);

    founder.machine.queue(marked(&fixture, 2)).await;
    let _ = founder.node.carry_one().await.expect("takes");
    let got = delivered(&joiner.machine, 2).await;
    assert_eq!(got.len(), 2, "the second packet opened it again");
    assert_eq!(got.last(), Some(&marked(&fixture, 2)));
}

// ---- Every operation is pushed to the neighbours, a burst once ------------------

/// How many devices a node's roster holds, once it holds at least `count`, or
/// when the bound has passed.
async fn devices_reach(node: &Arc<Node>, count: usize) -> usize {
    for _ in 0..200 {
        let held = node.state().await.map_or(0, |state| state.devices.len());
        if held >= count {
            return held;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    node.state().await.map_or(0, |state| state.devices.len())
}

/// Not only a revocation: an admission reaches a neighbour that has no session
/// open, without waiting for any period.
#[tokio::test]
async fn any_operation_reaches_a_neighbour_with_no_open_session() {
    let (fixture, founder, joiner) = apart().await;
    tokio::spawn(Arc::clone(&joiner.node).accept_forever());
    tokio::spawn(Arc::clone(&founder.node).spread_forever());
    let before = joiner.node.state().await.expect("derives").devices.len();

    founder.node.admit_without_activating(&fixture.add_a_third()).await.expect("admits");

    assert_eq!(devices_reach(&joiner.node, before + 1).await, before + 1, "it arrived");
}

/// An admin signing five acts at once makes one round of contact, not five.
#[tokio::test]
async fn a_burst_makes_one_contact_per_neighbour() {
    let (fixture, founder, joiner) = apart().await;
    let contacts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let joiner = Arc::clone(&joiner.node);
        let contacts = Arc::clone(&contacts);
        tokio::spawn(async move {
            while joiner.accept().await.is_ok() {
                contacts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
    }
    tokio::spawn(Arc::clone(&founder.node).spread_forever());

    for operation in fixture.a_chain_of_renames(5) {
        founder.node.admit_without_activating(&operation).await.expect("admits");
    }

    let renamed = async || {
        joiner.node.state().await.is_ok_and(|state| {
            state
                .devices
                .get(&fixture.joiner.device_id())
                .is_some_and(|record| record.name == "laptop-4")
        })
    };
    let mut arrived = false;
    for _ in 0..200 {
        if renamed().await {
            arrived = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(arrived, "all five arrived: the last rename is in force");
    // Long enough for any second round to have happened.
    tokio::time::sleep(Node::SPREAD_PAUSE * 2).await;
    assert_eq!(
        contacts.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one contact for the whole burst"
    );
}

/// A rename is in force where it was signed at once, and reaches the device it
/// renames: the old name is gone on both, and the new one is what both hold.
#[tokio::test]
async fn a_rename_is_in_force_on_both_members() {
    let (fixture, founder, joiner) = apart().await;
    {
        let joiner = Arc::clone(&joiner.node);
        tokio::spawn(async move { while joiner.accept().await.is_ok() {} });
    }
    tokio::spawn(Arc::clone(&founder.node).spread_forever());

    let rename = OperationCore::new(
        4,
        fixture.founder.signing_key().algorithm(),
        OperationBody::Rename { device: fixture.joiner.device_id(), name: "studio".to_owned() },
        fixture.roster().heads(),
        fixture.founder.signing_key().key_id(),
        fixture.network,
    )
    .expect("well-formed");
    let signed = sign_operation(&rename, fixture.founder.signer()).expect("signs");
    let before = joiner.node.state().await.expect("derives");
    assert_eq!(
        before.devices.get(&fixture.joiner.device_id()).map(|record| record.name.as_str()),
        Some("joiner"),
        "named `joiner` before"
    );
    founder.node.admit_without_activating(&signed).await.expect("admits");

    let name_on = async |node: &Arc<Node>| {
        node.state().await.ok().and_then(|state| {
            state.devices.get(&fixture.joiner.device_id()).map(|record| record.name.clone())
        })
    };
    assert_eq!(name_on(&founder.node).await.as_deref(), Some("studio"), "at once, where signed");

    let mut arrived = false;
    for _ in 0..200 {
        if name_on(&joiner.node).await.as_deref() == Some("studio") {
            arrived = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(arrived, "and on the device it renamed");
    for node in [&founder.node, &joiner.node] {
        let state = node.state().await.expect("derives");
        assert!(
            !state.devices.values().any(|record| record.name == "joiner"),
            "the old name is gone"
        );
    }
}

// ---- A device catches up when it comes back ---------------------------------------

/// A device that was down while an operation was admitted holds it shortly
/// after coming up, from the reconciliation it makes on the way up, without
/// waiting for any period.
#[tokio::test]
async fn a_device_coming_up_learns_what_it_missed() {
    let (fixture, founder, joiner) = apart().await;
    // The joiner is down: nothing is pushed to it, and it reaches nobody.
    let before = joiner.node.state().await.expect("derives").devices.len();
    founder.node.admit_without_activating(&fixture.add_a_third()).await.expect("admits");
    assert_eq!(joiner.node.state().await.expect("derives").devices.len(), before);

    // It comes up: the founder answers, and the joiner runs what the service
    // runs first on the way up.
    tokio::spawn(Arc::clone(&founder.node).accept_forever());
    joiner.node.reconcile_with_neighbours().await;

    assert_eq!(devices_reach(&joiner.node, before + 1).await, before + 1, "caught up");
}

// ---- A newcomer is not left refused ------------------------------------------------

/// A device admitted a moment ago reaches a member that has not heard of the
/// admission yet. The member refuses, catches up from its neighbours, and
/// accepts the newcomer when it tries again.
#[tokio::test]
async fn a_newcomer_is_accepted_on_retry_by_a_member_that_was_behind() {
    let fixture = Fixture::found();
    let fabric = MemoryFabric::new();
    let newcomer = Arc::new(NodeIdentity::generate().expect("generates"));
    let admission = fixture.admit(&newcomer);

    // The founder holds the admission; the joiner does not, yet.
    let founder_transport = Arc::new(
        MemoryTransport::join(&fabric, Arc::clone(&fixture.founder), fixture.state.clone()).await,
    );
    let founder =
        assemble(&fixture, &fixture.founder, founder_transport as Arc<dyn Transport>).await;
    founder.node.attest_change().await;
    founder.node.admit_without_activating(&admission).await.expect("admits");

    let joiner_transport = Arc::new(
        MemoryTransport::join(&fabric, Arc::clone(&fixture.joiner), fixture.state.clone()).await,
    );
    let joiner = assemble(&fixture, &fixture.joiner, joiner_transport as Arc<dyn Transport>).await;

    let mut held = fixture.roster();
    assert!(held.offer_bytes(&admission).is_accepted());
    let newcomer_state = held.state().expect("derives");
    let newcomer_transport =
        Arc::new(MemoryTransport::join(&fabric, Arc::clone(&newcomer), newcomer_state).await);
    let arrived =
        assemble_holding(&fixture, held, &newcomer, newcomer_transport as Arc<dyn Transport>).await;

    tokio::spawn(Arc::clone(&founder.node).accept_forever());
    tokio::spawn(Arc::clone(&joiner.node).accept_forever());
    tokio::spawn(Arc::clone(&arrived.node).accept_forever());

    let joiner_key = fixture.joiner.transport_key().public_key();
    let outcome = tokio::time::timeout(
        Node::NEWCOMER_RETRY * u32::try_from(Node::NEWCOMER_ATTEMPTS + 1).expect("small"),
        arrived.node.connect(&joiner_key),
    )
    .await
    .expect("within the retries");
    assert!(outcome.is_ok(), "accepted on a retry: {outcome:?}");
}

/// Refusing strangers in quick succession makes a member catch up once, not once
/// for each.
#[tokio::test]
async fn a_burst_of_strangers_makes_one_catch_up() {
    let (fixture, founder, joiner, fabric) = apart_on_fabric().await;
    let contacts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let founder = Arc::clone(&founder.node);
        let contacts = Arc::clone(&contacts);
        tokio::spawn(async move {
            while founder.accept().await.is_ok() {
                contacts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
    }
    tokio::spawn(Arc::clone(&joiner.node).accept_forever());

    let joiner_key = fixture.joiner.transport_key().public_key();
    for _ in 0..5 {
        let stranger = Arc::new(NodeIdentity::generate().expect("generates"));
        let stranger_transport =
            MemoryTransport::join(&fabric, stranger, fixture.state.clone()).await;
        let refused = stranger_transport.connect(&joiner_key).await;
        assert!(refused.is_err(), "a stranger is refused");
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert_eq!(
        contacts.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one catch-up for five strangers"
    );
}

// ---- Asking about members looks, rather than remembering -----------------------------

/// A member that is up, with no session open, is found when a person asks.
#[tokio::test]
async fn asking_finds_a_member_that_is_up() {
    let (fixture, founder, joiner) = apart().await;
    tokio::spawn(Arc::clone(&joiner.node).accept_forever());
    assert!(!founder.node.has_session(&fixture.joiner.device_id()).await);

    founder.node.probe(daemon::limits::PROBE_WITHIN, daemon::limits::PROBE_AT_MOST).await;

    assert!(founder.node.has_session(&fixture.joiner.device_id()).await, "reachable now");
}

/// A member that does not answer costs the question no more than the bound,
/// and is left to be reported by its last contact.
#[tokio::test]
async fn asking_about_a_member_that_is_off_waits_no_longer_than_the_bound() {
    let fixture = Fixture::found();
    let fabric = MemoryFabric::new();
    let founder_transport = Arc::new(
        MemoryTransport::join(&fabric, Arc::clone(&fixture.founder), fixture.state.clone()).await,
    );
    let founder =
        assemble(&fixture, &fixture.founder, founder_transport as Arc<dyn Transport>).await;

    let started = std::time::Instant::now();
    founder.node.probe(daemon::limits::PROBE_WITHIN, daemon::limits::PROBE_AT_MOST).await;

    assert!(started.elapsed() <= daemon::limits::PROBE_WITHIN + std::time::Duration::from_secs(1));
    assert!(!founder.node.has_session(&fixture.joiner.device_id()).await);
}

// ---- A failed attempt is not repeated at once ------------------------------------------

/// After a packet fails to reach a member, the next packets for it are dropped
/// for a while rather than opening another attempt each time it fails.
#[tokio::test]
async fn a_member_a_packet_failed_to_reach_is_rested() {
    let fixture = Fixture::found();
    let fabric = MemoryFabric::new();
    let founder_transport = Arc::new(
        MemoryTransport::join(&fabric, Arc::clone(&fixture.founder), fixture.state.clone()).await,
    );
    let founder =
        assemble(&fixture, &fixture.founder, founder_transport as Arc<dyn Transport>).await;

    founder.machine.queue(marked(&fixture, 1)).await;
    let _ = founder.node.carry_one().await.expect("takes");
    let mut first = None;
    for _ in 0..100 {
        first = founder.node.event().await;
        if first.as_ref().is_some_and(|event| event.cause.contains("were dropped")) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let first = first.expect("the first attempt failed and said so");

    for mark in 2..6 {
        founder.machine.queue(marked(&fixture, mark)).await;
        let _ = founder.node.carry_one().await.expect("takes");
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        founder.node.event().await.map(|event| event.at),
        Some(first.at),
        "no further attempt was made, so nothing further failed"
    );
}

//! A light member's sessions as a microcontroller opens them
//! (`light_node::sessions`), against this binding as a computer runs it.
//!
//! The microcontroller's side is driven here from a bare convesso node, as its
//! firmware drives it from convesso-embassy's events: what it sends and what it
//! believes are the machine's alone. It says it takes 2 KB messages, so what the
//! computer sends it comes in parts.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "a test reports failure by panicking"
)]

use std::time::Duration;

use convesso_core::identity::{Address, Identity, PeerId};
use convesso_tokio::{
    Config, Context, ContextEvent, ContextEvents, ContextOptions, Node, RelayLocation,
};
use light_node::engine::Engine;
use light_node::sessions::{DialFailure, Keys, Output, Sessions, To};
use roster::member::{DEFAULT_BUDGET, LightMember};
use roster::membership::{Evidence, Shown};
use transport::session::Transport;
use transport_convesso::ConvessoTransport;
use transport_convesso::fixture::{Network, TestRelay};
use transport_convesso::frame::Limits;

const PATIENCE: Duration = Duration::from_secs(20);

/// convesso's peer id of a transport key, as the firmware reads it.
struct ConvessoKeys;

impl Keys for ConvessoKeys {
    type Peer = PeerId;

    fn peer_of(&self, key: &[u8; 32]) -> Option<PeerId> {
        Address::parse(*key).ok().map(|address| address.peer_id())
    }
}

/// The joiner, as a microcontroller member: its bare convesso node, its engine
/// and its sessions.
struct Board {
    _node: Node,
    context: Context,
    events: ContextEvents,
    engine: Engine,
    sessions: Sessions<ConvessoKeys>,
    seen: Vec<Output<PeerId>>,
}

impl Board {
    async fn on(network: &Network, relay: &TestRelay) -> Self {
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
        node.set_reachable(true).await.unwrap();
        let (context, events) = node
            .context(transport_convesso::node::CONTEXT, ContextOptions::default())
            .await
            .unwrap();
        let own = network.evidence.get(&network.joiner.device_id()).unwrap().clone();
        let shown = Shown::from_bytes(&own).unwrap();
        let member = LightMember::new(
            Evidence { leaf: shown.leaf, proof: shown.proof, root: network.root.clone() },
            network.state.params.clone(),
            DEFAULT_BUDGET,
        )
        .unwrap();
        Self {
            _node: node,
            context,
            events,
            engine: Engine::new(member),
            sessions: Sessions::new(ConvessoKeys, Limits::LEAST, own),
            seen: Vec::new(),
        }
    }

    /// Sends what the sessions queued, keeping the rest to look at.
    async fn flush(&mut self) {
        while let Some(output) = self.sessions.poll_output() {
            match output {
                Output::Message { to: To::Key(key), bytes } => {
                    let _ = self.context.send_message(Address::parse(key).unwrap(), bytes).await;
                }
                Output::Message { to: To::Peer(peer), bytes } => {
                    let _ = self.context.send_message_to_peer(peer, bytes).await;
                }
                Output::Datagram { to, bytes } => {
                    let _ = self.context.send_to_peer(to, bytes).await;
                }
                other => self.seen.push(other),
            }
        }
    }

    /// Runs the board until `done` holds of what it saw, and gives that.
    async fn until(&mut self, done: impl Fn(&Output<PeerId>) -> bool) -> Output<PeerId> {
        self.flush().await;
        tokio::time::timeout(PATIENCE, async {
            loop {
                if let Some(at) = self.seen.iter().position(&done) {
                    return self.seen.remove(at);
                }
                let Some(event) = self.events.next().await else { panic!("the context ended") };
                match event {
                    ContextEvent::Message { peer, data } => {
                        self.sessions.on_message(&mut self.engine, peer, &data, 0);
                    }
                    ContextEvent::Datagram { peer, data, .. } => {
                        self.sessions.on_datagram(peer, &data, 0);
                    }
                    _ => {}
                }
                self.flush().await;
            }
        })
        .await
        .expect("the board saw it")
    }
}

/// A full member that shows its evidence, as a daemon holding a root does.
async fn full_showing(network: &Network) -> ConvessoTransport {
    let node = ConvessoTransport::bind(&network.founder, network.state.clone()).await.unwrap();
    node.update_evidence(network.evidence.get(&network.founder.device_id()).unwrap().clone());
    node
}

fn key_of(transport: &ConvessoTransport) -> [u8; 32] {
    transport.transport_key().as_bytes().try_into().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_board_dials_a_full_member_and_payloads_cross_both_ways_in_parts() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let full = full_showing(&network).await;
    tokio::time::timeout(PATIENCE, full.online()).await.unwrap();
    let mut board = Board::on(&network, &relay).await;

    board.sessions.dial(41, key_of(&full), 0);
    let (opened, accepted) = tokio::join!(
        board.until(|output| matches!(output, Output::Opened { .. })),
        tokio::time::timeout(PATIENCE, full.accept()),
    );
    let accepted = accepted.unwrap().unwrap();
    assert_eq!(opened, Output::Opened { id: 41, device: network.founder.device_id() });
    assert_eq!(
        accepted.peer(),
        network.joiner.device_id(),
        "the full member knows it by its state"
    );

    // Larger than the board's messages: it comes in parts, whole.
    let large = vec![9u8; 10_000];
    accepted.send(&large).await.unwrap();
    let arrived = board.until(|output| matches!(output, Output::Payload { .. })).await;
    assert_eq!(
        arrived,
        Output::Payload { id: 41, device: network.founder.device_id(), bytes: large.clone() }
    );

    assert!(board.sessions.send_payload(41, b"from the board"));
    board.flush().await;
    let received = tokio::time::timeout(PATIENCE, accepted.recv()).await.unwrap().unwrap();
    assert_eq!(received, b"from the board".to_vec());

    // Closed by the full member, closed on the board.
    accepted.close().await.unwrap();
    let closed = board.until(|output| matches!(output, Output::Closed { .. })).await;
    assert_eq!(closed, Output::Closed { id: 41, device: network.founder.device_id() });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_member_dials_a_board_and_is_known_by_its_evidence() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let full = full_showing(&network).await;
    tokio::time::timeout(PATIENCE, full.online()).await.unwrap();
    let mut board = Board::on(&network, &relay).await;
    // The relay knows the board once it has spoken there.
    board.sessions.dial(1, key_of(&full), 0);
    let _ = board.until(|output| matches!(output, Output::Opened { .. })).await;

    let joiner_key = network.joiner.transport_key().public_key();
    let (dialled, opened) = tokio::join!(
        tokio::time::timeout(PATIENCE, full.connect(&joiner_key)),
        board.until(|output| matches!(output, Output::Opened { id, .. } if *id != 1)),
    );
    let dialled = dialled.unwrap().unwrap();
    assert_eq!(dialled.peer(), network.joiner.device_id());
    let Output::Opened { device, .. } = opened else { panic!() };
    assert_eq!(device, network.founder.device_id(), "known by its evidence");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_board_refuses_a_peer_showing_another_devices_evidence() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    // The third device shows the founder's evidence: valid, and not its own.
    let impostor = ConvessoTransport::bind(&network.third, network.state.clone()).await.unwrap();
    impostor.update_evidence(network.evidence.get(&network.founder.device_id()).unwrap().clone());
    tokio::time::timeout(PATIENCE, impostor.online()).await.unwrap();
    let mut board = Board::on(&network, &relay).await;

    let key = key_of(&impostor);
    board.sessions.dial(7, key, 0);
    let failed = board.until(|output| matches!(output, Output::DialFailed { .. })).await;
    assert_eq!(failed, Output::DialFailed { key, failure: DialFailure::NotBelieved });
    assert!(board.sessions.devices().next().is_none());
}

/// The member whole, as a board runs it: on starting it dials, of its own
/// accord, the admin whose root it holds, and keeps the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_board_member_keeps_in_touch_with_the_admin_whose_root_it_holds() {
    use light_node::member::{Action, Member};

    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let full = full_showing(&network).await;
    tokio::time::timeout(PATIENCE, full.online()).await.unwrap();
    let Board { _node: node, context, mut events, engine, .. } = Board::on(&network, &relay).await;
    let mut member = Member::new(engine.into_member(), ConvessoKeys, Limits::LEAST);
    let mut next_id = 100_u64;
    let mut ids = || {
        next_id += 1;
        next_id
    };
    member.start(0, &mut ids);

    let founder = network.founder.device_id();
    let (kept, accepted) = tokio::join!(
        tokio::time::timeout(PATIENCE, async {
            loop {
                while let Some(action) = member.poll_action() {
                    if let Action::Message { to, bytes } = action {
                        match to {
                            To::Key(key) => {
                                let _ =
                                    context.send_message(Address::parse(key).unwrap(), bytes).await;
                            }
                            To::Peer(peer) => {
                                let _ = context.send_message_to_peer(peer, bytes).await;
                            }
                        }
                    }
                }
                if member.in_session().any(|device| device == founder) {
                    return;
                }
                if let Some(ContextEvent::Message { peer, data }) = events.next().await {
                    member.on_message(peer, &data, 0, &mut ids);
                }
            }
        }),
        tokio::time::timeout(PATIENCE, full.accept()),
    );
    kept.expect("the member reaches the admin");
    assert_eq!(accepted.unwrap().unwrap().peer(), network.joiner.device_id());
    drop(node);
}

/// A tunnel packet crosses a board's session both ways, larger than one
/// datagram on the way in, so in two fragments put back together.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_packet_crosses_a_boards_session_both_ways() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);
    let full = full_showing(&network).await;
    tokio::time::timeout(PATIENCE, full.online()).await.unwrap();
    let mut board = Board::on(&network, &relay).await;

    board.sessions.dial(41, key_of(&full), 0);
    let (_, accepted) = tokio::join!(
        board.until(|output| matches!(output, Output::Opened { .. })),
        tokio::time::timeout(PATIENCE, full.accept()),
    );
    let accepted = accepted.unwrap().unwrap();

    let large: Vec<u8> = (0..1_400_u32).map(|at| u8::try_from(at % 251).unwrap()).collect();
    accepted.send_packet(&large).await.unwrap();
    let arrived = board.until(|output| matches!(output, Output::Packet { .. })).await;
    assert_eq!(
        arrived,
        Output::Packet { id: 41, device: network.founder.device_id(), bytes: large.clone() }
    );

    assert!(board.sessions.send_packet(41, b"a small packet from the board"));
    board.flush().await;
    let received = tokio::time::timeout(PATIENCE, accepted.recv_packet()).await.unwrap().unwrap();
    assert_eq!(received, b"a small packet from the board".to_vec());
}

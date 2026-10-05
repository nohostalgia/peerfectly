//! A small network and the nodes that hold it, for tests that drive `Node`.
//!
//! Every layer below the daemon already had tests for membership, and every one
//! of them passed while two real machines refused each other for twenty minutes.
//! They passed because each supplied the new roster state itself — which is
//! precisely the thing the daemon could not do, and precisely what nothing
//! checked. So these fixtures assemble the component that owns the roster, over
//! the in-memory transport, on the interface the real one also satisfies.

#![allow(dead_code, reason = "each test file uses a different part of the fixture")]

use std::sync::Arc;
use std::time::Duration;

use daemon::gateway::Gateway;
use daemon::node::Node;
use daemon::router::Router;
use daemon::schedule::Schedule;
use daemon::state::Log;
use identity::NodeIdentity;
use roster::id::NetworkId;
use roster::roster::Roster;
use roster::sign::sign_operation;
use roster::types::{NetworkParams, OperationBody, OperationCore, Role};
use roster_sync::Syncer;
use transport::memory::{MemoryFabric, MemoryTransport};
use transport::session::Transport;
use tunnel::{Prefix, Tunnel as Rules};

/// A network of one, plus the signed operations that admit a second and a third
/// device.
pub struct Network {
    /// The founding admin.
    pub founder: Arc<NodeIdentity>,
    /// The second device, named `b`.
    pub joiner: Arc<NodeIdentity>,
    /// The third device, named `c`.
    pub third: Arc<NodeIdentity>,
    /// The founding operation.
    pub genesis: Vec<u8>,
    /// The operation admitting `b`.
    pub admit_joiner: Vec<u8>,
    /// The operation admitting `c`.
    pub admit_third: Vec<u8>,
}

impl Network {
    /// Everything up to and including the third device's admission.
    #[must_use]
    pub fn everything(&self) -> Vec<Vec<u8>> {
        vec![self.genesis.clone(), self.admit_joiner.clone(), self.admit_third.clone()]
    }

    /// The founding operation and the second device's admission.
    #[must_use]
    pub fn two_devices(&self) -> Vec<Vec<u8>> {
        vec![self.genesis.clone(), self.admit_joiner.clone()]
    }
}

/// Builds the network, signing each operation as the founder.
#[must_use]
pub fn a_network() -> Network {
    let founder = Arc::new(NodeIdentity::generate().expect("generates"));
    let joiner = Arc::new(NodeIdentity::generate().expect("generates"));
    let third = Arc::new(NodeIdentity::generate().expect("generates"));

    let params = NetworkParams::with_relay(
        vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
        None::<String>,
        "example.internal",
        2_592_000,
    )
    .expect("valid");

    let genesis = OperationCore::new(
        1,
        founder.signing_key().algorithm(),
        OperationBody::CreateNetwork {
            device: founder.device_spec("a", Role::Admin, true, vec![]).expect("spec"),
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
            joiner.device_spec("b", Role::Member, false, vec![]).expect("spec"),
        ),
        vec![genesis.id()],
        founder.signing_key().key_id(),
        network,
    )
    .expect("well-formed");
    let add_bytes = sign_operation(&add, founder.signer()).expect("signs");

    let add_third = OperationCore::new(
        3,
        founder.signing_key().algorithm(),
        OperationBody::AddDevice(
            third.device_spec("c", Role::Member, false, vec![]).expect("spec"),
        ),
        vec![add.id()],
        founder.signing_key().key_id(),
        network,
    )
    .expect("well-formed");
    let add_third_bytes = sign_operation(&add_third, founder.signer()).expect("signs");

    Network {
        founder,
        joiner,
        third,
        genesis: genesis_bytes,
        admit_joiner: add_bytes,
        admit_third: add_third_bytes,
    }
}

/// A node holding exactly the operations given, with a transport bound to the
/// state those operations describe — which is what the daemon does at bring-up.
pub async fn node_on(
    identity: &Arc<NodeIdentity>,
    operations: &[Vec<u8>],
    fabric: &MemoryFabric,
    scratch: &tempfile::TempDir,
) -> Arc<Node> {
    let node = node_off(identity, operations, scratch);
    let state = node.state().await.expect("a network");

    // Bound to the state as it is now, exactly as `bring_up` does. This is the
    // snapshot the whole membership defect lived in.
    let transport = MemoryTransport::join(fabric, Arc::clone(identity), state).await;
    node.started(Arc::new(transport) as Arc<dyn Transport>).await;
    node
}

/// The same node with no transport, as the daemon is before `up`.
///
/// The log is written as well as replayed, so a test can drop the node and
/// assemble a second one over the same directory — which is what a restart is.
#[must_use]
pub fn node_off(
    identity: &Arc<NodeIdentity>,
    operations: &[Vec<u8>],
    scratch: &tempfile::TempDir,
) -> Arc<Node> {
    let log = Log::at(scratch.path().join("roster.log"));
    let existing = log.read().expect("a readable log");

    // Whatever is already on disk is replayed first, exactly as the daemon does
    // at start-up, so that assembling a second node over the same directory is a
    // restart rather than a fresh device that happens to share a folder.
    let mut roster = Roster::new();
    for operation in &existing {
        roster.offer_bytes(operation);
    }
    for operation in operations {
        if existing.iter().any(|held| held == operation) {
            continue;
        }
        assert!(roster.offer_bytes(operation).is_accepted(), "the fixture's operations are valid");
        log.append(operation).expect("the log is writable");
    }
    // A real network has a snapshot from its first moment: founding signs one and
    // an admission delivers it. Without one here a node would hold a roster it
    // cannot confirm, refuse every peer that is not an admin, and fail these
    // tests for a reason that has nothing to do with what they are about.
    if let Ok(bytes) = daemon::snapshots::sign_over_heads(&roster, identity) {
        assert!(roster.offer_snapshot(&bytes).is_accepted(), "its own snapshot must load");
    }

    let prefix = Prefix::from_parameter(&[0xfd, 0, 0, 0, 0, 0, 0, 0]).expect("usable");

    Arc::new(Node::new(
        Arc::clone(identity),
        Syncer::new(roster),
        Arc::new(Gateway::new(Rules::new(prefix, identity.device_id()))),
        Router::new(prefix),
        log,
        Schedule::provisional(),
    ))
}

/// Waits for a condition, so a test does not depend on how fast a spawned task
/// gets scheduled.
pub async fn within<F>(what: &str, mut check: F)
where
    F: AsyncFnMut() -> bool,
{
    for _ in 0..200u32 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{what}");
}

//! Shared fixtures: real identities, real signatures, real histories.
//!
//! Nothing here fabricates an operation. Every one is signed by a key an
//! identity actually holds and verified by the roster on arrival, because a test
//! that skipped signing would prove nothing about the code that checks them.

#![allow(dead_code, reason = "each test file uses a different part of the fixture")]
#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::sync::Arc;

use identity::NodeIdentity;
use roster::id::{DeviceId, NetworkId, OperationId};
use roster::roster::Roster;
use roster::sign::sign_operation;
use roster::snapshot::{Snapshot, sign_snapshot};
use roster::types::{NetworkParams, OperationBody, OperationCore, Role};
use roster_sync::Syncer;

/// A network under construction, with the identities that authored it.
pub struct Fixture {
    /// The founding admin.
    pub founder: Arc<NodeIdentity>,
    /// Every other device, in the order they were added.
    pub members: Vec<Arc<NodeIdentity>>,
    /// The network id, which is the genesis operation's id.
    pub network: NetworkId,
    /// Every operation authored so far, in causal order, as signed bytes.
    pub operations: Vec<Vec<u8>>,
    /// The head each new operation will name as its parent.
    head: OperationId,
    /// The next timestamp, so ids differ. Timestamps never affect ordering.
    clock: u64,
}

impl Fixture {
    /// Founds a network with one admin.
    pub fn found() -> Self {
        let founder = Arc::new(NodeIdentity::generate().expect("generates"));
        let params =
            NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 2_592_000)
                .expect("valid");
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
        let bytes = sign_operation(&genesis, founder.signer()).expect("signs");
        let network = NetworkId::from_bytes(*genesis.id().as_bytes());

        Self {
            founder,
            members: Vec::new(),
            network,
            operations: vec![bytes],
            head: genesis.id(),
            clock: 1,
        }
    }

    /// Signs and records an operation authored by the founder.
    fn author(&mut self, body: OperationBody) -> OperationId {
        self.clock = self.clock.wrapping_add(1);
        let core = OperationCore::new(
            self.clock,
            self.founder.signing_key().algorithm(),
            body,
            vec![self.head],
            self.founder.signing_key().key_id(),
            self.network,
        )
        .expect("well-formed");
        let bytes = sign_operation(&core, self.founder.signer()).expect("signs");
        self.operations.push(bytes);
        self.head = core.id();
        core.id()
    }

    /// Adds a member device and returns its identity.
    pub fn add_member(&mut self, name: &str) -> Arc<NodeIdentity> {
        let joiner = Arc::new(NodeIdentity::generate().expect("generates"));
        let spec = joiner.device_spec(name, Role::Member, false, vec![]).expect("spec");
        self.author(OperationBody::AddDevice(spec));
        self.members.push(Arc::clone(&joiner));
        joiner
    }

    /// Revokes a device.
    pub fn revoke(&mut self, device: DeviceId) -> OperationId {
        self.author(OperationBody::RevokeDevice { device, reason: "test".to_owned() })
    }

    /// Renames a device, as a cheap way to lengthen a history.
    pub fn rename(&mut self, device: DeviceId, name: &str) -> OperationId {
        self.author(OperationBody::Rename { device, name: name.to_owned() })
    }

    /// Appends `count` further operations, each renaming the founder.
    pub fn extend(&mut self, count: usize) {
        let founder = self.founder.device_id();
        for index in 0..count {
            self.rename(founder, &format!("founder-{index}"));
        }
    }

    /// A roster holding every operation authored so far.
    pub fn roster(&self) -> Roster {
        self.roster_through(self.operations.len())
    }

    /// A roster holding the first `count` operations.
    pub fn roster_through(&self, count: usize) -> Roster {
        let mut node = Roster::new();
        for bytes in self.operations.iter().take(count) {
            let admission = node.offer_bytes(bytes);
            assert!(admission.is_accepted(), "fixture operation refused: {admission:?}");
        }
        node
    }

    /// A syncer over a roster holding every operation authored so far.
    pub fn syncer(&self) -> Syncer {
        Syncer::new(self.roster())
    }

    /// A syncer over a roster holding the first `count` operations.
    pub fn syncer_through(&self, count: usize) -> Syncer {
        Syncer::new(self.roster_through(count))
    }

    /// A snapshot signed by the founder over what `node` currently derives.
    ///
    /// Built from the node's own heads and depths, so it is a snapshot a node
    /// can actually verify rather than a fabricated one.
    pub fn snapshot_bytes(&self, node: &Roster, seq: u64) -> Vec<u8> {
        let state = node.state().expect("derives");
        let heads = node.heads();
        let depths: Vec<u64> = heads
            .iter()
            .map(|head| {
                let index = node.dag().position(head).expect("a held head");
                node.dag().depth(index)
            })
            .collect();
        let body = Snapshot::new(
            seq,
            state.to_bytes(),
            heads,
            depths,
            self.founder.signing_key().key_id(),
            self.network,
        )
        .expect("well-formed snapshot");
        sign_snapshot(&body, self.founder.signer()).expect("signs")
    }

    /// A syncer whose roster has adopted a snapshot at `seq`.
    pub fn syncer_with_snapshot(&self, seq: u64) -> Syncer {
        let mut node = self.roster();
        let bytes = self.snapshot_bytes(&node, seq);
        let admission = node.offer_snapshot(&bytes);
        assert!(admission.is_accepted(), "fixture snapshot refused: {admission:?}");
        Syncer::new(node)
    }

    /// The head a new operation should name as its parent.
    pub fn head(&self) -> OperationId {
        self.head
    }

    /// The id of the operation at `index`.
    pub fn id_at(&self, index: usize) -> OperationId {
        let bytes = self.operation(index);
        roster::sign::RawOperation::decode(bytes).expect("decodes").id()
    }

    /// Signs an operation naming an explicit parent, without recording it.
    ///
    /// This is how a test produces a genuine branch: two operations naming the
    /// same parent are concurrent, which is the case roster's conflict rules
    /// exist for and the case a partition actually creates.
    pub fn branch(&self, parent: OperationId, tag: u64, name: &str) -> Vec<u8> {
        let core = OperationCore::new(
            tag.wrapping_add(1000),
            self.founder.signing_key().algorithm(),
            OperationBody::Rename { device: self.founder.device_id(), name: name.to_owned() },
            vec![parent],
            self.founder.signing_key().key_id(),
            self.network,
        )
        .expect("well-formed");
        sign_operation(&core, self.founder.signer()).expect("signs")
    }

    /// The bytes of the operation at `index`.
    pub fn operation(&self, index: usize) -> &[u8] {
        self.operations.get(index).expect("operation exists")
    }

    /// The most recently authored operation's bytes.
    pub fn last(&self) -> &[u8] {
        self.operations.last().expect("at least the genesis")
    }
}

/// A well-formed operation belonging to a network nobody in a test holds.
///
/// Used where a test needs an orphan: something that decodes, carries a real
/// signature, and names parents this node will never have.
pub fn orphan(index: u64) -> Vec<u8> {
    let mut other = Fixture::found();
    other.extend(2);
    // Re-parent the last operation onto an id nothing holds, so it can never be
    // placed. It is still signed by a real key over its real contents.
    let founder = Arc::clone(&other.founder);
    let mut absent = [0u8; 32];
    absent[..8].copy_from_slice(&index.to_be_bytes());
    let core = OperationCore::new(
        index.wrapping_add(100),
        founder.signing_key().algorithm(),
        OperationBody::Rename { device: founder.device_id(), name: format!("orphan-{index}") },
        vec![OperationId::from_bytes(absent)],
        founder.signing_key().key_id(),
        other.network,
    )
    .expect("well-formed");
    sign_operation(&core, founder.signer()).expect("signs")
}

/// Derived membership, as a sorted list of device ids, for comparing two nodes.
pub fn membership(node: &Roster) -> Vec<DeviceId> {
    let state = node.state().expect("derives");
    let mut devices: Vec<DeviceId> = state.devices.keys().copied().collect();
    devices.sort_unstable();
    devices
}

/// Everything a node holds, sorted, for comparing two nodes.
pub fn held(node: &Roster) -> Vec<OperationId> {
    let mut ids: Vec<OperationId> =
        node.dag().operations().iter().map(roster::sign::VerifiedOperation::id).collect();
    ids.sort_unstable();
    ids
}

/// Many orphans from one foreign network, cheaply.
///
/// One identity, many operations, each naming a parent nothing holds. Building a
/// whole fixture per orphan would mean a key generation per orphan, and the
/// quota tests need dozens.
pub fn orphans(count: usize) -> Vec<Vec<u8>> {
    let other = Fixture::found();
    let founder = Arc::clone(&other.founder);
    (0..count)
        .map(|index| {
            let mut absent = [0u8; 32];
            absent[..8].copy_from_slice(&(index as u64).wrapping_add(1).to_be_bytes());
            let core = OperationCore::new(
                (index as u64).wrapping_add(100),
                founder.signing_key().algorithm(),
                OperationBody::Rename {
                    device: founder.device_id(),
                    name: format!("orphan-{index}"),
                },
                vec![OperationId::from_bytes(absent)],
                founder.signing_key().key_id(),
                other.network,
            )
            .expect("well-formed");
            sign_operation(&core, founder.signer()).expect("signs")
        })
        .collect()
}

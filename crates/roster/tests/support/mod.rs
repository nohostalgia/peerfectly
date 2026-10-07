//! Fixtures for building signed histories.
//!
//! Every test here needs the same thing: a genesis, some admins, and operations
//! hanging off chosen parents so that concurrency is exact rather than
//! incidental. Building that by hand each time buries the shape of the test
//! under key management.
//!
//! Keys come from fixed seeds. A failing test should fail the same way twice.

#![allow(dead_code, reason = "each test binary uses a different part of this module")]

use std::sync::atomic::{AtomicU64, Ordering};

use roster::attestation::{Attestation, sign_attestation};
use roster::dag::Dag;
use roster::id::{DeviceId, NetworkId, OperationId};
use roster::roster::Clock;
use roster::sign::{Ed25519Signer, RawOperation, Signer, VerifiedOperation, sign_operation};
use roster::snapshot::{Snapshot, sign_snapshot};
use roster::state::derive;
use roster::types::{
    Algorithm, Capability, DeviceSpec, KeyEntry, KeyPurpose, NetworkParams, OperationBody,
    OperationCore, Role,
};

/// A clock a test drives by hand, so nothing has to sleep.
///
/// Atomic rather than a `Cell` because `Clock` is `Send + Sync`: a roster has to
/// be able to cross threads, so everything it holds must too.
#[derive(Debug, Default)]
pub struct TestClock {
    /// The current reading, in seconds.
    seconds: AtomicU64,
}

impl TestClock {
    /// A clock starting at zero.
    #[must_use]
    pub fn new() -> Self {
        Self { seconds: AtomicU64::new(0) }
    }

    /// Moves the clock forward.
    pub fn advance(&self, seconds: u64) {
        let now = self.seconds.load(Ordering::SeqCst);
        self.seconds.store(now.saturating_add(seconds), Ordering::SeqCst);
    }

    /// Moves the clock backwards, as a wall clock correction would.
    pub fn rewind(&self, seconds: u64) {
        let now = self.seconds.load(Ordering::SeqCst);
        self.seconds.store(now.saturating_sub(seconds), Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_seconds(&self) -> u64 {
        self.seconds.load(Ordering::SeqCst)
    }

    /// The same reading, taken as Unix time, so that a test can sign an
    /// attestation at a chosen time and see it aged on arrival.
    fn unix_seconds(&self) -> Option<u64> {
        Some(self.now_seconds())
    }
}

/// A handle sharing one test clock between a roster and its test.
#[derive(Debug, Clone)]
pub struct SharedClock(pub std::sync::Arc<TestClock>);

impl SharedClock {
    /// A new shared clock.
    #[must_use]
    pub fn new() -> Self {
        Self(std::sync::Arc::new(TestClock::new()))
    }

    /// Moves it forward.
    pub fn advance(&self, seconds: u64) {
        self.0.advance(seconds);
    }

    /// Moves it backwards.
    pub fn rewind(&self, seconds: u64) {
        self.0.rewind(seconds);
    }
}

impl Default for SharedClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SharedClock {
    fn now_seconds(&self) -> u64 {
        self.0.now_seconds()
    }

    fn unix_seconds(&self) -> Option<u64> {
        self.0.unix_seconds()
    }
}

/// A signed time no test clock reaches.
///
/// An attestation carrying it has no age on arrival, so it is dated from its
/// receipt — exactly as every test written before attestations carried a time
/// expects. Tests about the signed time choose one with
/// [`History::attestation_issued`].
pub const UNDATED: u64 = u64::MAX;

/// A deterministic signer for a device.
#[must_use]
pub fn signer(seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed([seed; 32])
}

/// A device specification built from one seed, with a distinct key for each of
/// the three purposes.
#[must_use]
pub fn device(seed: u8, name: &str, role: Role, founder: bool) -> DeviceSpec {
    let signing = KeyEntry::new(
        Algorithm::Ed25519,
        KeyPurpose::Signing,
        signer(seed).public_key().as_bytes().to_vec(),
    )
    .expect("well-formed signing key");
    let transport = KeyEntry::new(
        Algorithm::Ed25519,
        KeyPurpose::Transport,
        signer(seed.wrapping_add(100)).public_key().as_bytes().to_vec(),
    )
    .expect("well-formed transport key");
    let attestation = KeyEntry::new(
        Algorithm::Ed25519,
        KeyPurpose::Attestation,
        signer(seed.wrapping_add(200)).public_key().as_bytes().to_vec(),
    )
    .expect("well-formed attestation key");
    DeviceSpec::new(
        sorted(vec![signing, transport, attestation]),
        name,
        role,
        founder,
        vec![Capability::new("serves").expect("short capability")],
    )
    .expect("well-formed device")
}

/// Sorts key entries into the canonical order a device record requires.
#[must_use]
pub fn sorted(mut keys: Vec<KeyEntry>) -> Vec<KeyEntry> {
    // The roster's own definition of the order, not an approximation of it.
    keys.sort_by_key(KeyEntry::order_key);
    keys
}

/// The device id of the fixture device with a given seed.
#[must_use]
pub fn device_id(seed: u8) -> DeviceId {
    device(seed, "fixture", Role::Member, false).device_id().expect("has a signing key")
}

/// Fixture network parameters.
#[must_use]
pub fn params() -> NetworkParams {
    NetworkParams::new(
        vec![0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        "example.internal",
        2_592_000,
    )
    .expect("well-formed parameters")
}

/// Network parameters with a chosen suffix, for telling concurrent
/// `set_network` operations apart.
#[must_use]
pub fn params_with(suffix: &str) -> NetworkParams {
    NetworkParams::new(vec![0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], suffix, 2_592_000)
        .expect("well-formed parameters")
}

/// One operation in a built history.
#[derive(Clone)]
pub struct Entry {
    /// The label the test addresses it by.
    pub label: String,
    /// Its id.
    pub id: OperationId,
    /// Its encoded bytes.
    pub bytes: Vec<u8>,
}

/// Builds signed histories with named operations.
///
/// Operations are addressed by label, so a test can say "hang this off `a`" and
/// mean it. That is how concurrency gets tested deliberately rather than by
/// accident.
pub struct History {
    /// Operations in creation order.
    entries: Vec<Entry>,
    /// The network, once the genesis exists.
    network: Option<NetworkId>,
    /// Makes otherwise-identical operations distinct.
    nonce: u64,
}

impl History {
    /// Starts an empty history.
    #[must_use]
    pub fn new() -> Self {
        Self { entries: Vec::new(), network: None, nonce: 0 }
    }

    /// Creates the network, founded by the device with `seed`.
    ///
    /// The founding operation carries the zero network id: a network *is* its
    /// genesis, so the genesis cannot name a value derived from itself.
    pub fn genesis(&mut self, label: &str, seed: u8) -> OperationId {
        self.genesis_with(label, seed, device(seed, "phone", Role::Admin, true), params())
    }

    /// Creates the network with an explicit founding device and parameters.
    pub fn genesis_with(
        &mut self,
        label: &str,
        seed: u8,
        founder: DeviceSpec,
        network_params: NetworkParams,
    ) -> OperationId {
        let core = OperationCore::new(
            1_735_689_600_000,
            Algorithm::Ed25519,
            OperationBody::CreateNetwork { device: founder, params: network_params },
            vec![],
            signer(seed).key_id(),
            NetworkId::from_bytes([0; 32]),
        )
        .expect("well-formed genesis core");
        let bytes = sign_operation(&core, &signer(seed)).expect("signs");
        let id = core.id();
        self.network = Some(NetworkId::from_bytes(*id.as_bytes()));
        self.record(label, id, bytes);
        id
    }

    /// Adds an operation authored by `seed`, hanging off the labelled parents.
    pub fn op(
        &mut self,
        label: &str,
        author_seed: u8,
        parents: &[&str],
        body: OperationBody,
    ) -> OperationId {
        let network = self.network.expect("the genesis must come first");
        self.op_in(label, author_seed, parents, body, network)
    }

    /// Adds an operation naming an explicit network, for cross-network tests.
    pub fn op_in(
        &mut self,
        label: &str,
        author_seed: u8,
        parents: &[&str],
        body: OperationBody,
        network: NetworkId,
    ) -> OperationId {
        let parent_ids: Vec<OperationId> = parents.iter().map(|name| self.id(name)).collect();
        self.nonce = self.nonce.wrapping_add(1);
        let core = OperationCore::new(
            1_735_689_600_000_u64.wrapping_add(self.nonce),
            Algorithm::Ed25519,
            body,
            parent_ids,
            signer(author_seed).key_id(),
            network,
        )
        .expect("well-formed core");
        let bytes = sign_operation(&core, &signer(author_seed)).expect("signs");
        let id = core.id();
        self.record(label, id, bytes);
        id
    }

    /// Records an operation under a label.
    fn record(&mut self, label: &str, id: OperationId, bytes: Vec<u8>) {
        self.entries.push(Entry { label: label.to_owned(), id, bytes });
    }

    /// The entry with a label.
    fn entry(&self, label: &str) -> &Entry {
        self.entries
            .iter()
            .find(|entry| entry.label == label)
            .unwrap_or_else(|| panic!("no operation labelled `{label}`"))
    }

    /// The id of a labelled operation.
    #[must_use]
    pub fn id(&self, label: &str) -> OperationId {
        self.entry(label).id
    }

    /// The bytes of a labelled operation.
    #[must_use]
    pub fn bytes(&self, label: &str) -> Vec<u8> {
        self.entry(label).bytes.clone()
    }

    /// Every operation, in creation order.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Every label, in creation order.
    #[must_use]
    pub fn labels(&self) -> Vec<String> {
        self.entries.iter().map(|entry| entry.label.clone()).collect()
    }

    /// The network id.
    #[must_use]
    pub fn network(&self) -> NetworkId {
        self.network.expect("the genesis must come first")
    }

    /// Verifies an operation against the fixture signer its author names.
    #[must_use]
    pub fn verify(&self, raw: &RawOperation<'_>) -> VerifiedOperation {
        for seed in 0u8..=255 {
            let candidate = signer(seed);
            if candidate.key_id() == raw.core().author {
                return raw.verify(&candidate.public_key()).expect("fixture signature verifies");
            }
        }
        panic!("no fixture signer matches the author");
    }

    /// Verifies a labelled operation.
    #[must_use]
    pub fn verified(&self, label: &str) -> VerifiedOperation {
        let bytes = self.bytes(label);
        let raw = RawOperation::decode(&bytes).expect("fixture decodes");
        self.verify(&raw)
    }

    /// Builds a graph containing the named operations, inserted in that order.
    #[must_use]
    pub fn dag_of(&self, labels: &[&str]) -> Dag {
        let mut dag = Dag::new();
        for label in labels {
            dag.insert(self.verified(label))
                .unwrap_or_else(|error| panic!("inserting `{label}` failed: {error:?}"));
        }
        dag
    }

    /// Builds a graph containing the named operations, tolerating rejection.
    ///
    /// For tests that offer something the graph should refuse.
    pub fn try_dag_of(&self, labels: &[&str]) -> roster::Result<Dag> {
        let mut dag = Dag::new();
        for label in labels {
            dag.insert(self.verified(label))?;
        }
        Ok(dag)
    }

    /// Builds a snapshot over the operations the labelled heads cover.
    ///
    /// The state and head depths are derived from the covered sub-graph, so the
    /// snapshot says what the history actually implies rather than what the
    /// test wishes it did.
    #[must_use]
    pub fn snapshot_at(&self, seq: u64, signer_seed: u8, head_labels: &[&str]) -> Vec<u8> {
        self.snapshot_with_state(seq, signer_seed, head_labels, None)
    }

    /// Builds a snapshot, optionally overriding the state it claims.
    ///
    /// The override exists so a test can produce the lying-admin case.
    #[must_use]
    pub fn snapshot_with_state(
        &self,
        seq: u64,
        signer_seed: u8,
        head_labels: &[&str],
        state_override: Option<Vec<u8>>,
    ) -> Vec<u8> {
        let covered = self.covered_dag(head_labels);
        let state = state_override
            .unwrap_or_else(|| derive(&covered).expect("the covered sub-graph derives").to_bytes());
        let heads: Vec<_> = head_labels.iter().map(|label| self.id(label)).collect();
        let depths: Vec<u64> = head_labels
            .iter()
            .map(|label| {
                let index = covered.position(&self.id(label)).expect("head is covered");
                covered.depth(index)
            })
            .collect();
        let body =
            Snapshot::new(seq, state, heads, depths, signer(signer_seed).key_id(), self.network())
                .expect("well-formed snapshot");
        sign_snapshot(&body, &signer(signer_seed)).expect("signs")
    }

    /// Builds an attestation over the labelled heads.
    ///
    /// Signed with the **attestation** key of the device built from `seed`,
    /// which `device` derives from `seed + 200`. A test that signed with the
    /// device's signing key would be testing that the roster refuses it, which
    /// is a different test and is written as one.
    #[must_use]
    pub fn attestation_at(&self, seq: u64, seed: u8, head_labels: &[&str]) -> Vec<u8> {
        self.attestation_signed_by(seq, seed.wrapping_add(200), head_labels)
    }

    /// The same, signed by whatever key the seed names.
    ///
    /// For the cases where the point is that the wrong key signed it.
    #[must_use]
    pub fn attestation_signed_by(&self, seq: u64, key_seed: u8, head_labels: &[&str]) -> Vec<u8> {
        self.attestation_signed_at(seq, key_seed, head_labels, UNDATED)
    }

    /// An attestation by the device with `seed`, signed at `issued_at`.
    #[must_use]
    pub fn attestation_issued(
        &self,
        seq: u64,
        seed: u8,
        head_labels: &[&str],
        issued_at: u64,
    ) -> Vec<u8> {
        self.attestation_signed_at(seq, seed.wrapping_add(200), head_labels, issued_at)
    }

    /// The general form: any key, any signed time.
    fn attestation_signed_at(
        &self,
        seq: u64,
        key_seed: u8,
        head_labels: &[&str],
        issued_at: u64,
    ) -> Vec<u8> {
        let heads: Vec<_> = head_labels.iter().map(|label| self.id(label)).collect();
        let body =
            Attestation::new(seq, heads, signer(key_seed).key_id(), self.network(), issued_at)
                .expect("well-formed attestation");
        sign_attestation(&body, &signer(key_seed)).expect("signs")
    }

    /// An attestation naming heads that are not in this history at all.
    #[must_use]
    pub fn attestation_over_unknown_heads(&self, seq: u64, seed: u8) -> Vec<u8> {
        let key_seed = seed.wrapping_add(200);
        let elsewhere = OperationId::from_bytes([0xee; 32]);
        let body = Attestation::new(
            seq,
            vec![elsewhere],
            signer(key_seed).key_id(),
            self.network(),
            UNDATED,
        )
        .expect("well-formed attestation");
        sign_attestation(&body, &signer(key_seed)).expect("signs")
    }

    /// The sub-graph the labelled heads cover.
    #[must_use]
    pub fn covered_dag(&self, head_labels: &[&str]) -> Dag {
        let full = self.dag();
        let mut wanted: Vec<usize> = Vec::new();
        for label in head_labels {
            let index = full.position(&self.id(label)).expect("head is held");
            wanted.push(index);
            wanted.extend(full.ancestors_of(index));
        }
        wanted.sort_unstable();
        wanted.dedup();

        let mut covered = Dag::new();
        for index in wanted {
            let operation = full.operation(index).expect("held").clone();
            covered.insert(operation).expect("the covered region is downward closed");
        }
        covered
    }

    /// The operations the labelled heads name, as verified operations.
    #[must_use]
    pub fn head_operations(&self, head_labels: &[&str]) -> Vec<VerifiedOperation> {
        head_labels.iter().map(|label| self.verified(label)).collect()
    }

    /// Builds a graph from every operation, in creation order.
    #[must_use]
    pub fn dag(&self) -> Dag {
        let labels = self.labels();
        let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        self.dag_of(&refs)
    }

    /// Builds a graph from every operation, in the order given.
    #[must_use]
    pub fn dag_ordered(&self, order: &[usize]) -> Dag {
        let labels = self.labels();
        let refs: Vec<&str> =
            order.iter().filter_map(|index| labels.get(*index)).map(String::as_str).collect();
        self.dag_of(&refs)
    }
}

impl Default for History {
    fn default() -> Self {
        Self::new()
    }
}

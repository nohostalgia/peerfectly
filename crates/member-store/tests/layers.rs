//! Batch layers on disk: a layer laid over a base kept in the store, its tree
//! spilled to the layers' file, reads back as the same state; the base written
//! over it takes in what was spilled; and an altered layer hides, never adds.

#![allow(clippy::unwrap_used, clippy::panic, reason = "a test reports failure by panicking")]

use std::collections::BTreeSet;
use std::sync::Arc;

use member_store::{Layers, Store};
use roster::batch::{BatchEntry, entries_tree};
use roster::id::{NetworkId, OperationId};
use roster::leaf::{DeviceLeaf, Mode};
use roster::members::{Layer, LayerStore, Members};
use roster::state::RosterState;
use roster::types::{Algorithm, KeyEntry, KeyPurpose, NetworkParams};

const CACHE: usize = 4 << 20;

/// A board's entry from a number, its keys made of hashes.
fn entry(n: u32) -> BatchEntry {
    let hash = |tag: &str| blake3::hash(format!("board-{tag}{n}").as_bytes()).as_bytes().to_vec();
    let mut keys: Vec<KeyEntry> = [
        ("signing", KeyPurpose::Signing),
        ("transport", KeyPurpose::Transport),
        ("attestation", KeyPurpose::Attestation),
    ]
    .into_iter()
    .map(|(tag, purpose)| KeyEntry::new(Algorithm::Ed25519, purpose, hash(tag)).unwrap())
    .collect();
    keys.sort_by_key(KeyEntry::order_key);
    let ipv4 = n.is_multiple_of(5).then(|| {
        let [_, _, high, low] = n.to_be_bytes();
        [100, 71, high, low]
    });
    BatchEntry { keys, name: format!("Board-{n}"), serial: n.to_be_bytes().to_vec(), ipv4 }
}

fn skeleton() -> RosterState {
    let params =
        NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 0).unwrap();
    RosterState::empty(NetworkId::from_bytes([7; 32]), params)
}

/// A base of ten devices made from a batch-like entry each, written to `store`,
/// and the state it reads back as.
fn base_in(store: &Arc<Store>) -> RosterState {
    let mut state = skeleton();
    let base: Vec<DeviceLeaf> = (10_000..10_010)
        .map(|n| {
            let entry = entry(n);
            let device = entry.device_id().unwrap();
            let layer =
                Layer::new(OperationId::from_bytes([2; 32]), Mode::Full, Vec::new(), vec![entry]);
            let mut members = Members::new();
            members.lay(Arc::new(layer), Arc::new(BTreeSet::new()));
            (*members.get(&device).unwrap()).clone()
        })
        .collect();
    state.devices = base.into_iter().collect();
    store.write(&state).unwrap();
    store.state().unwrap().unwrap()
}

#[test]
fn a_layer_over_a_stored_base_is_written_whole_and_reads_back() {
    let scratch = tempfile::tempdir().unwrap();
    let store = Store::open(&scratch.path().join("base.redb"), CACHE).unwrap();
    let layers = Layers::open(&scratch.path().join("layers.redb"), CACHE).unwrap();
    let mut state = base_in(&store);

    // A batch of five thousand boards, its entries in the layers' file, laid
    // over the base: the tree spills there as it goes.
    let entries: Vec<BatchEntry> = (0..5_000).map(entry).collect();
    let batch = OperationId::from_bytes([9; 32]);
    layers.put(&batch, &entries).unwrap();
    let root = entries_tree(&entries).unwrap().root();
    let layer = Layer::stored(
        batch,
        Mode::Light,
        Vec::new(),
        Arc::clone(&layers) as Arc<dyn LayerStore>,
        root,
        entries.len(),
    );
    state.devices.lay(Arc::new(layer), Arc::new(BTreeSet::new()));
    assert_eq!(state.devices.len(), 5_010);
    assert!(layers.node_count().unwrap() > 5_000, "the entries tree and the spilled paths");

    // What the same members make in memory: the root to agree with.
    let mut in_memory = skeleton();
    in_memory.devices = state.devices.values().map(|leaf| (*leaf).clone()).collect();
    assert_eq!(state.root(), in_memory.root(), "the layered tree is the state's");

    let one = entries.get(17).unwrap();
    let device = one.device_id().unwrap();
    let held = state.devices.get(&device).unwrap();
    assert_eq!(held.record.name, "Board-17");
    assert_eq!(held.settings.mode, Mode::Light);
    assert_eq!(state.devices.named("board-17").len(), 1, "found by name, case aside");
    let five = entries.get(5).unwrap();
    assert_eq!(
        state.devices.holding_address(five.ipv4.unwrap()),
        vec![five.device_id().unwrap()],
        "and by address"
    );
    let signing = one.keys.iter().find(|key| key.purpose == KeyPurpose::Signing).unwrap();
    assert_eq!(
        state
            .devices
            .holding(&signing.key_id(), Some(KeyPurpose::Signing))
            .map(|leaf| leaf.record.id),
        Some(device),
        "and by key"
    );

    // The base written over the layer takes in what was spilled, and reads back
    // whole, from disk alone.
    let expected = state.root();
    store.write(&state).unwrap();
    drop(state);
    drop(store);
    let store = Store::open(&scratch.path().join("base.redb"), CACHE).unwrap();
    store.verify(&expected_devices_root(&store)).unwrap();
    let reopened = store.state().unwrap().unwrap();
    assert_eq!(reopened.root(), expected, "the same state, from the base alone");
    assert_eq!(reopened.devices.len(), 5_010);
    assert_eq!(reopened.devices.get(&device).unwrap().record.name, "Board-17");
    assert!(!store.tampered() && !layers.tampered(), "and nothing was told it lied");
}

/// The devices root the store holds, which `verify` checks everything against.
fn expected_devices_root(store: &Arc<Store>) -> roster::merkle::Hash {
    store.state().unwrap().unwrap().devices.root()
}

#[test]
fn an_altered_layer_on_disk_hides_and_never_adds() {
    let scratch = tempfile::tempdir().unwrap();
    let layers = Layers::open(&scratch.path().join("layers.redb"), CACHE).unwrap();
    let entries: Vec<BatchEntry> = (0..50).map(entry).collect();
    let batch = OperationId::from_bytes([9; 32]);
    layers.put(&batch, &entries).unwrap();
    let root = entries_tree(&entries).unwrap().root();

    // The file changed behind the daemon's back: an entry the batch never held
    // slipped in under it.
    let stranger = entry(999);
    let replaced = entries.get(3).unwrap().clone();
    layers.put(&batch, std::slice::from_ref(&stranger)).unwrap();

    let layer = Layer::stored(
        batch,
        Mode::Full,
        Vec::new(),
        Arc::clone(&layers) as Arc<dyn LayerStore>,
        root,
        entries.len(),
    );
    let mut members = Members::new();
    members.lay(Arc::new(layer), Arc::new(BTreeSet::new()));
    assert!(members.get(&stranger.device_id().unwrap()).is_none(), "the stranger is not added");
    assert!(!members.keys().any(|device| device == stranger.device_id().unwrap()), "nor walked");
    assert!(members.get(&replaced.device_id().unwrap()).is_some(), "the batch's own stand");
    assert!(layers.tampered(), "and the store is told it lied");
}

/// Collecting keeps every node the live roots reach and lets go of the rest:
/// the entries tree of a batch still held reads whole after, and with no root
/// in use nothing is left.
#[test]
fn collecting_keeps_what_live_roots_reach() {
    let scratch = tempfile::tempdir().unwrap();
    let layers = Layers::open(&scratch.path().join("layers.redb"), CACHE).unwrap();
    let kept: Vec<BatchEntry> = (0..300).map(entry).collect();
    let gone: Vec<BatchEntry> = (300..600).map(entry).collect();
    let (one, two) = (OperationId::from_bytes([1; 32]), OperationId::from_bytes([2; 32]));
    layers.put(&one, &kept).unwrap();
    layers.put(&two, &gone).unwrap();
    layers.forget(&two);
    let all = layers.node_count().unwrap();

    let root = entries_tree(&kept).unwrap().root();
    let swept = layers.collect(&[root]).unwrap();
    assert!(swept > 0, "the forgotten batch's tree goes");
    assert_eq!(layers.node_count().unwrap(), all - swept);

    let layer = Layer::stored(
        one,
        Mode::Full,
        Vec::new(),
        Arc::clone(&layers) as Arc<dyn LayerStore>,
        root,
        kept.len(),
    );
    let mut members = Members::new();
    members.lay(Arc::new(layer), Arc::new(BTreeSet::new()));
    assert_eq!(members.keys().count(), 300, "the one still held reads whole");
    assert!(!layers.tampered());

    layers.collect(&[]).unwrap();
    assert_eq!(layers.node_count().unwrap(), 0, "with no root in use, nothing is left");
    layers.clear().unwrap();
}

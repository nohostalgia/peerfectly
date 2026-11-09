//! The base store: what it writes reads back as the same state, a change is
//! written as the change, and whatever is altered on disk is found out.

#![allow(clippy::unwrap_used, clippy::panic, reason = "a test reports failure by panicking")]

use std::path::Path;
use std::sync::Arc;

use member_store::{Error, Store};
use redb::{Database, TableDefinition};
use roster::id::{DeviceId, NetworkId, OperationId};
use roster::leaf::{DeviceLeaf, DeviceSettings, Mode};
use roster::state::RosterState;
use roster::types::{Algorithm, DeviceRecord, KeyEntry, KeyPurpose, NetworkParams, Role};

const CACHE: usize = 4 << 20;

/// A device made from a number, with three keys and an address on every
/// third one.
fn leaf(n: u32) -> DeviceLeaf {
    let hash = |tag: &str| blake3::hash(format!("{tag}{n}").as_bytes()).as_bytes().to_vec();
    let mut keys: Vec<KeyEntry> = [
        ("signing", KeyPurpose::Signing),
        ("transport", KeyPurpose::Transport),
        ("attestation", KeyPurpose::Attestation),
    ]
    .into_iter()
    .map(|(tag, purpose)| KeyEntry::new(Algorithm::Ed25519, purpose, hash(tag)).unwrap())
    .collect();
    keys.sort_by_key(KeyEntry::order_key);
    let id = DeviceId::of_signing_key(&hash("signing"));
    let record = DeviceRecord {
        id,
        keys,
        name: format!("d{n}"),
        role: Role::Member,
        founder: false,
        added_by: OperationId::from_bytes([1; 32]),
        capabilities: Vec::new(),
    };
    let address = n.is_multiple_of(3).then(|| {
        let [_, _, high, low] = n.to_be_bytes();
        [100, 70, high, low]
    });
    let settings = DeviceSettings::new(Mode::Full, Vec::new(), address, None).unwrap();
    DeviceLeaf { record, settings }
}

fn skeleton() -> RosterState {
    let params =
        NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 0).unwrap();
    RosterState::empty(NetworkId::from_bytes([7; 32]), params)
}

/// A state of `count` devices, in memory.
fn state(count: u32) -> RosterState {
    let mut state = skeleton();
    state.devices = (0..count).map(leaf).collect();
    state
}

fn transport_key(leaf: &DeviceLeaf) -> roster::id::KeyId {
    leaf.record.keys.iter().find(|entry| entry.purpose == KeyPurpose::Transport).unwrap().key_id()
}

#[test]
fn a_state_written_whole_reads_back_as_itself() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.redb");
    let written = state(300);
    {
        let store = Store::open(&path, CACHE).unwrap();
        assert!(store.state().unwrap().is_none(), "nothing written yet");
        store.write(&written).unwrap();
    }

    let store = Store::open(&path, CACHE).unwrap();
    let read = store.state().unwrap().unwrap();
    assert_eq!(read.root(), written.root());
    assert_eq!(read.devices.len(), 300);
    assert_eq!(read.devices.leaves(), written.devices.leaves());
    for n in [0, 7, 299] {
        let expected = leaf(n);
        let device = expected.record.id;
        assert_eq!(read.devices.get(&device).as_deref(), Some(&expected));
        assert_eq!(
            read.device_for_key_of_purpose(&transport_key(&expected), KeyPurpose::Transport)
                .map(|held| held.record.id),
            Some(device)
        );
    }
    assert_eq!(read.devices.holding_address([100, 70, 0, 9]), vec![leaf(9).record.id]);
    store.verify(&read.devices.root()).unwrap();
    assert!(!store.tampered());
}

#[test]
fn a_change_is_written_as_the_change_and_leaves_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.redb");
    let store = Store::open(&path, CACHE).unwrap();
    store.write(&state(200)).unwrap();

    // Derived on top of the store, as a compaction would: removals, changes,
    // admissions.
    let mut next = store.state().unwrap().unwrap();
    let mut memory = state(200);
    for n in 0..20 {
        let device = leaf(n).record.id;
        next.devices.remove(&device);
        memory.devices.remove(&device);
    }
    for n in 20..40 {
        let mut changed = leaf(n);
        changed.record.name = format!("renamed{n}");
        changed.settings.ipv4 = None;
        next.devices.insert_leaf(changed.clone());
        memory.devices.insert_leaf(changed);
    }
    for n in 1000..1050 {
        next.devices.insert_leaf(leaf(n));
        memory.devices.insert_leaf(leaf(n));
    }
    assert_eq!(next.root(), memory.root());
    store.write(&next).unwrap();
    drop(next);
    drop(store);

    let store = Store::open(&path, CACHE).unwrap();
    let read = store.state().unwrap().unwrap();
    assert_eq!(read.root(), memory.root());
    assert_eq!(read.devices.leaves(), memory.devices.leaves());
    assert!(read.devices.holding_address([100, 70, 0, 21]).is_empty(), "taken away");
    assert_eq!(
        read.device_for_key_of_purpose(&transport_key(&leaf(5)), KeyPurpose::Transport),
        None,
        "removed with its device"
    );
    // Whole, with no node, leaf, position or index more than the tree holds.
    store.verify(&read.devices.root()).unwrap();
}

/// Rewrites the file behind the store's back, as someone holding the disk
/// would.
fn behind_its_back(path: &Path, change: impl FnOnce(&redb::WriteTransaction)) {
    let db = Database::open(path).unwrap();
    let write = db.begin_write().unwrap();
    change(&write);
    write.commit().unwrap();
}

const LEAVES: TableDefinition<[u8; 32], &[u8]> = TableDefinition::new("leaves");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const KEYS: TableDefinition<([u8; 32], [u8; 32]), u8> = TableDefinition::new("keys");

fn written(path: &Path, count: u32) -> roster::merkle::Hash {
    let store = Store::open(path, CACHE).unwrap();
    let state = state(count);
    store.write(&state).unwrap();
    state.root()
}

#[test]
fn a_leaf_changed_on_disk_is_found_out() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.redb");
    written(&path, 50);
    let target = leaf(4);
    let mut altered = target.clone();
    altered.record.role = Role::Admin;
    behind_its_back(&path, |write| {
        let mut leaves = write.open_table(LEAVES).unwrap();
        leaves.insert(*target.record.id.as_bytes(), altered.to_bytes().as_slice()).unwrap();
    });

    let store = Store::open(&path, CACHE).unwrap();
    let read = store.state().unwrap().unwrap();
    assert_eq!(read.devices.get(&target.record.id), None, "not an admin, not anything");
    assert!(store.tampered());
    assert!(matches!(store.verify(&read.devices.root()), Err(Error::Tampered(_))));
}

#[test]
fn a_root_changed_on_disk_is_not_the_signed_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.redb");
    let signed = written(&path, 50);
    // A whole other state put in its place, consistent with itself.
    let other = state(60);
    {
        let store = Store::open(&path, CACHE).unwrap();
        store.write(&other).unwrap();
    }
    let store = Store::open(&path, CACHE).unwrap();
    let read = store.state().unwrap().unwrap();
    assert_ne!(read.root(), signed, "the caller's root tells them apart");

    // And only the root changed: the tree no longer holds what is there.
    drop(read);
    drop(store);
    behind_its_back(&path, |write| {
        let mut meta = write.open_table(META).unwrap();
        meta.insert("devices_root", [9_u8; 32].as_slice()).unwrap();
    });
    let store = Store::open(&path, CACHE).unwrap();
    let read = store.state().unwrap().unwrap();
    assert_ne!(read.root(), other.root());
    assert_eq!(read.devices.get(&leaf(1).record.id), None);
    assert!(store.tampered());
}

#[test]
fn an_index_entry_planted_on_disk_is_found_out() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.redb");
    written(&path, 50);
    // Device 2's transport key, said to be device 3's as well.
    let key = transport_key(&leaf(2));
    let planted = leaf(3).record.id;
    behind_its_back(&path, |write| {
        let mut keys = write.open_table(KEYS).unwrap();
        keys.insert((*key.as_bytes(), *planted.as_bytes()), 1).unwrap();
    });

    let store = Store::open(&path, CACHE).unwrap();
    let read = store.state().unwrap().unwrap();
    let holder = read.device_for_key_of_purpose(&key, KeyPurpose::Transport);
    // The lower id answers, whichever it is, and never device 3 for a key it
    // does not hold.
    assert_ne!(holder.map(|held| held.record.id), Some(planted));
    assert!(matches!(store.verify(&read.devices.root()), Err(Error::Tampered(_))));
}

#[test]
fn a_store_holds_one_state_at_a_time() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.redb");
    let store = Store::open(&path, CACHE).unwrap();
    store.write(&state(80)).unwrap();
    let smaller = state(10);
    store.write(&smaller).unwrap();
    let read: Arc<Store> = Store::open(&path, CACHE).unwrap_or_else(|_| store.clone());
    let state = read.state().unwrap().unwrap();
    assert_eq!(state.root(), smaller.root());
    read.verify(&state.devices.root()).unwrap();
}

#[test]
fn a_state_of_no_devices_is_written_and_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.redb");
    let store = Store::open(&path, CACHE).unwrap();
    store.write(&state(5)).unwrap();
    let empty = skeleton();
    store.write(&empty).unwrap();
    let read = store.state().unwrap().unwrap();
    assert_eq!(read.root(), empty.root());
    assert!(read.devices.is_empty());
    store.verify(&read.devices.root()).unwrap();
}

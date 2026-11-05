//! A state's devices over a base kept in a store: answering as the same
//! devices in memory do, and believing nothing the store changed.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod support;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use proptest::prelude::*;
use roster::id::{DeviceId, KeyId, OperationId};
use roster::leaf::{DeviceLeaf, DeviceSettings, Mode};
use roster::members::{MemberStore, Members};
use roster::merkle::{self, Hash, NodeSource, Stored};
use roster::types::{KeyPurpose, Role};
use support::device;

/// The rows of a derived index: each value, with the device deriving it.
type DerivedRows = Vec<([u8; 4], DeviceId)>;

/// A store kept in maps, as a disk would keep it, that can be altered behind
/// the tree's back.
#[derive(Default)]
struct Kept {
    leaves: Mutex<BTreeMap<DeviceId, DeviceLeaf>>,
    keys: Mutex<BTreeMap<(KeyId, DeviceId), KeyPurpose>>,
    addresses: Mutex<BTreeMap<([u8; 4], DeviceId), ()>>,
    nodes: Mutex<BTreeMap<Hash, Stored>>,
    derived: Mutex<BTreeMap<[u8; 32], DerivedRows>>,
    tampered: AtomicUsize,
}

impl NodeSource for Kept {
    fn node(&self, hash: &Hash) -> Option<Stored> {
        self.nodes.lock().unwrap().get(hash).copied()
    }

    fn tampered(&self) {
        self.tampered.fetch_add(1, Ordering::SeqCst);
    }
}

impl MemberStore for Kept {
    fn leaf(&self, device: &DeviceId) -> Option<DeviceLeaf> {
        self.leaves.lock().unwrap().get(device).cloned()
    }

    fn leaves_after(&self, after: Option<&DeviceId>, count: usize) -> Vec<DeviceLeaf> {
        let leaves = self.leaves.lock().unwrap();
        leaves
            .iter()
            .filter(|(device, _)| after.is_none_or(|after| *device > after))
            .take(count)
            .map(|(_, leaf)| leaf.clone())
            .collect()
    }

    fn key_holders(&self, key: &KeyId) -> Vec<(DeviceId, KeyPurpose)> {
        let keys = self.keys.lock().unwrap();
        keys.iter()
            .filter(|((held, _), _)| held == key)
            .map(|((_, device), purpose)| (*device, *purpose))
            .collect()
    }

    fn derived_holders(&self, tag: &[u8; 32], value: [u8; 4]) -> Option<Vec<DeviceId>> {
        let derived = self.derived.lock().unwrap();
        derived.get(tag).map(|rows| {
            rows.iter().filter(|(held, _)| *held == value).map(|(_, device)| *device).collect()
        })
    }

    fn put_derived(&self, tag: &[u8; 32], rows: &[([u8; 4], DeviceId)]) {
        self.derived.lock().unwrap().entry(*tag).or_default().extend_from_slice(rows);
    }

    fn address_holders(&self, address: [u8; 4]) -> Vec<DeviceId> {
        let addresses = self.addresses.lock().unwrap();
        addresses.keys().filter(|(held, _)| *held == address).map(|(_, device)| *device).collect()
    }

    fn address_claims_from(
        &self,
        from: ([u8; 4], DeviceId),
        count: usize,
    ) -> Vec<([u8; 4], DeviceId)> {
        let addresses = self.addresses.lock().unwrap();
        addresses.range(from..).take(count).map(|(claim, ())| *claim).collect()
    }

    fn name_holders(&self, name: &str) -> Vec<DeviceId> {
        let leaves = self.leaves.lock().unwrap();
        leaves
            .values()
            .filter(|leaf| leaf.record.name.to_ascii_lowercase() == name)
            .map(|leaf| leaf.record.id)
            .collect()
    }

    fn count(&self) -> usize {
        self.leaves.lock().unwrap().len()
    }
}

impl Kept {
    /// A store holding these leaves, and the root of their tree.
    fn of(leaves: &[DeviceLeaf]) -> (Arc<Self>, Hash) {
        let kept = Arc::new(Self::default());
        let mut positions: Vec<(Hash, Hash)> = Vec::new();
        for leaf in leaves {
            let device = leaf.record.id;
            for entry in &leaf.record.keys {
                kept.keys.lock().unwrap().insert((entry.key_id(), device), entry.purpose);
            }
            if let Some(address) = leaf.settings.ipv4 {
                kept.addresses.lock().unwrap().insert((address, device), ());
            }
            kept.leaves.lock().unwrap().insert(device, leaf.clone());
            positions.push((DeviceLeaf::position(&device), leaf.value_hash()));
        }
        positions.sort_unstable();
        let mut builder = merkle::Builder::new(|hash, node| {
            kept.nodes.lock().unwrap().insert(hash, node);
        });
        for (position, value) in positions {
            assert!(builder.push(position, value));
        }
        let root = builder.finish();
        (kept, root)
    }

    fn tampered(&self) -> usize {
        self.tampered.load(Ordering::SeqCst)
    }
}

/// The leaf of fixture device `seed`, with an address when `address` is set.
fn leaf(seed: u8, address: Option<u8>) -> DeviceLeaf {
    leaf_as(seed, address, Role::Member)
}

/// The leaf of fixture device `seed` in `role`.
fn leaf_as(seed: u8, address: Option<u8>, role: Role) -> DeviceLeaf {
    let record = device(seed, &format!("d{seed}"), role, false)
        .into_record(OperationId::from_bytes([seed; 32]))
        .unwrap();
    let settings =
        DeviceSettings::new(Mode::Full, Vec::new(), address.map(|last| [0, 0, 0, last]), None)
            .unwrap();
    DeviceLeaf { record, settings }
}

/// Seeds under a hundred: the fixture's keys for 1 and 101 would collide.
fn fixture(seeds: &[u8]) -> Vec<DeviceLeaf> {
    let mut leaves: Vec<DeviceLeaf> = seeds
        .iter()
        .map(|seed| {
            let seed = (seed % 99).saturating_add(1);
            let role = if seed % 7 == 0 { Role::Admin } else { Role::Member };
            leaf_as(seed, (seed % 3 == 0).then_some(seed), role)
        })
        .collect();
    leaves.sort_by_key(|leaf| leaf.record.id);
    leaves.dedup_by_key(|leaf| leaf.record.id);
    leaves
}

fn transport_key(leaf: &DeviceLeaf) -> KeyId {
    leaf.record
        .keys
        .iter()
        .find(|entry| entry.purpose == KeyPurpose::Transport)
        .map(roster::types::KeyEntry::key_id)
        .unwrap()
}

/// The lowest `count` offsets from 1 to `last` no member holds, each asked of
/// the index on its own: what [`Members::lowest_unclaimed`] reads in one pass.
fn lowest_by_lookup(members: &Members, last: u32, count: u32) -> Option<u32> {
    let mut run = 0_u32;
    for offset in 1..=last {
        if members.holding_address(offset.to_be_bytes()).is_empty() {
            run = run.saturating_add(1);
            if run == count {
                return Some(offset.saturating_add(1).saturating_sub(count));
            }
        } else {
            run = 0;
        }
    }
    None
}

/// The same devices in memory and over a store answer the same.
fn assert_same(memory: &Members, stored: &Members) {
    for count in [1_u32, 2, 3, 7] {
        let expected = lowest_by_lookup(memory, 120, count);
        assert_eq!(memory.lowest_unclaimed(120, count), expected, "in memory, {count}");
        assert_eq!(stored.lowest_unclaimed(120, count), expected, "over a store, {count}");
    }
    assert_eq!(stored.len(), memory.len());
    assert_eq!(stored.root(), memory.root());
    let in_memory: Vec<DeviceLeaf> = memory.leaves();
    assert_eq!(stored.leaves(), in_memory);
    for leaf in &in_memory {
        let device = leaf.record.id;
        assert_eq!(stored.get(&device).as_deref(), Some(leaf));
        assert_eq!(
            stored.holding(&transport_key(leaf), Some(KeyPurpose::Transport)).map(|l| l.record.id),
            Some(device)
        );
        if let Some(address) = leaf.settings.ipv4 {
            assert_eq!(stored.holding_address(address), memory.holding_address(address));
        }
        let named = |members: &Members| -> Vec<DeviceId> {
            members.named(&leaf.record.name.to_uppercase()).iter().map(|l| l.record.id).collect()
        };
        assert_eq!(named(stored), vec![device], "found by name, case aside");
        assert_eq!(named(memory), vec![device]);
    }
    // A page begins after any member, or none, as the whole listing goes on.
    let ids: Vec<DeviceId> = in_memory.iter().map(|leaf| leaf.record.id).collect();
    for (at, from) in core::iter::once(None).chain(ids.iter().copied().map(Some)).enumerate() {
        let rest = ids.get(at..).unwrap_or_default();
        let after = |members: &Members| -> Vec<DeviceId> {
            members.iter_after(from).map(|(device, _)| device).collect()
        };
        assert_eq!(after(memory), rest, "in memory, after {at}");
        assert_eq!(after(stored), rest, "over a store, after {at}");
    }
    // The admins, from an index, are those a pass over every member finds.
    let admins: Vec<DeviceId> = in_memory
        .iter()
        .filter(|leaf| leaf.record.role == Role::Admin)
        .map(|leaf| leaf.record.id)
        .collect();
    assert_eq!(memory.admins(), admins, "in memory");
    assert_eq!(stored.admins(), admins, "over a store");
}

proptest! {
    #[test]
    fn devices_over_a_store_answer_and_change_as_in_memory(
        base in proptest::collection::vec(any::<u8>(), 0..60),
        changes in proptest::collection::vec((0u8..4, any::<u8>()), 0..30),
    ) {
        let leaves = fixture(&base);
        let (kept, root) = Kept::of(&leaves);
        let mut memory: Members = leaves.iter().cloned().collect();
        let mut stored = Members::stored(kept.clone(), root);
        assert_same(&memory, &stored);

        for (act, seed) in changes {
            let seed = (seed % 99).saturating_add(1);
            let role = if act == 3 { Role::Admin } else { Role::Member };
            let changed = leaf_as(seed, (act == 2).then_some(seed), role);
            let device = changed.record.id;
            match act {
                0 => {
                    memory.remove(&device);
                    stored.remove(&device);
                }
                1 => {
                    memory.insert(device, changed.record.clone());
                    stored.insert(device, changed.record.clone());
                }
                _ => {
                    memory.insert_leaf(changed.clone());
                    stored.insert_leaf(changed);
                }
            }
            prop_assert_eq!(stored.root(), memory.root());
        }
        assert_same(&memory, &stored);
        prop_assert_eq!(kept.tampered(), 0);
    }
}

#[test]
fn a_leaf_changed_in_the_store_is_not_believed() {
    let leaves = fixture(&[3, 4, 5, 6]);
    let (kept, root) = Kept::of(&leaves);
    let members = Members::stored(kept.clone(), root);
    let target = leaves.first().unwrap().record.id;

    let mut altered = leaves.first().unwrap().clone();
    altered.record.name = "intruder".to_owned();
    kept.leaves.lock().unwrap().insert(target, altered);

    assert_eq!(members.get(&target), None, "not answered");
    assert!(kept.tampered() > 0, "and the store is told");
    assert_eq!(members.leaves().len(), leaves.len() - 1, "nor walked over");
}

#[test]
fn a_leaf_removed_from_the_store_is_noticed() {
    let leaves = fixture(&[3, 4, 5]);
    let (kept, root) = Kept::of(&leaves);
    let members = Members::stored(kept.clone(), root);
    let target = leaves.first().unwrap().record.id;
    kept.leaves.lock().unwrap().remove(&target);

    assert_eq!(members.get(&target), None);
    assert!(kept.tampered() > 0, "the tree still holds it");
}

#[test]
fn a_leaf_added_to_the_store_is_not_a_member() {
    let leaves = fixture(&[3, 4, 5]);
    let (kept, root) = Kept::of(&leaves);
    let members = Members::stored(kept.clone(), root);
    let stranger = leaf(50, None);
    let device = stranger.record.id;
    kept.leaves.lock().unwrap().insert(device, stranger);

    assert_eq!(members.get(&device), None, "the tree does not hold it");
    assert!(kept.tampered() > 0);
}

#[test]
fn an_index_naming_the_wrong_device_is_not_believed() {
    let leaves = fixture(&[3, 4, 5]);
    let (kept, root) = Kept::of(&leaves);
    let members = Members::stored(kept.clone(), root);
    let (one, other) = (leaves.first().unwrap(), leaves.get(1).unwrap());

    // The other's transport key, said to be the first device's.
    let key = transport_key(other);
    kept.keys.lock().unwrap().remove(&(key, other.record.id));
    kept.keys.lock().unwrap().insert((key, one.record.id), KeyPurpose::Transport);
    assert_eq!(members.holding(&key, Some(KeyPurpose::Transport)), None);
    assert!(kept.tampered() > 0);

    // An address said to be held by a device that does not hold it.
    let before = kept.tampered();
    kept.addresses.lock().unwrap().insert(([100, 70, 0, 77], one.record.id), ());
    assert!(members.holding_address([100, 70, 0, 77]).is_empty());
    assert!(kept.tampered() > before);
}

#[test]
fn a_tree_node_changed_in_the_store_is_not_believed() {
    let leaves = fixture(&[3, 4, 5, 6, 7, 8]);
    let (kept, root) = Kept::of(&leaves);
    let members = Members::stored(kept.clone(), root);
    let target = leaves.first().unwrap();

    // The leaf and its node both rewritten to agree with each other: only the
    // root, which the store does not hold, says they are not the network's.
    let mut altered = target.clone();
    altered.record.name = "intruder".to_owned();
    let node = merkle::leaf_hash(&DeviceLeaf::position(&target.record.id), &target.value_hash());
    kept.nodes.lock().unwrap().insert(
        node,
        Stored::Leaf { key: DeviceLeaf::position(&target.record.id), value: altered.value_hash() },
    );
    kept.leaves.lock().unwrap().insert(target.record.id, altered);

    assert_eq!(members.get(&target.record.id), None);
    assert!(kept.tampered() > 0);
}

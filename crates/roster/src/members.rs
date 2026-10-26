//! The devices a state holds, kept so that copying a state costs little and its
//! root costs nothing to read.
//!
//! # Why not a map
//!
//! A state used to hold its devices in an ordered map and build its tree from
//! them whenever its root was asked for. At a million devices that is 450 MB a
//! copy, and fifteen seconds a root — and derivation copies a state for every
//! operation in its window. So the devices are kept as a **shared base plus the
//! changes made on top of it**, and the tree as a persistent tree whose copies
//! share everything they did not change: a copy costs the changes, a change
//! costs one path, and a root costs nothing.
//!
//! Which device holds a key is asked for every operation, for its author;
//! which holds an address for every address a window assigns; which answers to
//! a name for every name looked up. Each is answered from an index rather than
//! by walking every device.
//!
//! The answers are the ones the map gave, in the same order: every iteration is
//! by device id, and a key two devices hold is answered with the lower id.
//!
//! # A base kept elsewhere
//!
//! The base is in memory, or in a [`MemberStore`] — on a disk, for a member
//! too big to hold a million devices in memory. A store is believed only
//! through the tree, whose root the caller trusts: every leaf read from it is
//! checked against the leaf the tree holds at the device's position, and every
//! index hit is checked against the leaf it names. What fails a check is not
//! answered, and the store is told, so that whoever keeps it stops believing it.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::id::{DeviceId, KeyId};
use crate::leaf::{DeviceLeaf, DeviceSettings};
use crate::merkle;
use crate::types::{DeviceRecord, KeyPurpose};

/// Where a state's base devices are kept when they are not in memory.
///
/// Nothing a store answers is believed on its own: [`Members`] checks it
/// against the tree, and calls [`merkle::NodeSource::tampered`] when it does
/// not hold.
pub trait MemberStore: merkle::NodeSource {
    /// The leaf the store holds for `device`, if any.
    fn leaf(&self, device: &DeviceId) -> Option<DeviceLeaf>;

    /// Up to `count` leaves with ids after `after` (from the first, when
    /// `None`), in id order.
    fn leaves_after(&self, after: Option<&DeviceId>, count: usize) -> Vec<DeviceLeaf>;

    /// The devices the store's index says hold `key`, with what for.
    fn key_holders(&self, key: &KeyId) -> Vec<(DeviceId, KeyPurpose)>;

    /// The devices the store's index says are assigned `address`.
    fn address_holders(&self, address: [u8; 4]) -> Vec<DeviceId>;

    /// The devices the store's index says answer to `name`, given in ASCII
    /// lower case.
    fn name_holders(&self, name: &str) -> Vec<DeviceId>;

    /// How many devices the store holds.
    fn count(&self) -> usize;
}

/// How many leaves a walk over a store reads at once.
const PAGE: usize = 512;

/// The devices a state starts from.
#[derive(Clone)]
enum Base {
    /// In memory, shared by every copy.
    Memory(Arc<Shared>),
    /// In a store, believed through the tree.
    Kept(Arc<dyn MemberStore>),
}

impl Default for Base {
    fn default() -> Self {
        Self::Memory(Arc::default())
    }
}

/// A base in memory: the leaves, and the indexes over them.
#[derive(Default)]
struct Shared {
    leaves: BTreeMap<DeviceId, Arc<DeviceLeaf>>,
    keys: BTreeMap<(KeyId, DeviceId), KeyPurpose>,
    addresses: BTreeSet<([u8; 4], DeviceId)>,
    names: BTreeSet<(String, DeviceId)>,
}

/// The devices of a state: their leaves, which device holds which key and which
/// address, and the tree over them.
///
/// The base, and on top of it what changed: a leaf, or `None` where a device
/// was removed; and the same for the indexes.
#[derive(Clone, Default)]
pub struct Members {
    base: Base,
    leaves: BTreeMap<DeviceId, Option<Arc<DeviceLeaf>>>,
    keys: BTreeMap<(KeyId, DeviceId), Option<KeyPurpose>>,
    addresses: BTreeMap<([u8; 4], DeviceId), bool>,
    names: BTreeMap<(String, DeviceId), bool>,
    len: usize,
    tree: merkle::Tree,
}

impl core::fmt::Debug for Members {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.base {
            Base::Memory(_) => f.debug_list().entries(self.values()).finish(),
            // A million devices are not printed.
            Base::Kept(_) => f
                .debug_struct("Members")
                .field("len", &self.len)
                .field("root", &self.root())
                .finish_non_exhaustive(),
        }
    }
}

/// Two sets of members are equal when their trees are: the root commits to
/// every leaf, record and settings alike.
impl PartialEq for Members {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.tree.root() == other.tree.root()
    }
}

impl Eq for Members {}

impl Members {
    /// No devices.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The devices `store` holds, under the tree with this root.
    ///
    /// `root` is the one thing believed: it must come from somewhere the store
    /// does not, a signed root or the machine's own checkpoint.
    #[must_use]
    pub fn stored(store: Arc<dyn MemberStore>, root: merkle::Hash) -> Self {
        let source: Arc<dyn merkle::NodeSource> = store.clone();
        Self {
            len: store.count(),
            tree: merkle::Tree::stored(root, source),
            base: Base::Kept(store),
            leaves: BTreeMap::new(),
            keys: BTreeMap::new(),
            addresses: BTreeMap::new(),
            names: BTreeMap::new(),
        }
    }

    /// The store the base is kept in, if it is not in memory.
    #[must_use]
    pub fn store(&self) -> Option<&Arc<dyn MemberStore>> {
        match &self.base {
            Base::Kept(store) => Some(store),
            Base::Memory(_) => None,
        }
    }

    /// The device with this id, if it is a member.
    #[must_use]
    pub fn get(&self, device: &DeviceId) -> Option<Arc<DeviceLeaf>> {
        match self.leaves.get(device) {
            Some(changed) => changed.clone(),
            None => self.base_leaf(device),
        }
    }

    /// A device's leaf in the base, checked against the tree where the base is
    /// a store.
    fn base_leaf(&self, device: &DeviceId) -> Option<Arc<DeviceLeaf>> {
        match &self.base {
            Base::Memory(shared) => shared.leaves.get(device).cloned(),
            Base::Kept(store) => {
                // The device is not among the changes, so the tree holds at its
                // position what the base holds.
                let committed = self.tree.get(&DeviceLeaf::position(device));
                match (committed, store.leaf(device)) {
                    (None, None) => None,
                    (Some(value), Some(leaf))
                        if leaf.record.id == *device && leaf.value_hash() == value =>
                    {
                        Some(Arc::new(leaf))
                    }
                    _ => {
                        store.tampered();
                        None
                    }
                }
            }
        }
    }

    /// Whether this device is a member.
    #[must_use]
    pub fn contains_key(&self, device: &DeviceId) -> bool {
        self.get(device).is_some()
    }

    /// How many members there are.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether there are none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The members' ids, in order.
    pub fn keys(&self) -> impl Iterator<Item = DeviceId> + '_ {
        self.iter().map(|(device, _)| device)
    }

    /// The members, by id.
    pub fn values(&self) -> impl Iterator<Item = Arc<DeviceLeaf>> + '_ {
        self.iter().map(|(_, leaf)| leaf)
    }

    /// The members with their ids, by id: the base and the changes merged.
    pub fn iter(&self) -> impl Iterator<Item = (DeviceId, Arc<DeviceLeaf>)> + '_ {
        let mut base = self.base_iter().peekable();
        let mut over = self.leaves.iter().peekable();
        core::iter::from_fn(move || {
            loop {
                let take_over = match (base.peek(), over.peek()) {
                    (None, None) => return None,
                    (Some(_), None) => false,
                    (None, Some(_)) => true,
                    (Some((base_id, _)), Some((over_id, _))) => *over_id <= base_id,
                };
                if take_over {
                    let (device, changed) = over.next()?;
                    // A change replaces what the base holds under that id.
                    if base.peek().is_some_and(|(base_id, _)| base_id == device) {
                        base.next();
                    }
                    if let Some(leaf) = changed {
                        return Some((*device, Arc::clone(leaf)));
                    }
                } else {
                    return base.next();
                }
            }
        })
    }

    /// The base's leaves by id, checked where the base is a store. A device
    /// among the changes is passed over unchecked: the changes answer for it.
    fn base_iter(&self) -> impl Iterator<Item = (DeviceId, Arc<DeviceLeaf>)> + '_ {
        let mut memory = match &self.base {
            Base::Memory(shared) => Some(shared.leaves.iter()),
            Base::Kept(_) => None,
        };
        let mut page: alloc::vec::IntoIter<DeviceLeaf> = Vec::new().into_iter();
        let mut after: Option<DeviceId> = None;
        let mut finished = false;
        core::iter::from_fn(move || {
            if let Some(memory) = memory.as_mut() {
                return memory.next().map(|(device, leaf)| (*device, Arc::clone(leaf)));
            }
            let Base::Kept(store) = &self.base else { return None };
            loop {
                if let Some(leaf) = page.next() {
                    let device = leaf.record.id;
                    after = Some(device);
                    if self.leaves.contains_key(&device)
                        || self.tree.get(&DeviceLeaf::position(&device)) == Some(leaf.value_hash())
                    {
                        return Some((device, Arc::new(leaf)));
                    }
                    store.tampered();
                    continue;
                }
                if finished {
                    return None;
                }
                let next = store.leaves_after(after.as_ref(), PAGE);
                finished = next.len() < PAGE;
                // A store answering out of order, or with what it was not
                // asked for, would loop or skip: stop believing it.
                let first_too_low = next
                    .first()
                    .is_some_and(|first| after.is_some_and(|last| first.record.id <= last));
                let unordered = next
                    .windows(2)
                    .any(|pair| matches!(pair, [one, two] if one.record.id >= two.record.id));
                if first_too_low || unordered {
                    store.tampered();
                    return None;
                }
                if next.is_empty() {
                    return None;
                }
                page = next.into_iter();
            }
        })
    }

    /// Admits `record`, or replaces the record of the device it names, keeping
    /// the settings it had. The record it replaced, if any.
    pub fn insert(&mut self, device: DeviceId, record: DeviceRecord) -> Option<Arc<DeviceLeaf>> {
        let settings = self.get(&device).map(|held| held.settings.clone()).unwrap_or_default();
        self.put(device, DeviceLeaf { record, settings })
    }

    /// Removes a member. Its leaf, if it was one.
    pub fn remove(&mut self, device: &DeviceId) -> Option<Arc<DeviceLeaf>> {
        let gone = self.get(device)?;
        self.unindex(device, &gone);
        self.leaves.insert(*device, None);
        self.tree.remove(&DeviceLeaf::position(device));
        self.len = self.len.saturating_sub(1);
        Some(gone)
    }

    /// Puts a whole leaf, record and settings, in place of what its device had.
    /// A leaf equal to the one held changes nothing.
    pub fn insert_leaf(&mut self, leaf: DeviceLeaf) {
        let device = leaf.record.id;
        if self.get(&device).is_some_and(|held| *held == leaf) {
            return;
        }
        self.put(device, leaf);
    }

    /// Changes the record of a member in place, keeping its settings. A device
    /// that is not a member is left alone.
    pub fn modify(&mut self, device: &DeviceId, change: impl FnOnce(&mut DeviceRecord)) {
        let Some(held) = self.get(device) else { return };
        let mut leaf = (*held).clone();
        change(&mut leaf.record);
        if leaf != *held {
            self.put(*device, leaf);
        }
    }

    /// Removes every member.
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Sets a member's settings. A device that is not a member is left alone.
    pub fn set_settings(&mut self, device: DeviceId, settings: DeviceSettings) {
        let Some(held) = self.get(&device) else { return };
        if held.settings == settings {
            return;
        }
        let record = held.record.clone();
        self.put(device, DeviceLeaf { record, settings });
    }

    /// A member's settings, where they are not the default.
    #[must_use]
    pub fn settings(&self, device: &DeviceId) -> Option<DeviceSettings> {
        self.get(device)
            .map(|leaf| leaf.settings.clone())
            .filter(|settings| *settings != DeviceSettings::default())
    }

    /// The members whose settings are not the default, with them, by id.
    pub fn changed_settings(&self) -> impl Iterator<Item = (DeviceId, DeviceSettings)> + '_ {
        self.iter()
            .filter(|(_, leaf)| leaf.settings != DeviceSettings::default())
            .map(|(device, leaf)| (device, leaf.settings.clone()))
    }

    /// The member holding `key` for `purpose`; of two, the one with the lower
    /// id.
    #[must_use]
    pub fn holding(&self, key: &KeyId, purpose: Option<KeyPurpose>) -> Option<Arc<DeviceLeaf>> {
        self.holding_for(key, |held_for| purpose.is_none_or(|purpose| held_for == purpose))
    }

    /// The member holding `key` for a purpose `accepts`; of two, the one with
    /// the lower id.
    #[must_use]
    pub fn holding_for(
        &self,
        key: &KeyId,
        accepts: impl Fn(KeyPurpose) -> bool,
    ) -> Option<Arc<DeviceLeaf>> {
        let from = (*key, DeviceId::from_bytes([0; 32]));
        // Every device said to hold the key, with what for and whether a
        // store said so.
        let mut holders: BTreeMap<DeviceId, (KeyPurpose, bool)> = BTreeMap::new();
        match &self.base {
            Base::Memory(shared) => {
                for ((_, device), purpose) in
                    shared.keys.range(from..).take_while(|((held, _), _)| held == key)
                {
                    holders.insert(*device, (*purpose, false));
                }
            }
            Base::Kept(store) => {
                for (device, purpose) in store.key_holders(key) {
                    holders.insert(device, (purpose, true));
                }
            }
        }
        for ((_, device), purpose) in
            self.keys.range(from..).take_while(|((held, _), _)| held == key)
        {
            match purpose {
                Some(purpose) => holders.insert(*device, (*purpose, false)),
                None => holders.remove(device),
            };
        }
        holders.into_iter().filter(|(_, (purpose, _))| accepts(*purpose)).find_map(
            |(device, (purpose, from_store))| {
                let leaf = self.get(&device)?;
                // A store's index is a hint: its hit stands only if the leaf
                // it names holds the key, for that.
                let holds = leaf
                    .record
                    .keys
                    .iter()
                    .any(|entry| entry.key_id() == *key && entry.purpose == purpose);
                if from_store && !holds {
                    self.told_tampered();
                    return None;
                }
                Some(leaf)
            },
        )
    }

    /// The members assigned `address`, by id. In a derived state there is at
    /// most one.
    #[must_use]
    pub fn holding_address(&self, address: [u8; 4]) -> Vec<DeviceId> {
        let from = (address, DeviceId::from_bytes([0; 32]));
        // Every device said to hold it, and whether a store said so.
        let mut holders: BTreeMap<DeviceId, bool> = BTreeMap::new();
        match &self.base {
            Base::Memory(shared) => {
                for (_, device) in
                    shared.addresses.range(from..).take_while(|(held, _)| *held == address)
                {
                    holders.insert(*device, false);
                }
            }
            Base::Kept(store) => {
                for device in store.address_holders(address) {
                    holders.insert(device, true);
                }
            }
        }
        for ((_, device), holds) in
            self.addresses.range(from..).take_while(|((held, _), _)| *held == address)
        {
            if *holds {
                holders.insert(*device, false);
            } else {
                holders.remove(device);
            }
        }
        holders
            .into_iter()
            .filter(|(device, from_store)| {
                if !from_store {
                    return true;
                }
                let holds =
                    self.get(device).is_some_and(|leaf| leaf.settings.ipv4 == Some(address));
                if !holds {
                    self.told_tampered();
                }
                holds
            })
            .map(|(device, _)| device)
            .collect()
    }

    /// The members answering to `name`, ASCII case aside, by id. Names are
    /// unique in a network a person keeps; two answering is a question the
    /// caller asks the person.
    #[must_use]
    pub fn named(&self, name: &str) -> Vec<Arc<DeviceLeaf>> {
        let lower = name.to_ascii_lowercase();
        let from = (lower.clone(), DeviceId::from_bytes([0; 32]));
        let mut holders: BTreeMap<DeviceId, bool> = BTreeMap::new();
        match &self.base {
            Base::Memory(shared) => {
                for (_, device) in
                    shared.names.range(from.clone()..).take_while(|(held, _)| *held == lower)
                {
                    holders.insert(*device, false);
                }
            }
            Base::Kept(store) => {
                for device in store.name_holders(&lower) {
                    holders.insert(device, true);
                }
            }
        }
        for ((_, device), holds) in self.names.range(from..).take_while(|((held, _), _)| *held == lower)
        {
            if *holds {
                holders.insert(*device, false);
            } else {
                holders.remove(device);
            }
        }
        holders
            .into_iter()
            .filter_map(|(device, from_store)| {
                let leaf = self.get(&device)?;
                let holds = leaf.record.name.eq_ignore_ascii_case(name);
                if from_store && !holds {
                    self.told_tampered();
                }
                holds.then_some(leaf)
            })
            .collect()
    }

    /// Tells the store, if there is one, that it answered what is not so.
    fn told_tampered(&self) {
        if let Base::Kept(store) = &self.base {
            store.tampered();
        }
    }

    /// The root of the tree over the members.
    #[must_use]
    pub fn root(&self) -> merkle::Hash {
        self.tree.root()
    }

    /// The tree over the members.
    #[must_use]
    pub const fn tree(&self) -> &merkle::Tree {
        &self.tree
    }

    /// The devices whose leaf differs between these members and `other`, or
    /// that only one of them holds, in order; `None` where the two do not rest
    /// on the same base, and only walking both can say.
    ///
    /// What follows a roster's changes without walking every device: two
    /// states derived over one base differ only where their changes do.
    #[must_use]
    pub fn differing(&self, other: &Self) -> Option<Vec<DeviceId>> {
        let same_base = match (&self.base, &other.base) {
            (Base::Memory(one), Base::Memory(two)) => Arc::ptr_eq(one, two),
            (Base::Kept(one), Base::Kept(two)) => {
                core::ptr::eq(Arc::as_ptr(one).cast::<()>(), Arc::as_ptr(two).cast::<()>())
                    && self.tree.stored_root() == other.tree.stored_root()
            }
            _ => false,
        };
        if !same_base {
            return None;
        }
        let touched: BTreeSet<DeviceId> =
            self.leaves.keys().chain(other.leaves.keys()).copied().collect();
        Some(
            touched
                .into_iter()
                .filter(|device| {
                    match (self.get(device), other.get(device)) {
                        (None, None) => false,
                        (Some(one), Some(two)) => !Arc::ptr_eq(&one, &two) && one != two,
                        _ => true,
                    }
                })
                .collect(),
        )
    }

    /// What changed on top of the base, by id: each device's new leaf, or
    /// `None` where it was removed. With [`merkle::Tree::dropped`] and
    /// [`merkle::Tree::fresh`], what a store writes to become these members.
    pub fn changes(&self) -> impl Iterator<Item = (DeviceId, Option<Arc<DeviceLeaf>>)> + '_ {
        self.leaves.iter().map(|(device, changed)| (*device, changed.clone()))
    }

    /// Folds the changes into a new shared base, so that copies made from here
    /// share all of it: what a state becomes when it is the base others are
    /// derived from. A base in a store is folded by writing the store.
    pub fn flatten(&mut self) {
        let Base::Memory(shared) = &self.base else { return };
        if self.leaves.is_empty() {
            return;
        }
        let mut merged = Shared {
            leaves: shared.leaves.clone(),
            keys: shared.keys.clone(),
            addresses: shared.addresses.clone(),
            names: shared.names.clone(),
        };
        for (device, changed) in &self.leaves {
            match changed {
                Some(leaf) => merged.leaves.insert(*device, Arc::clone(leaf)),
                None => merged.leaves.remove(device),
            };
        }
        for (entry, purpose) in &self.keys {
            match purpose {
                Some(purpose) => merged.keys.insert(*entry, *purpose),
                None => merged.keys.remove(entry),
            };
        }
        for (entry, holds) in &self.addresses {
            if *holds {
                merged.addresses.insert(*entry);
            } else {
                merged.addresses.remove(entry);
            }
        }
        for (entry, holds) in &self.names {
            if *holds {
                merged.names.insert(entry.clone());
            } else {
                merged.names.remove(entry);
            }
        }
        self.base = Base::Memory(Arc::new(merged));
        self.leaves.clear();
        self.keys.clear();
        self.addresses.clear();
        self.names.clear();
    }

    fn put(&mut self, device: DeviceId, leaf: DeviceLeaf) -> Option<Arc<DeviceLeaf>> {
        let hash = leaf.value_hash();
        let previous = self.get(&device);
        if let Some(previous) = &previous {
            self.unindex(&device, previous);
        } else {
            self.len = self.len.saturating_add(1);
        }
        for entry in &leaf.record.keys {
            self.keys.insert((entry.key_id(), device), Some(entry.purpose));
        }
        if let Some(address) = leaf.settings.ipv4 {
            self.addresses.insert((address, device), true);
        }
        self.names.insert((leaf.record.name.to_ascii_lowercase(), device), true);
        self.leaves.insert(device, Some(Arc::new(leaf)));
        self.tree.insert(DeviceLeaf::position(&device), hash);
        previous
    }

    /// Takes what `leaf` put in the indexes out of them.
    fn unindex(&mut self, device: &DeviceId, leaf: &DeviceLeaf) {
        for entry in &leaf.record.keys {
            self.keys.insert((entry.key_id(), *device), None);
        }
        if let Some(address) = leaf.settings.ipv4 {
            self.addresses.insert((address, *device), false);
        }
        self.names.insert((leaf.record.name.to_ascii_lowercase(), *device), false);
    }
}

impl FromIterator<DeviceLeaf> for Members {
    fn from_iter<I: IntoIterator<Item = DeviceLeaf>>(leaves: I) -> Self {
        let mut members = Self::new();
        for leaf in leaves {
            members.put(leaf.record.id, leaf);
        }
        members.flatten();
        members
    }
}

/// What a set of members needs of a list of leaves for tests and fixtures.
impl Members {
    /// The members' leaves, by id, as plain values.
    #[must_use]
    pub fn leaves(&self) -> Vec<DeviceLeaf> {
        self.values().map(|leaf| (*leaf).clone()).collect()
    }
}

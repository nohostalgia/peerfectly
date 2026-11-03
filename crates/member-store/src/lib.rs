//! A full member's base state on disk.
//!
//! The devices a compacted roster rests on, their indexes and their tree, kept
//! in a [redb] database so that a member of a million devices need not hold a
//! million in memory: what it holds is the changes since its base, and the
//! paths those changes made in the tree.
//!
//! # Believed only through a root kept elsewhere
//!
//! Anyone able to write the file can change it. So nothing it holds is taken
//! on its word: [`Store::state`] gives a state whose tree is rooted where the
//! store says, and the caller compares that state's root with the signed root
//! the machine's checkpoint names before using it. From there every node of
//! the tree is checked against its parent as it is loaded, every leaf against
//! the tree, and every index hit against the leaf it names — by
//! [`roster::members::Members`], which tells the store when a check fails.
//! [`Store::tampered`] then says so, and the store is to be discarded and
//! fetched again from peers. [`Store::verify`] checks it whole.
//!
//! # Tables
//!
//! - `meta`: the state with no devices (network and parameters), the root of
//!   the devices' tree, and how many there are;
//! - `leaves`: device id to the leaf's canonical bytes;
//! - `positions`: tree position to device id, for walking the tree's order;
//! - `keys`: (key id, device id) to the key's purpose;
//! - `addresses`: (assigned IPv4 address, device id);
//! - `names`: (name in ASCII lower case, device id);
//! - `nodes`: a tree node's hash to the node.
//!
//! [redb]: https://www.redb.org

pub mod layers;

pub use layers::Layers;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};
use roster::id::{DeviceId, KeyId};
use roster::leaf::DeviceLeaf;
use roster::members::{MemberStore, Members};
use roster::merkle::{self, Hash, NodeSource, STORED_LEN, Stored};
use roster::state::RosterState;
use roster::types::KeyPurpose;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const LEAVES: TableDefinition<[u8; 32], &[u8]> = TableDefinition::new("leaves");
const POSITIONS: TableDefinition<[u8; 32], [u8; 32]> = TableDefinition::new("positions");
const KEYS: TableDefinition<([u8; 32], [u8; 32]), u8> = TableDefinition::new("keys");
const ADDRESSES: TableDefinition<([u8; 4], [u8; 32]), ()> = TableDefinition::new("addresses");
const NAMES: TableDefinition<(&str, [u8; 32]), ()> = TableDefinition::new("names");
const NODES: TableDefinition<[u8; 32], [u8; STORED_LEN]> = TableDefinition::new("nodes");
/// The devices by a value each derives from its id alone, by the derivation's
/// tag: an index this process builds as asked, not part of the state, emptied
/// when the store is opened or written.
const DERIVED: TableDefinition<DerivedRow, ()> = TableDefinition::new("derived");
/// The derivations [`DERIVED`] holds whole.
const BUILT: TableDefinition<[u8; 32], ()> = TableDefinition::new("built");

/// A row of the derived index: the derivation's tag, the value, the device.
type DerivedRow = ([u8; 32], [u8; 4], [u8; 32]);

/// The state with no devices: the network and its parameters.
const SKELETON: &str = "skeleton";
/// The root of the devices' tree.
const DEVICES_ROOT: &str = "devices_root";
/// How many devices there are, as eight little-endian bytes.
const COUNT: &str = "count";

/// How many leaves, or nodes, a full write puts in one transaction: enough
/// that the tables keyed by hash, written in no order, are copied few times;
/// few enough that a million are not held in redb's write buffer at once.
///
/// Every transaction is committed durably. redb reuses the pages a commit
/// frees only after a durable one, and writing a million leaves in commits
/// that were not left a store of 8.8 GB where 0.5 GB was the state.
const BATCH: usize = 100_000;

/// What went wrong with a store.
#[derive(Debug)]
pub enum Error {
    /// The database could not be opened, read or written.
    Database(String),
    /// The store holds what it should not: it was changed by someone other
    /// than this daemon, or never finished being written.
    Tampered(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Database(cause) => write!(f, "the base store: {cause}"),
            Self::Tampered(what) => write!(f, "the base store does not check out: {what}"),
        }
    }
}

impl std::error::Error for Error {}

/// A key's id and its device's id, with the key's purpose: one row of the
/// key index.
type KeyHeld = (([u8; 32], [u8; 32]), u8);

fn database(cause: impl core::fmt::Display) -> Error {
    Error::Database(cause.to_string())
}

/// A full member's base, in redb.
pub struct Store {
    db: Database,
    count: AtomicUsize,
    tampered: AtomicBool,
    /// The tables lookups read, kept open from one write to the next: opening
    /// a transaction for each node of a walk down the tree was most of what a
    /// lookup cost.
    reading: std::sync::Mutex<Option<Arc<Reading>>>,
}

/// The tables a lookup reads, in one read transaction.
struct Reading {
    leaves: redb::ReadOnlyTable<[u8; 32], &'static [u8]>,
    keys: redb::ReadOnlyTable<([u8; 32], [u8; 32]), u8>,
    addresses: redb::ReadOnlyTable<([u8; 4], [u8; 32]), ()>,
    names: redb::ReadOnlyTable<(&'static str, [u8; 32]), ()>,
    nodes: redb::ReadOnlyTable<[u8; 32], [u8; STORED_LEN]>,
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Store")
            .field("count", &self.count.load(Ordering::SeqCst))
            .field("tampered", &self.tampered())
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Opens the store at `path`, creating an empty one where there is none,
    /// with redb's cache bounded to `cache` bytes.
    ///
    /// # Errors
    ///
    /// When the file cannot be opened as a database.
    pub fn open(path: &Path, cache: usize) -> Result<Arc<Self>, Error> {
        let db = Database::builder().set_cache_size(cache).create(path).map_err(database)?;
        let store = Self {
            db,
            count: AtomicUsize::new(0),
            tampered: AtomicBool::new(false),
            reading: std::sync::Mutex::new(None),
        };
        {
            let write = store.db.begin_write().map_err(database)?;
            write.open_table(LEAVES).map_err(database)?;
            write.open_table(META).map_err(database)?;
            write.open_table(POSITIONS).map_err(database)?;
            write.open_table(KEYS).map_err(database)?;
            write.open_table(ADDRESSES).map_err(database)?;
            write.open_table(NAMES).map_err(database)?;
            write.open_table(NODES).map_err(database)?;
            write.commit().map_err(database)?;
        }
        store.forget_derived()?;
        let count = store.read_meta(COUNT)?.map_or(Ok(0), |bytes| {
            <[u8; 8]>::try_from(bytes.as_slice())
                .map(u64::from_le_bytes)
                .map_err(|_| Error::Tampered("the count is not a number"))
                .and_then(|count| {
                    usize::try_from(count).map_err(|_| Error::Tampered("the count is too large"))
                })
        })?;
        store.count.store(count, Ordering::SeqCst);
        Ok(Arc::new(store))
    }

    /// Whether a check of something this store answered has failed: it was
    /// changed behind the daemon's back, or the disk lost it.
    #[must_use]
    pub fn tampered(&self) -> bool {
        self.tampered.load(Ordering::SeqCst)
    }

    /// The state the store holds, its devices read from the store as they are
    /// needed. `None` for a store never written.
    ///
    /// Believed only once its root is compared with one kept elsewhere: the
    /// root a signed snapshot names, which the machine's checkpoint allows.
    ///
    /// # Errors
    ///
    /// When the store cannot be read, or what it holds cannot be a state.
    pub fn state(self: &Arc<Self>) -> Result<Option<RosterState>, Error> {
        let (Some(skeleton), Some(root)) =
            (self.read_meta(SKELETON)?, self.read_meta(DEVICES_ROOT)?)
        else {
            return Ok(None);
        };
        let mut state = RosterState::from_bytes(&skeleton)
            .map_err(|_| Error::Tampered("the network and parameters do not read"))?;
        let root = Hash::try_from(root.as_slice())
            .map_err(|_| Error::Tampered("the root is not a hash"))?;
        let store: Arc<dyn MemberStore> = Arc::<Self>::clone(self);
        state.devices = Members::stored(store, root);
        Ok(Some(state))
    }

    /// Makes the store hold `state`.
    ///
    /// Where `state`'s devices rest on this store, only what changed since is
    /// written: the leaves, their indexes, the tree's new paths, and the nodes
    /// those paths replaced removed. Otherwise the store is written whole.
    /// Either is one transaction for what is believed: a write cut short
    /// leaves the store as it was, or, written whole, holding no state.
    ///
    /// # Errors
    ///
    /// When the database cannot be written.
    pub fn write(&self, state: &RosterState) -> Result<(), Error> {
        self.forget_derived()?;
        let rests_here = state.devices.store().is_some_and(|store| {
            core::ptr::eq(Arc::as_ptr(store).cast::<()>(), core::ptr::from_ref(self).cast::<()>())
        });
        self.stop_reading();
        let written = if rests_here { self.write_changes(state) } else { self.write_whole(state) };
        // What is read from here on is what was written.
        self.stop_reading();
        written
    }

    fn write_changes(&self, state: &RosterState) -> Result<(), Error> {
        let write = self.db.begin_write().map_err(database)?;
        {
            let mut leaves = write.open_table(LEAVES).map_err(database)?;
            let mut positions = write.open_table(POSITIONS).map_err(database)?;
            let mut keys = write.open_table(KEYS).map_err(database)?;
            let mut addresses = write.open_table(ADDRESSES).map_err(database)?;
            let mut names = write.open_table(NAMES).map_err(database)?;
            for (device, changed) in state.devices.changes() {
                let id = *device.as_bytes();
                let held = leaves
                    .remove(id)
                    .map_err(database)?
                    .and_then(|bytes| DeviceLeaf::from_bytes(bytes.value()).ok());
                if let Some(held) = held {
                    unindex(&mut keys, &mut addresses, &mut names, &held)?;
                }
                let position = DeviceLeaf::position(&device);
                match changed {
                    Some(leaf) => {
                        leaves.insert(id, leaf.to_bytes().as_slice()).map_err(database)?;
                        positions.insert(position, id).map_err(database)?;
                        index(&mut keys, &mut addresses, &mut names, &leaf)?;
                    }
                    None => {
                        positions.remove(position).map_err(database)?;
                    }
                }
            }
            let mut nodes = write.open_table(NODES).map_err(database)?;
            let tree = state.devices.tree();
            // The nodes the change replaced: noted as it was made, or, for a
            // tree that spilled and stopped noting them, found by walking the
            // root this store holds against the new one.
            let mut dropped: std::collections::HashSet<Hash> =
                tree.dropped().iter().copied().collect();
            if !tree.tracks_dropped()
                && let Some(old) = tree.stored_root()
            {
                tree.replaced(old, self, &mut |hash| {
                    dropped.insert(hash);
                });
            }
            for hash in &dropped {
                nodes.remove(*hash).map_err(database)?;
            }
            // What the tree made, in memory or spilled to the layers: every
            // node beneath one this store does not hold. Held is read as it
            // was before this write, less what it just removed.
            let before = self.db.begin_read().map_err(database)?;
            let held = before.open_table(NODES).map_err(database)?;
            let mut failed = None;
            tree.missing(
                &mut |hash| !dropped.contains(hash) && held.get(*hash).ok().flatten().is_some(),
                &mut |hash, node| {
                    if failed.is_none()
                        && let Err(cause) = nodes.insert(hash, node.to_bytes())
                    {
                        failed = Some(database(cause));
                    }
                },
            );
            if let Some(cause) = failed {
                return Err(cause);
            }
            let mut meta = write.open_table(META).map_err(database)?;
            put_meta(&mut meta, state, &tree.root(), state.devices.len())?;
        }
        write.commit().map_err(database)?;
        self.count.store(state.devices.len(), Ordering::SeqCst);
        Ok(())
    }

    fn write_whole(&self, state: &RosterState) -> Result<(), Error> {
        let leaves = state.devices.values().map(|leaf| (*leaf).clone());
        self.write_leaves(state, leaves, Some(state.devices.root())).map(|_| ())
    }

    /// Makes the store hold the network and parameters of `skeleton` and the
    /// leaves `leaves` gives, written as they come with no more than a batch
    /// in memory: how a base too big to hold is put on disk. Returns the root
    /// of the devices' tree.
    ///
    /// Where `expected` is given and the tree written is not that root, the
    /// store is left holding no state.
    ///
    /// # Errors
    ///
    /// When the database cannot be written, or the tree is not `expected`.
    pub fn write_leaves(
        &self,
        skeleton: &RosterState,
        leaves: impl IntoIterator<Item = DeviceLeaf>,
        expected: Option<Hash>,
    ) -> Result<Hash, Error> {
        self.forget_derived()?;
        self.stop_reading();
        let written = self.write_all(skeleton, leaves, expected);
        self.stop_reading();
        written
    }

    fn write_all(
        &self,
        skeleton: &RosterState,
        leaves: impl IntoIterator<Item = DeviceLeaf>,
        expected: Option<Hash>,
    ) -> Result<Hash, Error> {
        // First nothing: a store half written holds no state, and is written
        // again rather than believed.
        {
            let mut write = self.db.begin_write().map_err(database)?;
            write.set_durability(Durability::Immediate).map_err(database)?;
            write.delete_table(META).map_err(database)?;
            write.delete_table(LEAVES).map_err(database)?;
            write.delete_table(POSITIONS).map_err(database)?;
            write.delete_table(KEYS).map_err(database)?;
            write.delete_table(ADDRESSES).map_err(database)?;
            write.delete_table(NAMES).map_err(database)?;
            write.delete_table(NODES).map_err(database)?;
            // Made again empty, so that a state of no devices reads as one.
            write.open_table(META).map_err(database)?;
            write.open_table(LEAVES).map_err(database)?;
            write.open_table(POSITIONS).map_err(database)?;
            write.open_table(KEYS).map_err(database)?;
            write.open_table(ADDRESSES).map_err(database)?;
            write.open_table(NAMES).map_err(database)?;
            write.open_table(NODES).map_err(database)?;
            write.commit().map_err(database)?;
        }
        self.count.store(0, Ordering::SeqCst);

        // The leaves and their indexes, a batch at a time.
        let mut leaves = leaves.into_iter().peekable();
        while leaves.peek().is_some() {
            let mut write = self.db.begin_write().map_err(database)?;
            write.set_durability(Durability::Immediate).map_err(database)?;
            {
                let mut stored = write.open_table(LEAVES).map_err(database)?;
                let mut positions = write.open_table(POSITIONS).map_err(database)?;
                let mut keys = write.open_table(KEYS).map_err(database)?;
                let mut addresses = write.open_table(ADDRESSES).map_err(database)?;
                let mut names = write.open_table(NAMES).map_err(database)?;
                // Each table in its own key's order: the positions and keys are
                // hashes, and inserted as they come would touch a page each.
                let mut batch: Vec<DeviceLeaf> = leaves.by_ref().take(BATCH).collect();
                batch.sort_by_key(|leaf| leaf.record.id);
                for leaf in &batch {
                    stored
                        .insert(*leaf.record.id.as_bytes(), leaf.to_bytes().as_slice())
                        .map_err(database)?;
                }
                let mut placed: Vec<([u8; 32], [u8; 32])> = batch
                    .iter()
                    .map(|leaf| (DeviceLeaf::position(&leaf.record.id), *leaf.record.id.as_bytes()))
                    .collect();
                placed.sort_unstable();
                for (position, id) in placed {
                    positions.insert(position, id).map_err(database)?;
                }
                let mut held: Vec<KeyHeld> = batch
                    .iter()
                    .flat_map(|leaf| {
                        leaf.record.keys.iter().map(|entry| {
                            (
                                (*entry.key_id().as_bytes(), *leaf.record.id.as_bytes()),
                                purpose_byte(entry.purpose),
                            )
                        })
                    })
                    .collect();
                held.sort_unstable();
                for (key, purpose) in held {
                    keys.insert(key, purpose).map_err(database)?;
                }
                let mut assigned: Vec<([u8; 4], [u8; 32])> = batch
                    .iter()
                    .filter_map(|leaf| {
                        leaf.settings.ipv4.map(|address| (address, *leaf.record.id.as_bytes()))
                    })
                    .collect();
                assigned.sort_unstable();
                for entry in assigned {
                    addresses.insert(entry, ()).map_err(database)?;
                }
                let mut named: Vec<(String, [u8; 32])> = batch
                    .iter()
                    .map(|leaf| (leaf.record.name.to_ascii_lowercase(), *leaf.record.id.as_bytes()))
                    .collect();
                named.sort_unstable();
                for (name, id) in &named {
                    names.insert((name.as_str(), *id), ()).map_err(database)?;
                }
            }
            write.commit().map_err(database)?;
        }

        // The tree, built in the positions' order with a path of it in memory.
        let root = self.build_tree()?;
        if expected.is_some_and(|expected| expected != root) {
            return Err(Error::Tampered("the tree written is not the state's"));
        }

        // And last what makes it a state.
        let mut write = self.db.begin_write().map_err(database)?;
        write.set_durability(Durability::Immediate).map_err(database)?;
        let count;
        {
            let held = write.open_table(LEAVES).map_err(database)?;
            count = usize::try_from(held.len().map_err(database)?).unwrap_or(usize::MAX);
            let mut meta = write.open_table(META).map_err(database)?;
            put_meta(&mut meta, skeleton, &root, count)?;
        }
        write.commit().map_err(database)?;
        self.count.store(count, Ordering::SeqCst);
        Ok(root)
    }

    /// Builds the tree over every leaf the store holds, writing its nodes a
    /// batch at a time, and returns its root.
    fn build_tree(&self) -> Result<Hash, Error> {
        let mut pending: Vec<(Hash, Stored)> = Vec::with_capacity(BATCH);
        let mut failed: Option<Error> = None;
        let mut builder = merkle::Builder::new(|hash, node| {
            pending.push((hash, node));
            if pending.len() >= BATCH
                && failed.is_none()
                && let Err(cause) = self.put_nodes(&mut pending)
            {
                failed = Some(cause);
            }
        });
        // A batch of positions at a time, each read in a transaction of its
        // own and let go before any node is written: a reader held across the
        // writes would keep every page they free, and the file would grow by a
        // copy of the nodes per batch.
        let mut after: Option<[u8; 32]> = None;
        loop {
            let page = self.positions_after(after, BATCH)?;
            let Some(last) = page.last().map(|(position, _)| *position) else { break };
            for (position, value) in page {
                if !builder.push(position, value) {
                    return Err(Error::Tampered("positions out of order"));
                }
            }
            after = Some(last);
        }
        let root = builder.finish();
        if let Some(cause) = failed {
            return Err(cause);
        }
        self.put_nodes(&mut pending)?;
        Ok(root)
    }

    /// Up to `count` positions after `after`, each with the hash of the leaf
    /// it names.
    fn positions_after(
        &self,
        after: Option<[u8; 32]>,
        count: usize,
    ) -> Result<Vec<(Hash, Hash)>, Error> {
        let read = self.db.begin_read().map_err(database)?;
        let positions = read.open_table(POSITIONS).map_err(database)?;
        let leaves = read.open_table(LEAVES).map_err(database)?;
        let range = match after {
            Some(after) => positions
                .range((core::ops::Bound::Excluded(after), core::ops::Bound::Unbounded))
                .map_err(database)?,
            None => positions.range::<[u8; 32]>(..).map_err(database)?,
        };
        let mut page = Vec::with_capacity(count);
        for entry in range.take(count) {
            let (position, device) = entry.map_err(database)?;
            let bytes = leaves
                .get(device.value())
                .map_err(database)?
                .ok_or(Error::Tampered("a position names no leaf"))?;
            let leaf = DeviceLeaf::from_bytes(bytes.value())
                .map_err(|_| Error::Tampered("a leaf does not read"))?;
            page.push((position.value(), leaf.value_hash()));
        }
        Ok(page)
    }

    /// Writes `pending` nodes, emptying it.
    fn put_nodes(&self, pending: &mut Vec<(Hash, Stored)>) -> Result<(), Error> {
        let mut write = self.db.begin_write().map_err(database)?;
        write.set_durability(Durability::Immediate).map_err(database)?;
        {
            let mut nodes = write.open_table(NODES).map_err(database)?;
            pending.sort_unstable_by_key(|(hash, _)| *hash);
            for (hash, node) in pending.drain(..) {
                nodes.insert(hash, node.to_bytes()).map_err(database)?;
            }
        }
        write.commit().map_err(database)
    }

    /// Checks the whole store against `devices_root`: every node of the tree
    /// against its parent, every leaf against the tree, every leaf's position
    /// and indexes present, and nothing more than the tree holds.
    ///
    /// # Errors
    ///
    /// [`Error::Tampered`] naming the first thing that does not check out,
    /// after which [`Store::tampered`] says so too.
    pub fn verify(&self, devices_root: &Hash) -> Result<(), Error> {
        let checked = self.check(Some(devices_root));
        if matches!(checked, Err(Error::Tampered(_))) {
            self.told();
        }
        checked
    }

    /// Checks the whole store against the root it holds, as one transaction
    /// sees it: what a check in the background does once the root was held to
    /// a signed one, since the daemon may write a newer base meanwhile.
    ///
    /// # Errors
    ///
    /// As [`Store::verify`].
    pub fn verify_held(&self) -> Result<(), Error> {
        let checked = self.check(None);
        if matches!(checked, Err(Error::Tampered(_))) {
            self.told();
        }
        checked
    }

    fn check(&self, expected: Option<&Hash>) -> Result<(), Error> {
        let read = self.db.begin_read().map_err(database)?;
        let meta = read.open_table(META).map_err(database)?;
        let held_root = meta
            .get(DEVICES_ROOT)
            .map_err(database)?
            .and_then(|root| Hash::try_from(root.value()).ok())
            .ok_or(Error::Tampered("the store names no root"))?;
        let held_count = meta
            .get(COUNT)
            .map_err(database)?
            .and_then(|count| <[u8; 8]>::try_from(count.value()).ok())
            .map(u64::from_le_bytes)
            .and_then(|count| usize::try_from(count).ok())
            .ok_or(Error::Tampered("the store holds no count"))?;
        if expected.is_some_and(|expected| *expected != held_root) {
            return Err(Error::Tampered("the root it holds is not the one expected"));
        }
        let devices_root = &held_root;
        let nodes = read.open_table(NODES).map_err(database)?;
        let positions = read.open_table(POSITIONS).map_err(database)?;
        let leaves = read.open_table(LEAVES).map_err(database)?;
        let keys = read.open_table(KEYS).map_err(database)?;
        let addresses = read.open_table(ADDRESSES).map_err(database)?;
        let names = read.open_table(NAMES).map_err(database)?;

        // The tree in key order, from the root down, each node checked against
        // the hash its parent names; its leaves met against the positions.
        let mut positions_in_order = positions.iter().map_err(database)?;
        let mut walk: Vec<Hash> = vec![*devices_root];
        let mut met = 0_usize;
        let mut walked = 0_usize;
        while let Some(hash) = walk.pop() {
            if hash == merkle::EMPTY {
                continue;
            }
            let node = nodes
                .get(hash)
                .map_err(database)?
                .and_then(|node| Stored::from_bytes(&node.value()))
                .filter(|node| node.hash() == hash)
                .ok_or(Error::Tampered("a node of the tree"))?;
            walked = walked.saturating_add(1);
            match node {
                Stored::Branch { left, right } => {
                    // Right pushed first, so the left is walked first.
                    walk.push(right);
                    walk.push(left);
                }
                Stored::Leaf { key, value } => {
                    let (position, device) = positions_in_order
                        .next()
                        .ok_or(Error::Tampered("a leaf of the tree has no position"))?
                        .map_err(database)?;
                    if position.value() != key {
                        return Err(Error::Tampered("a position the tree does not hold"));
                    }
                    let device = DeviceId::from_bytes(device.value());
                    if DeviceLeaf::position(&device) != key {
                        return Err(Error::Tampered("a position naming another device"));
                    }
                    let leaf = leaves
                        .get(*device.as_bytes())
                        .map_err(database)?
                        .and_then(|bytes| DeviceLeaf::from_bytes(bytes.value()).ok())
                        .filter(|leaf| leaf.record.id == device && leaf.value_hash() == value)
                        .ok_or(Error::Tampered("a leaf"))?;
                    for entry in &leaf.record.keys {
                        let purpose = keys
                            .get((*entry.key_id().as_bytes(), *device.as_bytes()))
                            .map_err(database)?
                            .map(|purpose| purpose.value());
                        if purpose != Some(purpose_byte(entry.purpose)) {
                            return Err(Error::Tampered("the key index"));
                        }
                    }
                    if let Some(address) = leaf.settings.ipv4
                        && addresses.get((address, *device.as_bytes())).map_err(database)?.is_none()
                    {
                        return Err(Error::Tampered("the address index"));
                    }
                    let name = leaf.record.name.to_ascii_lowercase();
                    if names.get((name.as_str(), *device.as_bytes())).map_err(database)?.is_none() {
                        return Err(Error::Tampered("the name index"));
                    }
                    met = met.saturating_add(1);
                }
            }
        }
        if positions_in_order.next().is_some() {
            return Err(Error::Tampered("a position the tree does not hold"));
        }
        let indexed: usize = leaf_keys(&leaves)?;
        let held_keys = usize::try_from(keys.len().map_err(database)?).unwrap_or(usize::MAX);
        let held_leaves = usize::try_from(leaves.len().map_err(database)?).unwrap_or(usize::MAX);
        let held_addresses =
            usize::try_from(addresses.len().map_err(database)?).unwrap_or(usize::MAX);
        let held_nodes = usize::try_from(nodes.len().map_err(database)?).unwrap_or(usize::MAX);
        let held_names = usize::try_from(names.len().map_err(database)?).unwrap_or(usize::MAX);
        let assigned = assigned_addresses(&leaves)?;
        if held_leaves != met
            || held_count != met
            || held_keys != indexed
            || held_addresses != assigned
            || held_nodes != walked
            || held_names != met
        {
            return Err(Error::Tampered("more is held than the tree commits to"));
        }
        Ok(())
    }

    /// Empties the derived index: what the store held is about to change, or
    /// this process has not built it.
    fn forget_derived(&self) -> Result<(), Error> {
        self.stop_reading();
        let mut write = self.db.begin_write().map_err(database)?;
        write.set_durability(Durability::Immediate).map_err(database)?;
        write.delete_table(DERIVED).map_err(database)?;
        write.delete_table(BUILT).map_err(database)?;
        write.open_table(DERIVED).map_err(database)?;
        write.open_table(BUILT).map_err(database)?;
        write.commit().map_err(database)?;
        self.stop_reading();
        Ok(())
    }

    fn read_meta(&self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        let read = self.db.begin_read().map_err(database)?;
        let meta = read.open_table(META).map_err(database)?;
        Ok(meta.get(key).map_err(database)?.map(|value| value.value().to_vec()))
    }

    fn told(&self) {
        self.tampered.store(true, Ordering::SeqCst);
    }

    /// The tables lookups read, opened where they are not.
    fn reading(&self) -> Option<Arc<Reading>> {
        let mut held = self.reading.lock().ok()?;
        if let Some(reading) = held.as_ref() {
            return Some(Arc::clone(reading));
        }
        let read = self.db.begin_read().ok()?;
        let reading = Arc::new(Reading {
            leaves: read.open_table(LEAVES).ok()?,
            keys: read.open_table(KEYS).ok()?,
            addresses: read.open_table(ADDRESSES).ok()?,
            names: read.open_table(NAMES).ok()?,
            nodes: read.open_table(NODES).ok()?,
        });
        *held = Some(Arc::clone(&reading));
        Some(reading)
    }

    /// Lets go of the tables lookups read: before a write, so that they do not
    /// keep the pages it frees, and after, so that lookups read what it wrote.
    fn stop_reading(&self) {
        if let Ok(mut held) = self.reading.lock() {
            *held = None;
        }
    }
}

/// How many keys the leaves name in all.
fn leaf_keys(leaves: &impl ReadableTable<[u8; 32], &'static [u8]>) -> Result<usize, Error> {
    let mut count = 0_usize;
    for entry in leaves.iter().map_err(database)? {
        let (_, bytes) = entry.map_err(database)?;
        let leaf = DeviceLeaf::from_bytes(bytes.value()).map_err(|_| Error::Tampered("a leaf"))?;
        count = count.saturating_add(leaf.record.keys.len());
    }
    Ok(count)
}

/// How many leaves are assigned an address.
fn assigned_addresses(
    leaves: &impl ReadableTable<[u8; 32], &'static [u8]>,
) -> Result<usize, Error> {
    let mut count = 0_usize;
    for entry in leaves.iter().map_err(database)? {
        let (_, bytes) = entry.map_err(database)?;
        let leaf = DeviceLeaf::from_bytes(bytes.value()).map_err(|_| Error::Tampered("a leaf"))?;
        if leaf.settings.ipv4.is_some() {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

fn put_meta(
    meta: &mut redb::Table<'_, &str, &[u8]>,
    state: &RosterState,
    root: &Hash,
    count: usize,
) -> Result<(), Error> {
    let skeleton = RosterState::empty(state.network, state.params.clone()).to_bytes();
    meta.insert(SKELETON, skeleton.as_slice()).map_err(database)?;
    meta.insert(DEVICES_ROOT, root.as_slice()).map_err(database)?;
    let count = u64::try_from(count).unwrap_or(u64::MAX).to_le_bytes();
    meta.insert(COUNT, count.as_slice()).map_err(database)?;
    Ok(())
}

fn index(
    keys: &mut redb::Table<'_, ([u8; 32], [u8; 32]), u8>,
    addresses: &mut redb::Table<'_, ([u8; 4], [u8; 32]), ()>,
    names: &mut redb::Table<'_, (&str, [u8; 32]), ()>,
    leaf: &DeviceLeaf,
) -> Result<(), Error> {
    let name = leaf.record.name.to_ascii_lowercase();
    names.insert((name.as_str(), *leaf.record.id.as_bytes()), ()).map_err(database)?;
    let device = *leaf.record.id.as_bytes();
    for entry in &leaf.record.keys {
        keys.insert((*entry.key_id().as_bytes(), device), purpose_byte(entry.purpose))
            .map_err(database)?;
    }
    if let Some(address) = leaf.settings.ipv4 {
        addresses.insert((address, device), ()).map_err(database)?;
    }
    Ok(())
}

fn unindex(
    keys: &mut redb::Table<'_, ([u8; 32], [u8; 32]), u8>,
    addresses: &mut redb::Table<'_, ([u8; 4], [u8; 32]), ()>,
    names: &mut redb::Table<'_, (&str, [u8; 32]), ()>,
    leaf: &DeviceLeaf,
) -> Result<(), Error> {
    let name = leaf.record.name.to_ascii_lowercase();
    names.remove((name.as_str(), *leaf.record.id.as_bytes())).map_err(database)?;
    let device = *leaf.record.id.as_bytes();
    for entry in &leaf.record.keys {
        keys.remove((*entry.key_id().as_bytes(), device)).map_err(database)?;
    }
    if let Some(address) = leaf.settings.ipv4 {
        addresses.remove((address, device)).map_err(database)?;
    }
    Ok(())
}

const fn purpose_byte(purpose: KeyPurpose) -> u8 {
    match purpose {
        KeyPurpose::Signing => 0,
        KeyPurpose::Transport => 1,
        KeyPurpose::Attestation => 2,
    }
}

const fn purpose_of(byte: u8) -> Option<KeyPurpose> {
    match byte {
        0 => Some(KeyPurpose::Signing),
        1 => Some(KeyPurpose::Transport),
        2 => Some(KeyPurpose::Attestation),
        _ => None,
    }
}

impl NodeSource for Store {
    fn node(&self, hash: &Hash) -> Option<Stored> {
        let reading = self.reading()?;
        let node = reading.nodes.get(*hash).ok()??;
        Stored::from_bytes(&node.value())
    }

    fn tampered(&self) {
        self.told();
    }
}

impl MemberStore for Store {
    fn leaf(&self, device: &DeviceId) -> Option<DeviceLeaf> {
        let reading = self.reading()?;
        let bytes = reading.leaves.get(*device.as_bytes()).ok()??;
        DeviceLeaf::from_bytes(bytes.value()).ok()
    }

    fn leaves_after(&self, after: Option<&DeviceId>, count: usize) -> Vec<DeviceLeaf> {
        let read = || -> Result<Vec<DeviceLeaf>, redb::Error> {
            let Some(reading) = self.reading() else { return Ok(Vec::new()) };
            let leaves = &reading.leaves;
            let range = match after {
                Some(after) => leaves.range((
                    core::ops::Bound::Excluded(*after.as_bytes()),
                    core::ops::Bound::Unbounded,
                ))?,
                None => leaves.range::<[u8; 32]>(..)?,
            };
            let mut page = Vec::new();
            for entry in range.take(count) {
                let (_, bytes) = entry?;
                if let Ok(leaf) = DeviceLeaf::from_bytes(bytes.value()) {
                    page.push(leaf);
                }
            }
            Ok(page)
        };
        read().unwrap_or_else(|_| {
            self.told();
            Vec::new()
        })
    }

    fn key_holders(&self, key: &KeyId) -> Vec<(DeviceId, KeyPurpose)> {
        let read = || -> Result<Vec<(DeviceId, KeyPurpose)>, redb::Error> {
            let Some(reading) = self.reading() else { return Ok(Vec::new()) };
            let keys = &reading.keys;
            let key = *key.as_bytes();
            let mut holders = Vec::new();
            for entry in keys.range((key, [0; 32])..=(key, [0xff; 32]))? {
                let (held, purpose) = entry?;
                if let Some(purpose) = purpose_of(purpose.value()) {
                    holders.push((DeviceId::from_bytes(held.value().1), purpose));
                }
            }
            Ok(holders)
        };
        read().unwrap_or_default()
    }

    fn address_holders(&self, address: [u8; 4]) -> Vec<DeviceId> {
        let read = || -> Result<Vec<DeviceId>, redb::Error> {
            let Some(reading) = self.reading() else { return Ok(Vec::new()) };
            let addresses = &reading.addresses;
            let mut holders = Vec::new();
            for entry in addresses.range((address, [0; 32])..=(address, [0xff; 32]))? {
                let (held, _) = entry?;
                holders.push(DeviceId::from_bytes(held.value().1));
            }
            Ok(holders)
        };
        read().unwrap_or_default()
    }

    fn name_holders(&self, name: &str) -> Vec<DeviceId> {
        let read = || -> Result<Vec<DeviceId>, redb::Error> {
            let Some(reading) = self.reading() else { return Ok(Vec::new()) };
            let mut holders = Vec::new();
            for entry in reading.names.range((name, [0; 32])..=(name, [0xff; 32]))? {
                let (held, _) = entry?;
                holders.push(DeviceId::from_bytes(held.value().1));
            }
            Ok(holders)
        };
        read().unwrap_or_default()
    }

    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    fn derived_holders(&self, tag: &[u8; 32], value: [u8; 4]) -> Option<Vec<DeviceId>> {
        let read = self.db.begin_read().ok()?;
        read.open_table(BUILT).ok()?.get(*tag).ok()??;
        let derived = read.open_table(DERIVED).ok()?;
        let rows = derived.range((*tag, value, [0; 32])..=(*tag, value, [0xff; 32])).ok()?;
        rows.map(|row| row.ok().map(|(held, _)| DeviceId::from_bytes(held.value().2))).collect()
    }

    fn put_derived(&self, tag: &[u8; 32], rows: &[([u8; 4], DeviceId)]) {
        let written = (|| -> Result<(), redb::Error> {
            let mut write = self.db.begin_write()?;
            write.set_durability(Durability::None)?;
            {
                let mut derived = write.open_table(DERIVED)?;
                let mut sorted: Vec<DerivedRow> =
                    rows.iter().map(|(value, device)| (*tag, *value, *device.as_bytes())).collect();
                sorted.sort_unstable();
                for row in sorted {
                    derived.insert(row, ())?;
                }
                write.open_table(BUILT)?.insert(*tag, ())?;
            }
            write.commit()?;
            Ok(())
        })();
        if written.is_err() {
            self.told();
        }
    }
}

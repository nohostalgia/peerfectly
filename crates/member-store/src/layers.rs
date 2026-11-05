//! A full member's batch layers on disk.
//!
//! A batch's entries, by device, with the indexes over them by key, address and
//! name, and the nodes of its entries tree; and the nodes a state's tree spills
//! when a layer is laid in it. In a [redb] file of its own, beside the base's,
//! so that the base is checked as it always was and a layer is let go of
//! whole.
//!
//! # Believed only through a root kept elsewhere
//!
//! Nothing here is taken on its word. [`roster::members::Layer`] checks every
//! entry against the batch's entries tree, rooted where the signed header says;
//! every index hit against the entry it names; every node against the hash its
//! parent names. A check that fails tells the store, and [`Layers::tampered`]
//! then says so.
//!
//! # Tables
//!
//! - `entries`: (batch, device) to the entry's canonical bytes;
//! - `keys`: (batch, key id, device);
//! - `addresses`: (batch, assigned IPv4 address, device);
//! - `names`: (batch, name in ASCII lower case, device);
//! - `nodes`: a tree node's hash to the node, the entries trees' and the
//!   nodes spilled by states' trees alike.
//!
//! [redb]: https://www.redb.org

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use roster::batch::BatchEntry;
use roster::id::{DeviceId, KeyId, OperationId};
use roster::members::LayerStore;
use roster::merkle::{self, Hash, NodeSink, NodeSource, STORED_LEN, Stored};

use crate::Error;

const ENTRIES: TableDefinition<([u8; 32], [u8; 32]), &[u8]> = TableDefinition::new("entries");
/// A row of the key index: the batch, the key's id, the device.
type KeyRow = ([u8; 32], [u8; 32], [u8; 32]);
/// A row of the address index: the batch, the address, the device.
type AddressRow = ([u8; 32], [u8; 4], [u8; 32]);

const KEYS: TableDefinition<KeyRow, ()> = TableDefinition::new("keys");
const ADDRESSES: TableDefinition<AddressRow, ()> = TableDefinition::new("addresses");
const NAMES: TableDefinition<([u8; 32], &str, [u8; 32]), ()> = TableDefinition::new("names");
const NODES: TableDefinition<[u8; 32], [u8; STORED_LEN]> = TableDefinition::new("nodes");
/// A batch's devices by a value each derives from its id alone, by the
/// derivation's tag: built as asked, emptied with the file at each start.
const DERIVED: TableDefinition<LayerDerivedRow, ()> = TableDefinition::new("derived");
/// The (batch, derivation) pairs [`DERIVED`] holds whole.
const BUILT: TableDefinition<([u8; 32], [u8; 32]), ()> = TableDefinition::new("built");

/// A row of the derived index: the batch, the derivation's tag, the value,
/// the device.
type LayerDerivedRow = ([u8; 32], [u8; 32], [u8; 4], [u8; 32]);

/// The nodes a collection found in use: kept on disk while it runs, so that a
/// million of them are not held in memory.
const MARKS: TableDefinition<[u8; 32], ()> = TableDefinition::new("marks");

/// How many rows a write puts in one transaction.
const BATCH: usize = 100_000;

fn database(cause: impl core::fmt::Display) -> Error {
    Error::Database(cause.to_string())
}

/// A full member's batch layers, in redb.
pub struct Layers {
    db: Database,
    tampered: AtomicBool,
    /// The tables lookups read, kept open from one write to the next.
    reading: std::sync::Mutex<Option<Arc<Reading>>>,
}

/// The tables a lookup reads, in one read transaction.
struct Reading {
    entries: redb::ReadOnlyTable<([u8; 32], [u8; 32]), &'static [u8]>,
    keys: redb::ReadOnlyTable<KeyRow, ()>,
    addresses: redb::ReadOnlyTable<AddressRow, ()>,
    names: redb::ReadOnlyTable<([u8; 32], &'static str, [u8; 32]), ()>,
    nodes: redb::ReadOnlyTable<[u8; 32], [u8; STORED_LEN]>,
}

impl core::fmt::Debug for Layers {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Layers").field("tampered", &self.tampered()).finish_non_exhaustive()
    }
}

impl Layers {
    /// Opens the layers at `path`, creating an empty file where there is none,
    /// with redb's cache bounded to `cache` bytes.
    ///
    /// # Errors
    ///
    /// When the file cannot be opened as a database.
    pub fn open(path: &Path, cache: usize) -> Result<Arc<Self>, Error> {
        let db = Database::builder().set_cache_size(cache).create(path).map_err(database)?;
        let layers =
            Self { db, tampered: AtomicBool::new(false), reading: std::sync::Mutex::new(None) };
        let write = layers.db.begin_write().map_err(database)?;
        write.open_table(ENTRIES).map_err(database)?;
        write.open_table(KEYS).map_err(database)?;
        write.open_table(ADDRESSES).map_err(database)?;
        write.open_table(NAMES).map_err(database)?;
        write.open_table(NODES).map_err(database)?;
        write.open_table(DERIVED).map_err(database)?;
        write.open_table(BUILT).map_err(database)?;
        write.commit().map_err(database)?;
        Ok(Arc::new(layers))
    }

    /// Whether a check of something this store answered has failed: it was
    /// changed behind the daemon's back, or the disk lost it.
    #[must_use]
    pub fn tampered(&self) -> bool {
        self.tampered.load(Ordering::SeqCst)
    }

    /// How many tree nodes it holds.
    ///
    /// # Errors
    ///
    /// When the database cannot be read.
    pub fn node_count(&self) -> Result<u64, Error> {
        let read = self.db.begin_read().map_err(database)?;
        let nodes = read.open_table(NODES).map_err(database)?;
        redb::ReadableTableMetadata::len(&nodes).map_err(database)
    }

    /// Lets go of everything: what a daemon does as it starts, before the log
    /// is replayed and puts back the layers of the batches it still holds.
    /// Nothing holds a state over the layers then, so nothing can be left
    /// reaching for what is gone; and the batches compaction took into the
    /// base, and the paths states spilled since, go with it.
    ///
    /// # Errors
    ///
    /// When the database cannot be written.
    pub fn clear(&self) -> Result<(), Error> {
        self.stop_reading();
        let mut write = self.db.begin_write().map_err(database)?;
        write.set_durability(Durability::Immediate).map_err(database)?;
        write.delete_table(ENTRIES).map_err(database)?;
        write.delete_table(KEYS).map_err(database)?;
        write.delete_table(ADDRESSES).map_err(database)?;
        write.delete_table(NAMES).map_err(database)?;
        write.delete_table(NODES).map_err(database)?;
        write.delete_table(MARKS).map_err(database)?;
        write.delete_table(DERIVED).map_err(database)?;
        write.delete_table(BUILT).map_err(database)?;
        write.open_table(DERIVED).map_err(database)?;
        write.open_table(BUILT).map_err(database)?;
        write.open_table(ENTRIES).map_err(database)?;
        write.open_table(KEYS).map_err(database)?;
        write.open_table(ADDRESSES).map_err(database)?;
        write.open_table(NAMES).map_err(database)?;
        write.open_table(NODES).map_err(database)?;
        write.commit().map_err(database)?;
        self.stop_reading();
        Ok(())
    }

    /// Lets go of every node no tree in use reaches, and returns how many.
    ///
    /// Kept: every node `roots` reach, walked down from each through the nodes
    /// this file holds. A walk stops where a node is not here, which is the
    /// base's. The roots are those of the trees the roster still holds over
    /// its layers, and the entries trees of the batches it still holds
    /// (`roster::roster::Roster::layer_roots`).
    ///
    /// # Errors
    ///
    /// When the database cannot be read or written.
    pub fn collect(&self, roots: &[Hash]) -> Result<u64, Error> {
        self.stop_reading();
        let collected = self.mark(roots).and_then(|()| self.sweep());
        self.stop_reading();
        collected
    }

    fn mark(&self, roots: &[Hash]) -> Result<(), Error> {
        let mut write = self.db.begin_write().map_err(database)?;
        write.delete_table(MARKS).map_err(database)?;
        write.open_table(MARKS).map_err(database)?;
        write.commit().map_err(database)?;
        let mut walk: Vec<Hash> =
            roots.iter().copied().filter(|root| *root != merkle::EMPTY).collect();
        while !walk.is_empty() {
            write = self.db.begin_write().map_err(database)?;
            write.set_durability(Durability::None).map_err(database)?;
            {
                let nodes = write.open_table(NODES).map_err(database)?;
                let mut marks = write.open_table(MARKS).map_err(database)?;
                let mut marked = 0_usize;
                while let Some(hash) = walk.pop() {
                    if marks.get(hash).map_err(database)?.is_some() {
                        continue;
                    }
                    let Some(node) = nodes.get(hash).map_err(database)? else { continue };
                    marks.insert(hash, ()).map_err(database)?;
                    if let Some(Stored::Branch { left, right }) = Stored::from_bytes(&node.value())
                    {
                        walk.extend(
                            [left, right].into_iter().filter(|child| *child != merkle::EMPTY),
                        );
                    }
                    marked = marked.saturating_add(1);
                    if marked >= BATCH {
                        break;
                    }
                }
            }
            write.commit().map_err(database)?;
        }
        Ok(())
    }

    fn sweep(&self) -> Result<u64, Error> {
        let mut swept = 0_u64;
        let mut after: Option<[u8; 32]> = None;
        loop {
            let unmarked: Vec<[u8; 32]> = {
                let read = self.db.begin_read().map_err(database)?;
                let nodes = read.open_table(NODES).map_err(database)?;
                let marks = read.open_table(MARKS).map_err(database)?;
                let range = match after {
                    Some(after) => nodes
                        .range((core::ops::Bound::Excluded(after), core::ops::Bound::Unbounded))
                        .map_err(database)?,
                    None => nodes.range::<[u8; 32]>(..).map_err(database)?,
                };
                let mut page = Vec::new();
                let mut seen = 0_usize;
                for row in range {
                    let (hash, _) = row.map_err(database)?;
                    let hash = hash.value();
                    after = Some(hash);
                    seen = seen.saturating_add(1);
                    if marks.get(hash).map_err(database)?.is_none() {
                        page.push(hash);
                    }
                    if seen >= BATCH {
                        break;
                    }
                }
                if seen == 0 {
                    break;
                }
                page
            };
            if !unmarked.is_empty() {
                let mut write = self.db.begin_write().map_err(database)?;
                write.set_durability(Durability::Immediate).map_err(database)?;
                {
                    let mut nodes = write.open_table(NODES).map_err(database)?;
                    for hash in &unmarked {
                        nodes.remove(*hash).map_err(database)?;
                    }
                }
                write.commit().map_err(database)?;
                swept = swept.saturating_add(unmarked.len() as u64);
            }
        }
        let mut write = self.db.begin_write().map_err(database)?;
        write.set_durability(Durability::Immediate).map_err(database)?;
        write.delete_table(MARKS).map_err(database)?;
        write.commit().map_err(database)?;
        Ok(swept)
    }

    fn reading(&self) -> Option<Arc<Reading>> {
        let mut held = self.reading.lock().ok()?;
        if let Some(reading) = held.as_ref() {
            return Some(Arc::clone(reading));
        }
        let read = self.db.begin_read().ok()?;
        let reading = Arc::new(Reading {
            entries: read.open_table(ENTRIES).ok()?,
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

    fn told(&self) {
        self.tampered.store(true, Ordering::SeqCst);
    }

    fn write_entries(&self, batch: &OperationId, entries: &[BatchEntry]) -> Result<(), Error> {
        let batch = *batch.as_bytes();
        let mut placed: Vec<([u8; 32], &BatchEntry)> = entries
            .iter()
            .map(|entry| entry.device_id().map(|device| (*device.as_bytes(), entry)))
            .collect::<roster::Result<_>>()
            .map_err(|_| Error::Tampered("an entry names no device"))?;
        placed.sort_unstable_by_key(|(device, _)| *device);
        for chunk in placed.chunks(BATCH) {
            let mut write = self.db.begin_write().map_err(database)?;
            write.set_durability(Durability::Immediate).map_err(database)?;
            {
                let mut table = write.open_table(ENTRIES).map_err(database)?;
                for (device, entry) in chunk {
                    table
                        .insert((batch, *device), entry.to_bytes().as_slice())
                        .map_err(database)?;
                }
                let mut keys: Vec<([u8; 32], [u8; 32], [u8; 32])> = chunk
                    .iter()
                    .flat_map(|(device, entry)| {
                        entry.keys.iter().map(move |key| (batch, *key.key_id().as_bytes(), *device))
                    })
                    .collect();
                keys.sort_unstable();
                let mut table = write.open_table(KEYS).map_err(database)?;
                for key in keys {
                    table.insert(key, ()).map_err(database)?;
                }
                let mut table = write.open_table(ADDRESSES).map_err(database)?;
                for (device, entry) in chunk {
                    if let Some(address) = entry.ipv4 {
                        table.insert((batch, address, *device), ()).map_err(database)?;
                    }
                }
                let mut names: Vec<(String, [u8; 32])> = chunk
                    .iter()
                    .map(|(device, entry)| (entry.name.to_ascii_lowercase(), *device))
                    .collect();
                names.sort_unstable();
                let mut table = write.open_table(NAMES).map_err(database)?;
                for (name, device) in &names {
                    table.insert((batch, name.as_str(), *device), ()).map_err(database)?;
                }
            }
            write.commit().map_err(database)?;
        }
        Ok(())
    }

    fn write_nodes(&self, nodes: &mut Vec<(Hash, Stored)>) -> Result<(), Error> {
        nodes.sort_unstable_by_key(|(hash, _)| *hash);
        for chunk in nodes.chunks(BATCH) {
            let mut write = self.db.begin_write().map_err(database)?;
            write.set_durability(Durability::Immediate).map_err(database)?;
            {
                let mut table = write.open_table(NODES).map_err(database)?;
                for (hash, node) in chunk {
                    table.insert(*hash, node.to_bytes()).map_err(database)?;
                }
            }
            write.commit().map_err(database)?;
        }
        nodes.clear();
        Ok(())
    }

    fn rows_of<K>(&self, read: impl FnOnce(&Reading) -> Result<Vec<K>, redb::Error>) -> Vec<K> {
        let Some(reading) = self.reading() else { return Vec::new() };
        read(&reading).unwrap_or_else(|_| {
            self.told();
            Vec::new()
        })
    }
}

impl NodeSource for Layers {
    fn node(&self, hash: &Hash) -> Option<Stored> {
        let reading = self.reading()?;
        let node = reading.nodes.get(*hash).ok()??;
        Stored::from_bytes(&node.value())
    }

    fn tampered(&self) {
        self.told();
    }
}

impl NodeSink for Layers {
    fn put_nodes(&self, nodes: &[(Hash, Stored)]) {
        self.stop_reading();
        let mut owned = nodes.to_vec();
        if self.write_nodes(&mut owned).is_err() {
            // Unwritten, a node is missing when the tree goes for it, and the
            // store is told then.
            self.told();
        }
        self.stop_reading();
    }
}

impl LayerStore for Layers {
    fn put(&self, batch: &OperationId, entries: &[BatchEntry]) -> roster::Result<()> {
        self.stop_reading();
        let written = self.write_entries(batch, entries).and_then(|()| {
            // The entries tree, built in the positions' order with a path of
            // it in memory, its nodes written a batch at a time.
            let mut leaves: Vec<(Hash, Hash)> = entries
                .iter()
                .filter_map(|entry| {
                    entry
                        .device_id()
                        .ok()
                        .map(|device| (BatchEntry::position(&device), entry.value_hash()))
                })
                .collect();
            leaves.sort_unstable();
            let mut pending: Vec<(Hash, Stored)> = Vec::new();
            let mut failed = None;
            let mut builder = merkle::Builder::new(|hash, node| {
                pending.push((hash, node));
                if pending.len() >= BATCH
                    && failed.is_none()
                    && let Err(cause) = self.write_nodes(&mut pending)
                {
                    failed = Some(cause);
                }
            });
            for (position, value) in leaves {
                builder.push(position, value);
            }
            let _root = builder.finish();
            if let Some(cause) = failed {
                return Err(cause);
            }
            self.write_nodes(&mut pending)
        });
        self.stop_reading();
        written.map_err(|_| roster::Error::InvalidValue("a batch's layer could not be written"))
    }

    fn entry(&self, batch: &OperationId, device: &DeviceId) -> Option<BatchEntry> {
        let reading = self.reading()?;
        let bytes = reading.entries.get((*batch.as_bytes(), *device.as_bytes())).ok()??;
        BatchEntry::from_bytes(bytes.value()).ok()
    }

    fn entries_after(
        &self,
        batch: &OperationId,
        after: Option<&DeviceId>,
        count: usize,
    ) -> Vec<(DeviceId, BatchEntry)> {
        let batch = *batch.as_bytes();
        let from = after.map_or([0; 32], |after| *after.as_bytes());
        let read = |reading: &Reading| -> Result<Vec<(DeviceId, BatchEntry)>, redb::Error> {
            let mut page = Vec::with_capacity(count);
            for row in reading.entries.range((batch, from)..=(batch, [0xff; 32]))? {
                let (key, bytes) = row?;
                let device = key.value().1;
                if after.is_some_and(|after| device == *after.as_bytes()) {
                    continue;
                }
                if let Ok(entry) = BatchEntry::from_bytes(bytes.value()) {
                    page.push((DeviceId::from_bytes(device), entry));
                }
                if page.len() >= count {
                    break;
                }
            }
            Ok(page)
        };
        let Some(reading) = self.reading() else { return Vec::new() };
        read(&reading).unwrap_or_else(|_| {
            self.told();
            Vec::new()
        })
    }

    fn key_holders(&self, batch: &OperationId, key: &KeyId) -> Vec<DeviceId> {
        let (batch, key) = (*batch.as_bytes(), *key.as_bytes());
        self.rows_of(|reading| {
            reading
                .keys
                .range((batch, key, [0; 32])..=(batch, key, [0xff; 32]))?
                .map(|row| row.map(|(held, _)| DeviceId::from_bytes(held.value().2)))
                .collect::<Result<_, redb::StorageError>>()
                .map_err(redb::Error::from)
        })
    }

    fn address_holders(&self, batch: &OperationId, address: [u8; 4]) -> Vec<DeviceId> {
        let batch = *batch.as_bytes();
        self.rows_of(|reading| {
            reading
                .addresses
                .range((batch, address, [0; 32])..=(batch, address, [0xff; 32]))?
                .map(|row| row.map(|(held, _)| DeviceId::from_bytes(held.value().2)))
                .collect::<Result<_, redb::StorageError>>()
                .map_err(redb::Error::from)
        })
    }

    fn addresses(&self, batch: &OperationId) -> Vec<[u8; 4]> {
        let batch = *batch.as_bytes();
        let mut out: Vec<[u8; 4]> = self.rows_of(|reading| {
            reading
                .addresses
                .range((batch, [0; 4], [0; 32])..=(batch, [0xff; 4], [0xff; 32]))?
                .map(|row| row.map(|(held, _)| held.value().1))
                .collect::<Result<_, redb::StorageError>>()
                .map_err(redb::Error::from)
        });
        out.dedup();
        out
    }

    fn address_claims_from(
        &self,
        batch: &OperationId,
        from: ([u8; 4], DeviceId),
        count: usize,
    ) -> Vec<([u8; 4], DeviceId)> {
        let batch = *batch.as_bytes();
        self.rows_of(|reading| {
            reading
                .addresses
                .range((batch, from.0, *from.1.as_bytes())..=(batch, [0xff; 4], [0xff; 32]))?
                .take(count)
                .map(|row| {
                    row.map(|(held, _)| {
                        let (_, address, device) = held.value();
                        (address, DeviceId::from_bytes(device))
                    })
                })
                .collect::<Result<_, redb::StorageError>>()
                .map_err(redb::Error::from)
        })
    }

    fn name_holders(&self, batch: &OperationId, name: &str) -> Vec<DeviceId> {
        let batch = *batch.as_bytes();
        self.rows_of(|reading| {
            reading
                .names
                .range((batch, name, [0; 32])..=(batch, name, [0xff; 32]))?
                .map(|row| row.map(|(held, _)| DeviceId::from_bytes(held.value().2)))
                .collect::<Result<_, redb::StorageError>>()
                .map_err(redb::Error::from)
        })
    }

    fn forget(&self, batch: &OperationId) {
        self.stop_reading();
        let batch = *batch.as_bytes();
        let forgot = (|| -> Result<(), redb::Error> {
            let write = self.db.begin_write()?;
            {
                write
                    .open_table(ENTRIES)?
                    .retain_in((batch, [0; 32])..=(batch, [0xff; 32]), |_, _| false)?;
                write.open_table(KEYS)?.retain_in(
                    (batch, [0; 32], [0; 32])..=(batch, [0xff; 32], [0xff; 32]),
                    |_, ()| false,
                )?;
                write.open_table(ADDRESSES)?.retain_in(
                    (batch, [0; 4], [0; 32])..=(batch, [0xff; 4], [0xff; 32]),
                    |_, ()| false,
                )?;
                let mut names = write.open_table(NAMES)?;
                let held: Vec<(String, [u8; 32])> = names
                    .range((batch, "", [0; 32])..)?
                    .map_while(|row| {
                        row.ok().and_then(|(key, _)| {
                            let (owner, name, device) = key.value();
                            (owner == batch).then(|| (name.to_owned(), device))
                        })
                    })
                    .collect();
                for (name, device) in held {
                    names.remove((batch, name.as_str(), device))?;
                }
            }
            write.commit()?;
            Ok(())
        })();
        if forgot.is_err() {
            self.told();
        }
        self.stop_reading();
    }

    fn derived_holders(
        &self,
        batch: &OperationId,
        tag: &[u8; 32],
        value: [u8; 4],
    ) -> Option<Vec<DeviceId>> {
        let batch = *batch.as_bytes();
        let read = self.db.begin_read().ok()?;
        read.open_table(BUILT).ok()?.get((batch, *tag)).ok()??;
        let derived = read.open_table(DERIVED).ok()?;
        let rows =
            derived.range((batch, *tag, value, [0; 32])..=(batch, *tag, value, [0xff; 32])).ok()?;
        rows.map(|row| row.ok().map(|(held, _)| DeviceId::from_bytes(held.value().3))).collect()
    }

    fn put_derived(&self, batch: &OperationId, tag: &[u8; 32], rows: &[([u8; 4], DeviceId)]) {
        let batch = *batch.as_bytes();
        let written = (|| -> Result<(), redb::Error> {
            let mut write = self.db.begin_write()?;
            write.set_durability(Durability::None)?;
            {
                let mut derived = write.open_table(DERIVED)?;
                let mut sorted: Vec<LayerDerivedRow> = rows
                    .iter()
                    .map(|(value, device)| (batch, *tag, *value, *device.as_bytes()))
                    .collect();
                sorted.sort_unstable();
                for row in sorted {
                    derived.insert(row, ())?;
                }
                write.open_table(BUILT)?.insert((batch, *tag), ())?;
            }
            write.commit()?;
            Ok(())
        })();
        if written.is_err() {
            self.told();
        }
    }
}

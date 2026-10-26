//! Admitting many devices with one signature.
//!
//! A batch is one operation, its **header**, which commits to two Merkle
//! roots: one over its entries, by device, and one over the pieces those
//! entries travel in, by index. The pieces travel apart, each small enough for
//! the ordinary limits, so the header's one signature covers every entry while
//! no message grows with the batch. One signature is also one consent: a phone
//! whose key asks for its lock at every signature asks once for the whole lot.
//!
//! # Why the header commits to its pieces
//!
//! A node holding part of a batch has to say which part, so that a peer sends
//! only the rest, and has to pass on what it holds before it holds everything.
//! With the pieces committed, a piece proves on its own that it is the batch's
//! piece number *i*: what a node holds is a set of indices, said in a bitmap,
//! and no peer can make it believe it holds a piece it does not. The cut is
//! canonical — entries in device order, filled greedily — so every honest node
//! that holds the whole batch rebuilds the same pieces from its entries.

use alloc::string::String;
use alloc::vec::Vec;

use crate::cbor::{Reader, Writer};
use crate::error::{Error, Result};
use crate::leaf::{Group, Mode};
use crate::limits;
use crate::merkle::Hash;
use crate::types::{IPV4_RANGE_LEN, Ipv4Range};

/// Canonical key order of a batch header.
pub const BATCH_HEADER_SCHEMA: &[&str] =
    &["mode", "block", "count", "label", "groups", "layout", "pieces", "entries"];

/// What a batch's header commits to about its entries and their pieces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commitment {
    /// How many entries the batch holds.
    pub count: u64,
    /// The Merkle root of the entries, by device.
    pub entries: Hash,
    /// How many pieces the entries travel in.
    pub pieces: u64,
    /// The Merkle root of the pieces, by index.
    pub layout: Hash,
}

/// The signed part of a batch admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchHeader {
    /// How many entries the batch holds.
    pub count: u64,
    /// The Merkle root of the entries.
    pub entries: Hash,
    /// How many pieces the entries travel in.
    pub pieces: u64,
    /// The Merkle root of the pieces, by index.
    pub layout: Hash,
    /// The mode every entry is admitted in.
    pub mode: Mode,
    /// The groups every entry joins, sorted, without repeats.
    pub groups: Vec<Group>,
    /// The IPv4 block the entries' addresses are assigned from, if any.
    pub block: Option<Ipv4Range>,
    /// A line a person reads: which lot this is.
    pub label: String,
}

impl BatchHeader {
    /// Builds a header, checking every bound.
    ///
    /// # Errors
    ///
    /// When the batch is empty or larger than [`limits::MAX_BATCH_ENTRIES`],
    /// declares no piece or more pieces than entries, the label is too long, or
    /// the groups are too many or repeated.
    pub fn new(
        commitment: Commitment,
        mode: Mode,
        mut groups: Vec<Group>,
        block: Option<Ipv4Range>,
        label: impl Into<String>,
    ) -> Result<Self> {
        let Commitment { count, entries, pieces, layout } = commitment;
        let label = label.into();
        if count == 0 {
            return Err(Error::InvalidValue("an empty batch"));
        }
        if count > limits::MAX_BATCH_ENTRIES {
            return Err(Error::LimitExceeded("batch entries"));
        }
        if pieces == 0 || pieces > count {
            return Err(Error::InvalidValue("batch pieces"));
        }
        if label.len() > limits::MAX_BATCH_LABEL_LEN {
            return Err(Error::LimitExceeded("batch label length"));
        }
        if groups.len() > limits::MAX_GROUPS_PER_DEVICE {
            return Err(Error::LimitExceeded("groups per device"));
        }
        groups.sort();
        if groups.windows(2).any(|pair| matches!(pair, [first, second] if first == second)) {
            return Err(Error::InvalidValue("repeated group"));
        }
        Ok(Self { count, entries, pieces, layout, mode, groups, block, label })
    }

    /// Builds the header for a set of entries, committing to them and to the
    /// pieces they are cut into.
    ///
    /// # Errors
    ///
    /// As [`commit`] and [`Self::new`].
    pub fn for_entries(
        entries: &[BatchEntry],
        mode: Mode,
        groups: Vec<Group>,
        block: Option<Ipv4Range>,
        label: impl Into<String>,
    ) -> Result<Self> {
        Self::new(commit(entries)?, mode, groups, block, label)
    }

    /// What this header commits to.
    #[must_use]
    pub const fn commitment(&self) -> Commitment {
        Commitment {
            count: self.count,
            entries: self.entries,
            pieces: self.pieces,
            layout: self.layout,
        }
    }

    /// Writes the header.
    pub(crate) fn encode(&self, writer: &mut Writer) {
        writer.map(8);
        writer.key("mode").str(self.mode.as_str());
        writer
            .key("block")
            .bytes(self.block.map_or_else(Vec::new, |range| range.to_bytes().to_vec()).as_slice());
        writer.key("count").u64(self.count);
        writer.key("label").str(&self.label);
        writer.key("groups").array(self.groups.len() as u64);
        for group in &self.groups {
            writer.str(group.as_str());
        }
        writer.key("layout").bytes(&self.layout);
        writer.key("pieces").u64(self.pieces);
        writer.key("entries").bytes(&self.entries);
    }

    /// Reads a header, refusing anything not in canonical form.
    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let mut map = reader.map(BATCH_HEADER_SCHEMA)?;
        let mode = Mode::parse(map.key("mode")?.str(limits::MAX_MAP_KEY_LEN, "mode")?)?;
        let block =
            match map.key("block")?.bytes(IPV4_RANGE_LEN.saturating_add(1), "ipv4 range length")? {
                [] => None,
                bytes => Some(Ipv4Range::from_bytes(bytes)?),
            };
        let count = map.key("count")?.u64()?;
        let label =
            String::from(map.key("label")?.str(limits::MAX_BATCH_LABEL_LEN, "batch label length")?);
        let reader = map.key("groups")?;
        let group_count = reader.array(limits::MAX_GROUPS_PER_DEVICE, "groups per device")?;
        let mut groups = Vec::with_capacity(group_count);
        for _ in 0..group_count {
            groups.push(Group::new(reader.str(limits::MAX_GROUP_LEN, "group name length")?)?);
        }
        let layout = <Hash>::try_from(map.key("layout")?.fixed_bytes(32)?)
            .map_err(|_| Error::IdentifierLength)?;
        let pieces = map.key("pieces")?.u64()?;
        let entries = <Hash>::try_from(map.key("entries")?.fixed_bytes(32)?)
            .map_err(|_| Error::IdentifierLength)?;
        map.finish()?;
        if groups.windows(2).any(|pair| matches!(pair, [first, second] if first >= second)) {
            return Err(Error::NonCanonical);
        }
        Self::new(Commitment { count, entries, pieces, layout }, mode, groups, block, label)
    }
}

/// The context an entry's position in its batch's tree is derived under.
const ENTRY_POSITION_CONTEXT: &str = "peerfectly batch entry position v1";

/// The context an entry's bytes are hashed under.
const ENTRY_CONTEXT: &str = "peerfectly batch entry v1";

/// The context a piece's position in its batch's layout is derived under.
const PIECE_POSITION_CONTEXT: &str = "peerfectly batch piece position v1";

/// The context a piece's index and entries are hashed under.
const PIECE_CONTEXT: &str = "peerfectly batch piece v1";

/// Canonical key order of a batch entry.
pub const BATCH_ENTRY_SCHEMA: &[&str] = &["ipv4", "keys", "name", "serial"];

/// Canonical key order of a batch piece.
pub const BATCH_PIECE_SCHEMA: &[&str] = &["batch", "index", "proof", "entries"];

/// Maximum length in bytes of an entry's serial number.
pub const MAX_SERIAL_LEN: usize = 64;

/// Room kept in a piece for everything but its entries: the batch's id, the
/// index, the proof against the layout, and the framing around them.
///
/// A layout of 65,536 pieces is a tree some 16 levels deep, and a proof names
/// one hash per level: about 600 bytes. The rest is a margin a proof would
/// need many times that depth to use.
const PIECE_OVERHEAD: usize = 2048;

/// One device a batch admits.
///
/// What the board gave the production station over its cable: its public
/// keys, its proposed name, and its serial. The role is always member, and the
/// mode and groups are the header's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchEntry {
    /// Its public keys, in canonical order.
    pub keys: Vec<crate::types::KeyEntry>,
    /// The name it is admitted under.
    pub name: String,
    /// Its serial number, if it has one: empty otherwise.
    pub serial: Vec<u8>,
    /// The address assigned from the header's block, if the header has one.
    pub ipv4: Option<[u8; 4]>,
}

impl BatchEntry {
    /// The device this entry admits, as an operation would describe it.
    ///
    /// # Errors
    ///
    /// When the keys or the name break the rules every device keeps.
    pub fn spec(&self) -> Result<crate::types::DeviceSpec> {
        crate::types::DeviceSpec::new(
            self.keys.clone(),
            self.name.clone(),
            crate::types::Role::Member,
            false,
            Vec::new(),
        )
    }

    /// The device's id.
    ///
    /// # Errors
    ///
    /// When the entry names no signing key.
    pub fn device_id(&self) -> Result<crate::id::DeviceId> {
        self.spec()?.device_id()
    }

    /// Where the entry sits in its batch's tree.
    #[must_use]
    pub fn position(device: &crate::id::DeviceId) -> Hash {
        blake3::derive_key(ENTRY_POSITION_CONTEXT, device.as_bytes())
    }

    /// The hash its batch's tree holds for it.
    #[must_use]
    pub fn value_hash(&self) -> Hash {
        blake3::derive_key(ENTRY_CONTEXT, &self.to_bytes())
    }

    /// Its canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        self.encode(&mut writer);
        writer.finish()
    }

    pub(crate) fn encode(&self, writer: &mut Writer) {
        writer.map(4);
        writer.key("ipv4").bytes(self.ipv4.as_ref().map_or(&[][..], |address| &address[..]));
        writer.key("keys").array(self.keys.len() as u64);
        for entry in &self.keys {
            entry.encode(writer);
        }
        writer.key("name").str(&self.name);
        writer.key("serial").bytes(&self.serial);
    }

    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let mut map = reader.map(BATCH_ENTRY_SCHEMA)?;
        let ipv4 = match map.key("ipv4")?.bytes(4, "ipv4 address")? {
            [] => None,
            [a, b, c, d] => Some([*a, *b, *c, *d]),
            _ => return Err(Error::InvalidValue("ipv4 address length")),
        };
        let keys_reader = map.key("keys")?;
        let count = keys_reader.array(limits::MAX_KEYS_PER_DEVICE, "keys per device")?;
        let mut keys = Vec::with_capacity(count);
        for _ in 0..count {
            keys.push(crate::types::KeyEntry::decode(keys_reader)?);
        }
        let name = String::from(map.key("name")?.str(limits::MAX_NAME_LEN, "device name length")?);
        let serial = map.key("serial")?.bytes(MAX_SERIAL_LEN, "serial length")?.to_vec();
        map.finish()?;
        let entry = Self { keys, name, serial, ipv4 };
        // The rules every device keeps, checked as it arrives.
        entry.spec()?;
        Ok(entry)
    }
}

/// The tree over a batch's entries, by device.
///
/// # Errors
///
/// When an entry names no signing key, or two name the same device.
pub fn entries_tree(entries: &[BatchEntry]) -> Result<crate::merkle::Tree> {
    let mut tree = crate::merkle::Tree::new();
    for entry in entries {
        let position = BatchEntry::position(&entry.device_id()?);
        if tree.get(&position).is_some() {
            return Err(Error::InvalidValue("a device twice in one batch"));
        }
        tree.insert(position, entry.value_hash());
    }
    Ok(tree)
}

/// Where piece `index` sits in its batch's layout.
#[must_use]
pub fn piece_position(index: u64) -> Hash {
    blake3::derive_key(PIECE_POSITION_CONTEXT, &index.to_be_bytes())
}

/// The hash a batch's layout holds for piece `index`, whose entries encode to
/// `entries`.
#[must_use]
pub fn piece_hash(index: u64, entries: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new_derive_key(PIECE_CONTEXT);
    hasher.update(&index.to_be_bytes());
    hasher.update(entries);
    *hasher.finalize().as_bytes()
}

/// The entries of a piece, as the piece carries them.
fn encode_entries(entries: &[&BatchEntry]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.array(entries.len() as u64);
    for entry in entries {
        entry.encode(&mut writer);
    }
    writer.finish()
}

/// A batch's entries cut into pieces: in device order, each piece filled
/// until the next entry would not fit.
///
/// The one cut every node makes, so that a node holding the whole batch
/// rebuilds exactly the pieces its author sent. Returns each piece's encoded
/// entries.
///
/// # Errors
///
/// As [`entries_tree`], or when one entry alone does not fit a piece.
fn cut(entries: &[BatchEntry]) -> Result<Vec<Vec<u8>>> {
    entries_tree(entries)?;
    let mut ordered: Vec<(crate::id::DeviceId, &BatchEntry)> = entries
        .iter()
        .map(|entry| entry.device_id().map(|id| (id, entry)))
        .collect::<Result<_>>()?;
    ordered.sort_by_key(|(device, _)| *device);
    // Room for the entries alone, less the widest array header they could need.
    let room = limits::MAX_OPERATION_SIZE.saturating_sub(PIECE_OVERHEAD).saturating_sub(9);
    let mut pieces = Vec::new();
    let mut current: Vec<&BatchEntry> = Vec::new();
    let mut size = 0_usize;
    for (_, entry) in ordered {
        let length = entry.to_bytes().len();
        if length > room {
            return Err(Error::LimitExceeded("batch entry size"));
        }
        if size.saturating_add(length) > room {
            pieces.push(encode_entries(&current));
            current.clear();
            size = 0;
        }
        current.push(entry);
        size = size.saturating_add(length);
    }
    if !current.is_empty() {
        pieces.push(encode_entries(&current));
    }
    Ok(pieces)
}

/// The layout tree over a cut's pieces.
fn layout_tree(pieces: &[Vec<u8>]) -> crate::merkle::Tree {
    let mut tree = crate::merkle::Tree::new();
    for (index, entries) in pieces.iter().enumerate() {
        let index = index as u64;
        tree.insert(piece_position(index), piece_hash(index, entries));
    }
    tree
}

/// What a header over `entries` commits to.
///
/// # Errors
///
/// As [`entries_tree`], or when an entry alone does not fit a piece.
pub fn commit(entries: &[BatchEntry]) -> Result<Commitment> {
    let pieces = cut(entries)?;
    Ok(Commitment {
        count: entries.len() as u64,
        entries: entries_tree(entries)?.root(),
        pieces: pieces.len() as u64,
        layout: layout_tree(&pieces).root(),
    })
}

/// A batch's pieces, each at most an operation's size, each carrying its
/// index and its proof against the header's layout.
///
/// `batch` is the id of the header operation the pieces belong to. The pieces
/// are the canonical cut: whoever holds the same entries builds the same bytes.
///
/// # Errors
///
/// As [`commit`].
pub fn pieces_of(batch: &crate::id::OperationId, entries: &[BatchEntry]) -> Result<Vec<Vec<u8>>> {
    let pieces = cut(entries)?;
    let layout = layout_tree(&pieces);
    let mut out = Vec::with_capacity(pieces.len());
    for (index, body) in pieces.iter().enumerate() {
        let index = index as u64;
        let proof = layout
            .prove(&piece_position(index))
            .ok_or(Error::InvalidValue("a piece missing from its own layout"))?;
        let mut writer = Writer::new();
        writer.map(4);
        writer.key("batch");
        batch.encode(&mut writer);
        writer.key("index").u64(index);
        writer.key("proof");
        proof.encode(&mut writer);
        writer.key("entries");
        let mut bytes = writer.finish();
        bytes.extend_from_slice(body);
        if bytes.len() > limits::MAX_OPERATION_SIZE {
            return Err(Error::LimitExceeded("batch piece size"));
        }
        out.push(bytes);
    }
    Ok(out)
}

/// A piece of a batch, read and checked against the batch's header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchPiece {
    /// The header operation it belongs to.
    pub batch: crate::id::OperationId,
    /// Which of the batch's pieces it is.
    pub index: u64,
    /// Its entries.
    pub entries: Vec<BatchEntry>,
}

impl BatchPiece {
    /// The id of the batch a piece belongs to, read without checking anything
    /// else: enough to find the header it must be checked against.
    ///
    /// # Errors
    ///
    /// When the piece does not start as a piece does.
    pub fn batch_of(piece: &[u8]) -> Result<crate::id::OperationId> {
        let mut reader = Reader::new(piece);
        let mut map = reader.map(BATCH_PIECE_SCHEMA)?;
        crate::id::OperationId::decode(map.key("batch")?)
    }

    /// Reads a piece and checks it against `header`: that it is the batch's
    /// piece number `index`, exactly as its author cut it.
    ///
    /// # Errors
    ///
    /// When the piece is larger than an operation may be, is not canonical,
    /// belongs to another batch, names an index the header does not declare,
    /// or does not prove against the header's layout.
    pub fn verified(
        piece: &[u8],
        batch: &crate::id::OperationId,
        header: &BatchHeader,
    ) -> Result<Self> {
        if piece.len() > limits::MAX_OPERATION_SIZE {
            return Err(Error::LimitExceeded("batch piece size"));
        }
        let mut reader = Reader::new(piece);
        let mut map = reader.map(BATCH_PIECE_SCHEMA)?;
        let named = crate::id::OperationId::decode(map.key("batch")?)?;
        if named != *batch {
            return Err(Error::InvalidValue("a piece of another batch"));
        }
        let index = map.key("index")?.u64()?;
        if index >= header.pieces {
            return Err(Error::InvalidValue("a piece the header does not declare"));
        }
        let proof = crate::merkle::Proof::decode(map.key("proof")?)?;
        let entries_reader = map.key("entries")?;
        let count = entries_reader.array(limits::MAX_OPERATION_SIZE, "batch piece entries")?;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(BatchEntry::decode(entries_reader)?);
        }
        map.finish()?;
        reader.finish()?;
        // Canonical decoding means these are the bytes that arrived.
        let body = encode_entries(&entries.iter().collect::<Vec<_>>());
        if !proof.verifies(&header.layout, &piece_position(index), &piece_hash(index, &body)) {
            return Err(Error::SignatureInvalid);
        }
        Ok(Self { batch: named, index, entries })
    }
}

/// Whether a whole set of entries is the one `header` commits to.
///
/// Every piece proved against the layout, but only the whole set rebuilding
/// the entries root, and counting what the header says, shows the pieces hold
/// exactly the batch: two pieces naming one device, or a layout over entries
/// other than those the root commits to, would otherwise admit something
/// other than what was signed.
#[must_use]
pub fn matches(header: &BatchHeader, entries: &[BatchEntry]) -> bool {
    entries.len() as u64 == header.count
        && entries_tree(entries).is_ok_and(|tree| tree.root() == header.entries)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::cbor::is_canonical_schema;

    fn header() -> BatchHeader {
        BatchHeader::new(
            Commitment { count: 500, entries: [7; 32], pieces: 40, layout: [8; 32] },
            Mode::Light,
            alloc::vec![Group::new("sensori").unwrap()],
            Some(Ipv4Range::new([100, 70, 0, 0], 16).unwrap()),
            "lotto 2026-10-24 A",
        )
        .unwrap()
    }

    fn round_trip(value: &BatchHeader) -> Result<BatchHeader> {
        let mut writer = Writer::new();
        value.encode(&mut writer);
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes);
        let decoded = BatchHeader::decode(&mut reader)?;
        reader.finish()?;
        Ok(decoded)
    }

    fn commitment(count: u64, pieces: u64) -> Commitment {
        Commitment { count, entries: [0; 32], pieces, layout: [0; 32] }
    }

    #[test]
    fn the_schemas_are_canonical() {
        assert!(is_canonical_schema(BATCH_HEADER_SCHEMA));
        assert!(is_canonical_schema(BATCH_PIECE_SCHEMA));
        assert!(is_canonical_schema(BATCH_ENTRY_SCHEMA));
    }

    #[test]
    fn a_header_round_trips() {
        assert_eq!(round_trip(&header()).unwrap(), header());
        let mut plain = header();
        plain.block = None;
        plain.groups.clear();
        assert_eq!(round_trip(&plain).unwrap(), plain);
    }

    #[test]
    fn an_empty_or_oversized_batch_is_refused() {
        let new = |commitment| BatchHeader::new(commitment, Mode::Full, alloc::vec![], None, "x");
        assert!(new(commitment(0, 1)).is_err());
        assert_eq!(new(commitment(65_537, 1)), Err(Error::LimitExceeded("batch entries")));
        assert!(new(commitment(10, 0)).is_err(), "no piece");
        assert!(new(commitment(10, 11)).is_err(), "more pieces than entries");
    }
}

/// Why an entry of a batch has no effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// The device is already a member.
    AlreadyMember,
    /// Another device already holds the address the entry was assigned.
    AddressTaken,
    /// The entry was assigned an address outside the header's block, or one
    /// when the header declares no block.
    AddressOutsideBlock,
}

/// The entries of a batch that would have no effect over `held`, and why.
///
/// Derivation calls this with the state the batch's own ancestors imply; an
/// admin's device calls it with its current state, to show what would be
/// skipped before signing. One function for both, so the preview and the
/// outcome cannot disagree.
///
/// Entries are judged in device order, whatever order they are given in: of
/// two entries assigned one address, the one naming the smaller device keeps
/// it, on every node.
#[must_use]
pub fn skipped(
    held: &crate::state::RosterState,
    header: &BatchHeader,
    entries: &[BatchEntry],
) -> alloc::collections::BTreeMap<crate::id::DeviceId, Skip> {
    // The addresses entries before this one took; those members hold are asked
    // of the state's index, rather than gathered from every member.
    let mut taken: alloc::collections::BTreeSet<[u8; 4]> = alloc::collections::BTreeSet::new();
    let mut ordered: Vec<(crate::id::DeviceId, &BatchEntry)> = entries
        .iter()
        .filter_map(|entry| entry.device_id().ok().map(|device| (device, entry)))
        .collect();
    ordered.sort_by_key(|(device, _)| *device);
    let mut out = alloc::collections::BTreeMap::new();
    for (device, entry) in ordered {
        if held.devices.contains_key(&device) {
            out.insert(device, Skip::AlreadyMember);
            continue;
        }
        let Some(address) = entry.ipv4 else { continue };
        if !header.block.is_some_and(|block| block.contains(address)) {
            out.insert(device, Skip::AddressOutsideBlock);
        } else if !held.devices.holding_address(address).is_empty() || !taken.insert(address) {
            out.insert(device, Skip::AddressTaken);
        }
    }
    out
}

//! A compressed sparse Merkle tree over 256-bit keys.
//!
//! The roster's state is committed as one of these: every leaf sits at a key
//! that is a hash of what it names, so where a leaf goes depends on the leaf
//! alone and never on the order things were added. A node that rebuilt the
//! state from history and a node that received it as a set of leaves compute
//! the same root.
//!
//! # Compressed
//!
//! A subtree holding a single leaf *is* that leaf: it is not padded with
//! internal nodes down to depth 256. A subtree holding nothing is the empty
//! hash. So a tree of N leaves has internal nodes only where at least two
//! leaves share a prefix, and a proof is about log2(N) hashes plus the empty
//! siblings between them, which an encoding can carry as a bitmap.
//!
//! The shape is a function of the key set: inserting and removing in any
//! order lands on the same tree. Removing collapses a branch left with one
//! leaf back into that leaf, which is what keeps it so.
//!
//! # Hashing
//!
//! Leaves and branches hash under different domain-separation contexts, so a
//! branch can never be read as a leaf. A leaf commits to its key as well as
//! its value: a leaf moved to another key is another leaf.
//!
//! # Where it can run
//!
//! This module uses `core` and `alloc` only, so that the verification half can
//! be built for a microcontroller.

use alloc::sync::Arc;
use alloc::vec::Vec;

/// A 32-byte hash: a key, a value's hash, or a node.
pub type Hash = [u8; 32];

/// The hash of an empty subtree.
pub const EMPTY: Hash = [0; 32];

/// The context a leaf hashes under.
const LEAF_CONTEXT: &str = "peerfectly membership tree leaf v1";

/// The context a branch hashes under.
const BRANCH_CONTEXT: &str = "peerfectly membership tree branch v1";

/// How many levels a key has.
const KEY_BITS: usize = 256;

/// The hash of a leaf holding `value` at `key`.
#[must_use]
pub fn leaf_hash(key: &Hash, value: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new_derive_key(LEAF_CONTEXT);
    hasher.update(key);
    hasher.update(value);
    *hasher.finalize().as_bytes()
}

/// The hash of a branch over two subtrees.
#[must_use]
pub fn branch_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new_derive_key(BRANCH_CONTEXT);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Bit `depth` of `key`, counted from the most significant bit of the first
/// byte. `false` goes left.
fn bit(key: &Hash, depth: usize) -> bool {
    let Some(byte) = depth.checked_shr(3).and_then(|index| key.get(index)) else {
        return false;
    };
    let shift = 7_u32.saturating_sub(u32::try_from(depth & 7).unwrap_or(0));
    byte.checked_shr(shift).is_some_and(|shifted| shifted & 1 == 1)
}

/// A node as a store keeps it: by its hash, holding its children's hashes
/// rather than the children.
///
/// A tree kept this way is believed only through its root. A node loaded by
/// its hash is checked to hash to it, so a walk down from a root that is
/// trusted is checked at every step, and a node the store altered is never
/// taken for the one asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stored {
    /// A leaf: where it sits, and what it holds.
    Leaf {
        /// Where it sits.
        key: Hash,
        /// What it holds.
        value: Hash,
    },
    /// A branch, by its two subtrees' hashes; [`EMPTY`] for an empty one.
    Branch {
        /// The subtree whose keys have this level's bit clear.
        left: Hash,
        /// The subtree whose keys have it set.
        right: Hash,
    },
}

/// How long a stored node's bytes are: a tag and two hashes.
pub const STORED_LEN: usize = 65;

impl Stored {
    /// The hash this node is kept under.
    #[must_use]
    pub fn hash(&self) -> Hash {
        match self {
            Self::Leaf { key, value } => leaf_hash(key, value),
            Self::Branch { left, right } => branch_hash(left, right),
        }
    }

    /// The node's bytes: `0` and key and value for a leaf, `1` and the two
    /// subtrees' hashes for a branch.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; STORED_LEN] {
        let (tag, first, second) = match self {
            Self::Leaf { key, value } => (0, key, value),
            Self::Branch { left, right } => (1, left, right),
        };
        let mut bytes = [0; STORED_LEN];
        let (head, rest) = bytes.split_at_mut(1);
        let (one, two) = rest.split_at_mut(32);
        head.copy_from_slice(&[tag]);
        one.copy_from_slice(first);
        two.copy_from_slice(second);
        bytes
    }

    /// Reads a node's bytes. `None` for anything [`Stored::to_bytes`] does not
    /// write.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (&tag, rest) = bytes.split_first()?;
        let (first, second) = rest.split_at_checked(32)?;
        let first = Hash::try_from(first).ok()?;
        let second = Hash::try_from(second).ok()?;
        match tag {
            0 => Some(Self::Leaf { key: first, value: second }),
            1 => Some(Self::Branch { left: first, right: second }),
            _ => None,
        }
    }
}

/// Where a tree's nodes are kept when they are not in memory.
pub trait NodeSource: Send + Sync {
    /// The node kept under `hash`, if the source holds one. The tree checks
    /// that it hashes to `hash`.
    fn node(&self, hash: &Hash) -> Option<Stored>;

    /// Told when a node the source gave, or failed to give, is not the one a
    /// trusted parent names: whatever keeps the nodes was changed by someone
    /// other than the tree. The tree goes on as if the subtree were empty,
    /// which no honest tree has, so its roots stop agreeing with anyone's;
    /// what holds the source is to stop believing it.
    fn tampered(&self);
}

/// One node of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    /// Nothing below.
    Empty,
    /// One leaf, standing for its whole subtree.
    Leaf {
        /// Where it sits.
        key: Hash,
        /// What it holds.
        value: Hash,
    },
    /// At least two leaves below, split at this level.
    ///
    /// The subtrees are shared, not owned: a tree is copied by reference, and a
    /// change copies only the path from the root to what changed. That is what
    /// lets every state derived from a roster keep its own tree without paying
    /// for the whole of it.
    Branch {
        /// This branch's hash, kept so that a root costs nothing to read.
        hash: Hash,
        /// The subtree whose keys have this level's bit clear.
        left: Arc<Node>,
        /// The subtree whose keys have it set.
        right: Arc<Node>,
    },
    /// A subtree left in the tree's source, known here by its hash, and
    /// loaded when a walk goes into it.
    Stored(Hash),
}

/// What a walk into stored subtrees needs: where they are, and, for a change,
/// where to note the stored nodes it replaced.
struct Lazy<'a> {
    source: Option<&'a dyn NodeSource>,
    dropped: &'a mut Vec<Hash>,
}

impl Node {
    fn hash(&self) -> Hash {
        match self {
            Self::Empty => EMPTY,
            Self::Leaf { key, value } => leaf_hash(key, value),
            Self::Branch { hash, .. } | Self::Stored(hash) => *hash,
        }
    }

    /// The subtree with this hash, as a node to be loaded when needed.
    fn stub(hash: Hash) -> Self {
        if hash == EMPTY { Self::Empty } else { Self::Stored(hash) }
    }

    /// The node kept under `hash`, checked, with its children left stored.
    fn load(hash: &Hash, source: Option<&dyn NodeSource>) -> Self {
        let Some(source) = source else { return Self::Empty };
        match source.node(hash) {
            Some(stored) if stored.hash() == *hash => match stored {
                Stored::Leaf { key, value } => Self::Leaf { key, value },
                Stored::Branch { left, right } => Self::Branch {
                    hash: *hash,
                    left: Arc::new(Self::stub(left)),
                    right: Arc::new(Self::stub(right)),
                },
            },
            _ => {
                source.tampered();
                Self::Empty
            }
        }
    }

    /// This node, loaded if it is stored, for reading.
    fn read(&self, source: Option<&dyn NodeSource>) -> Option<Self> {
        match self {
            Self::Stored(hash) => Some(Self::load(hash, source)),
            _ => None,
        }
    }

    /// This node, loaded if it is stored, to be changed: a stored node loaded
    /// for a change is replaced by what the change makes of it.
    fn open(self, lazy: &mut Lazy<'_>) -> Self {
        match self {
            Self::Stored(hash) => {
                lazy.dropped.push(hash);
                Self::load(&hash, lazy.source)
            }
            node => node,
        }
    }

    fn branch(left: Self, right: Self) -> Self {
        Self::shared(Arc::new(left), Arc::new(right))
    }

    /// A branch over two subtrees already shared.
    fn shared(left: Arc<Self>, right: Arc<Self>) -> Self {
        let hash = branch_hash(&left.hash(), &right.hash());
        Self::Branch { hash, left, right }
    }

    /// A subtree holding exactly these two leaves, rooted at `depth`.
    ///
    /// Recurses while the keys agree, so the two land at the shallowest level
    /// where they differ.
    fn two(first: (Hash, Hash), second: (Hash, Hash), depth: usize) -> Self {
        if depth >= KEY_BITS {
            // Two different keys always differ somewhere in 256 bits; equal
            // keys never reach here. Keeping the first is the harmless answer.
            return Self::Leaf { key: first.0, value: first.1 };
        }
        let first_side = bit(&first.0, depth);
        let second_side = bit(&second.0, depth);
        let first_leaf = || Self::Leaf { key: first.0, value: first.1 };
        let second_leaf = || Self::Leaf { key: second.0, value: second.1 };
        let next = depth.saturating_add(1);
        match (first_side, second_side) {
            (false, true) => Self::branch(first_leaf(), second_leaf()),
            (true, false) => Self::branch(second_leaf(), first_leaf()),
            (false, false) => Self::branch(Self::two(first, second, next), Self::Empty),
            (true, true) => Self::branch(Self::Empty, Self::two(first, second, next)),
        }
    }

    fn insert(self, key: Hash, value: Hash, depth: usize, lazy: &mut Lazy<'_>) -> Self {
        match self.open(lazy) {
            Self::Empty | Self::Stored(_) => Self::Leaf { key, value },
            Self::Leaf { key: held, value: _ } if held == key => Self::Leaf { key, value },
            Self::Leaf { key: held, value: held_value } => {
                Self::two((held, held_value), (key, value), depth)
            }
            Self::Branch { left, right, .. } => {
                let next = depth.saturating_add(1);
                // Only the side the key goes down is rebuilt; the other is kept
                // as it is, shared with every copy that holds it.
                if bit(&key, depth) {
                    let right = Arc::unwrap_or_clone(right).insert(key, value, next, lazy);
                    Self::shared(left, Arc::new(right))
                } else {
                    let left = Arc::unwrap_or_clone(left).insert(key, value, next, lazy);
                    Self::shared(Arc::new(left), right)
                }
            }
        }
    }

    /// Removes `key`, collapsing any branch left holding a single leaf.
    fn remove(self, key: &Hash, depth: usize, lazy: &mut Lazy<'_>) -> Self {
        match self.open(lazy) {
            Self::Empty | Self::Stored(_) => Self::Empty,
            Self::Leaf { key: held, .. } if held == *key => Self::Empty,
            leaf @ Self::Leaf { .. } => leaf,
            Self::Branch { left, right, .. } => {
                let next = depth.saturating_add(1);
                let (left, right) = if bit(key, depth) {
                    (left, Arc::new(Arc::unwrap_or_clone(right).remove(key, next, lazy)))
                } else {
                    (Arc::new(Arc::unwrap_or_clone(left).remove(key, next, lazy)), right)
                };
                // A side left stored may be a single leaf, which must come up
                // in place of the branch: only loading it tells.
                let (left, right) = match (&*left, &*right) {
                    (Self::Empty, Self::Stored(_)) => {
                        (left, Arc::new(Arc::unwrap_or_clone(right).open(lazy)))
                    }
                    (Self::Stored(_), Self::Empty) => {
                        (Arc::new(Arc::unwrap_or_clone(left).open(lazy)), right)
                    }
                    _ => (left, right),
                };
                match (&*left, &*right) {
                    (Self::Empty, Self::Empty) => Self::Empty,
                    (Self::Empty, Self::Leaf { .. }) => Arc::unwrap_or_clone(right),
                    (Self::Leaf { .. }, Self::Empty) => Arc::unwrap_or_clone(left),
                    _ => Self::shared(left, right),
                }
            }
        }
    }

    fn get(&self, key: &Hash, depth: usize, source: Option<&dyn NodeSource>) -> Option<Hash> {
        if let Some(loaded) = self.read(source) {
            return loaded.get(key, depth, source);
        }
        match self {
            Self::Empty | Self::Stored(_) => None,
            Self::Leaf { key: held, value } => (held == key).then_some(*value),
            Self::Branch { left, right, .. } => {
                let next = depth.saturating_add(1);
                if bit(key, depth) {
                    right.get(key, next, source)
                } else {
                    left.get(key, next, source)
                }
            }
        }
    }

    /// Collects the siblings on the way to `key`, top first, if it is held.
    fn prove(
        &self,
        key: &Hash,
        depth: usize,
        siblings: &mut Vec<Option<Hash>>,
        source: Option<&dyn NodeSource>,
    ) -> bool {
        if let Some(loaded) = self.read(source) {
            return loaded.prove(key, depth, siblings, source);
        }
        match self {
            Self::Empty | Self::Stored(_) => false,
            Self::Leaf { key: held, .. } => held == key,
            Self::Branch { left, right, .. } => {
                let next = depth.saturating_add(1);
                let (towards, away) = if bit(key, depth) { (right, left) } else { (left, right) };
                let sibling = away.hash();
                siblings.push((sibling != EMPTY).then_some(sibling));
                towards.prove(key, next, siblings, source)
            }
        }
    }

    fn count(&self, source: Option<&dyn NodeSource>) -> usize {
        if let Some(loaded) = self.read(source) {
            return loaded.count(source);
        }
        match self {
            Self::Empty | Self::Stored(_) => 0,
            Self::Leaf { .. } => 1,
            Self::Branch { left, right, .. } => {
                left.count(source).saturating_add(right.count(source))
            }
        }
    }

    /// Hands every node held in memory to `emit`, stopping at stored ones.
    fn fresh(&self, emit: &mut dyn FnMut(Hash, Stored)) {
        match self {
            Self::Empty | Self::Stored(_) => {}
            Self::Leaf { key, value } => {
                emit(self.hash(), Stored::Leaf { key: *key, value: *value });
            }
            Self::Branch { hash, left, right } => {
                emit(*hash, Stored::Branch { left: left.hash(), right: right.hash() });
                left.fresh(emit);
                right.fresh(emit);
            }
        }
    }
}

/// A proof that a value sits at a key under some root.
///
/// The siblings run from the root down to the level where the leaf stands
/// alone; `None` is an empty sibling, which an encoding carries as one bit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// Each level's sibling, top first; `None` where it is empty.
    pub siblings: Vec<Option<Hash>>,
}

impl Proof {
    /// How many non-empty hashes the proof carries.
    #[must_use]
    pub fn hashes(&self) -> usize {
        self.siblings.iter().filter(|sibling| sibling.is_some()).count()
    }

    /// The root this proof leads to for `value` at `key`.
    ///
    /// `None` when the proof is longer than a key has levels, which no tree
    /// produces.
    #[must_use]
    pub fn root_for(&self, key: &Hash, value: &Hash) -> Option<Hash> {
        if self.siblings.len() > KEY_BITS {
            return None;
        }
        let mut hash = leaf_hash(key, value);
        for (depth, sibling) in self.siblings.iter().enumerate().rev() {
            let sibling = sibling.unwrap_or(EMPTY);
            hash = if bit(key, depth) {
                branch_hash(&sibling, &hash)
            } else {
                branch_hash(&hash, &sibling)
            };
        }
        Some(hash)
    }

    /// Whether `value` sits at `key` under `root`.
    #[must_use]
    pub fn verifies(&self, root: &Hash, key: &Hash, value: &Hash) -> bool {
        self.root_for(key, value).is_some_and(|computed| computed == *root)
    }

    /// Writes the proof: its depth, a bitmap of the non-empty siblings, and
    /// those siblings' hashes, top first.
    ///
    /// The bitmap has exactly one bit per level, padded to whole bytes with
    /// zeros, so a proof has one encoding.
    pub(crate) fn encode(&self, writer: &mut crate::cbor::Writer) {
        let mut bits = alloc::vec![0_u8; self.siblings.len().div_ceil(8)];
        for (level, sibling) in self.siblings.iter().enumerate() {
            if sibling.is_some()
                && let Some(byte) = level.checked_shr(3).and_then(|index| bits.get_mut(index))
            {
                let shift = 7_u32.saturating_sub(u32::try_from(level & 7).unwrap_or(0));
                *byte |= 1_u8.checked_shl(shift).unwrap_or(0);
            }
        }
        writer.map(3);
        writer.key("bits").bytes(&bits);
        writer.key("depth").u64(self.siblings.len() as u64);
        writer.key("hashes").array(self.hashes() as u64);
        for hash in self.siblings.iter().flatten() {
            writer.bytes(hash);
        }
    }

    /// Reads a proof, refusing any second spelling of one.
    pub(crate) fn decode(reader: &mut crate::cbor::Reader<'_>) -> crate::error::Result<Self> {
        use crate::error::Error;
        let mut map = reader.map(PROOF_SCHEMA)?;
        let bits = map.key("bits")?.bytes(KEY_BITS.div_ceil(8), "proof bitmap")?.to_vec();
        let depth = usize::try_from(map.key("depth")?.u64()?).map_err(|_| Error::NonCanonical)?;
        if depth > KEY_BITS || bits.len() != depth.div_ceil(8) {
            return Err(Error::NonCanonical);
        }
        let present = |level: usize| {
            level.checked_shr(3).and_then(|index| bits.get(index)).is_some_and(|byte| {
                let shift = 7_u32.saturating_sub(u32::try_from(level & 7).unwrap_or(0));
                byte.checked_shr(shift).is_some_and(|shifted| shifted & 1 == 1)
            })
        };
        // Padding bits past the depth must be zero.
        let set_bits: usize = bits.iter().map(|byte| byte.count_ones() as usize).sum();
        let counted = (0..depth).filter(|level| present(*level)).count();
        if set_bits != counted {
            return Err(Error::NonCanonical);
        }
        let reader = map.key("hashes")?;
        let count = reader.array(KEY_BITS, "proof hashes")?;
        if count != counted {
            return Err(Error::NonCanonical);
        }
        let mut hashes = Vec::with_capacity(count);
        for _ in 0..count {
            let bytes = reader.fixed_bytes(32)?;
            let hash = Hash::try_from(bytes).map_err(|_| Error::IdentifierLength)?;
            // An empty sibling is a clear bit, never the empty hash spelled out.
            if hash == EMPTY {
                return Err(Error::NonCanonical);
            }
            hashes.push(hash);
        }
        map.finish()?;
        let mut hashes = hashes.into_iter();
        let siblings =
            (0..depth).map(|level| if present(level) { hashes.next() } else { None }).collect();
        Ok(Self { siblings })
    }
}

/// Canonical key order of an encoded proof.
pub const PROOF_SCHEMA: &[&str] = &["bits", "depth", "hashes"];

/// A compressed sparse Merkle tree.
///
/// Held in memory, or rooted in a [`NodeSource`] and loaded as walks reach
/// into it: then only the paths a change made are in memory, and the stored
/// nodes those paths replaced are noted, so that whoever keeps the source can
/// write the change as the paths it made and the nodes it no longer needs.
#[derive(Clone, Default)]
pub struct Tree {
    root: Node,
    source: Option<Arc<dyn NodeSource>>,
    stored: Option<Hash>,
    dropped: Vec<Hash>,
}

impl Default for Node {
    fn default() -> Self {
        Self::Empty
    }
}

impl core::fmt::Debug for Tree {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tree").field("root", &self.root()).finish_non_exhaustive()
    }
}

/// Two trees are equal when their roots are: the root commits to every leaf,
/// however much of either is in memory.
impl PartialEq for Tree {
    fn eq(&self, other: &Self) -> bool {
        self.root() == other.root()
    }
}

impl Eq for Tree {}

impl Tree {
    /// An empty tree, whose root is [`EMPTY`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The tree with this root, its nodes kept in `source`.
    #[must_use]
    pub fn stored(root: Hash, source: Arc<dyn NodeSource>) -> Self {
        Self { root: Node::stub(root), source: Some(source), stored: Some(root), dropped: Vec::new() }
    }

    /// The root the tree was rooted at in its source, if it was: what tells
    /// two trees over one source apart once one of them has been written.
    #[must_use]
    pub const fn stored_root(&self) -> Option<Hash> {
        self.stored
    }

    fn source(&self) -> Option<&dyn NodeSource> {
        self.source.as_deref()
    }

    /// Puts `value` at `key`, replacing what was there.
    pub fn insert(&mut self, key: Hash, value: Hash) {
        let root = core::mem::take(&mut self.root);
        let mut lazy = Lazy { source: self.source.as_deref(), dropped: &mut self.dropped };
        self.root = root.insert(key, value, 0, &mut lazy);
    }

    /// Removes what is at `key`, if anything.
    pub fn remove(&mut self, key: &Hash) {
        let root = core::mem::take(&mut self.root);
        let mut lazy = Lazy { source: self.source.as_deref(), dropped: &mut self.dropped };
        self.root = root.remove(key, 0, &mut lazy);
    }

    /// The value at `key`, if any.
    #[must_use]
    pub fn get(&self, key: &Hash) -> Option<Hash> {
        self.root.get(key, 0, self.source())
    }

    /// The tree's root.
    #[must_use]
    pub fn root(&self) -> Hash {
        self.root.hash()
    }

    /// How many leaves the tree holds. A stored tree is walked whole.
    #[must_use]
    pub fn len(&self) -> usize {
        self.root.count(self.source())
    }

    /// Whether the tree holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self.root, Node::Empty)
    }

    /// A proof that the value now at `key` is there, or `None` if nothing is.
    #[must_use]
    pub fn prove(&self, key: &Hash) -> Option<Proof> {
        let mut siblings = Vec::new();
        self.root.prove(key, 0, &mut siblings, self.source()).then_some(Proof { siblings })
    }

    /// The stored nodes changes to this tree replaced, since it was rooted in
    /// its source. Some may be made again, unchanged, by the same changes:
    /// whoever writes the change removes these first and then puts every
    /// [`Tree::fresh`] node.
    #[must_use]
    pub fn dropped(&self) -> &[Hash] {
        &self.dropped
    }

    /// Hands every node of the tree held in memory, and not in its source, to
    /// `emit`: for a stored tree, the paths its changes made.
    pub fn fresh(&self, emit: &mut dyn FnMut(Hash, Stored)) {
        self.root.fresh(emit);
    }
}

/// Builds a tree's nodes from its leaves in key order, holding no more than a
/// path of it: what writes a store of a million leaves without a million in
/// memory. Every node goes to `emit` once, and the root is what
/// [`Tree::root`] would be over the same leaves.
pub struct Builder<F: FnMut(Hash, Stored)> {
    emit: F,
    /// Subtrees not yet joined, left to right: a key in each, the level of
    /// its top branch (none for a lone leaf), and its hash there.
    open: Vec<(Hash, Option<usize>, Hash)>,
    /// Between each two neighbours in `open`, the level they split at.
    splits: Vec<usize>,
    last: Option<Hash>,
}

impl<F: FnMut(Hash, Stored)> Builder<F> {
    /// A builder handing its nodes to `emit`.
    pub const fn new(emit: F) -> Self {
        Self { emit, open: Vec::new(), splits: Vec::new(), last: None }
    }

    /// Adds a leaf. Keys must come in increasing order: a key that does not
    /// is refused, and `false` returned.
    pub fn push(&mut self, key: Hash, value: Hash) -> bool {
        if self.last.is_some_and(|last| last >= key) {
            return false;
        }
        let leaf = Stored::Leaf { key, value };
        let hash = leaf.hash();
        (self.emit)(hash, leaf);
        if let Some(last) = self.last {
            // Sorted keys: the level the new leaf splits from the one before
            // is shallower than any split still open to its right of it.
            let split = common_prefix(&last, &key);
            while self.splits.last().is_some_and(|open| *open > split) {
                self.join_top();
            }
            self.splits.push(split);
        }
        self.open.push((key, None, hash));
        self.last = Some(key);
        true
    }

    /// The root over every leaf pushed.
    pub fn finish(mut self) -> Hash {
        while !self.splits.is_empty() {
            self.join_top();
        }
        match self.open.pop() {
            None => EMPTY,
            Some(top) => self.lifted(top, 0),
        }
    }

    /// Joins the two rightmost open subtrees at the level they split at.
    fn join_top(&mut self) {
        let (Some(split), Some(right), Some(left)) =
            (self.splits.pop(), self.open.pop(), self.open.pop())
        else {
            return;
        };
        let below = split.saturating_add(1);
        let left_hash = self.lifted(left, below);
        let right_hash = self.lifted(right, below);
        let branch = Stored::Branch { left: left_hash, right: right_hash };
        let hash = branch.hash();
        (self.emit)(hash, branch);
        self.open.push((left.0, Some(split), hash));
    }

    /// A subtree's hash seen from level `to`: the branches with one empty
    /// side between there and its top. A lone leaf stands at any level.
    fn lifted(&mut self, (key, top, hash): (Hash, Option<usize>, Hash), to: usize) -> Hash {
        let Some(top) = top else { return hash };
        let mut hash = hash;
        for level in (to..top).rev() {
            let branch = if bit(&key, level) {
                Stored::Branch { left: EMPTY, right: hash }
            } else {
                Stored::Branch { left: hash, right: EMPTY }
            };
            hash = branch.hash();
            (self.emit)(hash, branch);
        }
        hash
    }
}

/// How many leading bits two keys share.
fn common_prefix(first: &Hash, second: &Hash) -> usize {
    let mut shared = 0_usize;
    for (one, two) in first.iter().zip(second) {
        let differ = one ^ two;
        if differ != 0 {
            return shared.saturating_add(differ.leading_zeros() as usize);
        }
        shared = shared.saturating_add(8);
    }
    shared
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::*;
    use proptest::prelude::*;

    fn key(n: u32) -> Hash {
        *blake3::hash(&n.to_be_bytes()).as_bytes()
    }

    fn value(n: u32) -> Hash {
        *blake3::hash(&(n ^ 0xdead_beef).to_be_bytes()).as_bytes()
    }

    #[test]
    fn an_empty_tree_has_the_empty_root() {
        let tree = Tree::new();
        assert_eq!(tree.root(), EMPTY);
        assert!(tree.is_empty());
        assert_eq!(tree.prove(&key(1)), None);
    }

    #[test]
    fn a_single_leaf_is_the_root_and_proves_with_no_siblings() {
        let mut tree = Tree::new();
        tree.insert(key(1), value(1));
        assert_eq!(tree.root(), leaf_hash(&key(1), &value(1)));
        let proof = tree.prove(&key(1)).unwrap();
        assert!(proof.siblings.is_empty());
        assert!(proof.verifies(&tree.root(), &key(1), &value(1)));
    }

    #[test]
    fn every_leaf_proves_and_an_altered_one_does_not() {
        let mut tree = Tree::new();
        for n in 0..200 {
            tree.insert(key(n), value(n));
        }
        let root = tree.root();
        for n in 0..200 {
            let proof = tree.prove(&key(n)).unwrap();
            assert!(proof.verifies(&root, &key(n), &value(n)), "leaf {n}");
            assert!(!proof.verifies(&root, &key(n), &value(n + 1)), "altered value {n}");
            assert!(!proof.verifies(&root, &key(n + 1000), &value(n)), "moved leaf {n}");
        }
    }

    #[test]
    fn a_removed_leaf_no_longer_proves() {
        let mut tree = Tree::new();
        for n in 0..50 {
            tree.insert(key(n), value(n));
        }
        let old = tree.prove(&key(7)).unwrap();
        tree.remove(&key(7));
        assert_eq!(tree.prove(&key(7)), None);
        assert!(!old.verifies(&tree.root(), &key(7), &value(7)));
        assert_eq!(tree.len(), 49);
    }

    #[test]
    fn replacing_a_value_changes_the_root_and_proves_the_new_one() {
        let mut tree = Tree::new();
        for n in 0..20 {
            tree.insert(key(n), value(n));
        }
        let before = tree.root();
        tree.insert(key(3), value(99));
        assert_ne!(tree.root(), before);
        assert_eq!(tree.len(), 20);
        let proof = tree.prove(&key(3)).unwrap();
        assert!(proof.verifies(&tree.root(), &key(3), &value(99)));
        assert!(!proof.verifies(&tree.root(), &key(3), &value(3)));
    }

    #[test]
    fn a_proof_is_about_the_logarithm_of_the_leaf_count() {
        let mut tree = Tree::new();
        for n in 0..65_536 {
            tree.insert(key(n), value(n));
        }
        let longest = (0..65_536).map(|n| tree.prove(&key(n)).unwrap().hashes()).max().unwrap();
        // log2(65536) = 16; random keys put a few leaves some levels deeper.
        assert!(longest <= 40, "longest proof carried {longest} hashes");
    }

    fn encoded(proof: &Proof) -> Vec<u8> {
        let mut writer = crate::cbor::Writer::new();
        proof.encode(&mut writer);
        writer.finish()
    }

    fn decoded(bytes: &[u8]) -> crate::error::Result<Proof> {
        let mut reader = crate::cbor::Reader::new(bytes);
        let proof = Proof::decode(&mut reader)?;
        reader.finish()?;
        Ok(proof)
    }

    #[test]
    fn a_proof_round_trips_through_its_encoding() {
        assert!(crate::cbor::is_canonical_schema(PROOF_SCHEMA));
        let mut tree = Tree::new();
        for n in 0..300 {
            tree.insert(key(n), value(n));
        }
        for n in [0, 17, 299] {
            let proof = tree.prove(&key(n)).unwrap();
            let bytes = encoded(&proof);
            assert_eq!(decoded(&bytes).unwrap(), proof);
            assert!(bytes.len() < 40 * 33, "about one hash per level: {} bytes", bytes.len());
        }
        let alone = Proof { siblings: vec![] };
        assert_eq!(decoded(&encoded(&alone)).unwrap(), alone);
    }

    #[test]
    fn a_proof_with_padding_bits_set_is_refused() {
        let mut writer = crate::cbor::Writer::new();
        writer.map(3);
        writer.key("bits").bytes(&[0b0000_0001]);
        writer.key("depth").u64(3);
        writer.key("hashes").array(1);
        writer.bytes(&[7; 32]);
        assert_eq!(decoded(&writer.finish()), Err(crate::error::Error::NonCanonical));
    }

    #[test]
    fn a_proof_longer_than_a_key_is_refused() {
        let proof = Proof { siblings: vec![None; KEY_BITS + 1] };
        assert_eq!(proof.root_for(&key(1), &value(1)), None);
    }

    proptest! {
        #[test]
        fn the_root_depends_on_the_set_and_not_the_order(
            mut keys in proptest::collection::vec(0u32..5000, 1..120),
            seed in any::<u64>(),
        ) {
            keys.sort_unstable();
            keys.dedup();
            let mut forward = Tree::new();
            for n in &keys {
                forward.insert(key(*n), value(*n));
            }
            // A different order, chosen by the seed.
            let mut shuffled = keys.clone();
            let len = shuffled.len();
            for index in 0..len {
                let other = (seed.wrapping_mul(index as u64 + 1) % len as u64) as usize;
                shuffled.swap(index, other);
            }
            let mut backward = Tree::new();
            for n in &shuffled {
                backward.insert(key(*n), value(*n));
            }
            prop_assert_eq!(forward.root(), backward.root());
            prop_assert_eq!(&forward, &backward);
        }

        #[test]
        fn removing_what_was_added_returns_the_tree_it_was(
            mut base in proptest::collection::vec(0u32..5000, 0..80),
            mut extra in proptest::collection::vec(5000u32..10000, 1..40),
        ) {
            base.sort_unstable();
            base.dedup();
            extra.sort_unstable();
            extra.dedup();
            let mut tree = Tree::new();
            for n in &base {
                tree.insert(key(*n), value(*n));
            }
            let before = tree.clone();
            for n in &extra {
                tree.insert(key(*n), value(*n));
            }
            for n in extra.iter().rev() {
                tree.remove(&key(*n));
            }
            prop_assert_eq!(tree.root(), before.root());
            prop_assert_eq!(tree, before);
        }
    }

    /// Nodes kept in a map, as a store would keep them, counting how often a
    /// node was not what it was asked for.
    #[derive(Default)]
    struct Kept {
        nodes: std::sync::Mutex<std::collections::BTreeMap<Hash, Stored>>,
        tampered: std::sync::atomic::AtomicUsize,
    }

    impl NodeSource for Kept {
        fn node(&self, hash: &Hash) -> Option<Stored> {
            self.nodes.lock().unwrap().get(hash).copied()
        }

        fn tampered(&self) {
            self.tampered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Kept {
        /// A store of the tree over these leaves, built a leaf at a time.
        fn built(leaves: &[u32]) -> (Arc<Self>, Hash) {
            let kept = Arc::new(Self::default());
            let mut sorted: Vec<(Hash, Hash)> =
                leaves.iter().map(|n| (key(*n), value(*n))).collect();
            sorted.sort_unstable();
            sorted.dedup_by_key(|(key, _)| *key);
            let mut builder = Builder::new(|hash, node| {
                kept.nodes.lock().unwrap().insert(hash, node);
            });
            for (key, value) in sorted {
                assert!(builder.push(key, value));
            }
            let root = builder.finish();
            (kept, root)
        }

        /// Writes a changed tree as a store does: what it replaced out, then
        /// what it made in.
        fn write(&self, tree: &Tree) {
            let mut nodes = self.nodes.lock().unwrap();
            for hash in tree.dropped() {
                nodes.remove(hash);
            }
            tree.fresh(&mut |hash, node| {
                nodes.insert(hash, node);
            });
        }

        /// The hashes of every node reachable from `root`.
        fn reachable(&self, root: Hash) -> std::collections::BTreeSet<Hash> {
            let nodes = self.nodes.lock().unwrap();
            let mut seen = std::collections::BTreeSet::new();
            let mut walk = vec![root];
            while let Some(hash) = walk.pop() {
                if hash == EMPTY || !seen.insert(hash) {
                    continue;
                }
                if let Some(Stored::Branch { left, right }) = nodes.get(&hash) {
                    walk.push(*left);
                    walk.push(*right);
                }
            }
            seen
        }
    }

    #[test]
    fn a_builder_refuses_keys_out_of_order() {
        let mut builder = Builder::new(|_, _| {});
        let (low, high) = if key(1) < key(2) { (key(1), key(2)) } else { (key(2), key(1)) };
        assert!(builder.push(high, value(1)));
        assert!(!builder.push(low, value(2)), "a lower key");
        assert!(!builder.push(high, value(3)), "the same key");
    }

    #[test]
    fn an_altered_node_is_caught_on_the_way_down() {
        let leaves: Vec<u32> = (0..200).collect();
        let (kept, root) = Kept::built(&leaves);
        let tree = Tree::stored(root, kept.clone());
        assert_eq!(tree.get(&key(7)), Some(value(7)));
        assert_eq!(kept.tampered.load(std::sync::atomic::Ordering::SeqCst), 0);

        // The leaf of 7 swapped for one holding another value, kept under the
        // same hash: the store says it is the node asked for, and it is not.
        let leaf_hash = leaf_hash(&key(7), &value(7));
        kept.nodes
            .lock()
            .unwrap()
            .insert(leaf_hash, Stored::Leaf { key: key(7), value: value(8) });
        assert_eq!(tree.get(&key(7)), None, "not believed");
        assert_eq!(tree.prove(&key(7)), None);
        assert!(kept.tampered.load(std::sync::atomic::Ordering::SeqCst) > 0, "and reported");
    }

    proptest! {
        #[test]
        fn a_built_tree_is_the_tree_of_its_leaves(
            leaves in proptest::collection::vec(any::<u32>(), 0..300),
        ) {
            let mut tree = Tree::new();
            for n in &leaves {
                tree.insert(key(*n), value(*n));
            }
            let (kept, root) = Kept::built(&leaves);
            prop_assert_eq!(root, tree.root());

            // The nodes it wrote are the tree's, all of them and no more.
            let mut nodes = std::collections::BTreeMap::new();
            tree.fresh(&mut |hash, node| {
                nodes.insert(hash, node);
            });
            prop_assert_eq!(&*kept.nodes.lock().unwrap(), &nodes);

            let stored = Tree::stored(root, kept.clone());
            prop_assert_eq!(stored.len(), tree.len());
            for n in &leaves {
                prop_assert_eq!(stored.get(&key(*n)), Some(value(*n)));
                prop_assert_eq!(stored.prove(&key(*n)), tree.prove(&key(*n)));
            }
            prop_assert_eq!(kept.tampered.load(std::sync::atomic::Ordering::SeqCst), 0);
        }

        #[test]
        fn a_stored_tree_changes_as_one_in_memory_and_writes_only_what_it_reaches(
            base in proptest::collection::vec(0u32..400, 0..200),
            changes in proptest::collection::vec((any::<bool>(), 0u32..500, 0u32..3), 0..60),
        ) {
            let (kept, root) = Kept::built(&base);
            let mut stored = Tree::stored(root, kept.clone());
            let mut memory = Tree::new();
            for n in &base {
                memory.insert(key(*n), value(*n));
            }
            for (insert, n, salt) in &changes {
                if *insert {
                    stored.insert(key(*n), value(n ^ salt));
                    memory.insert(key(*n), value(n ^ salt));
                } else {
                    stored.remove(&key(*n));
                    memory.remove(&key(*n));
                }
                prop_assert_eq!(stored.root(), memory.root());
            }

            kept.write(&stored);
            let written = Tree::stored(stored.root(), kept.clone());
            prop_assert_eq!(written.len(), memory.len());
            prop_assert_eq!(
                kept.nodes.lock().unwrap().keys().copied().collect::<std::collections::BTreeSet<_>>(),
                kept.reachable(stored.root()),
                "no node left behind, none missing"
            );
            prop_assert_eq!(kept.tampered.load(std::sync::atomic::Ordering::SeqCst), 0);
        }
    }
}

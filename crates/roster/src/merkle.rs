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

use alloc::boxed::Box;
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
    Branch {
        /// This branch's hash, kept so that a root costs nothing to read.
        hash: Hash,
        /// The subtree whose keys have this level's bit clear.
        left: Box<Node>,
        /// The subtree whose keys have it set.
        right: Box<Node>,
    },
}

impl Node {
    fn hash(&self) -> Hash {
        match self {
            Self::Empty => EMPTY,
            Self::Leaf { key, value } => leaf_hash(key, value),
            Self::Branch { hash, .. } => *hash,
        }
    }

    fn branch(left: Self, right: Self) -> Self {
        let hash = branch_hash(&left.hash(), &right.hash());
        Self::Branch { hash, left: Box::new(left), right: Box::new(right) }
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

    fn insert(self, key: Hash, value: Hash, depth: usize) -> Self {
        match self {
            Self::Empty => Self::Leaf { key, value },
            Self::Leaf { key: held, value: _ } if held == key => Self::Leaf { key, value },
            Self::Leaf { key: held, value: held_value } => {
                Self::two((held, held_value), (key, value), depth)
            }
            Self::Branch { left, right, .. } => {
                let next = depth.saturating_add(1);
                if bit(&key, depth) {
                    Self::branch(*left, right.insert(key, value, next))
                } else {
                    Self::branch(left.insert(key, value, next), *right)
                }
            }
        }
    }

    /// Removes `key`, collapsing any branch left holding a single leaf.
    fn remove(self, key: &Hash, depth: usize) -> Self {
        match self {
            Self::Empty => Self::Empty,
            Self::Leaf { key: held, .. } if held == *key => Self::Empty,
            leaf @ Self::Leaf { .. } => leaf,
            Self::Branch { left, right, .. } => {
                let next = depth.saturating_add(1);
                let (left, right) = if bit(key, depth) {
                    (*left, right.remove(key, next))
                } else {
                    (left.remove(key, next), *right)
                };
                match (left, right) {
                    (Self::Empty, Self::Empty) => Self::Empty,
                    (Self::Empty, leaf @ Self::Leaf { .. })
                    | (leaf @ Self::Leaf { .. }, Self::Empty) => leaf,
                    (left, right) => Self::branch(left, right),
                }
            }
        }
    }

    fn get(&self, key: &Hash, depth: usize) -> Option<&Hash> {
        match self {
            Self::Empty => None,
            Self::Leaf { key: held, value } => (held == key).then_some(value),
            Self::Branch { left, right, .. } => {
                let next = depth.saturating_add(1);
                if bit(key, depth) { right.get(key, next) } else { left.get(key, next) }
            }
        }
    }

    /// Collects the siblings on the way to `key`, top first, if it is held.
    fn prove(&self, key: &Hash, depth: usize, siblings: &mut Vec<Option<Hash>>) -> bool {
        match self {
            Self::Empty => false,
            Self::Leaf { key: held, .. } => held == key,
            Self::Branch { left, right, .. } => {
                let next = depth.saturating_add(1);
                let (towards, away) = if bit(key, depth) { (right, left) } else { (left, right) };
                let sibling = away.hash();
                siblings.push((sibling != EMPTY).then_some(sibling));
                towards.prove(key, next, siblings)
            }
        }
    }

    fn count(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Leaf { .. } => 1,
            Self::Branch { left, right, .. } => left.count().saturating_add(right.count()),
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    root: Node,
}

impl Default for Tree {
    fn default() -> Self {
        Self { root: Node::Empty }
    }
}

impl Tree {
    /// An empty tree, whose root is [`EMPTY`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Puts `value` at `key`, replacing what was there.
    pub fn insert(&mut self, key: Hash, value: Hash) {
        let root = core::mem::replace(&mut self.root, Node::Empty);
        self.root = root.insert(key, value, 0);
    }

    /// Removes what is at `key`, if anything.
    pub fn remove(&mut self, key: &Hash) {
        let root = core::mem::replace(&mut self.root, Node::Empty);
        self.root = root.remove(key, 0);
    }

    /// The value at `key`, if any.
    #[must_use]
    pub fn get(&self, key: &Hash) -> Option<&Hash> {
        self.root.get(key, 0)
    }

    /// The tree's root.
    #[must_use]
    pub fn root(&self) -> Hash {
        self.root.hash()
    }

    /// How many leaves the tree holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.root.count()
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
        self.root.prove(key, 0, &mut siblings).then_some(Proof { siblings })
    }
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
}

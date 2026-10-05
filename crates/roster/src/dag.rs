//! The operation graph: causal ancestry, depth, and heads.
//!
//! This is the deterministic half of the roster. A `Dag` holds operations and
//! nothing else — no configuration, no clock, no notion of what arrived when.
//! Everything it reports is a function of the operation set alone, which is what
//! lets two nodes holding the same operations agree on the same household.
//!
//! # Ancestry
//!
//! Each operation carries a bitset of the operations that precede it causally.
//! Ancestry is then one bit test, and concurrency — neither operation preceding
//! the other — is two. The conflict rules ask that question a great many times,
//! so it is worth the space: the cost is quadratic in the operation count, which
//! [`limits::MAX_OPERATIONS`] caps at 2 MiB.
//!
//! # Why cycles are impossible but still checked
//!
//! An operation's id covers its parent list, so naming a descendant as a parent
//! would mean knowing that descendant's id before computing it. A cycle is
//! therefore not constructible. It is still detected rather than assumed away,
//! because the alternative to detecting it is looping forever on input someone
//! else supplied.

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::id::{KeyId, NetworkId, OperationId};
use crate::limits;
use crate::sign::VerifiedOperation;
use crate::snapshot::SignedSnapshot;
use crate::types::{OperationBody, OperationType};

/// What a graph rests on.
///
/// A graph normally reaches back to the founding operation. Once a node has
/// compacted, the ground beneath it is a snapshot instead: the operations that
/// established the state are gone, and the snapshot stands in for them.
#[derive(Debug, Clone)]
pub enum Foundation {
    /// The founding operation, at the given index.
    Genesis(usize),
    /// An accepted snapshot whose covered operations have been discarded.
    ///
    /// The covered heads are retained as ordinary operations so that later
    /// operations naming them as parents can still be placed; they are marked
    /// covered so their effects are not applied twice, being already inside the
    /// snapshot's state.
    Snapshot(Box<SignedSnapshot>),
}

/// A fixed set of operation indices.
///
/// Sized to the indices it can hold rather than to the maximum, so a household
/// roster of fifty operations does not carry four kilobits per entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct BitSet {
    /// Bits, least-significant first within each word.
    words: Vec<u64>,
}

impl BitSet {
    /// An empty set able to hold `capacity` indices.
    fn with_capacity(capacity: usize) -> Self {
        Self { words: vec![0; capacity.div_ceil(64)] }
    }

    /// Adds an index.
    fn insert(&mut self, index: usize) {
        let (word, bit) = (index.wrapping_div(64), index.wrapping_rem(64));
        if let Some(slot) = self.words.get_mut(word) {
            *slot |= 1u64 << bit;
        }
    }

    /// Reports whether an index is present.
    fn contains(&self, index: usize) -> bool {
        let (word, bit) = (index.wrapping_div(64), index.wrapping_rem(64));
        self.words.get(word).is_some_and(|value| value & (1u64 << bit) != 0)
    }

    /// Adds every index of `other`.
    fn union_with(&mut self, other: &Self) {
        for (slot, value) in self.words.iter_mut().zip(other.words.iter()) {
            *slot |= *value;
        }
    }

    /// Iterates the indices present, ascending.
    fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.words.iter().enumerate().flat_map(|(word_index, word)| {
            (0..64).filter_map(move |bit| {
                if word & (1u64 << bit) != 0 {
                    word_index.checked_mul(64)?.checked_add(bit)
                } else {
                    None
                }
            })
        })
    }
}

/// A causally ordered set of verified operations.
///
/// Operations are stored in a topological order: an operation's parents always
/// occupy a lower index than the operation itself. Every insert appends, which
/// keeps that invariant without a sort, because an operation may only be
/// inserted once all its parents are present.
#[derive(Debug, Clone, Default)]
pub struct Dag {
    /// Operations, in topological order.
    operations: Vec<VerifiedOperation>,
    /// Index of each operation by id.
    positions: HashMap<OperationId, usize>,
    /// Causal ancestors of each operation, by index.
    ancestors: Vec<BitSet>,
    /// Causal depth of each operation, by index.
    depths: Vec<u64>,
    /// Index of the founding operation, once present.
    genesis: Option<usize>,
    /// The snapshot this graph rests on, once it has compacted.
    base: Option<Box<SignedSnapshot>>,
    /// Whether each operation is already accounted for by the base snapshot.
    ///
    /// A covered operation is retained only as an anchor for its children. Its
    /// effects are inside the snapshot's state, so derivation must skip it or
    /// count it twice.
    covered: Vec<bool>,
    /// The network this graph belongs to, derived from the founding operation.
    network: Option<NetworkId>,
    /// Forks whose operations compaction would otherwise have discarded.
    ///
    /// Kept whole — body, signature and all — because they are the evidence of an
    /// accusation, and an accusation whose proof has been thrown away is one a
    /// person is asked to believe. Compaction is eligible to discard them:
    /// `Compaction preconditions` blocks a region only while a *held* operation
    /// is concurrent with it, and two forked operations are concurrent with each
    /// other, so a region containing both passes.
    ///
    /// This does not weaken the rule that every retained byte stays covered by a
    /// signature — it follows it. What that rule forbids is keeping *fragments*
    /// authenticated by nothing; a whole signed operation carries its own
    /// signature, which is the condition it states.
    kept_evidence: Vec<(KeyId, VerifiedOperation, VerifiedOperation)>,
    /// The operations each device authored, by index, in insertion order.
    ///
    /// Kept because an honest device anchors each operation it writes to its own
    /// previous one: it knows what it last wrote. Two operations by one author
    /// that are causally concurrent therefore mean a fork — a device signing two
    /// histories, or one identity running in two places — and finding that needs
    /// the operations grouped by who signed them.
    ///
    /// The founding operation is not indexed here. It has no parents, so it is
    /// concurrent with nothing, and two foundings by one author are two networks
    /// rather than one fork.
    by_author: HashMap<KeyId, Vec<usize>>,
    /// How many held operations are not revocations.
    ///
    /// Counted as they are inserted rather than scanned, because it is asked on
    /// every insert. It is what holds the reserve open: the ceiling is shared,
    /// and everything except a revocation is bounded below it, so a network that
    /// has run out of room can still expel whatever filled it.
    non_revocations: usize,
}

impl Dag {
    /// An empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a graph from an unordered set of operations.
    ///
    /// Operations are placed as their parents become available. Anything left
    /// over at the end either names a parent absent from the input, or takes
    /// part in a cycle — the two are distinguished, because they mean very
    /// different things about the sender.
    pub fn from_operations(operations: Vec<VerifiedOperation>) -> Result<Self> {
        let present: std::collections::HashSet<OperationId> =
            operations.iter().map(VerifiedOperation::id).collect();

        let mut dag = Self::new();
        let mut remaining = operations;
        while !remaining.is_empty() {
            let mut placed_any = false;
            let mut deferred = Vec::new();
            for operation in remaining {
                if dag.missing_parents(&operation).is_empty() {
                    dag.insert(operation)?;
                    placed_any = true;
                } else {
                    deferred.push(operation);
                }
            }
            if !placed_any {
                // Nothing could be placed. If every stalled operation has all
                // its parents inside the input, they can only be waiting on each
                // other.
                let cyclic = deferred
                    .iter()
                    .all(|operation| operation.core().parents.iter().all(|p| present.contains(p)));
                return Err(if cyclic { Error::CyclicHistory } else { Error::MissingGenesis });
            }
            remaining = deferred;
        }
        Ok(dag)
    }

    /// The ids of an operation's parents that this graph does not hold.
    #[must_use]
    pub fn missing_parents(&self, operation: &VerifiedOperation) -> Vec<OperationId> {
        operation
            .core()
            .parents
            .iter()
            .filter(|parent| !self.positions.contains_key(*parent))
            .copied()
            .collect()
    }

    /// Adds an operation whose parents are all present.
    ///
    /// Idempotent: offering an operation already held changes nothing and is
    /// not an error, because a peer re-sending what we have is ordinary.
    pub fn insert(&mut self, operation: VerifiedOperation) -> Result<()> {
        if self.positions.contains_key(&operation.id()) {
            return Ok(());
        }
        if self.operations.len() >= limits::MAX_OPERATIONS {
            return Err(Error::LimitExceeded("operations per roster"));
        }
        // Part of the ceiling is kept for revocations. A network that has run out
        // of room must still be able to expel the device that filled it —
        // otherwise reaching the ceiling is permanent, and the remedy for a
        // flooding device is to abandon the network and found it again.
        let revokes =
            matches!(operation.core().body, crate::types::OperationBody::RevokeDevice { .. });
        if !revokes && self.non_revocations >= limits::MAX_NON_REVOCATION_OPERATIONS {
            return Err(Error::LimitExceeded(
                "operations per roster, outside the revocation reserve",
            ));
        }
        if !self.missing_parents(&operation).is_empty() {
            // The caller is responsible for holding an operation until its
            // parents arrive; reaching here means that was not done.
            return Err(Error::MissingGenesis);
        }

        let index = self.operations.len();
        let is_genesis = operation.core().parents.is_empty();
        if !revokes {
            self.non_revocations = self.non_revocations.saturating_add(1);
        }

        // A graph resting on a snapshot has no genesis and expects none; its
        // covered heads are seeded directly rather than inserted.
        if self.base.is_some() && is_genesis {
            return Err(Error::DuplicateGenesis);
        }

        if is_genesis {
            if operation.core().operation_type() != OperationType::CreateNetwork {
                return Err(Error::ParentlessOperation);
            }
            if self.genesis.is_some() {
                return Err(Error::DuplicateGenesis);
            }
            // The network's identity is the identity of the operation that
            // founded it, so it covers the founding keys and parameters both.
            //
            // The founding operation itself carries the zero network id, and
            // must: its own `network` field is inside the bytes being hashed,
            // so naming the result there would require a hash of a structure
            // containing that hash. A network *is* its genesis, so there is
            // nothing for the field to say. Every later operation carries the
            // real value.
            if operation.core().network != NetworkId::from_bytes([0; 32]) {
                return Err(Error::ForeignNetwork);
            }
            let network = NetworkId::from_bytes(*operation.id().as_bytes());
            self.genesis = Some(index);
            self.network = Some(network);
        } else {
            if operation.core().operation_type() == OperationType::CreateNetwork {
                return Err(Error::DuplicateGenesis);
            }
            match self.network {
                None => return Err(Error::SnapshotUnverified),
                Some(network) if operation.core().network != network => {
                    return Err(Error::ForeignNetwork);
                }
                Some(_) => {}
            }
        }

        // Ancestors and depth, both computed from the parents that are already
        // placed. Every parent has a lower index, so this needs no fixpoint.
        let mut ancestors = BitSet::with_capacity(index.saturating_add(1));
        let mut depth = 0u64;
        for parent in &operation.core().parents {
            let parent_index = *self.positions.get(parent).ok_or(Error::MissingGenesis)?;
            ancestors.insert(parent_index);
            if let Some(parent_ancestors) = self.ancestors.get(parent_index) {
                ancestors.union_with(parent_ancestors);
            }
            let parent_depth = self.depths.get(parent_index).copied().unwrap_or(0);
            depth = depth.max(parent_depth.saturating_add(1));
        }

        if !is_genesis {
            self.by_author.entry(operation.core().author).or_default().push(index);
        }

        self.positions.insert(operation.id(), index);
        self.operations.push(operation);
        self.ancestors.push(ancestors);
        self.depths.push(depth);
        self.covered.push(false);
        Ok(())
    }

    /// How many operations the graph holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Whether the graph is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// The operations, in topological order.
    #[must_use]
    pub fn operations(&self) -> &[VerifiedOperation] {
        &self.operations
    }

    /// The operation at an index.
    #[must_use]
    pub fn operation(&self, index: usize) -> Option<&VerifiedOperation> {
        self.operations.get(index)
    }

    /// The index of an operation id.
    #[must_use]
    pub fn position(&self, id: &OperationId) -> Option<usize> {
        self.positions.get(id).copied()
    }

    /// Whether the graph holds an operation.
    #[must_use]
    pub fn contains(&self, id: &OperationId) -> bool {
        self.positions.contains_key(id)
    }

    /// The network this graph belongs to, once its founding operation is held.
    #[must_use]
    pub fn network(&self) -> Option<NetworkId> {
        self.network
    }

    /// The index of the founding operation.
    #[must_use]
    pub fn genesis(&self) -> Option<usize> {
        self.genesis
    }

    /// What this graph rests on.
    #[must_use]
    pub fn foundation(&self) -> Option<Foundation> {
        if let Some(snapshot) = &self.base {
            return Some(Foundation::Snapshot(snapshot.clone()));
        }
        self.genesis.map(Foundation::Genesis)
    }

    /// The snapshot this graph rests on, if it has compacted.
    #[must_use]
    pub fn base_snapshot(&self) -> Option<&SignedSnapshot> {
        self.base.as_deref()
    }

    /// Whether an operation is already accounted for by the base snapshot.
    ///
    /// Such an operation is retained only so its children can be placed.
    #[must_use]
    pub fn is_covered(&self, index: usize) -> bool {
        self.covered.get(index).copied().unwrap_or(false)
    }

    /// Builds a graph resting on a snapshot, seeded with its covered heads.
    ///
    /// The heads are supplied as whole signed operations because later
    /// operations name them as parents; everything beneath them is gone. Their
    /// depths come from the snapshot, which is why it carries them: guessing
    /// them would change the last-writer-wins tie-break across the boundary.
    pub fn from_snapshot(snapshot: SignedSnapshot, heads: Vec<VerifiedOperation>) -> Result<Self> {
        let body = snapshot.body().clone();
        if heads.len() != body.heads.len() {
            return Err(Error::SnapshotUnverified);
        }
        let mut dag = Self { network: Some(body.network), ..Self::default() };
        for head in heads {
            let Some(depth) = body.depth_of(&head.id()) else {
                return Err(Error::SnapshotUnverified);
            };
            if head.core().network != body.network {
                return Err(Error::ForeignNetwork);
            }
            let index = dag.operations.len();
            // A seeded head has no retained ancestors: everything beneath it
            // was discarded, and gate 1 guarantees nothing held is concurrent
            // with any of it.
            dag.positions.insert(head.id(), index);
            dag.operations.push(head);
            dag.ancestors.push(BitSet::with_capacity(index.saturating_add(1)));
            dag.depths.push(depth);
            dag.covered.push(true);
        }
        dag.base = Some(Box::new(snapshot));
        Ok(dag)
    }

    /// Discards the strict ancestors of a snapshot's covered heads.
    ///
    /// Whole operations go: body, signature and all. The heads themselves stay,
    /// as complete signed operations, so their children remain placeable. The
    /// caller is responsible for the preconditions; see
    /// [`crate::roster::Roster::compact`], which checks them.
    pub fn compact(&mut self, snapshot: SignedSnapshot) -> Result<usize> {
        let body = snapshot.body().clone();

        // Every head must be held, or the graph would lose its anchors.
        let mut head_indices = Vec::with_capacity(body.heads.len());
        for head in &body.heads {
            let Some(index) = self.positions.get(head).copied() else {
                return Err(Error::CompactionRefused("a covered head is not held"));
            };
            head_indices.push(index);
        }

        // The region is the heads plus everything beneath them.
        let mut in_region = vec![false; self.operations.len()];
        for index in &head_indices {
            if let Some(slot) = in_region.get_mut(*index) {
                *slot = true;
            }
            for ancestor in self.ancestors_of(*index) {
                if let Some(slot) = in_region.get_mut(ancestor) {
                    *slot = true;
                }
            }
        }

        // Keep the heads and everything outside the region; drop the rest.
        let keep: Vec<usize> = (0..self.operations.len())
            .filter(|index| {
                head_indices.contains(index) || !in_region.get(*index).copied().unwrap_or(false)
            })
            .collect();
        let discarded = self.operations.len().saturating_sub(keep.len());

        let mut rebuilt = Self { network: Some(body.network), ..Self::default() };

        // Evidence first, before the operations it points at are gone. Carried
        // forward from an earlier compaction, plus any fork this one would
        // discard.
        rebuilt.kept_evidence = core::mem::take(&mut self.kept_evidence);
        let surviving: std::collections::HashSet<usize> = keep.iter().copied().collect();
        for fork in self.forks() {
            if surviving.contains(&fork.first) && surviving.contains(&fork.second) {
                continue;
            }
            let (Some(first), Some(second)) =
                (self.operation(fork.first), self.operation(fork.second))
            else {
                continue;
            };
            let already = rebuilt
                .kept_evidence
                .iter()
                .any(|(_, one, other)| one.id() == first.id() && other.id() == second.id());
            if !already {
                rebuilt.kept_evidence.push((fork.author, first.clone(), second.clone()));
            }
        }

        for old_index in keep {
            let Some(operation) = self.operations.get(old_index) else { continue };
            let index = rebuilt.operations.len();
            let is_head = head_indices.contains(&old_index);

            let mut ancestors = BitSet::with_capacity(index.saturating_add(1));
            if !is_head {
                for parent in &operation.core().parents {
                    let Some(parent_index) = rebuilt.positions.get(parent).copied() else {
                        return Err(Error::CompactionRefused("a retained operation lost a parent"));
                    };
                    ancestors.insert(parent_index);
                    if let Some(parent_ancestors) = rebuilt.ancestors.get(parent_index) {
                        ancestors.union_with(parent_ancestors);
                    }
                }
            }

            // Depths are preserved exactly, from the snapshot for the heads and
            // from the original graph for everything after. Recomputing them
            // from the truncated graph would renumber the survivors and change
            // the last-writer-wins tie-break.
            let depth = self.depths.get(old_index).copied().unwrap_or(0);

            rebuilt.positions.insert(operation.id(), index);
            if !matches!(operation.core().body, OperationBody::RevokeDevice { .. }) {
                rebuilt.non_revocations = rebuilt.non_revocations.saturating_add(1);
            }
            rebuilt.operations.push(operation.clone());
            rebuilt.ancestors.push(ancestors);
            rebuilt.depths.push(depth);
            rebuilt.covered.push(is_head);
        }

        rebuilt.base = Some(Box::new(snapshot));
        *self = rebuilt;
        Ok(discarded)
    }

    /// The indices of operations in the region a snapshot covers.
    #[must_use]
    pub fn covered_region(&self, snapshot: &SignedSnapshot) -> Option<Vec<usize>> {
        let mut region = Vec::new();
        let mut seen = vec![false; self.operations.len()];
        for head in &snapshot.body().heads {
            let index = self.positions.get(head).copied()?;
            for candidate in core::iter::once(index).chain(self.ancestors_of(index)) {
                if let Some(slot) = seen.get_mut(candidate)
                    && !*slot
                {
                    *slot = true;
                    region.push(candidate);
                }
            }
        }
        region.sort_unstable();
        Some(region)
    }

    /// The founding operation's body.
    #[must_use]
    pub fn genesis_operation(&self) -> Option<&VerifiedOperation> {
        self.operations.get(self.genesis?)
    }

    /// The causal depth of an operation: zero at the founding operation, and
    /// otherwise one past the deepest parent.
    #[must_use]
    pub fn depth(&self, index: usize) -> u64 {
        self.depths.get(index).copied().unwrap_or(0)
    }

    /// The greatest depth in the graph.
    #[must_use]
    pub fn frontier_depth(&self) -> u64 {
        self.depths.iter().copied().max().unwrap_or(0)
    }

    /// Whether `ancestor` causally precedes `descendant`.
    #[must_use]
    pub fn is_ancestor(&self, ancestor: usize, descendant: usize) -> bool {
        self.ancestors.get(descendant).is_some_and(|set| set.contains(ancestor))
    }

    /// Whether two operations are causally concurrent: neither precedes the
    /// other, and they are not the same operation.
    ///
    /// This is the question the causal authorship rule turns on.
    #[must_use]
    pub fn concurrent(&self, a: usize, b: usize) -> bool {
        a != b && !self.is_ancestor(a, b) && !self.is_ancestor(b, a)
    }

    /// The indices of an operation's causal ancestors.
    pub fn ancestors_of(&self, index: usize) -> impl Iterator<Item = usize> + '_ {
        self.ancestors.get(index).into_iter().flat_map(BitSet::iter)
    }

    /// The operations that are nobody's parent.
    ///
    /// These are the tips a peer needs in order to tell what we already know.
    #[must_use]
    pub fn heads(&self) -> Vec<OperationId> {
        let mut is_parent = vec![false; self.operations.len()];
        for operation in &self.operations {
            for parent in &operation.core().parents {
                if let Some(index) = self.positions.get(parent)
                    && let Some(slot) = is_parent.get_mut(*index)
                {
                    *slot = true;
                }
            }
        }
        self.operations
            .iter()
            .enumerate()
            .filter(|(index, _)| !is_parent.get(*index).copied().unwrap_or(false))
            .map(|(_, operation)| operation.id())
            .collect()
    }

    /// The device a `revoke_device`, `demote`, `promote` or `rename` targets.
    #[must_use]
    pub(crate) fn target_of(body: &OperationBody) -> Option<crate::id::DeviceId> {
        match body {
            OperationBody::RevokeDevice { device, .. }
            | OperationBody::Promote { device, .. }
            | OperationBody::Demote { device }
            | OperationBody::Rename { device, .. } => Some(*device),
            OperationBody::CreateNetwork { .. }
            | OperationBody::AddDevice(_)
            | OperationBody::SetNetwork(_) => None,
        }
    }
}

/// Two operations by one author that are causally concurrent.
///
/// Evidence of a fork, and the pair is the evidence: anyone can verify both
/// signatures under the named key and see that neither is an ancestor of the
/// other, without trusting whoever reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fork {
    /// The device that signed both.
    pub author: KeyId,
    /// The earlier of the two by index, so a pair is named one way only.
    pub first: usize,
    /// The later of the two by index.
    pub second: usize,
}

impl Dag {
    /// Every fork this graph holds evidence of.
    ///
    /// A fork is two operations by one author that are causally concurrent.
    /// An honest device anchors each operation to its own previous one, so
    /// concurrency within one author's work means the author signed two
    /// histories — deliberately, or by running one identity in two places.
    /// Those are the same problem and the same evidence.
    ///
    /// **A function of the operation set alone.** The result does not depend
    /// on the order operations arrived in, on timestamps, or on sequence
    /// numbers, so two nodes holding the same operations reach the same
    /// verdict. Pairs are reported by ascending index and the list is
    /// ordered, which makes the answer identical rather than merely
    /// equivalent.
    ///
    /// A later merge by the author does not erase anything: both operations
    /// were signed and both exist, and an operation naming them both as
    /// parents does not make them cease to be concurrent with each other.
    ///
    /// Concurrency between *different* authors is not a fork. Two admins
    /// acting at once is ordinary, and the merge rules exist for it.
    #[must_use]
    pub fn forks(&self) -> Vec<Fork> {
        let mut found = Vec::new();

        for (author, indices) in &self.by_author {
            for (position, &one) in indices.iter().enumerate() {
                for &other in indices.iter().skip(position.saturating_add(1)) {
                    if !self.concurrent(one, other) {
                        continue;
                    }
                    // Named by operation id, never by position. Indices are the
                    // order operations arrived in, so a pair named by index is
                    // reported with its halves swapped on a node that received
                    // them the other way round: the same pair, but not the same
                    // report. "The verdict does not depend on arrival order"
                    // means identical, not equivalent — and an id is a content
                    // address that every node computes the same.
                    let swap = match (self.operation(one), self.operation(other)) {
                        (Some(left), Some(right)) => right.id() < left.id(),
                        _ => false,
                    };
                    let (first, second) = if swap { (other, one) } else { (one, other) };
                    found.push(Fork { author: *author, first, second });
                }
            }
        }

        // Ordered by what the operations are, not by where they landed, for the
        // same reason: `by_author` is a hash map whose iteration order two nodes
        // do not agree on, and indices are arrival order.
        found.sort_unstable_by_key(|fork| {
            (
                fork.author,
                self.operation(fork.first).map(VerifiedOperation::id),
                self.operation(fork.second).map(VerifiedOperation::id),
            )
        });
        found
    }

    /// Whether an operation is part of a fork its author signed.
    #[must_use]
    pub fn is_equivocated(&self, index: usize) -> bool {
        self.is_equivocated_within(index, None)
    }

    /// Whether an operation is equivocated **as seen from inside a set**.
    ///
    /// `scope` restricts which other operations count as evidence: `None` is the
    /// whole graph, which is what deriving state uses, and a mask is a subset,
    /// which is what judging an operation against its own ancestors uses.
    ///
    /// The distinction matters because equivocation is a property of the graph
    /// and not of an operation's ancestry: a sibling that arrives later can make
    /// an operation equivocated that was not before. A judgement that has to mean
    /// the same on every node — admission — therefore cannot look outside the set
    /// of ancestors it is judging against, or two nodes would answer differently
    /// about the same operation depending on what else had reached them.
    #[must_use]
    pub fn is_equivocated_within(&self, index: usize, scope: Option<&[bool]>) -> bool {
        let Some(operation) = self.operations.get(index) else {
            return false;
        };
        let Some(indices) = self.by_author.get(&operation.core().author) else {
            return false;
        };
        indices.iter().any(|&other| {
            scope.is_none_or(|mask| mask.get(other).copied().unwrap_or(false))
                && self.concurrent(index, other)
        })
    }

    /// Forks kept as evidence past a compaction that would have discarded them.
    ///
    /// Separate from the graph because their ancestry is gone: the operations
    /// between them were discarded, so they can no longer be placed. What
    /// survives is what the accusation needs — two whole signed operations and
    /// the device that signed both.
    #[must_use]
    pub fn kept_evidence(&self) -> &[(KeyId, VerifiedOperation, VerifiedOperation)] {
        &self.kept_evidence
    }

    /// Drops evidence about devices that have since been revoked.
    ///
    /// The question the evidence answers has been settled by a signed operation,
    /// and the revoked set carries the outcome, so the pair has nothing left to
    /// prove. This is what bounds the retention.
    pub fn release_evidence_about(&mut self, settled: &dyn Fn(&KeyId) -> bool) {
        self.kept_evidence.retain(|(author, _, _)| !settled(author));
    }

    /// The operations each device authored, by index.
    ///
    /// Exposed so a caller can check what this graph believes about
    /// authorship without reaching into it.
    #[must_use]
    pub fn authored_by(&self, author: &KeyId) -> &[usize] {
        self.by_author.get(author).map_or(&[], Vec::as_slice)
    }
}

#[cfg(test)]
mod tests {
    use super::BitSet;

    #[test]
    fn bitset_holds_and_reports_indices() {
        let mut set = BitSet::with_capacity(200);
        set.insert(0);
        set.insert(63);
        set.insert(64);
        set.insert(199);
        assert!(set.contains(0));
        assert!(set.contains(63));
        assert!(set.contains(64));
        assert!(set.contains(199));
        assert!(!set.contains(1));
        assert!(!set.contains(198));
        assert_eq!(set.iter().collect::<Vec<_>>(), vec![0, 63, 64, 199]);
    }

    #[test]
    fn bitset_union_keeps_both_sides() {
        let mut a = BitSet::with_capacity(128);
        a.insert(1);
        let mut b = BitSet::with_capacity(128);
        b.insert(70);
        a.union_with(&b);
        assert!(a.contains(1));
        assert!(a.contains(70));
    }

    /// A shorter set unioned into a longer one must not reach past its own
    /// length or be truncated.
    #[test]
    fn bitset_union_tolerates_differing_lengths() {
        let mut wide = BitSet::with_capacity(200);
        wide.insert(150);
        let mut narrow = BitSet::with_capacity(8);
        narrow.insert(3);
        wide.union_with(&narrow);
        assert!(wide.contains(150));
        assert!(wide.contains(3));
    }

    #[test]
    fn out_of_range_index_is_ignored_not_panicking() {
        let mut set = BitSet::with_capacity(8);
        set.insert(1000);
        assert!(!set.contains(1000));
    }
}

//! What a member holding no roster knows, and how it judges a peer.
//!
//! A light member holds one current root and the chain of roots before it that
//! it can remember, each with its delta, and a set of invalidations carried by
//! roots it did not choose. It needs no admin keys and no clock:
//!
//! - **a root is valid** when its signer, proved against the root it follows,
//!   was an admin there, and no root this member holds that does not precede it
//!   demotes or revokes that signer;
//! - **a root is adopted** when it follows the current one; of two that do not
//!   follow each other, the heavier stays — higher generation, then greater root
//!   hash — so every member converges without talking;
//! - **a revocation applies from any valid root**, chosen or not: its delta goes
//!   into the invalidations not yet joined, and leaves only once a root following
//!   it is adopted;
//! - **a peer's proof is accepted** against a root of the chain while every
//!   delta from that root on is still remembered and none names the peer. Older
//!   than that, the proof must be renewed.
//!
//! How much is remembered is this member's own choice, bounded by its memory,
//! and decides nothing anybody else derives.
//!
//! Uses `core` and `alloc` only, so it runs on a microcontroller.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::id::{DeviceId, NetworkId};
use crate::leaf::DeviceLeaf;
use crate::membership::MembershipProof;
use crate::merkle::Hash;
use crate::snapshot::Snapshot;

/// Canonical key order of a light member's view.
pub const LIGHT_VIEW_SCHEMA: &[&str] = &["aside", "chain", "budget", "network", "unjoined"];

/// Canonical key order of a remembered root.
pub const REMEMBERED_SCHEMA: &[&str] = &["root", "delta", "previous", "generation"];

/// Canonical key order of an invalidation not yet joined.
pub const UNJOINED_SCHEMA: &[&str] = &["root", "device"];

/// The most roots a view read back may remember: what a member's budget could
/// ever reasonably be.
const MAX_REMEMBERED: usize = 4096;

/// A root as a light member remembers it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Remembered {
    /// Its state root.
    root: Hash,
    /// Its generation.
    generation: u64,
    /// The devices it invalidated.
    delta: Vec<DeviceId>,
    /// The roots it follows: what a branch set aside is climbed back by, to
    /// the root where it left the chain.
    previous: Vec<Hash>,
}

impl Remembered {
    fn of(snapshot: &Snapshot) -> Self {
        Self {
            root: snapshot.root,
            generation: snapshot.generation,
            delta: snapshot.delta.clone(),
            previous: snapshot.previous.clone(),
        }
    }

    /// The order siblings are weighed by.
    fn weight(&self) -> (u64, Hash) {
        (self.generation, self.root)
    }

    fn encode(&self, writer: &mut crate::cbor::Writer) {
        writer.map(4);
        writer.key("root").bytes(&self.root);
        writer.key("delta").array(self.delta.len() as u64);
        for device in &self.delta {
            writer.bytes(device.as_bytes());
        }
        writer.key("previous").array(self.previous.len() as u64);
        for root in &self.previous {
            writer.bytes(root);
        }
        writer.key("generation").u64(self.generation);
    }

    fn decode(reader: &mut crate::cbor::Reader<'_>) -> crate::error::Result<Self> {
        use crate::error::Error;
        let hash = |reader: &mut crate::cbor::Reader<'_>| -> crate::error::Result<Hash> {
            Hash::try_from(reader.fixed_bytes(32)?).map_err(|_| Error::IdentifierLength)
        };
        let mut entry = reader.map(REMEMBERED_SCHEMA)?;
        let root = hash(entry.key("root")?)?;
        let devices = entry.key("delta")?;
        let many = devices.array(crate::limits::MAX_OPERATION_SIZE, "delta")?;
        let mut delta = Vec::with_capacity(many);
        for _ in 0..many {
            delta.push(DeviceId::from_bytes(hash(devices)?));
        }
        let roots = entry.key("previous")?;
        let many = roots.array(MAX_REMEMBERED, "roots followed")?;
        let mut previous = Vec::with_capacity(many);
        for _ in 0..many {
            previous.push(hash(roots)?);
        }
        let generation = entry.key("generation")?.u64()?;
        entry.finish()?;
        Ok(Self { root, generation, delta, previous })
    }
}

/// What became of an offered root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootOutcome {
    /// It follows the current root and is now current.
    Adopted,
    /// It is the current root, or one already remembered.
    AlreadyKnown,
    /// A sibling heavier than the current root: now current.
    Switched,
    /// A sibling lighter than the current root: kept aside, its revocations
    /// applied.
    KeptAside,
    /// It follows a root this member does not remember: the chain between is
    /// needed first.
    NeedsChain,
    /// Not a valid root here.
    Refused(RootRefusal),
}

/// Why an offered root was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootRefusal {
    /// It belongs to another network.
    ForeignNetwork,
    /// Its signer is not proved an admin in the root it follows.
    SignerNotProved,
    /// Its signer was demoted or revoked by a root this member holds that does
    /// not precede it.
    SignerInvalidated,
}

/// What a light member makes of a peer's proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofVerdict {
    /// The peer is a member, as its leaf says.
    Accepted,
    /// The proof is against a root older than what this member remembers, or
    /// one it does not know: the peer must renew it.
    Renew,
    /// The proof does not hold, or a delta this member holds names the peer.
    Refused,
}

/// A light member's view of its network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightView {
    /// The network.
    network: NetworkId,
    /// The remembered chain, oldest first; the last is current.
    chain: VecDeque<Remembered>,
    /// How many roots to remember at most.
    budget: usize,
    /// Invalidations carried by roots not on the chain: the device, and the
    /// root that carried it.
    unjoined: Vec<(DeviceId, Hash)>,
    /// Roots valid but not on the chain — siblings kept aside, or the branch
    /// left for a heavier one — most recent last.
    ///
    /// A root joining two branches proves its signer against one of them,
    /// which may be the one set aside. A heavier root continuing a branch set
    /// aside is switched to by climbing that branch back to the chain.
    aside: VecDeque<Remembered>,
}

impl LightView {
    /// Starts from a root this member was given — at its admission, over a
    /// cable — and so trusts by how it arrived.
    ///
    /// `budget` is how many roots to remember; at least one is kept.
    #[must_use]
    pub fn starting_from(root: &Snapshot, budget: usize) -> Self {
        let mut chain = VecDeque::new();
        chain.push_back(Remembered::of(root));
        Self {
            network: root.network,
            chain,
            budget: budget.max(1),
            unjoined: Vec::new(),
            aside: VecDeque::new(),
        }
    }

    /// The current root.
    #[must_use]
    pub fn current(&self) -> Option<Hash> {
        self.chain.back().map(|remembered| remembered.root)
    }

    /// Whether `root` is one this member remembers, on the chain or set aside.
    #[must_use]
    pub fn knows(&self, root: &Hash) -> bool {
        self.position(root).is_some() || self.is_aside(root)
    }

    /// How many roots are remembered.
    #[must_use]
    pub fn remembered(&self) -> usize {
        self.chain.len()
    }

    /// Whether a delta not yet joined names `device`.
    #[must_use]
    pub fn invalidated(&self, device: &DeviceId) -> bool {
        self.unjoined.iter().any(|(named, _)| named == device)
    }

    /// Offers a root.
    pub fn offer(&mut self, root: &Snapshot) -> RootOutcome {
        if root.network != self.network {
            return RootOutcome::Refused(RootRefusal::ForeignNetwork);
        }
        if self.position(&root.root).is_some() || self.is_aside(&root.root) {
            return RootOutcome::AlreadyKnown;
        }
        // The root its signer is proved in must be one this member remembers,
        // on the chain or set aside.
        let proved_against = root.proved_against();
        if self.position(&proved_against).is_none() && !self.is_aside(&proved_against) {
            return RootOutcome::NeedsChain;
        }
        if !root.signer_proved(&proved_against) {
            return RootOutcome::Refused(RootRefusal::SignerNotProved);
        }
        // The roots it follows that sit on the chain, and the latest of them:
        // everything after that on the chain does not precede it. None on the
        // chain: it continues a branch set aside.
        let Some(follows_at) =
            root.previous.iter().filter_map(|previous| self.position(previous)).max()
        else {
            return self.continue_aside(root);
        };
        let signer = root.signer.record.id;
        let after = self.chain.iter().skip(follows_at.saturating_add(1));
        if after.flat_map(|remembered| remembered.delta.iter()).any(|named| *named == signer)
            || self.invalidated(&signer)
        {
            return RootOutcome::Refused(RootRefusal::SignerInvalidated);
        }

        let offered = Remembered::of(root);
        let current_at = self.chain.len().saturating_sub(1);
        if follows_at == current_at {
            self.adopt(offered, &root.previous);
            return RootOutcome::Adopted;
        }

        // A sibling of the current branch. Its revocations hold whichever is
        // kept.
        let current_weight = self.chain.back().map(Remembered::weight);
        if current_weight.is_some_and(|weight| offered.weight() > weight) {
            // The branch it leaves goes aside, its revocations kept.
            while self.chain.len() > follows_at.saturating_add(1) {
                if let Some(dropped) = self.chain.pop_back() {
                    for device in &dropped.delta {
                        self.unjoined.push((*device, dropped.root));
                    }
                    self.set_aside(dropped);
                }
            }
            self.adopt(offered, &root.previous);
            RootOutcome::Switched
        } else {
            for device in &offered.delta {
                self.unjoined.push((*device, offered.root));
            }
            self.set_aside(offered);
            RootOutcome::KeptAside
        }
    }

    /// A valid root continuing a branch set aside: its revocations hold.
    ///
    /// Heavier than the current root, it is switched to: the branch it
    /// continues is climbed back to the chain, the chain from there goes
    /// aside, and the branch takes its place. Where the branch cannot be
    /// climbed back, the chain between is needed first. Found in the
    /// testbed (18.1): a light member following one admin's branch, handed
    /// the other's chain, set every root of it aside and believed nobody.
    fn continue_aside(&mut self, root: &Snapshot) -> RootOutcome {
        let offered = Remembered::of(root);
        let heavier = self.chain.back().is_none_or(|current| offered.weight() > current.weight());
        if heavier && let Some((fork, branch)) = self.branch_back(&offered.previous) {
            // Its signer may be named by nothing on the chain it leaves, nor
            // by an invalidation from anywhere but the branch it continues.
            let signer = root.signer.record.id;
            let named_on_chain = self
                .chain
                .iter()
                .skip(fork.saturating_add(1))
                .any(|remembered| remembered.delta.contains(&signer));
            let named_elsewhere = self
                .unjoined
                .iter()
                .any(|(device, carrier)| *device == signer && !branch.contains(carrier));
            if named_on_chain || named_elsewhere {
                return RootOutcome::Refused(RootRefusal::SignerInvalidated);
            }
            while self.chain.len() > fork.saturating_add(1) {
                if let Some(dropped) = self.chain.pop_back() {
                    for device in &dropped.delta {
                        self.unjoined.push((*device, dropped.root));
                    }
                    self.set_aside(dropped);
                }
            }
            for hash in &branch {
                let Some(at) = self.aside.iter().position(|aside| aside.root == *hash) else {
                    continue;
                };
                if let Some(taken) = self.aside.remove(at) {
                    // On the chain now: its delta counts from there.
                    self.unjoined.retain(|(_, carrier)| carrier != hash);
                    self.chain.push_back(taken);
                }
            }
            let follows = offered.previous.clone();
            self.adopt(offered, &follows);
            return RootOutcome::Switched;
        }
        // Its revocations hold either way, once each.
        for device in &offered.delta {
            if !self.unjoined.contains(&(*device, offered.root)) {
                self.unjoined.push((*device, offered.root));
            }
        }
        if heavier {
            // Not set aside: still unknown, it is what a peer is asked the
            // chain to.
            return RootOutcome::NeedsChain;
        }
        self.set_aside(offered);
        RootOutcome::KeptAside
    }

    /// The branch set aside that ends at one of `previous`, oldest first, and
    /// where on the chain it starts: climbed back through the roots set aside
    /// until one follows a root on the chain. `None` where it never gets there.
    fn branch_back(&self, previous: &[Hash]) -> Option<(usize, Vec<Hash>)> {
        let mut branch: Vec<Hash> = Vec::new();
        let mut at = previous.iter().find(|hash| self.is_aside(hash)).copied()?;
        // Every step is a root set aside, and there are no more of those.
        for _ in 0..=self.aside.len() {
            let remembered = self.aside.iter().find(|aside| aside.root == at)?;
            branch.push(at);
            if let Some(fork) =
                remembered.previous.iter().filter_map(|hash| self.position(hash)).max()
            {
                branch.reverse();
                return Some((fork, branch));
            }
            at = remembered.previous.iter().find(|hash| self.is_aside(hash)).copied()?;
        }
        None
    }

    /// Whether a root is one set aside.
    fn is_aside(&self, root: &Hash) -> bool {
        self.aside.iter().any(|aside| aside.root == *root)
    }

    /// Remembers a root set aside, within budget.
    fn set_aside(&mut self, root: Remembered) {
        self.aside.push_back(root);
        while self.aside.len() > self.budget {
            self.aside.pop_front();
        }
    }

    /// Judges a peer's leaf and proof against `against`, one of the roots on
    /// this member's chain.
    #[must_use]
    pub fn judge(
        &self,
        leaf: &DeviceLeaf,
        proof: &MembershipProof,
        against: &Hash,
    ) -> ProofVerdict {
        let Some(at) = self.position(against) else {
            return ProofVerdict::Renew;
        };
        let device = leaf.record.id;
        let named_since = self
            .chain
            .iter()
            .skip(at.saturating_add(1))
            .any(|remembered| remembered.delta.contains(&device));
        if named_since || self.invalidated(&device) {
            return ProofVerdict::Refused;
        }
        if proof.verifies(against, &self.network, leaf) {
            ProofVerdict::Accepted
        } else {
            ProofVerdict::Refused
        }
    }

    /// Where `device` stands under `against`, one of the roots on this
    /// member's chain, without a proof to check: for a proof already checked.
    #[must_use]
    pub fn standing(&self, device: &DeviceId, against: &Hash) -> ProofVerdict {
        let Some(at) = self.position(against) else {
            return ProofVerdict::Renew;
        };
        let named_since = self
            .chain
            .iter()
            .skip(at.saturating_add(1))
            .any(|remembered| remembered.delta.contains(device));
        if named_since || self.invalidated(device) {
            ProofVerdict::Refused
        } else {
            ProofVerdict::Accepted
        }
    }

    /// Writes the view.
    pub(crate) fn encode(&self, writer: &mut crate::cbor::Writer) {
        writer.map(5);
        writer.key("aside").array(self.aside.len() as u64);
        for remembered in &self.aside {
            remembered.encode(writer);
        }
        writer.key("chain").array(self.chain.len() as u64);
        for remembered in &self.chain {
            remembered.encode(writer);
        }
        writer.key("budget").u64(self.budget as u64);
        writer.key("network").bytes(self.network.as_bytes());
        writer.key("unjoined").array(self.unjoined.len() as u64);
        for (device, root) in &self.unjoined {
            writer.map(2);
            writer.key("root").bytes(root);
            writer.key("device").bytes(device.as_bytes());
        }
    }

    /// Reads a view back.
    pub(crate) fn decode(reader: &mut crate::cbor::Reader<'_>) -> crate::error::Result<Self> {
        use crate::error::Error;
        let hash = |reader: &mut crate::cbor::Reader<'_>| -> crate::error::Result<Hash> {
            Hash::try_from(reader.fixed_bytes(32)?).map_err(|_| Error::IdentifierLength)
        };
        let mut map = reader.map(LIGHT_VIEW_SCHEMA)?;
        let field = map.key("aside")?;
        let count = field.array(MAX_REMEMBERED, "roots set aside")?;
        let mut aside = VecDeque::with_capacity(count);
        for _ in 0..count {
            aside.push_back(Remembered::decode(field)?);
        }
        let field = map.key("chain")?;
        let count = field.array(MAX_REMEMBERED, "roots remembered")?;
        let mut chain = VecDeque::with_capacity(count);
        for _ in 0..count {
            chain.push_back(Remembered::decode(field)?);
        }
        let budget = usize::try_from(map.key("budget")?.u64()?).map_err(|_| Error::NonCanonical)?;
        let network = NetworkId::from_bytes(hash(map.key("network")?)?);
        let field = map.key("unjoined")?;
        let count = field.array(crate::limits::MAX_OPERATION_SIZE, "invalidations")?;
        let mut unjoined = Vec::with_capacity(count);
        for _ in 0..count {
            let mut entry = field.map(UNJOINED_SCHEMA)?;
            let root = hash(entry.key("root")?)?;
            let device = DeviceId::from_bytes(hash(entry.key("device")?)?);
            entry.finish()?;
            unjoined.push((device, root));
        }
        map.finish()?;
        if chain.is_empty() {
            return Err(Error::InvalidValue("a view remembering no root"));
        }
        Ok(Self { network, chain, budget: budget.max(1), unjoined, aside })
    }

    /// Makes `offered` current, joining what it follows and keeping to budget.
    fn adopt(&mut self, offered: Remembered, follows: &[Hash]) {
        // Invalidations carried by a root this one follows are joined into it.
        self.unjoined.retain(|(_, carrier)| !follows.contains(carrier));
        self.aside.retain(|aside| !follows.contains(&aside.root));
        self.chain.push_back(offered);
        while self.chain.len() > self.budget {
            self.chain.pop_front();
        }
    }

    /// Where a root sits on the chain, if it is remembered.
    fn position(&self, root: &Hash) -> Option<usize> {
        self.chain.iter().position(|remembered| remembered.root == *root)
    }
}

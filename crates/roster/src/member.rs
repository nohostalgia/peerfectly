//! A light member: what a device holding no roster keeps, and how it keeps it.
//!
//! It holds:
//! - its own evidence — its leaf, the proof of it, and the root they rest on;
//! - its view of the network's roots ([`LightView`]): the current one, the
//!   chain before it it can remember, and the invalidations not yet joined;
//! - the network's parameters, as far as it uses them;
//! - the peers it has checked, each with the leaf and proof it was shown —
//!   among them the full members it can turn to besides its contact.
//!
//! The parameters follow the roots: a full member hands over the parameters
//! with the root of the devices' tree, and the two together must make the root
//! this member holds — so a member far from any admin still moves with a relay
//! change or a new anchor list, and believes nothing it cannot check.
//!
//! From these it answers what a full member answers from its roster, for the
//! devices it knows: [`LightMember::state`] is a roster state holding itself and
//! its checked peers, so everything that reads a state — addresses, names,
//! routes — works on a light member unchanged, over what it knows.
//!
//! Uses `core` and `alloc` only, so it runs on a microcontroller.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::cbor::{Reader, Writer};
use crate::error::{Error, Result};
use crate::id::{DeviceId, NetworkId};
use crate::leaf::{DeviceLeaf, Mode};
use crate::light::{LightView, ProofVerdict, RootOutcome};
use crate::membership::{Evidence, MembershipProof};
use crate::merkle::Hash;
use crate::snapshot::{RawSnapshot, Snapshot};
use crate::state::RosterState;
use crate::types::NetworkParams;

/// Canonical key order of a light member.
pub const LIGHT_MEMBER_SCHEMA: &[&str] = &["own", "view", "peers", "params", "contact", "network"];

/// Canonical key order of a peer a light member checked.
pub const KNOWN_PEER_SCHEMA: &[&str] = &["leaf", "proof", "against"];

/// How many roots a light member remembers unless told otherwise.
pub const DEFAULT_BUDGET: usize = 64;

/// A peer a light member checked: its leaf, and the proof it was shown.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Known {
    leaf: DeviceLeaf,
    proof: MembershipProof,
    /// The root the proof is against.
    against: Hash,
}

/// What a light member holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightMember {
    network: NetworkId,
    own: Evidence,
    view: LightView,
    params: NetworkParams,
    peers: BTreeMap<DeviceId, Known>,
    /// The admin that signed the latest root this member took: a full member,
    /// and the one it reaches first where it knows no anchor.
    contact: DeviceLeaf,
}

/// The signed root behind `bytes`, its signature checked against the key its
/// own signer leaf names: whether that signer had the authority to sign is the
/// view's to judge.
fn signed_root(bytes: &[u8]) -> Result<Snapshot> {
    signed_raw(&RawSnapshot::decode(bytes)?)
}

/// As [`signed_root`], for a root already read.
fn signed_raw(raw: &RawSnapshot) -> Result<Snapshot> {
    let author = raw.body().author;
    let key = raw
        .body()
        .signer
        .record
        .keys
        .iter()
        .find(|entry| entry.key_id() == author)
        .ok_or(Error::UnauthorizedAuthor)
        .and_then(|entry| crate::sign::PublicKey::new(entry.alg, entry.value.clone()))?;
    Ok(raw.verify(&key)?.body().clone())
}

impl LightMember {
    /// A member starting from the evidence its admission gave it, which it
    /// trusts by how it arrived, and the parameters it uses.
    ///
    /// # Errors
    ///
    /// When the root does not verify under its signer's key, or the proof does
    /// not lead to it.
    pub fn new(own: Evidence, params: NetworkParams, budget: usize) -> Result<Self> {
        let root = signed_root(&own.root)?;
        if !own.proof.verifies(&root.root, &root.network, &own.leaf) {
            return Err(Error::SignatureInvalid);
        }
        Ok(Self {
            network: root.network,
            view: LightView::starting_from(&root, budget),
            contact: root.signer.clone(),
            own,
            params,
            peers: BTreeMap::new(),
        })
    }

    /// The network.
    #[must_use]
    pub const fn network(&self) -> NetworkId {
        self.network
    }

    /// This device.
    #[must_use]
    pub const fn device(&self) -> DeviceId {
        self.own.leaf.record.id
    }

    /// What this device shows a peer, as bytes.
    #[must_use]
    pub fn evidence(&self) -> Vec<u8> {
        self.own.to_bytes()
    }

    /// The parameters this member uses.
    #[must_use]
    pub const fn params(&self) -> &NetworkParams {
        &self.params
    }

    /// The full member this one reaches first where it knows no anchor: the
    /// admin that signed the latest root it took.
    #[must_use]
    pub const fn contact(&self) -> DeviceId {
        self.contact.record.id
    }

    /// The current root's hash.
    #[must_use]
    pub fn current(&self) -> Option<Hash> {
        self.view.current()
    }

    /// Where a peer's evidence rests on `root`, a root of this network this
    /// member knows nothing of: the root to ask the peer the chain after —
    /// its own current one. `None` for a root it knows, or of another network.
    #[must_use]
    pub fn behind(&self, root: &RawSnapshot) -> Option<Hash> {
        let body = root.body();
        if body.network != self.network || self.view.knows(&body.root) {
            return None;
        }
        self.view.current()
    }

    /// Takes a chain of roots a peer sent, in the order sent, and again while
    /// any of those that could not be placed yet can now: a peer's chain is in
    /// the order it took them, which need not be the order they follow each
    /// other. Whether any was taken.
    pub fn take_chain(&mut self, roots: &[Vec<u8>]) -> bool {
        let mut waiting: Vec<&[u8]> = roots.iter().map(Vec::as_slice).collect();
        let mut taken = false;
        loop {
            let before = waiting.len();
            waiting.retain(|bytes| match self.offer_root(bytes) {
                Ok(RootOutcome::Adopted | RootOutcome::Switched | RootOutcome::KeptAside) => {
                    taken = true;
                    false
                }
                Ok(RootOutcome::NeedsChain) => true,
                Ok(RootOutcome::AlreadyKnown | RootOutcome::Refused(_)) | Err(_) => false,
            });
            if waiting.is_empty() || waiting.len() == before {
                return taken;
            }
        }
    }

    /// The full members this one can turn to besides its contact: the peers it
    /// checked whose leaf says they are full. Sorted.
    #[must_use]
    pub fn known_fulls(&self) -> Vec<DeviceId> {
        self.peers
            .values()
            .filter(|known| known.leaf.settings.mode == Mode::Full)
            .map(|known| known.leaf.record.id)
            .filter(|device| *device != self.contact())
            .collect()
    }

    /// Takes the parameters a full member handed over, with the root of the
    /// devices' tree beside them: believed only where the two make the current
    /// root, which this member holds signed. Whether they changed anything.
    ///
    /// # Errors
    ///
    /// When this member holds no root, or the two do not make it.
    pub fn take_params(&mut self, devices_root: &Hash, params: NetworkParams) -> Result<bool> {
        let current = self.view.current().ok_or(Error::SnapshotUnverified)?;
        let made = RosterState::root_of(&self.network, devices_root, &params.tree().root());
        if made != current {
            return Err(Error::SnapshotStateMismatch);
        }
        let changed = params != self.params;
        self.params = params;
        Ok(changed)
    }

    /// Whether this member's own proof must be renewed: a root it holds names
    /// it, or no root it remembers is the one its proof rests on.
    #[must_use]
    pub fn needs_renewal(&self) -> bool {
        let Ok(root) = RawSnapshot::decode(&self.own.root) else { return true };
        self.view.standing(&self.device(), &root.body().root) != ProofVerdict::Accepted
    }

    /// The state this member knows: itself and the peers it checked, under its
    /// parameters.
    #[must_use]
    pub fn state(&self) -> RosterState {
        let mut state = RosterState::empty(self.network, self.params.clone());
        // The contact too, where nothing since revoked it: not proved under the
        // current root, and not needing to be — it is only dialled, and proves
        // itself as any peer does when the session opens.
        let contact = (!self.view.invalidated(&self.contact.record.id)).then_some(&self.contact);
        let leaves = core::iter::once(&self.own.leaf)
            .chain(contact)
            .chain(self.peers.values().map(|known| &known.leaf));
        for leaf in leaves {
            state.devices.insert(leaf.record.id, leaf.record.clone());
            state.set_settings(leaf.record.id, leaf.settings.clone());
        }
        state
    }

    /// Whether this member believes `leaf` under the root `root`: the root is
    /// one it remembers, and nothing since names the device.
    #[must_use]
    pub fn believes(&self, root: &RawSnapshot, leaf: &DeviceLeaf) -> bool {
        root.body().network == self.network
            && self.view.standing(&leaf.record.id, &root.body().root) == ProofVerdict::Accepted
    }

    /// Offers a root, as bytes. On adopting one, the peers it names are
    /// forgotten: they are judged again when next met.
    ///
    /// # Errors
    ///
    /// When the bytes are not a root signed by its own signer.
    pub fn offer_root(&mut self, bytes: &[u8]) -> Result<RootOutcome> {
        Ok(self.offer_signed(&signed_root(bytes)?))
    }

    /// Offers the root a peer showed beside its evidence: one newer than this
    /// member's is verified as any root is, and adopted where it follows.
    ///
    /// # Errors
    ///
    /// When it is not a root signed by its own signer.
    pub fn offer_shown_root(&mut self, root: &RawSnapshot) -> Result<RootOutcome> {
        Ok(self.offer_signed(&signed_raw(root)?))
    }

    fn offer_signed(&mut self, root: &Snapshot) -> RootOutcome {
        let outcome = self.view.offer(root);
        if matches!(outcome, RootOutcome::Adopted | RootOutcome::Switched) {
            self.contact = root.signer.clone();
        }
        if matches!(outcome, RootOutcome::Adopted | RootOutcome::Switched | RootOutcome::KeptAside)
        {
            let view = &self.view;
            self.peers.retain(|device, known| {
                !view.invalidated(device)
                    && view.standing(device, &known.against) != ProofVerdict::Refused
            });
        }
        outcome
    }

    /// Checks a peer's evidence and remembers the peer.
    ///
    /// # Errors
    ///
    /// When the evidence does not read, its proof does not hold, or this
    /// member does not believe it.
    pub fn learn(&mut self, evidence: &[u8]) -> Result<DeviceId> {
        let evidence = Evidence::from_bytes(evidence)?;
        let root = RawSnapshot::decode(&evidence.root)?;
        let against = root.body().root;
        match self.view.judge(&evidence.leaf, &evidence.proof, &against) {
            ProofVerdict::Accepted => {}
            ProofVerdict::Renew => return Err(Error::SnapshotUnverified),
            ProofVerdict::Refused => return Err(Error::SignatureInvalid),
        }
        let device = evidence.leaf.record.id;
        if device == self.device() {
            return Ok(device);
        }
        self.peers.insert(device, Known { leaf: evidence.leaf, proof: evidence.proof, against });
        Ok(device)
    }

    /// What this member shows without the root, as bytes: for an announcement.
    #[must_use]
    pub fn shown(&self) -> Vec<u8> {
        self.own.shown().map_or_else(|_| Vec::new(), |shown| shown.to_bytes())
    }

    /// Checks a peer's compact evidence against a root this member remembers,
    /// and remembers the peer.
    ///
    /// # Errors
    ///
    /// When it does not read, rests on a root this member does not remember,
    /// or does not hold.
    pub fn learn_shown(&mut self, shown: &[u8]) -> Result<DeviceId> {
        let shown = crate::membership::Shown::from_bytes(shown)?;
        match self.view.judge(&shown.leaf, &shown.proof, &shown.against) {
            ProofVerdict::Accepted => {}
            ProofVerdict::Renew => return Err(Error::SnapshotUnverified),
            ProofVerdict::Refused => return Err(Error::SignatureInvalid),
        }
        let device = shown.leaf.record.id;
        if device != self.device() {
            self.peers.insert(
                device,
                Known { leaf: shown.leaf, proof: shown.proof, against: shown.against },
            );
        }
        Ok(device)
    }

    /// Replaces this member's own evidence with a renewed one.
    ///
    /// # Errors
    ///
    /// When it is not this device's, or this member does not believe it.
    pub fn renew(&mut self, evidence: Evidence) -> Result<()> {
        if evidence.leaf.record.id != self.device() {
            return Err(Error::InvalidValue("another device's evidence"));
        }
        let root = RawSnapshot::decode(&evidence.root)?;
        if self.view.judge(&evidence.leaf, &evidence.proof, &root.body().root)
            != ProofVerdict::Accepted
        {
            return Err(Error::SignatureInvalid);
        }
        self.own = evidence;
        Ok(())
    }

    /// Replaces the parameters this member uses, as a full member gave them.
    pub fn set_params(&mut self, params: NetworkParams) {
        self.params = params;
    }

    /// Its canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.map(6);
        writer.key("own").bytes(&self.own.to_bytes());
        writer.key("view");
        self.view.encode(&mut writer);
        writer.key("peers").array(self.peers.len() as u64);
        for known in self.peers.values() {
            writer.map(3);
            writer.key("leaf");
            known.leaf.encode(&mut writer);
            writer.key("proof");
            known.proof.encode(&mut writer);
            writer.key("against").bytes(&known.against);
        }
        writer.key("params");
        self.params.encode(&mut writer);
        writer.key("contact");
        self.contact.encode(&mut writer);
        writer.key("network").bytes(self.network.as_bytes());
        writer.finish()
    }

    /// Reads a member back.
    ///
    /// # Errors
    ///
    /// When the bytes are not a canonical light member.
    pub fn from_bytes(input: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(input);
        let mut map = reader.map(LIGHT_MEMBER_SCHEMA)?;
        let own = Evidence::from_bytes(map.key("own")?.bytes(usize::MAX, "evidence")?)?;
        let view = LightView::decode(map.key("view")?)?;
        let peers_reader = map.key("peers")?;
        let count = peers_reader.array(input.len(), "known peers")?;
        let mut peers = BTreeMap::new();
        for _ in 0..count {
            let mut entry = peers_reader.map(KNOWN_PEER_SCHEMA)?;
            let leaf = DeviceLeaf::decode(entry.key("leaf")?)?;
            let proof = MembershipProof::decode(entry.key("proof")?)?;
            let against = Hash::try_from(entry.key("against")?.fixed_bytes(32)?)
                .map_err(|_| Error::IdentifierLength)?;
            entry.finish()?;
            peers.insert(leaf.record.id, Known { leaf, proof, against });
        }
        let params = NetworkParams::decode(map.key("params")?)?;
        let contact = DeviceLeaf::decode(map.key("contact")?)?;
        let network = NetworkId::decode(map.key("network")?)?;
        map.finish()?;
        reader.finish()?;
        Ok(Self { network, own, view, params, peers, contact })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::is_canonical_schema;

    #[test]
    fn the_schemas_are_canonical() {
        assert!(is_canonical_schema(LIGHT_MEMBER_SCHEMA));
        assert!(is_canonical_schema(KNOWN_PEER_SCHEMA));
    }
}

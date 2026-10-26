//! Deriving the roster from the graph.
//!
//! [`derive`] is a free function of a [`Dag`] and nothing else. It takes no
//! configuration, reads no clock, and cannot see the order in which operations
//! arrived. That is not stylistic: if any of those could reach this code, two
//! nodes holding the same operations would derive different households, and a
//! revoked laptop would stay reachable on one of them.
//!
//! # Validity is a fixpoint, not a single pass
//!
//! Ancestor-relative validity alone would be a plain topological pass: an
//! operation's authority comes from its own ancestors, which always precede it.
//!
//! The causal authorship rule breaks that. An operation is void if it is
//! *concurrent* with the removal of its author's authority, and a concurrent
//! operation has no ordering relative to it — the removal may sit at a higher
//! index, or a lower one, and its own validity may in turn depend on the
//! operation being judged. Two admins demoting each other simultaneously is the
//! smallest case: each demotion's validity depends on the other's.
//!
//! So validity is computed by rounds. Every operation starts valid; each round
//! recomputes the whole verdict from the previous round's set and marks the
//! failures; **an operation once marked invalid is never restored.** That last
//! clause is what makes it terminate rather than oscillate, and it settles the
//! mutual-demotion case the safe way: both demotions are void and both admins
//! keep their roles, leaving a person to resolve it deliberately.
//!
//! Each round reads only the previous round's set, so no operation's verdict
//! depends on the order operations are visited within a round.
//!
//! # A round has two stages, and the order of them is the point
//!
//! Within a round, every rule but the causal authorship one is applied first.
//! What survives that is *authorised*: written by an author entitled to write it.
//! Only then is the causal authorship rule applied, and only **authorised**
//! removals count as removals.
//!
//! Marks are permanent, so an operation voided by a removal that later turns out
//! to be void itself would never come back — the two stages are what stop that
//! from arising. Before they existed, a revocation that had no effect at all
//! still took its concurrent neighbours down with it: a member's revocation of an
//! admin, or an admin's revocation of a founder, silently voided the work of the
//! device it named. An act nobody was entitled to make is not a removal, and
//! removes nothing.

use std::collections::{BTreeMap, BTreeSet};

use crate::cbor::{Reader, Writer};
use crate::dag::{Dag, Foundation};
use crate::error::{Error, Result};
use crate::id::{DeviceId, KeyId, OperationId};
use crate::leaf::{DeviceLeaf, DeviceSettings, Mode, SettingsChange};
use crate::merkle;
use crate::parameters::{PARAMETER_NAMES, Parameter};
use crate::types::{DeviceRecord, DeviceSpec, NetworkParams, OperationBody, Role};

/// Field names of the canonical roster-state encoding, in canonical order.
pub const ROSTER_STATE_SCHEMA: &[&str] = &["params", "devices", "network", "settings"];

/// The roster as an operation set implies it.
///
/// Ordered containers throughout, so that iteration, debugging output, and the
/// canonical encoding are all identical on every node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterState {
    /// The network's identifier, which is its founding operation's id.
    pub network: crate::id::NetworkId,
    /// The current network parameters.
    pub params: NetworkParams,
    /// Devices currently in the network, with their settings, keyed by id: a
    /// shared base and the changes on top of it, with the tree over them kept
    /// as they change (`crate::members`).
    pub devices: crate::members::Members,
    /// Devices removed by a revocation this node still holds, and not admitted
    /// again.
    ///
    /// For telling an expelled device from a stranger, and nothing else. It is
    /// not committed by the root nor carried in the state's bytes: once a
    /// checkpoint absorbs a revocation, the device is merely absent, and a node
    /// that holds the window and one that holds the whole history agree on
    /// everything the root commits to.
    pub revoked: BTreeSet<DeviceId>,
}

/// The context the state's root is derived under.
const STATE_ROOT_CONTEXT: &str = "peerfectly state root v1";

impl RosterState {
    /// A device's settings: those an admin set, or the default.
    #[must_use]
    pub fn settings_of(&self, device: &DeviceId) -> DeviceSettings {
        self.devices.get(device).map(|leaf| leaf.settings.clone()).unwrap_or_default()
    }

    /// A state from its parts as maps: the devices' records, and the settings
    /// of those whose settings are not the default.
    #[must_use]
    pub fn from_parts(
        network: crate::id::NetworkId,
        params: NetworkParams,
        devices: BTreeMap<DeviceId, DeviceRecord>,
        revoked: BTreeSet<DeviceId>,
        mut settings: BTreeMap<DeviceId, DeviceSettings>,
    ) -> Self {
        let devices = devices
            .into_iter()
            .map(|(device, record)| DeviceLeaf {
                record,
                settings: settings.remove(&device).unwrap_or_default(),
            })
            .collect();
        Self { network, params, devices, revoked }
    }

    /// A state of `network` under `params`, with no devices.
    #[must_use]
    pub fn empty(network: crate::id::NetworkId, params: NetworkParams) -> Self {
        Self {
            network,
            params,
            devices: crate::members::Members::new(),
            revoked: BTreeSet::new(),
        }
    }

    /// The device holding a key of any purpose.
    #[must_use]
    pub fn device_holding(&self, key: &KeyId) -> Option<DeviceId> {
        self.devices.holding(key, None).map(|leaf| leaf.record.id)
    }

    /// The devices `previous` held whose leaf this state no longer holds as it
    /// was: revoked, or changed in any way. Sorted.
    ///
    /// Admissions are not listed: a device `previous` did not hold has no
    /// earlier proof to invalidate.
    #[must_use]
    pub fn delta_from(&self, previous: &Self) -> Vec<DeviceId> {
        // Over one base, only where either changed; otherwise every device.
        if let Some(differing) = self.devices.differing(&previous.devices) {
            return differing
                .into_iter()
                .filter(|device| previous.devices.contains_key(device))
                .collect();
        }
        previous
            .devices
            .iter()
            .filter(|(device, leaf)| self.devices.get(device).as_deref() != Some(&**leaf))
            .map(|(device, _)| device)
            .collect()
    }

    /// Records a device's settings, keeping only those that differ from the
    /// default, so that one state has one representation.
    pub fn set_settings(&mut self, device: DeviceId, settings: DeviceSettings) {
        self.devices.set_settings(device, settings);
    }

    /// A device as the state tree holds it, if it is a member.
    #[must_use]
    pub fn leaf(&self, device: &DeviceId) -> Option<DeviceLeaf> {
        self.devices.get(device).map(|leaf| (*leaf).clone())
    }

    /// The tree of the state's devices, one leaf per member: kept as they
    /// change, so this costs a copy of a reference.
    #[must_use]
    pub fn devices_tree(&self) -> merkle::Tree {
        self.devices.tree().clone()
    }

    /// The root committing to this state: the network, its devices and its
    /// parameters.
    ///
    /// A function of the state alone, so a node that derived the state from
    /// the whole history and one that holds only the recent window compute the
    /// same root.
    #[must_use]
    pub fn root(&self) -> merkle::Hash {
        Self::root_of(&self.network, &self.devices.root(), &self.params.tree().root())
    }

    /// The state root over a network and the roots of its two subtrees.
    #[must_use]
    pub fn root_of(
        network: &crate::id::NetworkId,
        devices: &merkle::Hash,
        parameters: &merkle::Hash,
    ) -> merkle::Hash {
        let mut hasher = blake3::Hasher::new_derive_key(STATE_ROOT_CONTEXT);
        hasher.update(network.as_bytes());
        hasher.update(devices);
        hasher.update(parameters);
        *hasher.finalize().as_bytes()
    }

    /// Whether a device is currently an admin.
    #[must_use]
    pub fn is_admin(&self, device: &DeviceId) -> bool {
        self.devices.get(device).is_some_and(|record| record.role == Role::Admin)
    }

    /// Whether a device is a founder.
    #[must_use]
    pub fn is_founder(&self, device: &DeviceId) -> bool {
        self.devices.get(device).is_some_and(|record| record.founder)
    }

    /// The device holding a given signing key.
    ///
    /// An operation's `author` is a key id, not a device id: the two coincide
    /// for a device with one signing key and differ for a device that also
    /// holds an enclave key, so this lookup is not the identity function.
    #[must_use]
    pub fn device_for_key(&self, key: &KeyId) -> Option<alloc::sync::Arc<DeviceLeaf>> {
        self.device_for_key_of_purpose(key, crate::types::KeyPurpose::Signing)
    }

    /// The device holding a given key *for a stated purpose*.
    ///
    /// The purpose is not a filter for convenience; it is the check. A device's
    /// signing key and transport key are distinct by construction precisely so
    /// that one cannot stand in for the other, and a lookup that ignored purpose
    /// would let a signing key authenticate a transport session — the
    /// cross-protocol confusion the separation exists to prevent.
    ///
    /// Kept here, beside the roster's own use of it, so there is one definition
    /// rather than one per caller that needs a purpose other than signing.
    #[must_use]
    pub fn device_for_key_of_purpose(
        &self,
        key: &KeyId,
        purpose: crate::types::KeyPurpose,
    ) -> Option<alloc::sync::Arc<DeviceLeaf>> {
        self.devices.holding(key, Some(purpose))
    }

    /// The canonical bytes of this state.
    ///
    /// Two nodes deriving the same roster must produce the same bytes here, so
    /// merge vectors can pin an expected result and tests can compare states
    /// byte for byte rather than field by field.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.map(4);
        writer.key("params");
        self.params.encode(&mut writer);
        writer.key("devices").array(self.devices.len() as u64);
        for leaf in self.devices.values() {
            leaf.record.encode(&mut writer);
        }
        writer.key("network").bytes(self.network.as_bytes());
        // Only devices whose settings differ from the default, by id.
        let changed: Vec<(DeviceId, DeviceSettings)> = self.devices.changed_settings().collect();
        writer.key("settings").array(changed.len() as u64);
        for (device, settings) in &changed {
            writer.array(2);
            device.encode(&mut writer);
            settings.encode(&mut writer);
        }
        writer.finish()
    }

    /// Reads state back from its canonical bytes.
    ///
    /// A snapshot carries state as bytes, and a node bootstrapping from one has
    /// to turn them back into a roster. Decoding is as strict as everywhere
    /// else: a snapshot whose state is not canonical is not a snapshot.
    pub fn from_bytes(input: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(input);
        let mut map = reader.map(ROSTER_STATE_SCHEMA)?;
        let params = NetworkParams::decode(map.key("params")?)?;

        let devices_reader = map.key("devices")?;
        let device_count = devices_reader.array(crate::limits::MAX_OPERATIONS, "device count")?;
        let mut devices = BTreeMap::new();
        for _ in 0..device_count {
            let record = DeviceRecord::decode(devices_reader)?;
            devices.insert(record.id, record);
        }

        let network = crate::id::NetworkId::decode(map.key("network")?)?;

        let settings_reader = map.key("settings")?;
        let settings_count =
            settings_reader.array(crate::limits::MAX_OPERATIONS, "device settings count")?;
        let mut settings = BTreeMap::new();
        let mut last: Option<DeviceId> = None;
        for _ in 0..settings_count {
            if settings_reader.array(2, "device settings")? != 2 {
                return Err(Error::NonCanonical);
            }
            let device = DeviceId::decode(settings_reader)?;
            let value = DeviceSettings::decode(settings_reader)?;
            // By id, each once, members only, and never the default: one
            // spelling for one state.
            if last.is_some_and(|previous| previous >= device)
                || !devices.contains_key(&device)
                || value == DeviceSettings::default()
            {
                return Err(Error::NonCanonical);
            }
            last = Some(device);
            settings.insert(device, value);
        }

        map.finish()?;
        reader.finish()?;
        // Revocations are not part of the committed state: a node starting from
        // these bytes knows of none until it holds the operations that make them.
        let devices = devices
            .into_iter()
            .map(|(device, record)| DeviceLeaf {
                record,
                settings: settings.remove(&device).unwrap_or_default(),
            })
            .collect();
        Ok(Self { network, params, devices, revoked: BTreeSet::new() })
    }

    /// A short digest of the state, for comparing two nodes cheaply.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        crate::id::digest(&self.to_bytes())
    }
}

/// Why an operation contributes nothing to derived state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalidity {
    /// The author did not hold the admin role in the state derived from this
    /// operation's own causal ancestors.
    UnauthorizedAuthor,
    /// The operation is causally concurrent with the removal of its author's
    /// authority.
    ConcurrentWithAuthorRemoval,
    /// A `revoke_device` or `demote` targeted a founder other than its author.
    FounderProtected,
    /// The founding operation did not declare its own author as an admin
    /// founder.
    MalformedGenesis,
    /// Its author signed two causally concurrent operations — two histories from
    /// one identity — and neither branch is granted effect.
    Equivocated,
}

impl Invalidity {
    /// A stable, language-neutral name, matching the corresponding
    /// [`Error::kind`] so a merge vector and a negative vector can name the
    /// same reason the same way.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::UnauthorizedAuthor => "unauthorized_author",
            Self::ConcurrentWithAuthorRemoval => "concurrent_with_author_removal",
            Self::Equivocated => "equivocated",
            Self::FounderProtected => "founder_protected",
            Self::MalformedGenesis => "missing_genesis",
        }
    }
}

impl From<Invalidity> for Error {
    fn from(value: Invalidity) -> Self {
        match value {
            Invalidity::UnauthorizedAuthor => Self::UnauthorizedAuthor,
            Invalidity::ConcurrentWithAuthorRemoval => Self::ConcurrentWithAuthorRemoval,
            Invalidity::FounderProtected => Self::FounderProtected,
            Invalidity::MalformedGenesis => Self::MissingGenesis,
            Invalidity::Equivocated => Self::Equivocated,
        }
    }
}

/// The outcome of judging every operation in a graph.
#[derive(Debug, Clone)]
pub struct Verdicts {
    /// Why each operation was rejected, by index; `None` where it stands.
    reasons: Vec<Option<Invalidity>>,
}

impl Verdicts {
    /// Whether the operation at an index contributes to derived state.
    #[must_use]
    pub fn is_valid(&self, index: usize) -> bool {
        self.reasons.get(index).is_some_and(Option::is_none)
    }

    /// Why the operation at an index was rejected.
    #[must_use]
    pub fn reason(&self, index: usize) -> Option<Invalidity> {
        self.reasons.get(index).copied().flatten()
    }

    /// How many operations were rejected.
    #[must_use]
    pub fn rejected_count(&self) -> usize {
        self.reasons.iter().filter(|reason| reason.is_some()).count()
    }
}

/// Derives the roster implied by a graph.
///
/// This takes a [`Dag`] and not a [`crate::roster::Roster`] on purpose. The
/// roster owns node-local policy — the staleness threshold, the pending set —
/// and none of it may reach here. If it could, two nodes holding identical
/// operations would derive different households depending on what each had seen,
/// which is a consensus split rather than a configuration difference. Keeping
/// this a free function over the graph makes that mistake fail to compile.
pub fn derive(dag: &Dag) -> Result<RosterState> {
    Ok(derive_with_verdicts(dag)?.0)
}

/// Derives the roster, and says why any operation was disregarded.
pub fn derive_with_verdicts(dag: &Dag) -> Result<(RosterState, Verdicts)> {
    let foundation = dag.foundation().ok_or(Error::MissingGenesis)?;
    let base = Base::build(dag, &foundation)?;
    let verdicts = judge(dag, &base)?;
    let mask: Vec<bool> = (0..dag.len())
        // A covered head is retained only as an anchor for its children: its
        // effects are already inside the snapshot's state, so applying it again
        // would count it twice.
        .map(|index| verdicts.is_valid(index) && !dag.is_covered(index))
        .collect();
    let state = resolve(dag, &base, &mask).ok_or(Error::MissingGenesis)?;
    Ok((state, verdicts))
}

/// Derives the state a region of the graph implies, judging its operations
/// against each other and nothing outside it.
///
/// The region is a downward-closed set of indices — a root's covered set — and
/// the result is what a node holding exactly those operations would derive.
/// Works on a compacted graph too: the region then rests on the graph's base,
/// as every derivation on it does, and that is what makes verifying the next
/// root possible after the last compaction.
///
/// # Errors
///
/// When the graph rests on nothing.
pub fn derive_region(dag: &Dag, region: &[usize]) -> Result<RosterState> {
    let foundation = dag.foundation().ok_or(Error::MissingGenesis)?;
    let base = Base::build(dag, &foundation)?;
    let mut scope = vec![false; dag.len()];
    for index in region {
        if let Some(slot) = scope.get_mut(*index) {
            *slot = true;
        }
    }
    let verdicts = judge_within(dag, &base, Some(&scope))?;
    let mask: Vec<bool> = (0..dag.len())
        .map(|index| {
            scope.get(index).copied().unwrap_or(false)
                && verdicts.is_valid(index)
                && !dag.is_covered(index)
        })
        .collect();
    resolve(dag, &base, &mask).ok_or(Error::MissingGenesis)
}

/// The state a derivation starts from, and the rank everything in it carries.
///
/// Either the founding operation, or a snapshot standing in for the operations
/// that have been discarded. Both reduce to the same two things: a seed state,
/// and a rank that every later operation must outrank.
struct Base {
    /// The state the foundation establishes.
    state: RosterState,
    /// The rank of everything the foundation covers.
    ///
    /// Every operation after the foundation has strictly greater causal depth,
    /// so it always wins the last-writer-wins comparison. That is what lets a
    /// compacted node reach the same answer as one that discarded nothing.
    rank: Rank,
    /// The founding operation's id, where there is one.
    genesis: Option<usize>,
}

impl Base {
    /// Builds the starting point for a derivation.
    fn build(dag: &Dag, foundation: &Foundation) -> Result<Self> {
        match foundation {
            Foundation::Genesis(index) => {
                let operation = dag.operation(*index).ok_or(Error::MissingGenesis)?;
                let OperationBody::CreateNetwork { device, params } = &operation.core().body else {
                    return Err(Error::MissingGenesis);
                };
                let network = dag.network().ok_or(Error::MissingGenesis)?;
                let id = device.device_id()?;
                let mut state = RosterState::empty(network, params.clone());
                state.devices.insert(id, device.clone().into_record(operation.id())?);
                Ok(Self {
                    state,
                    rank: Rank::new(0, operation.id()),
                    genesis: Some(*index),
                })
            }
            Foundation::Snapshot(footing) => {
                let body = footing.snapshot.body();
                let state = footing.state.clone();
                if state.network != body.network {
                    return Err(Error::ForeignNetwork);
                }
                Ok(Self {
                    state,
                    // Everything the snapshot covers sits at or below its
                    // deepest head, so this is the rank a post-snapshot
                    // operation must beat — and always does.
                    rank: Rank::new(body.frontier_depth(), OperationId::from_bytes([0; 32])),
                    genesis: None,
                })
            }
        }
    }
}

/// Runs the validity rounds described in the module documentation.
fn judge(dag: &Dag, base: &Base) -> Result<Verdicts> {
    judge_within(dag, base, None)
}

/// Judges every operation, optionally within a subset of the graph.
///
/// `scope` is `None` for deriving state, which judges the whole graph. It is a
/// mask when an operation is being judged against **its own ancestors**, where
/// nothing outside that set may be consulted: the answer has to be the same on
/// every node holding those ancestors, and what else a node holds is not
/// something the operation's author could know or the network could agree on.
fn judge_within(dag: &Dag, base: &Base, scope: Option<&[bool]>) -> Result<Verdicts> {
    let count = dag.len();
    let mut reasons: Vec<Option<Invalidity>> = vec![None; count];

    // The founding operation stands or falls on its own: it must declare its
    // own author as an admin founder, since there is no earlier state to
    // consult. A graph resting on a snapshot has no founding operation to
    // check; the snapshot was checked when it was accepted.
    if let Some(genesis) = base.genesis
        && let Some(reason) = judge_genesis(dag, genesis)
    {
        return Err(reason.into());
    }

    let within = |index: usize| scope.is_none_or(|mask| mask.get(index).copied().unwrap_or(false));

    loop {
        let valid_now: Vec<bool> = reasons
            .iter()
            .enumerate()
            .map(|(index, reason)| reason.is_none() && within(index))
            .collect();
        let mut newly_invalid: Vec<(usize, Invalidity)> = Vec::new();
        // What each operation's ancestors imply, against this round's valid
        // set: fixed for the round, so computed once and shared by every rule.
        let eligible: Vec<bool> = valid_now
            .iter()
            .enumerate()
            .map(|(index, valid)| *valid && !dag.is_covered(index))
            .collect();
        let mut memo = Memo::new();

        // Every rule but the causal authorship one, which needs this answer
        // before it can be asked. An operation is *authorised* when its author
        // was entitled to write it — which is what decides whether it counts as
        // a removal below, and is a different question from whether it survived
        // being concurrent with somebody else's.
        let mut authorised = valid_now.clone();
        for index in 0..count {
            if !valid_now.get(index).copied().unwrap_or(false) {
                continue;
            }
            // The foundation is not judged: the genesis bootstraps the rule, and
            // a covered head was judged before the snapshot that covers it was
            // accepted.
            if base.genesis == Some(index) || dag.is_covered(index) {
                continue;
            }
            if let Some(reason) = judge_one(dag, base, index, &eligible, scope, &mut memo) {
                newly_invalid.push((index, reason));
                if let Some(slot) = authorised.get_mut(index) {
                    *slot = false;
                }
            }
        }

        // Then the causal authorship rule, against the removals that were
        // somebody's to make. An operation already failing another rule is left
        // with the reason it failed, which is the more specific complaint.
        for index in 0..count {
            if !authorised.get(index).copied().unwrap_or(false) {
                continue;
            }
            if base.genesis == Some(index) || dag.is_covered(index) {
                continue;
            }
            let Some(author) = author_of(dag, base, index, &eligible, &mut memo) else { continue };
            if let Some(reason) = voided_by_concurrent_removal(dag, index, author, &authorised) {
                newly_invalid.push((index, reason));
            }
        }

        if newly_invalid.is_empty() {
            break;
        }
        for (index, reason) in newly_invalid {
            if let Some(slot) = reasons.get_mut(index) {
                // Never restored once marked: this is what makes the rounds
                // terminate instead of oscillating between two operations that
                // invalidate each other.
                *slot = Some(reason);
            }
        }
    }

    Ok(Verdicts { reasons })
}

/// Checks the founding operation against itself.
fn judge_genesis(dag: &Dag, genesis: usize) -> Option<Invalidity> {
    let operation = dag.operation(genesis)?;
    let OperationBody::CreateNetwork { device, .. } = &operation.core().body else {
        return Some(Invalidity::MalformedGenesis);
    };
    if device.role != Role::Admin || !device.founder {
        return Some(Invalidity::MalformedGenesis);
    }
    // The author must be one of the signing keys of the device it declares,
    // or the network is founded by a key it does not itself name.
    let declares_author = device.keys.iter().any(|entry| {
        entry.purpose == crate::types::KeyPurpose::Signing
            && entry.key_id() == operation.core().author
    });
    if declares_author { None } else { Some(Invalidity::MalformedGenesis) }
}

/// The state implied by the ancestors of an operation that is **not** in the
/// graph — the parents it names, and everything they descend from.
///
/// This is what admission judges an offered operation against, and it is built
/// the way derivation builds the same thing: the valid, uncovered ancestors of
/// those parents, resolved over the foundation. An operation inserted into the
/// graph is then judged by `judge_one` against exactly this state, so the two
/// cannot answer differently about the same operation.
///
/// Every parent must be present; a caller holding an operation with a missing
/// parent has a pending operation, not one to judge.
///
/// # Errors
///
/// [`Error::MissingGenesis`] when the graph has no foundation, when a parent is
/// absent, or when the state cannot be resolved.
pub fn state_for_parents(dag: &Dag, parents: &[OperationId]) -> Result<RosterState> {
    let foundation = dag.foundation().ok_or(Error::MissingGenesis)?;
    let base = Base::build(dag, &foundation)?;

    // The parents themselves as well as what they descend from: an operation's
    // ancestors include the operations it names.
    let mut scope = vec![false; dag.len()];
    for parent in parents {
        let index = dag.position(parent).ok_or(Error::MissingGenesis)?;
        for ancestor in core::iter::once(index).chain(dag.ancestors_of(index)) {
            if let Some(slot) = scope.get_mut(ancestor) {
                *slot = true;
            }
        }
    }

    // Judged inside that set and nowhere else. An operation's ancestors are
    // fixed the moment its author signs it, so a verdict that reads only them is
    // the same verdict on every node — which is what lets admission refuse
    // without two nodes disagreeing about what the network holds.
    let verdicts = judge_within(dag, &base, Some(&scope))?;
    let mask: Vec<bool> = (0..dag.len())
        .map(|index| {
            scope.get(index).copied().unwrap_or(false)
                && verdicts.is_valid(index)
                && !dag.is_covered(index)
        })
        .collect();
    resolve(dag, &base, &mask).ok_or(Error::MissingGenesis)
}

/// The state after one operation that **extends every head** of the graph, or
/// `None` where only deriving can say.
///
/// The fast path of admission and of keeping state. An operation whose parents
/// are all the current heads is concurrent with nothing: no operation already
/// held changes its verdict, nothing already held becomes equivocated, and
/// last-writer-wins has no other writer to compare against. So the whole update
/// is this operation applied to the state its parents imply, which is the state
/// the graph was already in.
///
/// It must be called only in that case. Anywhere else — a merge, an operation
/// anchored behind the frontier, an integration from the pending set — the roster
/// derives instead, because there the comparisons this skips are the ones that
/// decide the answer. `Roster` is what holds to that, and the property tests
/// check the result against [`derive`] after every admission.
///
/// Even then, some operations decide by more than the state shows. Derivation
/// settles an address two devices were assigned, and an admin's light setting,
/// over every operation held, so the device that lost keeps its claim: a
/// revocation, a promotion or demotion, or a change of mode or address can give
/// back what an earlier operation was overruled on, and the state no longer
/// says what. For those this answers `None`, and the roster derives — which
/// costs the window, not the network. Founder protection is among what
/// derivation then judges.
#[must_use]
pub fn extend(
    state: &RosterState,
    operation: &crate::sign::VerifiedOperation,
) -> Option<RosterState> {
    let mut next = state.clone();
    match &operation.core().body {
        // The founding operation names no parents, so it never extends a head.
        // A batch takes effect only once every entry is held, which is the
        // batch handling's to decide, not one operation's.
        OperationBody::CreateNetwork { .. } | OperationBody::AdmitBatch(_) => {}
        OperationBody::RevokeDevice { .. }
        | OperationBody::Promote { .. }
        | OperationBody::Demote { .. } => return None,
        OperationBody::AddDevice(spec) => {
            let Ok(id) = spec.device_id() else { return Some(next) };
            // The first add wins: a second add changes a device that is already
            // a member not at all. An add extending every head follows every
            // revocation held, so a revoked device is admitted again.
            if next.devices.contains_key(&id) {
                return Some(next);
            }
            next.revoked.remove(&id);
            next.devices.insert(
                id,
                DeviceRecord {
                    id,
                    keys: spec.keys.clone(),
                    name: spec.name.clone(),
                    role: spec.role,
                    founder: spec.founder,
                    added_by: operation.id(),
                    capabilities: spec.capabilities.clone(),
                },
            );
        }
        OperationBody::Rename { device, name } => {
            next.devices.modify(device, |record| record.name.clone_from(name));
        }
        OperationBody::SetNetwork(params) => next.params = params.clone(),
        OperationBody::SetDevice { device, change } => {
            if change.mode.is_some() || change.ipv4.is_some() {
                return None;
            }
            let settings = next.settings_of(device).changed_by(change);
            next.set_settings(*device, settings);
        }
    }
    keep_member_anchors(&mut next);
    Some(next)
}

/// Drops from the anchor list every entry that names no member.
///
/// An anchor revoked, or never admitted, is ignored the same way on every node,
/// without an admin having to remove it.
fn keep_member_anchors(state: &mut RosterState) {
    let devices = &state.devices;
    state.params.anchors.retain(|anchor| devices.contains_key(anchor));
}

/// Whether an author lacks the authority every operation but `create_network`
/// requires, in a given state.
///
/// The one place the rule lives. Derivation judges an operation against the state
/// its own ancestors imply; admission judges an offered operation against the same
/// thing before it is inserted, so that an operation which can never have effect
/// never occupies a slot. Two copies of this rule would be two answers to "who may
/// write to this network", and the roster may only have one.
///
/// **An author the state does not name is unauthorised**, and saying so is the
/// point rather than a detail. It reads as an obvious case only once it is
/// written down: a device can anchor an operation *before its own admission*, so
/// that the state its ancestors imply does not name it at all. Answering "no
/// invalidity" there — which is what falling through used to do — let any member
/// author anything it liked, founder protection included, by anchoring at the
/// founding operation.
#[must_use]
pub fn unauthorized_author(state: &RosterState, author: &KeyId) -> Option<Invalidity> {
    let Some(device) = state.device_for_key(author) else {
        return Some(Invalidity::UnauthorizedAuthor);
    };
    if device.role != Role::Admin || state.revoked.contains(&device.id) {
        return Some(Invalidity::UnauthorizedAuthor);
    }
    None
}

/// Judges one non-genesis operation against the currently-valid set.
fn judge_one(
    dag: &Dag,
    base: &Base,
    index: usize,
    eligible: &[bool],
    scope: Option<&[bool]>,
    memo: &mut Memo,
) -> Option<Invalidity> {
    let operation = dag.operation(index)?;

    // Equivocation, judged first because it is a property of the graph alone and
    // needs none of the ancestor state computed below.
    //
    // An honest device anchors each operation to its own previous one. Two by one
    // author that are causally concurrent mean it signed two histories, and
    // neither is granted effect: choosing between them would be letting the
    // equivocator pick, since it chose what to show whom.
    //
    // **Only the author's own two operations lose their effect.** Another
    // device's work that merely anchored to one of them keeps its validity — it
    // is judged by its own author, below. Voiding descendants instead would hand
    // an equivocator a way to erase a month of the network's history by signing
    // one late sibling, firing backwards at a moment of its choosing.
    //
    // Revocation is exempt, as it is everywhere in this file. A rule that let
    // somebody un-revoke a device by forking would be worse than the fork.
    let revokes = matches!(operation.core().body, OperationBody::RevokeDevice { .. });
    if !revokes && dag.is_equivocated_within(index, scope) {
        return Some(Invalidity::Equivocated);
    }

    // The state this operation's own ancestors imply — never current state, so
    // that demoting an admin does not retroactively void what they wrote. On a
    // compacted graph the discarded ancestors are exactly those the base
    // already accounts for, so the two together are the same set.
    let ancestor_state = ancestor_state(dag, base, eligible, index, memo)?;

    if let Some(reason) = unauthorized_author(ancestor_state, &operation.core().author) {
        return Some(reason);
    }
    // Present, admin and unrevoked, by the check above.
    let author_id = match ancestor_state.device_for_key(&operation.core().author) {
        Some(device) => device.id,
        None => return Some(Invalidity::UnauthorizedAuthor),
    };

    // Founder protection, judged in the same ancestor-relative state: only a
    // founder may retire itself, and no admin may retire another.
    if let Some(target) = Dag::target_of(&operation.core().body) {
        let removes_authority = matches!(
            operation.core().body,
            OperationBody::RevokeDevice { .. } | OperationBody::Demote { .. }
        );
        if removes_authority && ancestor_state.is_founder(&target) && target != author_id {
            return Some(Invalidity::FounderProtected);
        }
    }

    None
}

/// Whether an operation is void because its author was removed concurrently.
///
/// The causal authorship rule. Work this author did before losing authority is a
/// causal ancestor of the removal and stands; work concurrent with the removal
/// does not.
///
/// **Only an authorised removal counts.** `authorised` says which operations are
/// valid by every rule *except* this one — which is exactly the question "was
/// this act one its author was entitled to make". A removal that was not is no
/// removal at all: a member's revocation of an admin, or an admin's revocation of
/// a founder, has no effect on the device it names, and must have none on
/// anything else either. Reading the running valid set here instead would let an
/// operation that is itself void take the work of others down with it, and the
/// marks are permanent, so nothing would ever bring them back.
fn voided_by_concurrent_removal(
    dag: &Dag,
    index: usize,
    author: DeviceId,
    authorised: &[bool],
) -> Option<Invalidity> {
    for (other, other_authorised) in authorised.iter().enumerate().take(dag.len()) {
        if !*other_authorised || other == index {
            continue;
        }
        let candidate = dag.operation(other)?;
        let removes = matches!(
            candidate.core().body,
            OperationBody::RevokeDevice { .. } | OperationBody::Demote { .. }
        );
        if !removes {
            continue;
        }
        if Dag::target_of(&candidate.core().body) == Some(author) && dag.concurrent(index, other) {
            return Some(Invalidity::ConcurrentWithAuthorRemoval);
        }
    }
    None
}

/// The device that authored an operation, in the state its ancestors imply.
///
/// `None` when the operation cannot be placed or its author is not named there —
/// in which case [`judge_one`] has already refused it.
fn author_of(
    dag: &Dag,
    base: &Base,
    index: usize,
    eligible: &[bool],
    memo: &mut Memo,
) -> Option<DeviceId> {
    let operation = dag.operation(index)?;
    let ancestor_state = ancestor_state(dag, base, eligible, index, memo)?;
    ancestor_state.device_for_key(&operation.core().author).map(|device| device.id)
}

/// Derives state over exactly the operations the mask selects.
///
/// Used twice: once per operation to obtain its ancestor-relative state, and
/// once over the whole valid set to obtain the roster. Sharing the code is what
/// keeps the two consistent.
fn resolve(dag: &Dag, base: &Base, mask: &[bool]) -> Option<RosterState> {
    resolve_in(dag, base, mask, &mut Memo::new())
}

/// The state each operation's ancestors imply, by the operation's index, for
/// one top-level derivation.
///
/// Valid across nested derivations: an operation's ancestors within an
/// ancestor's region are its ancestors within the whole region, since every
/// ancestor of an ancestor is one too. Without it, each `set_network` and
/// each batch would derive its ancestors afresh, and the ones among them
/// would do the same, doubling the cost with every one in the window.
type Memo = BTreeMap<usize, Option<RosterState>>;

/// [`resolve`], sharing what nested derivations already computed.
fn resolve_in(dag: &Dag, base: &Base, mask: &[bool], memo: &mut Memo) -> Option<RosterState> {
    let network = base.state.network;
    let genesis_params = &base.state.params;

    // Rule 1: a revocation wins over every admission it does not precede.
    //
    // An admission stands only if it descends from every selected revocation of
    // its device: a revocation concurrent with it, or after it, removes the
    // device, in whichever order the two arrived. An admission that causally
    // follows every revocation is a deliberate act and admits the device again.
    //
    // The base contributes no revocations. It holds the devices that were
    // members when it was taken; a device revoked before it is simply absent.
    // Every operation still held descends from the base — compaction refuses a
    // region anything held is concurrent with — so a held revocation of a base
    // device always follows its admission.
    let mut revocations: BTreeMap<DeviceId, Vec<usize>> = BTreeMap::new();
    for (index, operation) in selected(dag, mask) {
        if let OperationBody::RevokeDevice { device, .. } = &operation.core().body {
            revocations.entry(*device).or_default().push(index);
        }
    }
    // Only the devices the window names can come out different from the base.
    // Every rule below reads a device's own operations, and a base device no
    // held operation names keeps the record and settings the base gives it:
    // the base is itself a derived state, so it already keeps the rules among
    // its own devices. The one rule that reaches across devices is an address,
    // which a device the window assigns it takes from a base device holding
    // it — so the base's holder of every address the window assigns is
    // touched too. Everything else is carried over from the base as it is,
    // which is what lets a window over a million devices cost the window.
    let mut touched: BTreeSet<DeviceId> = BTreeSet::new();
    let mut assigning: BTreeSet<[u8; 4]> = BTreeSet::new();
    for (_, operation) in selected(dag, mask) {
        match &operation.core().body {
            OperationBody::AddDevice(spec) => touched.extend(spec.device_id().ok()),
            OperationBody::AdmitBatch(_) => {
                for entry in dag.entries_of(&operation.id()).unwrap_or_default() {
                    touched.extend(entry.device_id().ok());
                    assigning.extend(entry.ipv4);
                }
            }
            body => {
                if let OperationBody::SetDevice { change, .. } = body {
                    assigning.extend(change.ipv4.flatten());
                }
                touched.extend(Dag::target_of(body));
            }
        }
    }
    for address in assigning {
        touched.extend(base.state.devices.holding_address(address));
    }

    let survives = |device: &DeviceId, added_at: Option<usize>| -> bool {
        let Some(revoking) = revocations.get(device) else { return true };
        match added_at {
            None => false,
            Some(add_index) => {
                revoking.iter().all(|revocation| dag.is_ancestor(*revocation, add_index))
            }
        }
    };

    // The record each device was added by. Where two concurrent `add_device`
    // operations name the same device id — the same signing key, but perhaps a
    // different transport key — the deeper one wins, ties broken by id, so the
    // whole record comes from one operation rather than being spliced.
    let mut added: BTreeMap<DeviceId, (Rank, DeviceSpec, OperationId)> = BTreeMap::new();
    for id in &touched {
        let Some(record) = base.state.devices.get(id) else { continue };
        if !survives(id, None) {
            continue;
        }
        added.insert(
            *id,
            (
                base.rank,
                DeviceSpec {
                    keys: record.keys.clone(),
                    name: record.name.clone(),
                    role: record.role,
                    founder: record.founder,
                    capabilities: record.capabilities.clone(),
                },
                record.added_by,
            ),
        );
    }
    for (index, operation) in selected(dag, mask) {
        // A batch admits each of its entries as an `add_device` would, all at
        // the header's rank, except those that collide with what its own
        // ancestors hold: those are skipped, and the rest stand.
        if let OperationBody::AdmitBatch(header) = &operation.core().body {
            let rank = Rank::new(dag.depth(index), operation.id());
            let entries = dag.entries_of(&operation.id()).unwrap_or_default();
            let skips = crate::batch::skipped(
                ancestor_state(dag, base, mask, index, memo)?,
                header,
                entries,
            );
            for entry in entries {
                let (Ok(id), Ok(spec)) = (entry.device_id(), entry.spec()) else { continue };
                if skips.contains_key(&id) || !survives(&id, Some(index)) {
                    continue;
                }
                let replace = added.get(&id).is_none_or(|(existing, _, _)| rank < *existing);
                if replace {
                    added.insert(id, (rank, spec, operation.id()));
                }
            }
            continue;
        }
        if let OperationBody::AddDevice(spec) = &operation.core().body {
            let Ok(id) = spec.device_id() else { continue };
            if !survives(&id, Some(index)) {
                continue;
            }
            let rank = Rank::new(dag.depth(index), operation.id());
            // The *first* add wins, not the last. Adding a device that already
            // exists changes nothing — the mirror of an operation having no
            // effect before its target exists.
            //
            // Last-add-wins would reset the device's name and role, discarding
            // every rename written before the re-add. A snapshot taken between
            // two adds has already folded those renames into its state and has
            // no way to mark them as superseded, so a compacted node would keep
            // a name an uncompacted one had thrown away. Found by the
            // compaction property test.
            //
            // Where two adds are causally concurrent the shallower wins, ties
            // broken by the smaller id: arbitrary, but the same on every node.
            let replace = added.get(&id).is_none_or(|(existing, _, _)| rank < *existing);
            if replace {
                added.insert(id, (rank, spec.clone(), operation.id()));
            }
        }
    }

    // Roles. Rule 2: a demote concurrent with a promote wins; causally ordered,
    // the deeper one wins, so a promote descending from a demote re-promotes.
    let mut roles: BTreeMap<DeviceId, Role> = BTreeMap::new();
    for (device, (_, spec, _)) in &added {
        roles.insert(*device, spec.role);
    }
    for (device, (_, _, added_by)) in &added {
        let added_at = dag.position(added_by);
        if let Some(role) = resolve_role(dag, mask, *device, added_at, roles.get(device).copied()) {
            roles.insert(*device, role);
        }
    }

    // Founder status is granted and never withdrawn: a founder leaves by
    // revoking itself, not by ceasing to be one.
    let mut founders: BTreeSet<DeviceId> = BTreeSet::new();
    for (device, (_, spec, _)) in &added {
        if spec.founder {
            founders.insert(*device);
        }
    }
    for (index, operation) in selected(dag, mask) {
        if let OperationBody::Promote { device, founder: true } = &operation.core().body {
            let Some((_, _, added_by)) = added.get(device) else { continue };
            if !applies_to(dag, dag.position(added_by), index) {
                continue;
            }
            founders.insert(*device);
        }
    }

    // Rule 3: last-writer-wins by causal depth, ties broken by the greater
    // operation id. Arbitrary, but identical everywhere.
    let mut names: BTreeMap<DeviceId, (Rank, String)> = BTreeMap::new();
    for id in &touched {
        let Some(record) = base.state.devices.get(id) else { continue };
        // Only where the base's own admission still stands: a device the window
        // revoked and admitted again starts from its new admission's name.
        if added.get(id).is_some_and(|(_, _, added_by)| *added_by == record.added_by) {
            names.insert(*id, (base.rank, record.name.clone()));
        }
    }
    for (index, operation) in selected(dag, mask) {
        if let OperationBody::Rename { device, name } = &operation.core().body {
            let Some((_, _, added_by)) = added.get(device) else {
                // Nothing to rename.
                continue;
            };
            if !applies_to(dag, dag.position(added_by), index) {
                continue;
            }
            let rank = Rank::new(dag.depth(index), operation.id());
            let replace = names.get(device).is_none_or(|(existing, _)| rank > *existing);
            if replace {
                names.insert(*device, (rank, name.clone()));
            }
        }
    }

    // Parameters, each leaf on its own. A `set_network` sets the leaves where
    // the parameters it carries differ from those its own ancestors imply, and
    // the latest writer of each leaf wins. Two admins changing different
    // parameters at once both take effect; a relay move, which changes the
    // relay and the relay being left together, still sets both.
    let mut leaves: BTreeMap<&'static str, (Rank, Option<Parameter>)> =
        PARAMETER_NAMES.iter().map(|name| (*name, (base.rank, None))).collect();
    for leaf in genesis_params.leaves() {
        leaves.insert(leaf.name(), (base.rank, Some(leaf)));
    }
    for (index, operation) in selected(dag, mask) {
        if let OperationBody::SetNetwork(new_params) = &operation.core().body {
            let before = ancestor_state(dag, base, mask, index, memo)?.params.clone();
            let rank = Rank::new(dag.depth(index), operation.id());
            let wanted = leaf_values(new_params);
            let had = leaf_values(&before);
            for name in PARAMETER_NAMES {
                let value = wanted.get(name).cloned();
                if value == had.get(name).cloned() {
                    continue;
                }
                if leaves.get(name).is_none_or(|(existing, _)| rank > *existing) {
                    leaves.insert(name, (rank, value));
                }
            }
        }
    }
    let params = params_from_leaves(
        leaves.into_values().filter_map(|(_, value)| value).collect(),
        genesis_params,
    );

    // Settings, each field of each device on its own, last writer wins. A
    // device starts from the settings the base held for it, where the base's
    // admission still stands; every held operation is later than the base.
    let mut fields: BTreeMap<(DeviceId, u8), (Rank, SettingsChange)> = BTreeMap::new();
    for (index, operation) in selected(dag, mask) {
        if let OperationBody::SetDevice { device, change } = &operation.core().body {
            let Some((_, _, added_by)) = added.get(device) else { continue };
            if !applies_to(dag, dag.position(added_by), index) {
                continue;
            }
            let rank = Rank::new(dag.depth(index), operation.id());
            for (field, single) in change.fields() {
                if fields.get(&(*device, field)).is_none_or(|(existing, _)| rank > *existing) {
                    fields.insert((*device, field), (rank, single));
                }
            }
        }
    }
    let mut settings: BTreeMap<DeviceId, DeviceSettings> = BTreeMap::new();
    for (device, (_, _, added_by)) in &added {
        let mut current = match base.state.devices.get(device) {
            Some(record) if record.added_by == *added_by => base.state.settings_of(device),
            _ => batch_settings(dag, added_by, device).unwrap_or_default(),
        };
        for ((_, _), (_, single)) in fields.range((*device, 0)..=(*device, u8::MAX)) {
            current = current.changed_by(single);
        }
        if current != DeviceSettings::default() {
            settings.insert(*device, current);
        }
    }

    // One address, one device. Where two devices are assigned the same address,
    // by concurrent `set_device`s or batches, the later assignment keeps it
    // (rule 3) and the other falls back to its derived candidate. An address
    // set by no held operation dates from the device's admission.
    let mut assigned: BTreeMap<[u8; 4], Vec<(Rank, DeviceId)>> = BTreeMap::new();
    for (device, current) in &settings {
        let Some(address) = current.ipv4 else { continue };
        let rank = fields
            .get(&(*device, IPV4_FIELD))
            .map(|(rank, _)| *rank)
            .or_else(|| added.get(device).map(|(rank, _, _)| *rank))
            .unwrap_or(base.rank);
        assigned.entry(address).or_default().push((rank, *device));
    }
    for mut claims in assigned.into_values().filter(|claims| claims.len() > 1) {
        claims.sort();
        claims.pop();
        for (_, device) in claims {
            if let Some(current) = settings.get_mut(&device) {
                current.ipv4 = None;
            }
            if settings.get(&device).is_some_and(|current| *current == DeviceSettings::default()) {
                settings.remove(&device);
            }
        }
    }

    // Admins are full: an admin signs roots, and must hold the state it vouches
    // for. Where a device would be both an admin and light, the later of the
    // two decisions stands — a promotion after the device went light has no
    // effect, and neither has a switch to light after it became an admin.
    let both: Vec<DeviceId> = settings
        .iter()
        .filter(|(device, current)| {
            current.mode == Mode::Light && roles.get(*device) == Some(&Role::Admin)
        })
        .map(|(device, _)| *device)
        .collect();
    for device in both {
        let light_at = fields.get(&(device, 0)).map_or(base.rank, |(rank, _)| *rank);
        let admitted_at = added.get(&device).map_or(base.rank, |(rank, _, _)| *rank);
        let added_at = added.get(&device).and_then(|(_, _, added_by)| dag.position(added_by));
        let admin_at = latest_promote(dag, mask, device, added_at).unwrap_or(admitted_at);
        if light_at > admin_at {
            if let Some(current) = settings.get_mut(&device) {
                current.mode = Mode::Full;
            }
            if settings.get(&device).is_some_and(|current| *current == DeviceSettings::default()) {
                settings.remove(&device);
            }
        } else {
            roles.insert(device, Role::Member);
        }
    }

    let mut devices: BTreeMap<DeviceId, DeviceRecord> = BTreeMap::new();
    for (device, (_, spec, added_by)) in added {
        let name = names.get(&device).map_or_else(|| spec.name.clone(), |(_, name)| name.clone());
        devices.insert(
            device,
            DeviceRecord {
                id: device,
                keys: spec.keys,
                name,
                role: roles.get(&device).copied().unwrap_or(spec.role),
                founder: founders.contains(&device),
                added_by,
                capabilities: spec.capabilities,
            },
        );
    }

    // Revoked, for telling an expelled device from a stranger: devices a held
    // revocation removed and nothing admitted again. Not committed by the root:
    // once a checkpoint absorbs the revocation, the device is merely absent.
    let revoked: BTreeSet<DeviceId> =
        revocations.keys().filter(|device| !devices.contains_key(*device)).copied().collect();

    // The base's devices, with what the window made of the ones it touched.
    let mut members = base.state.devices.clone();
    for device in &touched {
        match devices.remove(device) {
            Some(record) => members.insert_leaf(DeviceLeaf {
                record,
                settings: settings.remove(device).unwrap_or_default(),
            }),
            None => {
                members.remove(device);
            }
        }
    }
    let mut state = RosterState { network, params, devices: members, revoked };
    keep_member_anchors(&mut state);
    Some(state)
}

/// The number `SettingsChange::fields` gives the address field.
const IPV4_FIELD: u8 = 2;

/// The settings a device admitted by a batch starts with: the header's mode
/// and groups, and the address its entry was assigned.
fn batch_settings(dag: &Dag, added_by: &OperationId, device: &DeviceId) -> Option<DeviceSettings> {
    let operation = dag.operation(dag.position(added_by)?)?;
    let OperationBody::AdmitBatch(header) = &operation.core().body else { return None };
    let entry = dag
        .entries_of(added_by)?
        .iter()
        .find(|entry| entry.device_id().is_ok_and(|id| id == *device))?;
    DeviceSettings::new(header.mode, header.groups.clone(), entry.ipv4, None).ok()
}

/// The state an operation's own ancestors imply, computed once per derivation.
fn ancestor_state<'memo>(
    dag: &Dag,
    base: &Base,
    mask: &[bool],
    index: usize,
    memo: &'memo mut Memo,
) -> Option<&'memo RosterState> {
    if !memo.contains_key(&index) {
        let mut ancestor_mask = vec![false; dag.len()];
        for ancestor in dag.ancestors_of(index) {
            if mask.get(ancestor).copied().unwrap_or(false)
                && let Some(slot) = ancestor_mask.get_mut(ancestor)
            {
                *slot = true;
            }
        }
        let state = resolve_in(dag, base, &ancestor_mask, memo);
        memo.insert(index, state);
    }
    memo.get(&index)?.as_ref()
}

/// Parameters as their leaves, by name.
fn leaf_values(params: &NetworkParams) -> BTreeMap<&'static str, Parameter> {
    params.leaves().into_iter().map(|leaf| (leaf.name(), leaf)).collect()
}

/// Parameters built from the leaves each writer left.
///
/// Leaves set by concurrent operations can together break a rule the
/// parameters keep: a relay being left with no relay to move to, or equal to
/// the relay. The relay being left is then dropped — the same way everywhere,
/// since every node holds the same leaves. Anything else cannot fail, because
/// every leaf was valid on its own; the founding parameters stand in should it.
fn params_from_leaves(leaves: Vec<Parameter>, fallback: &NetworkParams) -> NetworkParams {
    NetworkParams::from_leaves(leaves.clone())
        .or_else(|_| {
            NetworkParams::from_leaves(
                leaves.into_iter().filter(|leaf| !matches!(leaf, Parameter::Leaving(_))).collect(),
            )
        })
        .unwrap_or_else(|_| fallback.clone())
}

/// Whether an operation targeting a device takes effect.
///
/// An operation that causally *precedes* the one adding its target changes
/// nothing: there was no such device yet to rename or to promote. Without this
/// the effect would sit latent, applying if the device were added later — and a
/// snapshot's state has nowhere to record a name or a role for a device it does
/// not contain, so a node that compacted would lose it and derive a different
/// roster from one that did not. Found by the compaction property test, which
/// is exactly the sort of corner an argument about composition steps over.
///
/// Concurrent operations still apply: they are not *before* the add, and
/// compaction refuses any region a held operation is concurrent with, so no
/// divergence follows from them.
///
/// Revocation is deliberately exempt and handled as a set union: a revoked
/// device id stays revoked whenever the revocation was written, and the
/// snapshot carries the revoked set explicitly, so nothing is lost.
fn applies_to(dag: &Dag, added_at: Option<usize>, operation: usize) -> bool {
    // A device from the foundation predates everything still retained.
    let Some(add_index) = added_at else { return true };
    !dag.is_ancestor(operation, add_index)
}

/// Resolves one device's role from the selected promote and demote operations.
fn resolve_role(
    dag: &Dag,
    mask: &[bool],
    device: DeviceId,
    added_at: Option<usize>,
    initial: Option<Role>,
) -> Option<Role> {
    let mut promotes: Vec<usize> = Vec::new();
    let mut demotes: Vec<usize> = Vec::new();
    for (index, operation) in selected(dag, mask) {
        if !applies_to(dag, added_at, index) {
            continue;
        }
        match &operation.core().body {
            OperationBody::Promote { device: target, .. } if *target == device => {
                promotes.push(index);
            }
            OperationBody::Demote { device: target } if *target == device => {
                demotes.push(index);
            }
            _ => {}
        }
    }
    if promotes.is_empty() && demotes.is_empty() {
        return initial;
    }

    // Rule 2 in its concurrent form: a race between raising and lowering
    // resolves downwards, on every node, in either merge order.
    for promote in &promotes {
        for demote in &demotes {
            if dag.concurrent(*promote, *demote) {
                return Some(Role::Member);
            }
        }
    }

    // Otherwise they are causally ordered with respect to each other, and the
    // deepest one is the most recent deliberate decision.
    let deepest_promote =
        promotes.iter().map(|index| Rank::new(dag.depth(*index), operation_id(dag, *index))).max();
    let deepest_demote =
        demotes.iter().map(|index| Rank::new(dag.depth(*index), operation_id(dag, *index))).max();
    match (deepest_promote, deepest_demote) {
        (Some(promote), Some(demote)) => {
            Some(if promote > demote { Role::Admin } else { Role::Member })
        }
        (Some(_), None) => Some(Role::Admin),
        (None, Some(_)) => Some(Role::Member),
        (None, None) => initial,
    }
}

/// The rank of the latest promotion of a device that takes effect, if any.
fn latest_promote(
    dag: &Dag,
    mask: &[bool],
    device: DeviceId,
    added_at: Option<usize>,
) -> Option<Rank> {
    selected(dag, mask)
        .filter(|(index, operation)| {
            matches!(&operation.core().body, OperationBody::Promote { device: target, .. } if *target == device)
                && applies_to(dag, added_at, *index)
        })
        .map(|(index, operation)| Rank::new(dag.depth(index), operation.id()))
        .max()
}

/// The id at an index, or a zero id when the index is out of range.
fn operation_id(dag: &Dag, index: usize) -> OperationId {
    dag.operation(index).map_or_else(|| OperationId::from_bytes([0; 32]), |op| op.id())
}

/// Iterates the operations a mask selects, with their indices.
fn selected<'a>(
    dag: &'a Dag,
    mask: &'a [bool],
) -> impl Iterator<Item = (usize, &'a crate::sign::VerifiedOperation)> + 'a {
    dag.operations()
        .iter()
        .enumerate()
        .filter(move |(index, _)| mask.get(*index).copied().unwrap_or(false))
}

/// The last-writer-wins ordering: causal depth first, then operation id.
///
/// The id tie-break is arbitrary by design. What matters is that every node
/// breaks the tie the same way, so a coin toss that is not a coin toss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Rank {
    /// Causal depth.
    depth: u64,
    /// Operation id, compared as bytes.
    id: [u8; 32],
}

impl Rank {
    /// Ranks an operation.
    fn new(depth: u64, id: OperationId) -> Self {
        Self { depth, id: *id.as_bytes() }
    }
}

#[cfg(test)]
mod tests {
    use super::Rank;
    use crate::id::OperationId;

    #[test]
    fn rank_orders_by_depth_before_id() {
        let deep_small = Rank::new(9, OperationId::from_bytes([0x00; 32]));
        let shallow_large = Rank::new(2, OperationId::from_bytes([0xff; 32]));
        assert!(deep_small > shallow_large, "depth dominates the id tie-break");
    }

    #[test]
    fn rank_breaks_equal_depth_by_greater_id() {
        let low = Rank::new(4, OperationId::from_bytes([0x01; 32]));
        let high = Rank::new(4, OperationId::from_bytes([0x02; 32]));
        assert!(high > low);
    }
}

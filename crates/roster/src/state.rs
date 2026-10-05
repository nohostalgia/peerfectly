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
use crate::types::{DeviceRecord, DeviceSpec, NetworkParams, OperationBody, Role};

/// Field names of the canonical roster-state encoding, in canonical order.
pub const ROSTER_STATE_SCHEMA: &[&str] = &["params", "devices", "network", "revoked"];

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
    /// Devices currently in the network, keyed by id.
    pub devices: BTreeMap<DeviceId, DeviceRecord>,
    /// Devices that have been revoked. Revocation is definitive, so a device
    /// here never returns to `devices`.
    pub revoked: BTreeSet<DeviceId>,
}

impl RosterState {
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
    pub fn device_for_key(&self, key: &KeyId) -> Option<&DeviceRecord> {
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
    ) -> Option<&DeviceRecord> {
        self.devices.values().find(|record| {
            record.keys.iter().any(|entry| entry.purpose == purpose && entry.key_id() == *key)
        })
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
        for record in self.devices.values() {
            record.encode(&mut writer);
        }
        writer.key("network").bytes(self.network.as_bytes());
        writer.key("revoked").array(self.revoked.len() as u64);
        for device in &self.revoked {
            writer.bytes(device.as_bytes());
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

        let revoked_reader = map.key("revoked")?;
        let revoked_count = revoked_reader.array(crate::limits::MAX_OPERATIONS, "device count")?;
        let mut revoked = BTreeSet::new();
        for _ in 0..revoked_count {
            revoked.insert(DeviceId::decode(revoked_reader)?);
        }

        map.finish()?;
        reader.finish()?;
        Ok(Self { network, params, devices, revoked })
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
                let mut devices = BTreeMap::new();
                devices.insert(id, device.clone().into_record(operation.id())?);
                Ok(Self {
                    state: RosterState {
                        network,
                        params: params.clone(),
                        devices,
                        revoked: BTreeSet::new(),
                    },
                    rank: Rank::new(0, operation.id()),
                    genesis: Some(*index),
                })
            }
            Foundation::Snapshot(snapshot) => {
                let body = snapshot.body();
                let state = RosterState::from_bytes(&body.state)?;
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
            if let Some(reason) = judge_one(dag, base, index, &valid_now, scope) {
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
            let Some(author) = author_of(dag, base, index, &valid_now) else { continue };
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

/// The state after one operation that **extends every head** of the graph.
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
/// The operation must already have passed admission: its author is an admin and
/// unrevoked here, and anything it names exists. What remains to judge is founder
/// protection, which admission deliberately leaves to derivation, so an operation
/// that breaks it returns the state unchanged — exactly as being disregarded
/// would.
#[must_use]
pub fn extend(state: &RosterState, operation: &crate::sign::VerifiedOperation) -> RosterState {
    let mut next = state.clone();
    let author = state.device_for_key(&operation.core().author).map(|device| device.id);

    // Founder protection, judged here as derivation judges it: only a founder
    // may retire itself, and no admin may retire another.
    if let Some(target) = Dag::target_of(&operation.core().body) {
        let removes_authority = matches!(
            operation.core().body,
            OperationBody::RevokeDevice { .. } | OperationBody::Demote { .. }
        );
        if removes_authority && state.is_founder(&target) && Some(target) != author {
            return next;
        }
    }

    match &operation.core().body {
        // The founding operation names no parents, so it never extends a head.
        OperationBody::CreateNetwork { .. } => {}
        OperationBody::AddDevice(spec) => {
            let Ok(id) = spec.device_id() else { return next };
            // Revocation is definitive, and the first add wins: neither a
            // re-add nor a second add changes a device that is already known.
            if next.revoked.contains(&id) || next.devices.contains_key(&id) {
                return next;
            }
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
        OperationBody::RevokeDevice { device, .. } => {
            next.revoked.insert(*device);
            next.devices.remove(device);
        }
        OperationBody::Promote { device, founder } => {
            if let Some(record) = next.devices.get_mut(device) {
                record.role = Role::Admin;
                // Founder status is granted and never withdrawn.
                record.founder = record.founder || *founder;
            }
        }
        OperationBody::Demote { device } => {
            if let Some(record) = next.devices.get_mut(device) {
                record.role = Role::Member;
            }
        }
        OperationBody::Rename { device, name } => {
            if let Some(record) = next.devices.get_mut(device) {
                record.name = name.clone();
            }
        }
        OperationBody::SetNetwork(params) => next.params = params.clone(),
    }
    next
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
    valid: &[bool],
    scope: Option<&[bool]>,
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
    let mut ancestor_mask = vec![false; dag.len()];
    for ancestor in dag.ancestors_of(index) {
        if valid.get(ancestor).copied().unwrap_or(false)
            && !dag.is_covered(ancestor)
            && let Some(slot) = ancestor_mask.get_mut(ancestor)
        {
            *slot = true;
        }
    }
    let ancestor_state = resolve(dag, base, &ancestor_mask)?;

    if let Some(reason) = unauthorized_author(&ancestor_state, &operation.core().author) {
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
fn author_of(dag: &Dag, base: &Base, index: usize, valid: &[bool]) -> Option<DeviceId> {
    let operation = dag.operation(index)?;
    let mut ancestor_mask = vec![false; dag.len()];
    for ancestor in dag.ancestors_of(index) {
        if valid.get(ancestor).copied().unwrap_or(false)
            && !dag.is_covered(ancestor)
            && let Some(slot) = ancestor_mask.get_mut(ancestor)
        {
            *slot = true;
        }
    }
    let ancestor_state = resolve(dag, base, &ancestor_mask)?;
    ancestor_state.device_for_key(&operation.core().author).map(|device| device.id)
}

/// Derives state over exactly the operations the mask selects.
///
/// Used twice: once per operation to obtain its ancestor-relative state, and
/// once over the whole valid set to obtain the roster. Sharing the code is what
/// keeps the two consistent.
fn resolve(dag: &Dag, base: &Base, mask: &[bool]) -> Option<RosterState> {
    let network = base.state.network;
    let genesis_params = &base.state.params;

    // Rule 1, first and unconditionally: revocation is a set union over the
    // selected operations, which is as order-proof as an operation gets. The
    // base contributes whatever it already knew to be revoked.
    let mut revoked: BTreeSet<DeviceId> = base.state.revoked.clone();
    for (index, operation) in selected(dag, mask) {
        let _ = index;
        if let OperationBody::RevokeDevice { device, .. } = &operation.core().body {
            revoked.insert(*device);
        }
    }

    // The record each device was added by. Where two concurrent `add_device`
    // operations name the same device id — the same signing key, but perhaps a
    // different transport key — the deeper one wins, ties broken by id, so the
    // whole record comes from one operation rather than being spliced.
    let mut added: BTreeMap<DeviceId, (Rank, DeviceSpec, OperationId)> = BTreeMap::new();
    for (id, record) in &base.state.devices {
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
        if let OperationBody::AddDevice(spec) = &operation.core().body {
            let Ok(id) = spec.device_id() else { continue };
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
    for (id, record) in &base.state.devices {
        names.insert(*id, (base.rank, record.name.clone()));
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

    let mut params = genesis_params.clone();
    let mut params_rank = base.rank;
    for (index, operation) in selected(dag, mask) {
        if let OperationBody::SetNetwork(new_params) = &operation.core().body {
            let rank = Rank::new(dag.depth(index), operation.id());
            if rank > params_rank {
                params_rank = rank;
                params = new_params.clone();
            }
        }
    }

    let mut devices: BTreeMap<DeviceId, DeviceRecord> = BTreeMap::new();
    for (device, (_, spec, added_by)) in added {
        if revoked.contains(&device) {
            continue;
        }
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

    Some(RosterState { network, params, devices, revoked })
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

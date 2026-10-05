//! Turning what the roster holds into what the report says about membership.
//!
//! Pure functions over the roster and a few facts the node supplies, so every
//! rule here — who is named how, what is owed to whom, what one equivocating
//! device may put in front of a person — is tested without a session.
//!
//! # One way of naming a device
//!
//! Every name in the report goes through one [`Directory`], built once per report.
//! Four builders that each looked names up their own way would disagree the first
//! time one of them changed, and "the same device has the same id everywhere"
//! would be true only by coincidence.

use std::collections::{BTreeMap, BTreeSet};

use roster::id::{DeviceId, KeyId};
use roster::roster::Roster;
use roster::sign::VerifiedOperation;
use roster::state::RosterState;
use roster::types::{DeviceSpec, OperationBody};

use crate::confirmations::Confirmed;
use crate::contacts::LastContacts;
use crate::control::{
    Accused, Act, Branch, Contact, Named, Owed, Revocation, Revoked, Signed, Waiting,
};

/// How many operations other than revocations the report lists.
///
/// Revocations are never counted against it. See [`waiting`].
pub(crate) const WAITING_LISTED: usize = 20;

/// What the report says about one network's membership.
#[derive(Debug, Clone)]
pub(crate) struct Membership {
    /// How every device is named.
    pub(crate) directory: Directory,
    /// The devices held as revoked.
    pub(crate) revoked: Vec<Revoked>,
    /// The devices with evidence against them.
    pub(crate) accused: Vec<Accused>,
    /// What signed here is owed to whom.
    pub(crate) waiting: Vec<Waiting>,
    /// How many further operations are waiting and not listed.
    pub(crate) waiting_unlisted: usize,
    /// When each device was last in contact with this one.
    pub(crate) contacts: LastContacts,
}

/// Every device this roster names, and every key it knows the owner of.
#[derive(Debug, Clone, Default)]
pub(crate) struct Directory {
    /// The name each device goes by: its current name if it is a member, and the
    /// name it was admitted under otherwise.
    names: BTreeMap<DeviceId, String>,
    /// The device each key belongs to.
    owners: BTreeMap<KeyId, DeviceId>,
}

impl Directory {
    /// Builds the directory from the derived state and the valid operations held.
    ///
    /// Admissions first, in the order held, keeping the first for a device — a
    /// roster keeps the first admission of a device id for good. Then the current
    /// members overwrite with the names they go by now, which also covers members
    /// whose admission a snapshot discarded.
    ///
    /// **Valid operations only.** The graph holds everything that verified,
    /// including operations the roster's rules then disregarded. An admission any
    /// member signed for somebody else's key, under a name of its choosing, is in
    /// the graph; were it read here, it could put that name on a revoked device.
    pub(crate) fn of(state: &RosterState, valid: &[&VerifiedOperation]) -> Self {
        let mut directory = Self::default();

        for operation in valid {
            let spec = match operation.body() {
                OperationBody::CreateNetwork { device, .. } | OperationBody::AddDevice(device) => {
                    device
                }
                _ => continue,
            };
            directory.admit(spec);
        }

        for record in state.devices.values() {
            directory.names.insert(record.id, record.name.clone());
            for key in &record.keys {
                directory.owners.insert(KeyId::of_public_key(&key.value), record.id);
            }
        }
        directory
    }

    /// Records one admission's name and keys, unless the device is already named.
    fn admit(&mut self, spec: &DeviceSpec) {
        let Ok(device) = spec.device_id() else { return };
        self.names.entry(device).or_insert_with(|| spec.name.clone());
        for key in &spec.keys {
            self.owners.entry(KeyId::of_public_key(&key.value)).or_insert(device);
        }
    }

    /// A device, named as well as this roster can.
    pub(crate) fn named(&self, device: &DeviceId) -> Named {
        Named::new(device, self.names.get(device).cloned())
    }

    /// The device behind a key.
    ///
    /// A key this roster holds no admission for is still somebody's: a device's id
    /// is the digest of its identifying signing key, which is the key that signs,
    /// so the same bytes name the device.
    pub(crate) fn owner(&self, key: &KeyId) -> DeviceId {
        self.owners.get(key).copied().unwrap_or_else(|| DeviceId::from_bytes(*key.as_bytes()))
    }

    /// What an operation does, with every device in it named.
    pub(crate) fn act(&self, body: &OperationBody) -> Act {
        match body {
            OperationBody::CreateNetwork { .. } => Act::Founds,
            // The name this operation gives, not the directory's: this describes
            // what the operation says, and a branch of an equivocation says things
            // the roster never counted. The id beside it is the identity.
            OperationBody::AddDevice(spec) => Act::Admits(Named {
                name: Some(spec.name.clone()),
                id: spec
                    .device_id()
                    .map(|device| crate::control::short_id(&device))
                    .unwrap_or_default(),
            }),
            OperationBody::RevokeDevice { device, .. } => Act::Revokes(self.named(device)),
            OperationBody::Promote { device, founder } => {
                Act::Promotes(self.named(device), *founder)
            }
            OperationBody::Demote { device } => Act::Demotes(self.named(device)),
            OperationBody::Rename { device, name } => {
                Act::Renames(self.named(device), name.clone())
            }
            OperationBody::SetNetwork(_) => Act::SetsParameters,
        }
    }
}

/// Last contact as the report states it.
pub(crate) fn contact(contacts: &LastContacts, device: &DeviceId) -> Contact {
    contacts
        .minute(device)
        .and_then(crate::clock::minute_as_time)
        .map_or(Contact::NoneRecorded, |at| Contact::Recorded { at })
}

/// Every device the roster holds as revoked, with every valid revocation of it.
///
/// Built from the revoked set, not from the revocations: a roster adopted from a
/// snapshot can hold a device as revoked with the operation that did it long
/// gone, and such a device is listed by id rather than left out.
///
/// Only revocations the roster counts are listed. A member that is not an admin
/// can still sign a revocation, and the graph holds it; listing it beside the real
/// one would put a reason of its choosing in front of the person reading this.
pub(crate) fn revoked(
    directory: &Directory,
    state: &RosterState,
    valid: &[&VerifiedOperation],
    contacts: &LastContacts,
) -> Vec<Revoked> {
    state
        .revoked
        .iter()
        .map(|device| Revoked {
            device: directory.named(device),
            revocations: valid
                .iter()
                .filter_map(|operation| match operation.body() {
                    OperationBody::RevokeDevice { device: revoked, reason }
                        if revoked == device =>
                    {
                        Some(Revocation {
                            by: directory.named(&directory.owner(&operation.core().author)),
                            reason: reason.clone(),
                            signer_clock: Signed::from_ts(operation.core().ts),
                        })
                    }
                    _ => None,
                })
                .collect(),
            last_contact: contact(contacts, device),
        })
        .collect()
}

/// One pair per accused device, and how many pairs it has.
///
/// Every pair of one author's concurrent operations counts as a fork, so a device
/// that signs `n` of them on purpose produces `n(n-1)/2`. Listing them would let
/// it make the report unusable. The pair kept is the roster's first, which is the
/// same on every device holding the same operations.
pub(crate) fn accused(directory: &Directory, roster: &Roster) -> Vec<Accused> {
    let mut by_author: BTreeMap<DeviceId, Accused> = BTreeMap::new();

    for evidence in roster.equivocations() {
        let device = directory.owner(&evidence.author);
        if let Some(held) = by_author.get_mut(&device) {
            held.pairs = held.pairs.saturating_add(1);
            continue;
        }
        let (Some(first), Some(second)) = (
            branch(directory, roster, &evidence.first),
            branch(directory, roster, &evidence.second),
        ) else {
            continue;
        };
        by_author
            .insert(device, Accused { device: directory.named(&device), pairs: 1, first, second });
    }
    by_author.into_values().collect()
}

/// One branch, decoded from the evidence itself.
///
/// From the proof's own bytes rather than looked up in the graph, so evidence a
/// compaction kept and evidence still in the graph take one path. The proof was
/// verified when it was admitted; this only reads what it says.
fn branch(directory: &Directory, roster: &Roster, proof: &roster::roster::Proof) -> Option<Branch> {
    let bytes = roster::sign::assemble_operation(&proof.core_bytes, &proof.signature);
    let raw = roster::sign::RawOperation::decode(&bytes).ok()?;
    let dag = roster.dag();
    Some(Branch {
        does: directory.act(&raw.core().body),
        depth: dag.position(&proof.id).map(|index| dag.depth(index)),
    })
}

/// Whether an operation can be owed to a member at all.
///
/// Never to the device it revokes. That device will not confirm — its sessions
/// are refused — and an entry that can never clear teaches a person to stop
/// reading the list. Derivation already drops revoked records from the state, but
/// this is stated here so that nothing rests on it.
pub(crate) fn owed_to(operation: &VerifiedOperation, member: &DeviceId) -> bool {
    !matches!(operation.body(), OperationBody::RevokeDevice { device, .. } if device == member)
}

/// What signed here some member has not said it holds, per operation.
///
/// Revocations first, then the rest in the order they are held, and the rest
/// bounded by [`WAITING_LISTED`]. Revocations are never bounded: the one list a
/// person reads before deciding a stolen laptop is dealt with cannot be the list
/// that dropped its revocation at entry twenty-one.
pub(crate) fn waiting(
    directory: &Directory,
    state: &RosterState,
    authored: &[&VerifiedOperation],
    me: &DeviceId,
    confirmed: &Confirmed,
    connected: &BTreeSet<DeviceId>,
    contacts: &LastContacts,
) -> (Vec<Waiting>, usize) {
    let mut revocations = Vec::new();
    let mut others = Vec::new();

    for operation in authored {
        let owed: Vec<Owed> = state
            .devices
            .keys()
            .filter(|member| *member != me)
            .filter(|member| owed_to(operation, member))
            .filter(|member| !confirmed.holds(member, &operation.id()))
            .map(|member| Owed {
                device: directory.named(member),
                connected: connected.contains(member),
                last_contact: contact(contacts, member),
            })
            .collect();
        if owed.is_empty() {
            continue;
        }

        let entry = Waiting {
            does: directory.act(operation.body()),
            signed_here: Signed::from_ts(operation.core().ts),
            owed,
        };
        if entry.does.is_revocation() {
            revocations.push(entry);
        } else {
            others.push(entry);
        }
    }

    let unlisted = others.len().saturating_sub(WAITING_LISTED);
    revocations.extend(others.into_iter().take(WAITING_LISTED));
    (revocations, unlisted)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "a test reports failure by panicking")]
mod tests {
    use roster::dag::Dag;
    use roster::id::{NetworkId, OperationId};
    use roster::sign::{Ed25519Signer, Signer, sign_operation};
    use roster::snapshot::{Snapshot, sign_snapshot};
    use roster::types::{Algorithm, KeyEntry, KeyPurpose, NetworkParams, OperationCore, Role};

    use super::*;

    /// A time that reads as one: any minute after 2001 does.
    const SIGNED: u64 = 1_757_000_040_000;

    fn signer(seed: u8) -> Ed25519Signer {
        Ed25519Signer::from_seed([seed; 32])
    }

    fn device(seed: u8, name: &str, role: Role, founder: bool) -> DeviceSpec {
        let signing = KeyEntry::new(
            Algorithm::Ed25519,
            KeyPurpose::Signing,
            signer(seed).public_key().as_bytes().to_vec(),
        )
        .unwrap();
        let transport = KeyEntry::new(
            Algorithm::Ed25519,
            KeyPurpose::Transport,
            signer(seed.wrapping_add(100)).public_key().as_bytes().to_vec(),
        )
        .unwrap();
        let attestation = KeyEntry::new(
            Algorithm::Ed25519,
            KeyPurpose::Attestation,
            signer(seed.wrapping_add(200)).public_key().as_bytes().to_vec(),
        )
        .unwrap();
        let mut keys = vec![signing, transport, attestation];
        keys.sort_by_key(KeyEntry::order_key);
        DeviceSpec::new(keys, name, role, founder, vec![]).unwrap()
    }

    fn id(seed: u8) -> DeviceId {
        device(seed, "any", Role::Member, false).device_id().unwrap()
    }

    /// Signed operations addressed by label, so concurrency is exact.
    #[derive(Default)]
    struct History {
        entries: Vec<(String, OperationId, Vec<u8>)>,
        network: Option<NetworkId>,
        minutes: u64,
    }

    impl History {
        fn founded_by(seed: u8, name: &str) -> Self {
            let mut history = Self::default();
            let params =
                NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 2_592_000)
                    .unwrap();
            let core = OperationCore::new(
                SIGNED,
                Algorithm::Ed25519,
                OperationBody::CreateNetwork {
                    device: device(seed, name, Role::Admin, true),
                    params,
                },
                vec![],
                signer(seed).key_id(),
                NetworkId::from_bytes([0; 32]),
            )
            .unwrap();
            let bytes = sign_operation(&core, &signer(seed)).unwrap();
            history.network = Some(NetworkId::from_bytes(*core.id().as_bytes()));
            history.entries.push(("g".to_owned(), core.id(), bytes));
            history
        }

        fn op(&mut self, label: &str, author: u8, parents: &[&str], body: OperationBody) {
            self.op_at(label, author, parents, body, None);
        }

        fn op_at(
            &mut self,
            label: &str,
            author: u8,
            parents: &[&str],
            body: OperationBody,
            ts: Option<u64>,
        ) {
            self.minutes = self.minutes.saturating_add(1);
            let core = OperationCore::new(
                ts.unwrap_or_else(|| SIGNED.saturating_add(self.minutes.saturating_mul(60_000))),
                Algorithm::Ed25519,
                body,
                parents.iter().map(|parent| self.id(parent)).collect(),
                signer(author).key_id(),
                self.network.unwrap(),
            )
            .unwrap();
            let bytes = sign_operation(&core, &signer(author)).unwrap();
            self.entries.push((label.to_owned(), core.id(), bytes));
        }

        fn id(&self, label: &str) -> OperationId {
            self.entries.iter().find(|(held, ..)| held == label).map(|(_, id, _)| *id).unwrap()
        }

        fn roster(&self, staleness: u64) -> Roster {
            let (roster, refused) = self.roster_with_refusals(staleness);
            assert!(refused.is_empty(), "these were refused: {refused:?}");
            roster
        }

        /// The roster, and the labels of whatever it refused.
        ///
        /// Most histories here are meant to be admitted whole, and `roster`
        /// insists on it. One is not: the roster refuses an operation whose
        /// author had no authority to write it, and a test about what such an
        /// operation does needs to see that it was refused rather than be
        /// stopped by it.
        fn roster_with_refusals(&self, staleness: u64) -> (Roster, Vec<String>) {
            let mut roster = Roster::with_staleness_depth(staleness);
            let mut refused = Vec::new();
            for (label, _, bytes) in &self.entries {
                if !roster.offer_bytes(bytes).is_accepted() {
                    refused.push(label.clone());
                }
            }
            (roster, refused)
        }

        /// A snapshot over what the labelled heads cover, derived honestly.
        fn snapshot_at(&self, roster: &Roster, signer_seed: u8, heads: &[&str]) -> Vec<u8> {
            let full = roster.dag();
            let mut wanted = Vec::new();
            for head in heads {
                let index = full.position(&self.id(head)).unwrap();
                wanted.push(index);
                wanted.extend(full.ancestors_of(index));
            }
            wanted.sort_unstable();
            wanted.dedup();
            let mut covered = Dag::new();
            for index in wanted {
                covered.insert(full.operation(index).unwrap().clone()).unwrap();
            }
            let state = roster::state::derive(&covered).unwrap().to_bytes();
            let depths = heads
                .iter()
                .map(|head| covered.depth(covered.position(&self.id(head)).unwrap()))
                .collect();
            let ids = heads.iter().map(|head| self.id(head)).collect();
            let body = Snapshot::new(
                1,
                state,
                ids,
                depths,
                signer(signer_seed).key_id(),
                self.network.unwrap(),
            )
            .unwrap();
            sign_snapshot(&body, &signer(signer_seed)).unwrap()
        }
    }

    /// The valid operations and the directory, as the node builds them.
    fn view(roster: &Roster) -> (RosterState, Vec<VerifiedOperation>, Directory) {
        let state = roster.state().unwrap();
        let dag = roster.dag();
        let (_, verdicts) = roster::state::derive_with_verdicts(dag).unwrap();
        let valid: Vec<VerifiedOperation> = dag
            .operations()
            .iter()
            .enumerate()
            .filter(|(index, _)| verdicts.is_valid(*index))
            .map(|(_, operation)| operation.clone())
            .collect();
        let held: Vec<&VerifiedOperation> = valid.iter().collect();
        let directory = Directory::of(&state, &held);
        (state, valid, directory)
    }

    fn name(named: &Named) -> Option<&str> {
        named.name.as_deref()
    }

    // ---- 1.3 the directory ----------------------------------------------------

    #[test]
    fn a_member_is_named_as_it_is_now_and_a_revoked_device_as_it_was_admitted() {
        let mut history = History::founded_by(1, "nas");
        history.op(
            "add",
            1,
            &["g"],
            OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
        );
        history.op(
            "add3",
            1,
            &["add"],
            OperationBody::AddDevice(device(3, "phone", Role::Member, false)),
        );
        history.op(
            "rename3",
            1,
            &["add3"],
            OperationBody::Rename { device: id(3), name: "pixel".to_owned() },
        );
        history.op(
            "rename2",
            1,
            &["rename3"],
            OperationBody::Rename { device: id(2), name: "old".to_owned() },
        );
        history.op(
            "revoke",
            1,
            &["rename2"],
            OperationBody::RevokeDevice { device: id(2), reason: "lost".to_owned() },
        );

        let (_, _, directory) = view(&history.roster(64));
        assert_eq!(
            name(&directory.named(&id(3))),
            Some("pixel"),
            "a member goes by its current name"
        );
        assert_eq!(
            name(&directory.named(&id(2))),
            Some("laptop"),
            "a revoked device, by its admission"
        );
        assert_eq!(directory.named(&id(2)).id, crate::control::short_id(&id(2)));
    }

    #[test]
    fn an_admin_revoked_after_revoking_is_still_named() {
        let mut history = History::founded_by(1, "nas");
        history.op(
            "desk",
            1,
            &["g"],
            OperationBody::AddDevice(device(3, "desk", Role::Admin, false)),
        );
        history.op(
            "laptop",
            3,
            &["desk"],
            OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
        );
        history.op(
            "out2",
            3,
            &["laptop"],
            OperationBody::RevokeDevice { device: id(2), reason: "stolen".to_owned() },
        );
        history.op(
            "out3",
            1,
            &["out2"],
            OperationBody::RevokeDevice { device: id(3), reason: "left".to_owned() },
        );

        let roster = history.roster(64);
        let (state, valid, directory) = view(&roster);
        let held: Vec<&VerifiedOperation> = valid.iter().collect();
        let revoked = revoked(&directory, &state, &held, &LastContacts::default());

        let laptop = revoked
            .iter()
            .find(|entry| entry.device.id == crate::control::short_id(&id(2)))
            .unwrap();
        let revocation = laptop.revocations.first().unwrap();
        assert_eq!(name(&revocation.by), Some("desk"), "the revoking admin, though revoked since");
        assert_eq!(revocation.reason, "stolen");
        assert!(matches!(revocation.signer_clock, Signed::At { .. }));
    }

    // ---- 3.x revoked devices --------------------------------------------------

    #[test]
    fn two_revocations_of_one_device_are_both_listed() {
        let mut history = History::founded_by(1, "nas");
        history.op(
            "desk",
            1,
            &["g"],
            OperationBody::AddDevice(device(3, "desk", Role::Admin, false)),
        );
        history.op(
            "laptop",
            1,
            &["desk"],
            OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
        );
        history.op(
            "by-nas",
            1,
            &["laptop"],
            OperationBody::RevokeDevice { device: id(2), reason: "lost".to_owned() },
        );
        history.op(
            "by-desk",
            3,
            &["laptop"],
            OperationBody::RevokeDevice { device: id(2), reason: "stolen".to_owned() },
        );

        let roster = history.roster(64);
        let (state, valid, directory) = view(&roster);
        let held: Vec<&VerifiedOperation> = valid.iter().collect();
        let listed = revoked(&directory, &state, &held, &LastContacts::default());
        let laptop = listed.first().unwrap();
        let mut by: Vec<Option<&str>> =
            laptop.revocations.iter().map(|entry| name(&entry.by)).collect();
        by.sort_unstable();
        assert_eq!(by, vec![Some("desk"), Some("nas")]);
    }

    /// A member may sign a revocation; the roster refuses it. It is not listed,
    /// or a reason of its choosing would sit beside the real one.
    ///
    /// It used to be admitted and then disregarded, which left it occupying a
    /// slot in a bounded graph. Now it does not reach the graph at all, and the
    /// listing is the same either way — which is the point: what a person is
    /// shown does not depend on how far the roster got before refusing it.
    #[test]
    fn a_revocation_the_roster_disregards_is_not_listed() {
        let mut history = History::founded_by(1, "nas");
        history.op(
            "laptop",
            1,
            &["g"],
            OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
        );
        history.op(
            "phone",
            1,
            &["laptop"],
            OperationBody::AddDevice(device(4, "phone", Role::Member, false)),
        );
        history.op(
            "real",
            1,
            &["phone"],
            OperationBody::RevokeDevice { device: id(2), reason: "stolen".to_owned() },
        );
        history.op(
            "forged",
            4,
            &["phone"],
            OperationBody::RevokeDevice {
                device: id(2),
                reason: "nas did it, ask them".to_owned(),
            },
        );

        let (roster, refused) = history.roster_with_refusals(64);
        assert_eq!(refused, vec!["forged".to_owned()], "the member's revocation is refused");

        let (state, valid, directory) = view(&roster);
        let held: Vec<&VerifiedOperation> = valid.iter().collect();
        let listed = revoked(&directory, &state, &held, &LastContacts::default());
        let reasons: Vec<&str> = listed
            .iter()
            .flat_map(|entry| entry.revocations.iter())
            .map(|entry| entry.reason.as_str())
            .collect();
        assert_eq!(reasons, vec!["stolen"]);
    }

    /// The admission is gone; the revocation is permanent. Listed by id.
    #[test]
    fn a_revoked_device_whose_admission_was_compacted_away_is_listed_by_id() {
        let mut history = History::founded_by(1, "nas");
        history.op(
            "laptop",
            1,
            &["g"],
            OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
        );
        history.op(
            "phone",
            1,
            &["laptop"],
            OperationBody::AddDevice(device(3, "phone", Role::Member, false)),
        );
        history.op(
            "revoke",
            1,
            &["phone"],
            OperationBody::RevokeDevice { device: id(2), reason: "stolen".to_owned() },
        );
        let mut previous = "revoke".to_owned();
        for index in 0..8 {
            let label = format!("n{index}");
            history.op(
                &label,
                1,
                &[previous.as_str()],
                OperationBody::Rename { device: id(3), name: format!("phone{index}") },
            );
            previous = label;
        }

        let mut roster = history.roster(2);
        let snapshot = history.snapshot_at(&roster, 1, &["n2"]);
        assert!(roster.offer_snapshot(&snapshot).is_accepted());
        assert!(roster.compact().unwrap() > 0);
        assert!(!roster.dag().contains(&history.id("laptop")), "the admission is gone");

        let (state, valid, directory) = view(&roster);
        let held: Vec<&VerifiedOperation> = valid.iter().collect();
        let listed = revoked(&directory, &state, &held, &LastContacts::default());
        let laptop =
            listed.iter().find(|entry| entry.device.id == crate::control::short_id(&id(2)));
        let laptop = laptop.expect("a revoked device is never left out");
        assert_eq!(laptop.device.name, None, "and nothing held names it");
    }

    // ---- 5.x equivocation -----------------------------------------------------

    #[test]
    fn an_equivocation_is_described_by_its_branches() {
        let mut history = History::founded_by(1, "nas");
        history.op(
            "laptop",
            1,
            &["g"],
            OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
        );
        history.op(
            "left",
            1,
            &["laptop"],
            OperationBody::AddDevice(device(5, "tablet", Role::Member, false)),
        );
        history.op(
            "right",
            1,
            &["laptop"],
            OperationBody::RevokeDevice { device: id(2), reason: "x".to_owned() },
        );

        let roster = history.roster(64);
        let (_, _, directory) = view(&roster);
        let found = accused(&directory, &roster);
        let only = found.first().unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(name(&only.device), Some("nas"));
        assert_eq!(only.pairs, 1);
        let acts = [&only.first.does, &only.second.does];
        assert!(
            acts.iter()
                .any(|act| matches!(act, Act::Admits(device) if name(device) == Some("tablet")))
        );
        assert!(
            acts.iter()
                .any(|act| matches!(act, Act::Revokes(device) if name(device) == Some("laptop")))
        );
        assert!(
            only.first.depth.is_some() && only.second.depth.is_some(),
            "the graph still holds both"
        );
    }

    /// Four concurrent operations from one author are six pairs, reported once.
    #[test]
    fn many_pairs_from_one_device_are_counted_not_listed() {
        let mut history = History::founded_by(1, "nas");
        history.op(
            "laptop",
            1,
            &["g"],
            OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
        );
        for index in 0..4u8 {
            history.op(
                &format!("fork{index}"),
                1,
                &["laptop"],
                OperationBody::Rename { device: id(2), name: format!("name{index}") },
            );
        }

        let roster = history.roster(64);
        let (_, _, directory) = view(&roster);
        let found = accused(&directory, &roster);
        assert_eq!(found.len(), 1, "one entry per accused device");
        assert_eq!(found.first().unwrap().pairs, 6);
    }

    /// Evidence a compaction kept goes the same way, with no depth to give.
    #[test]
    fn evidence_kept_after_compaction_takes_the_same_path() {
        let mut history = History::founded_by(1, "nas");
        history.op(
            "a",
            1,
            &["g"],
            OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
        );
        history.op(
            "left",
            1,
            &["a"],
            OperationBody::Rename { device: id(2), name: "left".to_owned() },
        );
        history.op(
            "right",
            1,
            &["a"],
            OperationBody::Rename { device: id(2), name: "right".to_owned() },
        );
        history.op(
            "merge",
            1,
            &["left", "right"],
            OperationBody::Rename { device: id(2), name: "merged".to_owned() },
        );
        let mut previous = "merge".to_owned();
        for index in 0..12 {
            let label = format!("n{index}");
            history.op(
                &label,
                1,
                &[previous.as_str()],
                OperationBody::Rename { device: id(2), name: format!("n{index}") },
            );
            previous = label;
        }

        let mut roster = history.roster(2);
        let snapshot = history.snapshot_at(&roster, 1, &["n2"]);
        assert!(roster.offer_snapshot(&snapshot).is_accepted());
        assert!(roster.compact().unwrap() > 0);
        assert!(
            !roster.dag().contains(&history.id("left")),
            "the branches are gone from the graph"
        );

        let (_, _, directory) = view(&roster);
        let found = accused(&directory, &roster);
        let only = found.first().expect("the accusation stands");
        assert!(matches!(&only.first.does, Act::Renames(_, to) if to == "left" || to == "right"));
        assert_eq!(only.first.depth, None);
        assert_eq!(only.second.depth, None);
    }

    // ---- 6.x what is waiting --------------------------------------------------

    /// Constructed so the revoked device is still a member in the state read:
    /// exclusion by derivation cannot be what makes this pass.
    #[test]
    fn an_operation_is_never_owed_to_the_device_it_revokes() {
        let mut history = History::founded_by(1, "nas");
        history.op(
            "laptop",
            1,
            &["g"],
            OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
        );
        let before = history.roster(64);
        let state_before = before.state().unwrap();
        assert!(state_before.devices.contains_key(&id(2)), "still a member in this state");

        history.op(
            "revoke",
            1,
            &["laptop"],
            OperationBody::RevokeDevice { device: id(2), reason: "stolen".to_owned() },
        );
        let after = history.roster(64);
        let revocation = after
            .dag()
            .operations()
            .iter()
            .find(|op| op.id() == history.id("revoke"))
            .unwrap()
            .clone();

        assert!(!owed_to(&revocation, &id(2)));
        assert!(owed_to(&revocation, &id(7)), "and owed to anybody else");

        let (_, _, directory) = view(&before);
        let (listed, _) = waiting(
            &directory,
            &state_before,
            &[&revocation],
            &id(1),
            &Confirmed::default(),
            &BTreeSet::new(),
            &LastContacts::default(),
        );
        assert!(listed.is_empty(), "the only other member is the one it revokes: {listed:?}");
    }

    #[test]
    fn revocations_come_first_and_the_bound_never_hides_one() {
        let mut history = History::founded_by(1, "nas");
        history.op(
            "phone",
            1,
            &["g"],
            OperationBody::AddDevice(device(3, "phone", Role::Member, false)),
        );
        history.op(
            "laptop",
            1,
            &["phone"],
            OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
        );
        let mut previous = "laptop".to_owned();
        for index in 0..25u8 {
            let label = format!("admit{index}");
            history.op(
                &label,
                1,
                &[previous.as_str()],
                OperationBody::AddDevice(device(
                    index.saturating_add(10),
                    &format!("d{index}"),
                    Role::Member,
                    false,
                )),
            );
            previous = label;
        }
        history.op(
            "revoke",
            1,
            &[previous.as_str()],
            OperationBody::RevokeDevice { device: id(2), reason: "stolen".to_owned() },
        );

        let roster = history.roster(64);
        let (state, valid, directory) = view(&roster);
        let mine: Vec<&VerifiedOperation> = valid
            .iter()
            .filter(|op| {
                matches!(op.body(), OperationBody::AddDevice(spec) if spec.name.starts_with('d'))
                    || matches!(op.body(), OperationBody::RevokeDevice { .. })
            })
            .collect();
        let (listed, unlisted) = waiting(
            &directory,
            &state,
            &mine,
            &id(1),
            &Confirmed::default(),
            &BTreeSet::from([id(3)]),
            &LastContacts::default(),
        );

        assert!(
            listed.first().unwrap().does.is_revocation(),
            "the revocation is first, though signed last"
        );
        assert_eq!(listed.iter().filter(|entry| entry.does.is_revocation()).count(), 1);
        assert_eq!(listed.len(), 21, "the revocation and twenty others");
        assert_eq!(unlisted, 5);

        let owed = &listed.first().unwrap().owed;
        let phone = owed.iter().find(|entry| name(&entry.device) == Some("phone")).unwrap();
        assert!(phone.connected, "connection state is carried per member");
        assert_eq!(phone.last_contact, Contact::NoneRecorded);
        assert!(matches!(listed.first().unwrap().signed_here, Signed::At { .. }));
    }

    #[test]
    fn a_confirmed_member_is_not_owed_and_a_contact_is_carried() {
        let mut history = History::founded_by(1, "nas");
        history.op(
            "phone",
            1,
            &["g"],
            OperationBody::AddDevice(device(3, "phone", Role::Member, false)),
        );
        history.op(
            "laptop",
            1,
            &["phone"],
            OperationBody::AddDevice(device(2, "laptop", Role::Member, false)),
        );
        history.op(
            "desk",
            1,
            &["laptop"],
            OperationBody::AddDevice(device(4, "desk", Role::Member, false)),
        );

        let roster = history.roster(64);
        let (state, valid, directory) = view(&roster);
        let desk: Vec<&VerifiedOperation> =
            valid.iter().filter(|op| op.id() == history.id("desk")).collect();

        let mut confirmed = Confirmed::default();
        confirmed.confirm(id(3), [history.id("desk")]);
        let mut contacts = LastContacts::default();
        contacts.touch(id(2), 29_283_334);

        let (listed, _) =
            waiting(&directory, &state, &desk, &id(1), &confirmed, &BTreeSet::new(), &contacts);
        let owed: Vec<Option<&str>> =
            listed.first().unwrap().owed.iter().map(|entry| name(&entry.device)).collect();
        assert!(owed.contains(&Some("laptop")) && owed.contains(&Some("desk")));
        assert!(!owed.contains(&Some("phone")), "the member that said it holds it is not owed it");

        let laptop = listed
            .first()
            .unwrap()
            .owed
            .iter()
            .find(|entry| name(&entry.device) == Some("laptop"))
            .unwrap();
        assert!(matches!(laptop.last_contact, Contact::Recorded { .. }));
    }
}

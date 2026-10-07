//! The local half: admission, the pending set, and the staleness filter.
//!
//! Everything here is allowed to differ between nodes, because it depends on
//! what a node happens to know. Two nodes may reasonably disagree about whether
//! to *admit* an operation — one has seen recent history, the other has been
//! switched off for a month.
//!
//! What they may never disagree about is the roster a set of operations
//! implies. That is why [`crate::state::derive`] takes a [`Dag`] and not a
//! `Roster`: nothing in this module can reach derivation, so no amount of local
//! policy can move derived state. Moving the staleness check inside derivation
//! would make two nodes holding identical operations compute different
//! households, order-dependently — a consensus split wearing the costume of a
//! configuration option.
//!
//! # The pending set holds unverified operations
//!
//! An operation whose parents are missing usually *cannot* be signature-checked
//! yet: the author's public key is resolved from roster state, which is derived
//! from the very ancestors that are absent. So pending entries have passed only
//! the self-contained checks — bounded size, canonical encoding, and an id that
//! matches the bytes. Verification happens at integration, never before.
//!
//! Discarding an operation because its parents have not arrived is not an
//! option. The operation that cannot yet be placed may be a revocation.

use std::collections::HashMap;

use crate::attestation::{RawAttestation, SignedAttestation};
use crate::dag::Dag;
use crate::error::{Error, Result};
use crate::id::DeviceId;
use crate::id::KeyId;
use crate::id::OperationId;
use crate::limits;
use crate::sign::{PublicKey, RawOperation, VerifiedOperation};
use crate::snapshot::{RawSnapshot, SignedSnapshot};
use crate::state::{RosterState, derive};
use crate::types::{OperationCore, Role};

/// A source of local elapsed time.
///
/// Injected rather than read directly, for two reasons. Tests can drive it
/// without sleeping; and it is visible in the type signatures that
/// [`crate::state::derive`] never receives one, so no amount of clock skew can
/// move derived state.
///
/// `Send + Sync` because a [`Roster`] holding one must be able to cross threads.
/// Without it a roster is pinned to the thread that built it, and any daemon
/// wanting to reconcile on one task while carrying packets on another cannot
/// hold one at all — which is how this bound came to be added: `windows-daemon`
/// was the first thing to try.
pub trait Clock: core::fmt::Debug + Send + Sync {
    /// Seconds elapsed on some monotonic-if-possible scale.
    ///
    /// Only differences are ever used, never the absolute value, so the epoch
    /// does not matter. A monotonic source is preferred; where only a wall
    /// clock is available a backwards jump is reported rather than absorbed.
    fn now_seconds(&self) -> u64;

    /// Seconds since the Unix epoch, where this clock knows them.
    ///
    /// The one absolute reading a roster needs. An attestation says when its
    /// author signed it on that scale, so a roster can only age a received
    /// attestation by the time it already had, or date one it signs, where its
    /// clock can say what time it is. `None` — the default, and what a clock of
    /// elapsed time answers — dates a received attestation from its receipt, as
    /// before attestations carried a time, and signs none.
    fn unix_seconds(&self) -> Option<u64> {
        None
    }
}

/// The clock a daemon uses: elapsed time since process start.
#[derive(Debug)]
pub struct SystemClock {
    /// When this clock was created.
    origin: std::time::Instant,
}

impl SystemClock {
    /// Starts a clock.
    #[must_use]
    pub fn new() -> Self {
        Self { origin: std::time::Instant::now() }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_seconds(&self) -> u64 {
        // `Instant` is monotonic on every platform this runs on, so this cannot
        // go backwards. The backwards-jump reporting exists for hosts that must
        // substitute a wall clock.
        self.origin.elapsed().as_secs()
    }
}

/// What became of an offered attestation.
///
/// Exhaustive, as [`SnapshotAdmission`] is: a caller that has to decide what to
/// keep and what to report should stop compiling when a new outcome appears,
/// rather than fall through a wildcard arm that quietly does nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationAdmission {
    /// Accepted: this node holds the heads it names, and its author is an admin
    /// this roster knows and has not revoked.
    Accepted {
        /// Its sequence number.
        seq: u64,
    },

    /// Valid, and about heads this node does not have.
    ///
    /// Not a refusal of the attestation, and not freshness either. The author
    /// knew more than this node does; what the node has learned is that it is
    /// behind, and being behind is what syncing is for.
    HeadsNotHeld {
        /// Its sequence number.
        seq: u64,
    },

    /// Refused, with the reason.
    Refused {
        /// Why.
        reason: Error,
    },
}

impl AttestationAdmission {
    /// Whether this attestation dated the roster.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }
}

/// What became of an offered snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotAdmission {
    /// Verified against operations this node holds, and accepted.
    Accepted {
        /// Its sequence number.
        seq: u64,
    },
    /// Adopted without verification, because this node holds none of the
    /// operations it covers.
    ///
    /// The state rests on the signing admin's key alone. A node in this
    /// position has nothing to check against, and nothing to discard either.
    AdoptedUnverified {
        /// Its sequence number.
        seq: u64,
    },
    /// Already held; nothing changed.
    AlreadyHeld {
        /// Its sequence number.
        seq: u64,
    },
    /// Refused, with the reason.
    Refused {
        /// Why.
        reason: Error,
    },
}

impl SnapshotAdmission {
    /// Whether the snapshot is now this node's base.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(
            self,
            Self::Accepted { .. } | Self::AdoptedUnverified { .. } | Self::AlreadyHeld { .. }
        )
    }

    /// The refusal reason, if it was refused.
    #[must_use]
    pub const fn refusal(&self) -> Option<&Error> {
        match self {
            Self::Refused { reason } => Some(reason),
            _ => None,
        }
    }
}

/// How current this node believes its roster to be.
///
/// Measured from **local receipt time**, never from a timestamp carried in a
/// snapshot or an operation. Do not "fix" this by reading `ts`: the signer
/// chooses that value, so a compromised admin would set it far in the future
/// and leave the revocation window unbounded on every node that accepted the
/// snapshot — worse than having no window, because it would still look like a
/// protection. It would also break the rule that timestamps never influence
/// validity.
///
/// The one signed time it uses is an attestation's `issued_at`, and only to move
/// the receipt **back** by the age the attestation already had — so that one
/// relayed late reads as old as it is. It can never move the receipt forward,
/// which is the direction the paragraph above forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// A snapshot was accepted within the network's window.
    Fresh,
    /// The window has elapsed with nothing fresher. §3.3's cautious mode.
    Stale,
    /// No snapshot has been accepted, so there is nothing to measure against.
    Unknown,
    /// The clock moved backwards between observations.
    ///
    /// A correction and tampering look identical from in here, and only one is
    /// benign, so this is reported rather than absorbed.
    ClockWentBackwards,
}

/// What became of an offered operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Integrated into the graph.
    Accepted(OperationId),
    /// Already held; nothing changed.
    AlreadyHeld(OperationId),
    /// Held awaiting parents, which are named so the caller can fetch them.
    ///
    /// This is deliberately not an error. A caller that treated it as one, and
    /// dropped the operation, would eventually drop a revocation.
    Pending {
        /// The operation now waiting.
        operation: OperationId,
        /// The parents it is waiting for.
        missing: Vec<OperationId>,
    },
    /// Refused, with the reason.
    Refused {
        /// The operation refused.
        operation: OperationId,
        /// Why.
        reason: Error,
    },
}

impl Admission {
    /// Whether the operation is now in the graph.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted(_) | Self::AlreadyHeld(_))
    }

    /// Whether the operation is waiting for parents.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending { .. })
    }

    /// The refusal reason, if it was refused.
    #[must_use]
    pub const fn refusal(&self) -> Option<&Error> {
        match self {
            Self::Refused { reason, .. } => Some(reason),
            _ => None,
        }
    }
}

/// A node's view of one network: the graph it holds, plus local policy.
///
/// Everything this type owns beyond the graph is local and may differ between
/// nodes. Nothing here can reach [`crate::state::derive`], which takes the graph
/// alone — move the staleness check inside derivation and two nodes holding the
/// same operations will compute different rosters, order-dependently.
#[derive(Debug)]
pub struct Roster {
    /// The deterministic graph.
    dag: Dag,
    /// The state at the current heads, kept rather than derived each time.
    ///
    /// Deriving costs more than a pass over the graph, and admission needs a
    /// state for every operation offered — which is how a member flooding a
    /// network came to cost every node twenty-four minutes of CPU. Kept here, the
    /// ordinary case costs one operation applied to what was already known.
    ///
    /// `None` before the graph has a foundation, and whenever anything happened
    /// that this cannot follow in one step; the next reader derives afresh.
    /// Derivation remains the authority — this is only ever what derivation
    /// would say, and the property tests check that after every admission.
    at_heads: Option<RosterState>,
    /// Operations waiting for parents: their bytes, and the parents they wait
    /// on. Bytes rather than a decoded operation, because a pending entry has
    /// not been verified and `VerifiedOperation` is proof that it has. Bounded
    /// by `MAX_PENDING_OPERATIONS` times the maximum operation size.
    pending: HashMap<OperationId, PendingEntry>,
    /// How far behind the frontier an operation may be anchored.
    staleness_depth: u64,
    /// Refusals since the last drain, oldest first.
    refusals: Vec<(OperationId, Error)>,
    /// The accepted snapshot, if any.
    snapshot: Option<SignedSnapshot>,
    /// Whether that snapshot was verified against operations this node holds.
    /// Only a verified snapshot may be compacted against.
    snapshot_verified: bool,
    /// Local time at which the snapshot was accepted.
    ///
    /// Kept because a restored snapshot is still dated, and because a caller
    /// asks what it holds. It no longer decides freshness: an attestation does.
    snapshot_received_at: Option<u64>,
    /// The accepted attestation, if any.
    attestation: Option<SignedAttestation>,
    /// Local time at which that attestation counts as having arrived: its
    /// receipt, moved back by the age it already had when it arrived.
    ///
    /// A snapshot carries state and is delivered where a device needs state;
    /// dating a roster is a different job, done by an object that can say nothing
    /// else.
    attestation_received_at: Option<u64>,
    /// What freshness is measured from: the dating of the last attestation that
    /// counts for this node.
    ///
    /// Usually the held attestation's. It differs where the network has more
    /// than one admin and the held attestation is this node's own: an admin's
    /// word about itself does not keep it fresh while there are others who could
    /// have revoked something it has not heard about.
    freshness_since: Option<u64>,
    /// This node's own device, where the caller has said which it is.
    own_device: Option<DeviceId>,
    /// The highest attestation sequence accepted, which never decreases.
    attestation_seq: Option<u64>,
    /// The highest sequence number accepted, which never decreases.
    highest_seq: Option<u64>,
    /// Sequence numbers found to carry conflicting snapshots.
    ///
    /// Once a number is here, no snapshot at that number is ever accepted:
    /// choosing between two claims when one may be a forgery is exactly what
    /// this refuses to do.
    conflicting_seqs: Vec<u64>,
    /// The last clock reading, for spotting a backwards jump.
    last_reading: Option<u64>,
    /// The local clock.
    clock: Box<dyn Clock>,
}

impl Default for Roster {
    fn default() -> Self {
        Self::new()
    }
}

/// One operation, as the bytes that arrived and the signature over them.
///
/// The received bytes and not a re-encoding: a re-serialized operation is no
/// longer the thing that was signed, so evidence that had been through a decode
/// and encode round trip would fail to verify under the accused key and prove
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// The operation's identifier.
    pub id: OperationId,
    /// The exact received bytes of the signed core.
    pub core_bytes: Vec<u8>,
    /// The signature over them.
    pub signature: [u8; crate::limits::SIGNATURE_LEN],
}

/// Evidence that one device signed two histories.
///
/// **What the pair proves on its own:** that both signatures verify under the
/// accused device's key and that it authored both. That is the half which names
/// a culprit, and it needs nothing but these bytes.
///
/// **What it does not:** that the two are causally concurrent. One could be an
/// ancestor of the other through a chain neither names directly, so settling that
/// needs the operations between them. Every member already holds them — the
/// roster is synced — so any member reaches the verdict from its own copy without
/// trusting whoever reported it. The evidence removes the need to be believed, not
/// the need to hold the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Equivocation {
    /// The device that signed both.
    pub author: KeyId,
    /// One of the two.
    pub first: Proof,
    /// The other.
    pub second: Proof,
}

/// What a set of operations would make of a roster, before any of them is signed.
///
/// See [`Roster::preview`]. Everything a snapshot body needs from the graph, and
/// nothing that could be mistaken for a roster that holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    /// The state the graph would derive.
    pub state: RosterState,
    /// Its heads.
    pub heads: Vec<OperationId>,
    /// The causal depth of each head, positionally matching `heads`.
    pub depths: Vec<u64>,
}

impl Roster {
    /// An empty roster using the default staleness threshold.
    #[must_use]
    pub fn new() -> Self {
        Self::with_clock(Box::new(SystemClock::new()))
    }

    /// An empty roster driven by a given clock.
    #[must_use]
    pub fn with_clock(clock: Box<dyn Clock>) -> Self {
        Self {
            dag: Dag::new(),
            at_heads: None,
            pending: HashMap::new(),
            staleness_depth: limits::DEFAULT_STALENESS_DEPTH,
            refusals: Vec::new(),
            snapshot: None,
            snapshot_verified: false,
            snapshot_received_at: None,
            attestation: None,
            attestation_received_at: None,
            freshness_since: None,
            own_device: None,
            attestation_seq: None,
            highest_seq: None,
            conflicting_seqs: Vec::new(),
            last_reading: None,
            clock,
        }
    }

    /// An empty roster with an explicit staleness threshold.
    ///
    /// Tightening this narrows the window in which a demoted admin's backdated
    /// operation can be admitted, at the cost of refusing honest work from a
    /// device that was legitimately away. It cannot affect derived state.
    #[must_use]
    pub fn with_staleness_depth(depth: u64) -> Self {
        Self { staleness_depth: depth, ..Self::new() }
    }

    /// An empty roster with an explicit threshold and clock.
    #[must_use]
    pub fn with_staleness_and_clock(depth: u64, clock: Box<dyn Clock>) -> Self {
        Self { staleness_depth: depth, ..Self::with_clock(clock) }
    }

    /// The accepted snapshot, if any.
    #[must_use]
    pub const fn snapshot(&self) -> Option<&SignedSnapshot> {
        self.snapshot.as_ref()
    }

    /// Whether the accepted snapshot was verified against held operations.
    #[must_use]
    pub const fn snapshot_is_verified(&self) -> bool {
        self.snapshot_verified
    }

    /// The highest snapshot sequence number accepted.
    #[must_use]
    pub const fn highest_sequence(&self) -> Option<u64> {
        self.highest_seq
    }

    /// Every fork this roster holds evidence of, with the evidence.
    ///
    /// One device signed two causally concurrent operations: two histories from
    /// one identity. An honest device anchors each operation to its own previous
    /// one, so this means a deliberate fork or one identity running in two
    /// places — the same evidence and the same remedy either way.
    ///
    /// **Nothing here revokes anything.** Membership changes because a signed
    /// operation says so; an accusation and an expulsion are different acts, and
    /// the second is a person's. What this returns is what that person acts on.
    #[must_use]
    pub fn equivocations(&self) -> Vec<Equivocation> {
        let mut found = self
            .dag
            .forks()
            .into_iter()
            .filter_map(|fork| {
                let one = self.dag.operation(fork.first)?;
                let other = self.dag.operation(fork.second)?;

                // Already named by id rather than by position: `forks` does
                // that, so every consumer gets the same pair the same way round.
                let (first, second) = (one, other);

                Some(Equivocation {
                    author: fork.author,
                    first: Proof {
                        id: first.id(),
                        core_bytes: first.core_bytes().to_vec(),
                        signature: *first.signature(),
                    },
                    second: Proof {
                        id: second.id(),
                        core_bytes: second.core_bytes().to_vec(),
                        signature: *second.signature(),
                    },
                })
            })
            .collect::<Vec<_>>();

        // Forks whose operations a compaction discarded. Their ancestry is gone,
        // so the graph can no longer find them, but the accusation stands and so
        // does its proof.
        for (author, first, second) in self.dag.kept_evidence() {
            let already = found.iter().any(|held: &Equivocation| held.first.id == first.id());
            if !already {
                found.push(Equivocation {
                    author: *author,
                    first: Proof {
                        id: first.id(),
                        core_bytes: first.core_bytes().to_vec(),
                        signature: *first.signature(),
                    },
                    second: Proof {
                        id: second.id(),
                        core_bytes: second.core_bytes().to_vec(),
                        signature: *second.signature(),
                    },
                });
            }
        }

        // A revocation settles the question. The revoked set carries the outcome
        // from then on, so the accusation has nothing left to add and reporting
        // it would keep a person looking at something already dealt with.
        if let Ok(state) = self.state() {
            found.retain(|held| {
                state
                    .device_for_key(&held.author)
                    .is_some_and(|device| !state.revoked.contains(&device.id))
            });
        }

        found.sort_by(|left, right| {
            (left.author, left.first.id, left.second.id).cmp(&(
                right.author,
                right.first.id,
                right.second.id,
            ))
        });
        found
    }

    /// Sequence numbers at which conflicting snapshots were seen.
    ///
    /// A non-empty list is the signal equivocation detection consumes: either
    /// two admins acted at once, or one is showing different branches to
    /// different peers.
    #[must_use]
    pub fn conflicting_sequences(&self) -> &[u64] {
        &self.conflicting_seqs
    }

    /// Offers a snapshot as bytes, received now.
    ///
    /// The order of checks is deliberate: signature first, because an unsigned
    /// claim deserves nothing else; then authority; then the sequence rules,
    /// which are cheap; then the state comparison, which is the expensive one
    /// and the one that matters.
    pub fn offer_snapshot(&mut self, bytes: &[u8]) -> SnapshotAdmission {
        let now = self.observe_clock();
        self.take_snapshot(bytes, now)
    }

    /// Restores a snapshot that was accepted earlier, with the receipt time it
    /// was given then.
    ///
    /// Every check [`Self::offer_snapshot`] makes is made again: a stored
    /// snapshot is bytes off a disk, and a caller handing them back is not
    /// evidence of anything. What differs is only the moment it counts as having
    /// arrived.
    ///
    /// **This is what makes freshness outlive a process.** A snapshot is not an
    /// operation and is not in the log, so a node that replayed its log would hold
    /// none, and one that re-offered its own stored snapshot on start would date
    /// it from the start. The second is the dangerous one: it would make
    /// restarting a way out of a stale roster, and a stale roster is exactly the
    /// state a device should not be able to leave by turning itself off and on.
    ///
    /// `received_at` must be read from the same clock this roster was given.
    pub fn restore_snapshot(&mut self, bytes: &[u8], received_at: u64) -> SnapshotAdmission {
        // The reading is still taken, so that a clock which has moved backwards
        // since is caught on the next question rather than on the one after.
        let _now = self.observe_clock();
        self.take_snapshot(bytes, received_at)
    }

    /// Accepts a snapshot as having arrived at `received_at`.
    fn take_snapshot(&mut self, bytes: &[u8], received_at: u64) -> SnapshotAdmission {
        let raw = match RawSnapshot::decode(bytes) {
            Ok(raw) => raw,
            Err(reason) => return SnapshotAdmission::Refused { reason },
        };

        if let Some(network) = self.dag.network()
            && raw.body().network != network
        {
            return SnapshotAdmission::Refused { reason: Error::ForeignNetwork };
        }

        let Some(key) = self.resolve_snapshot_signer(&raw) else {
            return SnapshotAdmission::Refused { reason: Error::UnauthorizedAuthor };
        };
        let signed = match raw.verify(&key) {
            Ok(signed) => signed,
            Err(reason) => return SnapshotAdmission::Refused { reason },
        };

        if !self.signer_is_admin(&signed) {
            return SnapshotAdmission::Refused { reason: Error::UnauthorizedAuthor };
        }

        let seq = signed.body().seq;

        // A number already known to carry conflicting claims is closed for
        // good; recovery is a higher number, not a re-run of the same one.
        if self.conflicting_seqs.contains(&seq) {
            return SnapshotAdmission::Refused { reason: Error::SnapshotSequenceConflict };
        }

        if let Some(held) = &self.snapshot
            && held.body().seq == seq
        {
            if held.same_content(&signed) {
                return SnapshotAdmission::AlreadyHeld { seq };
            }
            // Two claims at one number. Refuse both, drop the one held, and
            // record the number: picking a winner would hide an author
            // showing different histories to different peers.
            self.conflicting_seqs.push(seq);
            self.conflicting_seqs.sort_unstable();
            self.snapshot = None;
            self.snapshot_verified = false;
            self.snapshot_received_at = None;
            return SnapshotAdmission::Refused { reason: Error::SnapshotSequenceConflict };
        }

        if self.highest_seq.is_some_and(|highest| seq <= highest) {
            return SnapshotAdmission::Refused { reason: Error::SnapshotSequenceRegressed };
        }

        // Verification before trust: where this node holds what the snapshot
        // covers, its own derivation is authoritative.
        let coverage = self.coverage_of(&signed);
        let verified = match coverage {
            Coverage::Full => match self.derive_covered_state(&signed) {
                Some(expected) if expected == signed.body().state => true,
                Some(_) => {
                    return SnapshotAdmission::Refused { reason: Error::SnapshotStateMismatch };
                }
                None => {
                    return SnapshotAdmission::Refused { reason: Error::SnapshotUnverified };
                }
            },
            // Holding part of the covered set is not partial verification: the
            // claimed state cannot be reproduced, so nothing has been checked.
            Coverage::Partial | Coverage::None => false,
        };

        self.snapshot = Some(signed);
        self.snapshot_verified = verified;
        self.snapshot_received_at = Some(received_at);
        self.highest_seq = Some(seq);
        if verified {
            SnapshotAdmission::Accepted { seq }
        } else {
            SnapshotAdmission::AdoptedUnverified { seq }
        }
    }

    /// How much of a snapshot's covered set this node holds.
    fn coverage_of(&self, snapshot: &SignedSnapshot) -> Coverage {
        let held = snapshot.body().heads.iter().filter(|head| self.dag.contains(head)).count();
        if held == snapshot.body().heads.len() && !snapshot.body().heads.is_empty() {
            Coverage::Full
        } else if held == 0 {
            Coverage::None
        } else {
            Coverage::Partial
        }
    }

    /// Derives the state a snapshot claims, from operations this node holds.
    fn derive_covered_state(&self, snapshot: &SignedSnapshot) -> Option<Vec<u8>> {
        let region = self.dag.covered_region(snapshot)?;
        let mut covered = Dag::new();
        // Rebuilding in topological order is safe: the region is downward
        // closed, so every parent of a member is a member.
        for index in region {
            let operation = self.dag.operation(index)?;
            covered.insert(operation.clone()).ok()?;
        }
        derive(&covered).ok().map(|state| state.to_bytes())
    }

    /// The public key that signed a snapshot, if this node can name it.
    ///
    /// Tried against this node's own derived state first. A node with no
    /// operations falls back to the state the snapshot itself claims — which is
    /// circular, and is exactly the bootstrapping limit: such a node trusts the
    /// admin's signature and has no way to check the claim.
    fn resolve_snapshot_signer(&self, raw: &RawSnapshot) -> Option<PublicKey> {
        let author = raw.body().author;
        if let Ok(state) = self.state()
            && let Some(key) = signing_key_of(&state, &author)
        {
            return Some(key);
        }
        let claimed = RosterState::from_bytes(&raw.body().state).ok()?;
        signing_key_of(&claimed, &author)
    }

    /// Whether a snapshot's signer holds the admin role.
    fn signer_is_admin(&self, snapshot: &SignedSnapshot) -> bool {
        let signer = snapshot.signer();
        if let Ok(state) = self.state()
            && let Some(record) = state.device_for_key(&signer)
        {
            return record.role == Role::Admin && !state.revoked.contains(&record.id);
        }
        let Ok(claimed) = RosterState::from_bytes(&snapshot.body().state) else {
            return false;
        };
        claimed.device_for_key(&signer).is_some_and(|record| {
            record.role == Role::Admin && !claimed.revoked.contains(&record.id)
        })
    }

    /// Discards the operations the accepted snapshot covers.
    ///
    /// Deliberate rather than a side effect of accepting a snapshot: nothing is
    /// ever thrown away because a message arrived.
    pub fn compact(&mut self) -> Result<usize> {
        let Some(snapshot) = self.snapshot.clone() else {
            return Err(Error::CompactionRefused("no snapshot accepted"));
        };

        // Gate 3. Discarding on an unverified snapshot would throw away the
        // evidence needed to notice it lied.
        if !self.snapshot_verified {
            return Err(Error::CompactionRefused("snapshot was not verified locally"));
        }

        let Some(region) = self.dag.covered_region(&snapshot) else {
            return Err(Error::CompactionRefused("a covered head is not held"));
        };
        let in_region: Vec<bool> =
            (0..self.dag.len()).map(|index| region.binary_search(&index).is_ok()).collect();

        // Gate 1. A held operation concurrent with the region still needs the
        // ancestry that discarding would destroy.
        for outside in 0..self.dag.len() {
            if in_region.get(outside).copied().unwrap_or(false) {
                continue;
            }
            for inside in &region {
                if self.dag.concurrent(outside, *inside) {
                    return Err(Error::CompactionRefused(
                        "a held operation is concurrent with the covered region",
                    ));
                }
            }
        }

        // Gate 2. Anything anchoring into the region later would already be
        // refused as stale, and the frontier only advances. Without this, a
        // divergent history defeats gate 1: an operation deep on one branch is
        // genuinely concurrent with a shallow one on another.
        let frontier = self.dag.frontier_depth();
        let deepest = region.iter().map(|index| self.dag.depth(*index)).max().unwrap_or(0);
        if frontier.saturating_sub(deepest) <= self.staleness_depth {
            return Err(Error::CompactionRefused(
                "the covered region is within the staleness horizon",
            ));
        }

        self.dag.compact(snapshot)
    }

    /// When the accepted snapshot was received, on this roster's own clock.
    ///
    /// For a caller deciding whether to sign a fresher one. [`Self::freshness`]
    /// answers whether the window has passed, which is too late to be the trigger
    /// for replacing it: an admin that waited for stale would leave every other
    /// device stale first.
    #[must_use]
    pub const fn snapshot_received_at(&self) -> Option<u64> {
        self.snapshot_received_at
    }

    /// The accepted attestation, if any.
    #[must_use]
    pub const fn attestation(&self) -> Option<&SignedAttestation> {
        self.attestation.as_ref()
    }

    /// When the accepted attestation was received, on this roster's own clock.
    ///
    /// For a caller deciding whether to produce a fresher one, and for the one
    /// that stores it beside the log so freshness outlives the process.
    #[must_use]
    pub const fn attestation_received_at(&self) -> Option<u64> {
        self.attestation_received_at
    }

    /// When freshness is measured from, on this roster's own clock.
    ///
    /// The same as [`Self::attestation_received_at`] except where the held
    /// attestation is this node's own and the network has other admins. A caller
    /// that keeps attestations beside the log keeps the one this dates too, so
    /// that a restart does not lose it.
    #[must_use]
    pub const fn freshness_since(&self) -> Option<u64> {
        self.freshness_since
    }

    /// Says which device this node is.
    ///
    /// Only freshness uses it: an attestation this device signed does not keep
    /// its own roster fresh where the network has more than one admin.
    pub fn set_own_device(&mut self, device: DeviceId) {
        self.own_device = Some(device);
    }

    /// The time since the Unix epoch, where this roster's clock knows it.
    ///
    /// What an attestation signed here is dated with. See
    /// [`Clock::unix_seconds`].
    #[must_use]
    pub fn unix_now(&self) -> Option<u64> {
        self.clock.unix_seconds()
    }

    /// Offers an attestation, dated as arriving now — less the age it already
    /// had, where this roster's clock can tell.
    pub fn offer_attestation(&mut self, bytes: &[u8]) -> AttestationAdmission {
        let now = self.observe_clock();
        self.take_attestation(bytes, now, true)
    }

    /// Restores an attestation accepted earlier, with the receipt time it had.
    ///
    /// Every check [`Self::offer_attestation`] makes is made again: stored bytes
    /// are bytes off a disk, and a caller handing them back is not evidence of
    /// anything. What differs is only the moment it counts as having arrived —
    /// which is what stops a restart being a way out of a stale roster.
    pub fn restore_attestation(&mut self, bytes: &[u8], received_at: u64) -> AttestationAdmission {
        // The reading is still taken, so a clock that has moved backwards since
        // is caught on the next question rather than the one after.
        let _now = self.observe_clock();
        // What was stored is already the dating it was given on arrival, its age
        // included, so it is not aged a second time.
        self.take_attestation(bytes, received_at, false)
    }

    /// Accepts an attestation as having arrived at `received_at`.
    ///
    /// With `age` set, the arrival is moved back by the age the attestation
    /// already had: the time between its author signing it and now, on the
    /// Unix clock. Measuring from the earlier of the two is what makes a
    /// signer-chosen time safe — it can only move the start back. A time in the
    /// future gives no age, and the attestation is dated from its receipt, as one
    /// was before attestations carried a time.
    fn take_attestation(
        &mut self,
        bytes: &[u8],
        received_at: u64,
        age: bool,
    ) -> AttestationAdmission {
        let raw = match RawAttestation::decode(bytes) {
            Ok(raw) => raw,
            Err(reason) => return AttestationAdmission::Refused { reason },
        };

        if let Some(network) = self.dag.network()
            && raw.body().network != network
        {
            return AttestationAdmission::Refused { reason: Error::ForeignNetwork };
        }

        // Resolved against this node's own roster and nothing else. An
        // attestation carries no state, so there is nothing in it that could
        // claim who its author is — the case a snapshot has, and this does not.
        let Ok(state) = self.state() else {
            return AttestationAdmission::Refused { reason: Error::UnauthorizedAuthor };
        };
        let Some(key) = attestation_key_of(&state, &raw.body().author) else {
            return AttestationAdmission::Refused { reason: Error::UnauthorizedAuthor };
        };
        let signed = match raw.verify(&key) {
            Ok(signed) => signed,
            Err(reason) => return AttestationAdmission::Refused { reason },
        };

        let Some(record) = state
            .device_for_key_of_purpose(&signed.signer(), crate::types::KeyPurpose::Attestation)
        else {
            return AttestationAdmission::Refused { reason: Error::UnauthorizedAuthor };
        };
        if record.role != Role::Admin || state.revoked.contains(&record.id) {
            return AttestationAdmission::Refused { reason: Error::UnauthorizedAuthor };
        }

        let seq = signed.body().seq;
        if self.attestation_seq.is_some_and(|held| seq <= held) {
            return AttestationAdmission::Refused { reason: Error::SnapshotSequenceRegressed };
        }

        // The rule that makes this mean something: an admin's word that it knew
        // these heads says nothing to a node that does not have them. Such a
        // node has learned that it is behind, which is not freshness.
        if !signed.body().heads.iter().all(|head| self.dag.contains(head)) {
            return AttestationAdmission::HeadsNotHeld { seq };
        }

        let dated = if age {
            let already = self
                .clock
                .unix_seconds()
                .map_or(0, |unix| unix.saturating_sub(signed.body().issued_at));
            received_at.saturating_sub(already)
        } else {
            received_at
        };

        // An admin's own word dates its roster only where nobody else could have
        // revoked anything: with other admins, an admin isolated from all of them
        // would otherwise stay fresh for ever and honour a device they expelled.
        let own = self.own_device.is_some_and(|own| own == record.id);
        let admins = state
            .devices
            .values()
            .filter(|device| device.role == Role::Admin && !state.revoked.contains(&device.id))
            .count();
        if !own || admins <= 1 {
            self.freshness_since = Some(dated);
        }

        self.attestation = Some(signed);
        self.attestation_received_at = Some(dated);
        self.attestation_seq = Some(seq);
        AttestationAdmission::Accepted { seq }
    }

    /// How current this node believes its roster to be.
    ///
    /// Measured from the earlier of local receipt and the attestation's signed
    /// time, never from a timestamp that could move it later. A signer-chosen
    /// expiry would let a compromised admin set a far-future value and leave the
    /// revocation window unbounded on every node that accepted it — worse than no
    /// window, because it would look like a protection. A signed time that can
    /// only make a roster older cannot do that.
    pub fn freshness(&mut self) -> Freshness {
        let Some(received_at) = self.freshness_since else {
            return Freshness::Unknown;
        };
        let previous = self.last_reading;
        let now = self.observe_clock();
        if previous.is_some_and(|earlier| now < earlier) {
            return Freshness::ClockWentBackwards;
        }
        // A receipt later than the clock's own reading is a clock that moved, not
        // a roster that just arrived. Left to the subtraction below it would
        // saturate to zero elapsed and read as fresh, so a clock set forward once
        // while a snapshot was accepted would leave this node fresh for ever.
        if now < received_at {
            return Freshness::ClockWentBackwards;
        }
        let window = match self.state() {
            Ok(state) => state.params.snapshot_window,
            Err(_) => return Freshness::Unknown,
        };
        if now.saturating_sub(received_at) > window { Freshness::Stale } else { Freshness::Fresh }
    }

    /// Reads the clock and remembers the reading.
    fn observe_clock(&mut self) -> u64 {
        let now = self.clock.now_seconds();
        self.last_reading = Some(now);
        now
    }

    /// The graph, for deriving state.
    #[must_use]
    pub const fn dag(&self) -> &Dag {
        &self.dag
    }

    /// The roster this node's operations imply.
    pub fn state(&self) -> Result<RosterState> {
        // What was kept, when it is there. It is only ever what `derive` would
        // say — `follow` either applies one operation to it, in the case where
        // that is the whole of the answer, or derives afresh.
        match &self.at_heads {
            Some(state) => Ok(state.clone()),
            None => derive(&self.dag),
        }
    }

    /// The state `derive` computes from the graph, ignoring what was kept.
    ///
    /// For the checks that hold the kept state to derivation. Nothing on the
    /// ordinary path should need this: if the two ever differ, the bug is here
    /// and not in the caller.
    ///
    /// # Errors
    ///
    /// As [`Self::state`].
    pub fn derived_state(&self) -> Result<RosterState> {
        derive(&self.dag)
    }

    /// The roster these operations would make, before any of them is signed.
    ///
    /// # Why this exists
    ///
    /// An administrative act can need several signatures — an operation, and a
    /// snapshot over the roster once the operation is in. Signing them one at a
    /// time means asking a person once for each, and showing them the second
    /// only after they have authorised the first. Neither depends on the other's
    /// signature: an operation's id hashes its core, and a snapshot covers ids
    /// and the derived state. So the whole act can be prepared first — and the
    /// snapshot needs *this*, the state the operations will imply.
    ///
    /// # Why it is safe
    ///
    /// Nothing here is admitted. The operations go into a **copy** of the graph,
    /// that copy is derived and dropped, and this roster is untouched. What
    /// leaves is a state, heads and depths — the ingredients of a snapshot body
    /// that somebody will then sign, and that a roster (this one included) will
    /// accept only by deriving the same state from operations it has verified.
    /// A wrong preview is therefore a refused snapshot, never a trusted one.
    ///
    /// The operations are taken in order, each after its parents, as they will
    /// be admitted.
    ///
    /// # Errors
    ///
    /// When an operation's parents are not in the graph or earlier in `cores`,
    /// or when the result derives no state.
    pub fn preview(&self, cores: &[OperationCore]) -> Result<Preview> {
        let mut dag = self.dag.clone();
        for core in cores {
            dag.insert(VerifiedOperation::unsigned_for_preview(core))?;
        }
        let state = derive(&dag)?;
        let heads = dag.heads();
        let mut depths = Vec::with_capacity(heads.len());
        for head in &heads {
            let index = dag.position(head).ok_or(Error::MissingField)?;
            depths.push(dag.depth(index));
        }
        Ok(Preview { state, heads, depths })
    }

    /// How many operations are waiting for parents.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// The ids of operations waiting for parents.
    #[must_use]
    pub fn pending_ids(&self) -> Vec<OperationId> {
        let mut ids: Vec<OperationId> = self.pending.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// The tips a peer needs in order to tell what this node already knows.
    #[must_use]
    pub fn heads(&self) -> Vec<OperationId> {
        self.dag.heads()
    }

    /// Refusals recorded so far, oldest first.
    ///
    /// A refusal is never merely dropped: a stale operation authored by a key
    /// that is still a valid admin means either a backdating attempt or a badly
    /// out-of-date device, and both are worth a person's attention.
    #[must_use]
    pub fn refusals(&self) -> &[(OperationId, Error)] {
        &self.refusals
    }

    /// Takes the recorded refusals, clearing them.
    pub fn take_refusals(&mut self) -> Vec<(OperationId, Error)> {
        core::mem::take(&mut self.refusals)
    }

    /// Whether a refused operation was authored by a key that currently holds
    /// the admin role — the case that deserves an alert rather than a log line.
    #[must_use]
    pub fn refusal_is_from_current_admin(&self, operation: &VerifiedOperation) -> bool {
        let Ok(state) = self.state() else { return false };
        state
            .device_for_key(&operation.core().author)
            .is_some_and(|record| record.role == crate::types::Role::Admin)
    }

    /// Offers an operation as bytes, exactly as it arrived from a peer.
    ///
    /// This is the single entry point; everything else routes through it, so
    /// there is one place only where the order of checks is decided.
    pub fn offer_bytes(&mut self, bytes: &[u8]) -> Admission {
        match RawOperation::decode(bytes) {
            Ok(raw) => self.offer(&raw),
            Err(reason) => {
                // The stated id cannot be trusted from bytes that did not
                // decode, so the refusal is recorded against what arrived.
                let id = OperationId::of_core(bytes);
                self.refuse(id, reason)
            }
        }
    }

    /// Offers a decoded operation, verifying it against this roster.
    ///
    /// Order matters. Parents first, because an operation that cannot be placed
    /// cannot be verified either. Then staleness, which is cheap and needs no
    /// state. Then authority and the signature.
    pub fn offer(&mut self, raw: &RawOperation<'_>) -> Admission {
        let id = raw.id();
        if self.dag.contains(&id) {
            return Admission::AlreadyHeld(id);
        }
        if self.pending.contains_key(&id) {
            return Admission::Pending { operation: id, missing: self.missing_for(raw) };
        }

        // Structural, and so independent of what this node happens to hold:
        // only the founding operation may be parentless. Checking it here keeps
        // the refusal reason the same whatever order operations arrive in.
        if raw.core().parents.is_empty()
            && raw.core().operation_type() != crate::types::OperationType::CreateNetwork
        {
            return self.refuse(id, Error::ParentlessOperation);
        }

        let missing = self.missing_for(raw);
        if !missing.is_empty() {
            return self.hold(raw, missing);
        }

        if let Some(reason) = self.staleness_refusal(raw) {
            return self.refuse(id, reason);
        }

        // Whether this operation extends every head, which decides both how it
        // is judged and how the kept state follows it. Read before the insert,
        // because inserting is what changes the heads.
        let extends_every_head = self.extends_every_head(raw);

        // Authority, before anything is inserted. The graph is bounded and every
        // node forwards what it admits, so an operation admitted and then
        // disregarded costs every node in the network a slot it cannot recover —
        // which is how one member could leave a network unable to revoke anybody
        // again. The rule is derivation's own, judged against the state this
        // operation's own ancestors imply, so an operation valid when it was
        // signed is admitted by every node whatever order it arrives in.
        if let Some(reason) = self.without_authority(raw, extends_every_head) {
            return self.refuse(id, reason);
        }

        let Some(key) = self.resolve_author_key(raw) else {
            // Every parent is present, so derived state is as complete as it is
            // going to get. An author it still does not name has no authority.
            return self.refuse(id, Error::UnauthorizedAuthor);
        };
        match raw.verify(&key) {
            Ok(verified) => match self.dag.insert(verified) {
                Ok(()) => {
                    self.follow(extends_every_head);
                    self.integrate_pending();
                    Admission::Accepted(id)
                }
                Err(reason) => self.refuse(id, reason),
            },
            Err(reason) => self.refuse(id, reason),
        }
    }

    /// Offers an already-verified operation, for callers that hold one.
    pub fn admit(&mut self, operation: VerifiedOperation) -> Admission {
        self.offer_bytes(&operation.to_bytes())
    }

    /// The parents of an operation this node does not hold.
    fn missing_for(&self, raw: &RawOperation<'_>) -> Vec<OperationId> {
        raw.core().parents.iter().filter(|parent| !self.dag.contains(parent)).copied().collect()
    }

    /// Why an offered operation may not be inserted, when it may not.
    ///
    /// The founding operation is exempt: it declares the admin it is authored by,
    /// and there is no earlier state to consult. Everything else is judged
    /// against the state its own parents imply, by the roster's one authority
    /// rule — [`crate::state::unauthorized_author`] — so that this cannot drift
    /// from what derivation decides about the same operation.
    ///
    /// A graph this node cannot derive a state for yields `None`: judging is then
    /// impossible, and refusing on a question that could not be asked would make
    /// admission depend on this node's own trouble rather than on the operation.
    fn without_authority(&self, raw: &RawOperation<'_>, extends_every_head: bool) -> Option<Error> {
        if raw.core().parents.is_empty() {
            return None;
        }

        // Asked first because it costs a scan and answers most of the attack.
        // Working out an author's authority properly means resolving the state
        // its ancestors imply, and an attacker chooses the ancestors: operations
        // anchored just behind the frontier are within the staleness window and
        // are not the current heads, so each would cost a derivation. Refusing at
        // a derivation apiece is still a denial of service.
        if self.never_granted_admin(&raw.core().author) {
            return Some(Error::UnauthorizedAuthor);
        }

        // An operation naming every head descends from the whole graph, so the
        // state at the heads *is* the state its ancestors imply — already kept,
        // and the case an honest client produces. Anything else is resolved from
        // its own ancestors, which costs a derivation over them.
        let ancestor_state = match (extends_every_head, self.at_heads.as_ref()) {
            (true, Some(state)) => state.clone(),
            _ => crate::state::state_for_parents(&self.dag, &raw.core().parents).ok()?,
        };
        if crate::state::unauthorized_author(&ancestor_state, &raw.core().author).is_some() {
            return Some(Error::UnauthorizedAuthor);
        }

        // And that the operation has somebody to act on. An operation naming a
        // device its own ancestors do not know can never have an effect —
        // derivation ignores it — so admitting it would spend a slot on nothing.
        // A revocation is the case that matters: without this, the room kept for
        // revocations could be filled with revocations of invented devices.
        if let Some(target) = crate::dag::Dag::target_of(&raw.core().body) {
            let absent = !ancestor_state.devices.contains_key(&target);
            let already_revoked = ancestor_state.revoked.contains(&target);
            if absent || already_revoked {
                return Some(Error::UnknownTarget);
            }
        }
        None
    }

    /// Whether an offered operation names exactly the graph's current heads.
    ///
    /// The case an honest client produces: it writes from where it is. Such an
    /// operation is concurrent with nothing, so its ancestors are the whole graph
    /// and the state at the heads is the state it must be judged against.
    fn extends_every_head(&self, raw: &RawOperation<'_>) -> bool {
        let heads = self.dag.heads();
        !heads.is_empty()
            && heads.len() == raw.core().parents.len()
            && heads.iter().all(|head| raw.core().parents.contains(head))
    }

    /// Brings the kept state up to what the graph now says.
    ///
    /// `in_one_step` is whether the operation just inserted extended every head,
    /// which is the only case that can be followed by applying it. Anything else
    /// derives: a merge, an integration from the pending set, an operation
    /// anchored behind the frontier. Deriving is the expensive path and the
    /// correct one, and it is taken whenever there is any doubt at all.
    fn follow(&mut self, in_one_step: bool) {
        let extended = in_one_step.then_some(self.at_heads.as_ref()).flatten().and_then(|state| {
            self.dag.operations().last().map(|operation| crate::state::extend(state, operation))
        });
        self.at_heads = match extended {
            Some(next) => Some(next),
            None => derive(&self.dag).ok(),
        };
    }

    /// Whether nothing in this graph has ever granted a key's device the admin
    /// role.
    ///
    /// A cheap, monotone over-approximation of "has no authority anywhere". A
    /// device is a candidate for authority only if the `add_device` that
    /// introduced it declared the admin role, if some `promote` names it, or if
    /// it is the founder. That set only grows as operations arrive, and it
    /// contains every device that could be an admin in any ancestor state — so a
    /// key outside it can be refused without resolving any state at all.
    ///
    /// Being an over-approximation is what makes it safe: a device promoted and
    /// later demoted stays in it and gets the precise check below. This can only
    /// ever say "look more carefully", never "refuse".
    ///
    /// A graph resting on a snapshot answers `false`: the devices the snapshot
    /// carries were admitted before the operations it discarded, so the grants
    /// are no longer here to find, and the precise check must decide.
    fn never_granted_admin(&self, author: &crate::id::KeyId) -> bool {
        if !matches!(self.dag.foundation(), Some(crate::dag::Foundation::Genesis(_))) {
            return false;
        }

        let mut admin_devices: Vec<crate::id::DeviceId> = Vec::new();
        let mut keys_of: Vec<(crate::id::DeviceId, Vec<crate::id::KeyId>)> = Vec::new();
        for operation in self.dag.operations() {
            match &operation.core().body {
                crate::types::OperationBody::CreateNetwork { device, .. }
                | crate::types::OperationBody::AddDevice(device) => {
                    let Ok(id) = device.device_id() else { continue };
                    let signing: Vec<crate::id::KeyId> = device
                        .keys
                        .iter()
                        .filter(|entry| entry.purpose == crate::types::KeyPurpose::Signing)
                        .map(crate::types::KeyEntry::key_id)
                        .collect();
                    if device.role == crate::types::Role::Admin {
                        admin_devices.push(id);
                    }
                    keys_of.push((id, signing));
                }
                crate::types::OperationBody::Promote { device, .. } => admin_devices.push(*device),
                _ => {}
            }
        }

        !keys_of.iter().any(|(id, signing)| {
            admin_devices.contains(id) && signing.iter().any(|key| key == author)
        })
    }

    /// The public key that should have signed an operation, if this node knows
    /// the author.
    fn resolve_author_key(&self, raw: &RawOperation<'_>) -> Option<PublicKey> {
        // The founding operation carries its own author's key, so it can be
        // verified with nothing else held.
        if raw.core().parents.is_empty()
            && let crate::types::OperationBody::CreateNetwork { device, .. } = &raw.core().body
        {
            return device
                .keys
                .iter()
                .find(|entry| {
                    entry.purpose == crate::types::KeyPurpose::Signing
                        && entry.key_id() == raw.core().author
                })
                .and_then(|entry| PublicKey::new(entry.alg, entry.value.clone()).ok());
        }
        let state = self.state().ok()?;
        let record = state.device_for_key(&raw.core().author)?;
        record
            .keys
            .iter()
            .find(|entry| {
                entry.purpose == crate::types::KeyPurpose::Signing
                    && entry.key_id() == raw.core().author
            })
            .and_then(|entry| PublicKey::new(entry.alg, entry.value.clone()).ok())
    }

    /// Whether an operation is anchored too far behind the local frontier.
    ///
    /// Local policy. The comparison uses the deepest parent this node holds,
    /// which is the best evidence available of where the author was standing.
    fn staleness_refusal(&self, operation: &RawOperation<'_>) -> Option<Error> {
        if self.dag.is_empty() {
            return None;
        }
        let anchor_depth = operation
            .core()
            .parents
            .iter()
            .filter_map(|parent| self.dag.position(parent))
            .map(|index| self.dag.depth(index))
            .max()?;
        let frontier = self.dag.frontier_depth();
        let behind = frontier.saturating_sub(anchor_depth);
        (behind > self.staleness_depth).then_some(Error::StaleOperation)
    }

    /// Puts an operation in the pending set.
    fn hold(&mut self, raw: &RawOperation<'_>, missing: Vec<OperationId>) -> Admission {
        let id = raw.id();
        if self.pending.len() >= limits::MAX_PENDING_OPERATIONS {
            // Reported, never silent. A caller that is not told the set is full
            // cannot tell a busy sync from a peer flooding it.
            return self.refuse(id, Error::LimitExceeded("pending operations"));
        }
        self.pending.insert(
            id,
            PendingEntry { bytes: raw.to_bytes(), parents: raw.core().parents.clone() },
        );
        Admission::Pending { operation: id, missing }
    }

    /// Records a refusal and reports it.
    fn refuse(&mut self, operation: OperationId, reason: Error) -> Admission {
        self.refusals.push((operation, reason.clone()));
        Admission::Refused { operation, reason }
    }

    /// Integrates every pending operation whose parents are now present,
    /// cascading through entries the previous round unblocked.
    fn integrate_pending(&mut self) {
        loop {
            // Sorted, so a round integrates entries in the same order on every
            // node. Derivation does not care, but a reproducible refusal log is
            // worth having when diagnosing a sync.
            let mut ready: Vec<OperationId> = self
                .pending
                .iter()
                .filter(|(_, entry)| entry.parents.iter().all(|p| self.dag.contains(p)))
                .map(|(id, _)| *id)
                .collect();
            if ready.is_empty() {
                return;
            }
            ready.sort_unstable();

            for id in ready {
                let Some(entry) = self.pending.remove(&id) else { continue };
                let Ok(raw) = RawOperation::decode(&entry.bytes) else {
                    self.refusals.push((id, Error::NonCanonical));
                    continue;
                };
                if let Some(reason) = self.staleness_refusal(&raw) {
                    self.refusals.push((id, reason));
                    continue;
                }
                // The same authority check `offer` makes, because this is the
                // other door into the graph. Without it, offering a child before
                // its parent would be a way to walk past admission entirely: the
                // child waits here, and the arrival of its parent lets it in
                // unexamined.
                if let Some(reason) = self.without_authority(&raw, false) {
                    self.refusals.push((id, reason));
                    continue;
                }
                // Verification happens here rather than on the way in: the key
                // that checks this signature only became resolvable now that the
                // ancestors establishing its author are present.
                let Some(key) = self.resolve_author_key(&raw) else {
                    self.refusals.push((id, Error::UnauthorizedAuthor));
                    continue;
                };
                match raw.verify(&key) {
                    Ok(verified) => {
                        // Integration is never the simple case: the operation
                        // waited, so the graph moved on around it.
                        if let Err(reason) = self.dag.insert(verified) {
                            self.refusals.push((id, reason));
                        }
                        self.follow(false);
                    }
                    Err(reason) => self.refusals.push((id, reason)),
                }
            }
        }
    }
}

/// How much of a snapshot's covered set a node holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coverage {
    /// Every covered head is held, so the claim can be checked.
    Full,
    /// Some but not all: the claim cannot be reproduced, so nothing is checked.
    Partial,
    /// None. A bootstrapping node.
    None,
}

/// The signing key a state holds for a given key id.
///
/// Looked up by name rather than found by trial, so a signature that does not
/// verify is reported as such instead of being mistaken for an unknown signer.
fn attestation_key_of(state: &RosterState, author: &crate::id::KeyId) -> Option<PublicKey> {
    let record = state.device_for_key_of_purpose(author, crate::types::KeyPurpose::Attestation)?;
    let entry = record.keys.iter().find(|entry| {
        entry.purpose == crate::types::KeyPurpose::Attestation && entry.key_id() == *author
    })?;
    PublicKey::new(entry.alg, entry.value.clone()).ok()
}

/// The signing key a device record names, by its key id.
fn signing_key_of(state: &RosterState, author: &crate::id::KeyId) -> Option<PublicKey> {
    for record in state.devices.values() {
        for entry in &record.keys {
            if entry.purpose != crate::types::KeyPurpose::Signing {
                continue;
            }
            if entry.key_id() != *author {
                continue;
            }
            return PublicKey::new(entry.alg, entry.value.clone()).ok();
        }
    }
    None
}

/// An operation held until its parents arrive.
#[derive(Debug, Clone)]
struct PendingEntry {
    /// The operation exactly as it arrived.
    bytes: Vec<u8>,
    /// The parents it is waiting for.
    parents: Vec<OperationId>,
}

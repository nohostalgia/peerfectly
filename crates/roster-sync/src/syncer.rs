//! The reconciliation itself: messages in, messages out.
//!
//! [`Syncer`] is synchronous and owns no runtime. It says what to send when a
//! session opens, what a received payload produces, and what to forward when an
//! operation is admitted locally. It spawns nothing.
//!
//! That is deliberate. `windows-daemon` will decide the concurrency shape, and it
//! knows things this crate does not — how many peers, on what schedule, under
//! what power constraints. A crate that spawned its own tasks would have to be
//! worked around. It also makes partition and interleaving testable by calling
//! functions in a chosen order, rather than by racing threads.
//!
//! # It decides which bytes move, and nothing else
//!
//! Every operation and snapshot received goes through the roster. Nothing
//! reaches derived state by another path, and no judgement about validity,
//! membership or authority is made here.

use std::collections::BTreeSet;

use roster::id::{DeviceId, OperationId};
use roster::roster::{Admission, AttestationAdmission, Roster};
use roster::sign::RawOperation;
use roster::snapshot::RawSnapshot;

use crate::error::{Error, Result};
use crate::message::{Message, Offer};
use crate::quota::Quota;

/// Something a peer sent that was not acted on, and why.
///
/// Refusals are reported rather than swallowed. A node that quietly dropped what
/// it would not accept would also quietly drop the evidence that an author had
/// equivocated — which `equivocation-detection` is going to need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The peer the message came from.
    pub peer: DeviceId,
    /// The operation refused, when the refusal was about one.
    pub operation: Option<OperationId>,
    /// Why.
    pub reason: Error,
}

/// What a peer's offer showed it already holds.
///
/// The peer is carried with the ids rather than left to the caller to remember.
/// Propagation is a question about a particular device — an operation one member
/// holds and another lacks has reached one of them — and a caller that could
/// take the ids without the device could answer it for the wrong one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// The peer whose offer named them.
    pub peer: DeviceId,
    /// Operations that peer named which this node also holds.
    pub ids: Vec<OperationId>,
}

/// What a received payload produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reception {
    /// Messages to send back to the peer this came from.
    pub replies: Vec<Message>,
    /// What the peer's own offer said it holds, of what this node holds too.
    ///
    /// Present only for an offer, because only an offer is evidence. Transmitting
    /// an operation, a session that stays open and the absence of an error all
    /// look the same from this side whether or not the far end ever read it.
    pub held: Option<Held>,
    /// A message to send to every *other* open session.
    ///
    /// Carries only operations newly accepted, so a cycle of nodes terminates:
    /// an operation already held produces nothing to forward. It is never sent
    /// back to the peer it arrived from.
    pub forward: Option<Message>,
    /// What was refused, and why.
    pub refusals: Vec<Refusal>,
    /// Operations that entered the verified set as a result.
    pub admitted: Vec<OperationId>,
    /// The exact bytes of those operations, as they arrived.
    ///
    /// Separate from [`Self::forward`], which holds the same bytes today. They
    /// answer different questions — what must be kept, and what must be passed
    /// on — and a caller that persisted whatever it was relaying would stop
    /// persisting the moment relaying policy and admission stopped agreeing.
    ///
    /// It is the bytes rather than the ids because a store must write what was
    /// signed. Re-encoding a decoded structure is how two implementations come
    /// to disagree about what a signature covers.
    pub accepted: Vec<Vec<u8>>,
    /// The exact bytes of a snapshot newly accepted, as they arrived.
    ///
    /// Reported for the same reason and under the same rule as [`Self::accepted`]
    /// — a store must write what was signed — and separately from it because a
    /// snapshot is not an operation: it does not belong in a log, and a caller
    /// that appended it to one would have produced a log it could not replay.
    pub snapshot: Option<Vec<u8>>,
    /// The exact bytes of an attestation newly accepted, as they arrived.
    ///
    /// Kept for the same reason as the snapshot, and used for one more: an
    /// attestation is what freshness is measured from, so a caller that did not
    /// store it — with the moment it arrived — would let a restart date the
    /// roster from the restart, which is the way out of a stale roster that must
    /// not exist.
    pub attestation: Option<Vec<u8>>,
}

impl Reception {
    /// Whether anything was refused.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.refusals.is_empty()
    }
}

/// A node's half of reconciliation.
#[derive(Debug)]
pub struct Syncer {
    /// The roster. The only authority on what is true.
    roster: Roster,
    /// Which peer each pending entry is charged to.
    quota: Quota,
}

impl Syncer {
    /// Wraps a roster.
    #[must_use]
    pub fn new(roster: Roster) -> Self {
        Self { roster, quota: Quota::new() }
    }

    /// The roster, for callers that need to read derived state.
    #[must_use]
    pub const fn roster(&self) -> &Roster {
        &self.roster
    }

    /// The roster, for callers that author operations on this node.
    pub const fn roster_mut(&mut self) -> &mut Roster {
        &mut self.roster
    }

    /// How many pending entries a peer currently occupies.
    #[must_use]
    pub fn charged_to(&self, peer: &DeviceId) -> usize {
        self.quota.charged_to(peer)
    }

    /// What this node holds, as it tells a peer.
    ///
    /// Only the verified set. Pending operations are never offered and never
    /// relayed: forwarding what this node has not checked would make it an
    /// amplifier for junk, would let one peer's flood consume quota on nodes it
    /// never contacted, and would destroy attribution — a bad signature could no
    /// longer be pinned on the peer that sent it.
    #[must_use]
    pub fn offer(&self) -> Offer {
        Offer {
            ids: self
                .roster
                .dag()
                .operations()
                .iter()
                .map(roster::sign::VerifiedOperation::id)
                .collect(),
            snapshot: self.roster.snapshot().map(|held| held.body().seq),
        }
    }

    /// What to send when a session opens.
    ///
    /// Both sides send this immediately, without waiting to be asked. There is
    /// no server: a node that has just joined and the node that founded the
    /// network run the same exchange. A protocol where one side asks and the
    /// other answers has a privileged role in it, and §4.7 says there is none.
    #[must_use]
    pub fn greeting(&self) -> Message {
        Message::Offer(self.offer())
    }

    /// Handles a payload from `peer`.
    pub fn receive(&mut self, peer: DeviceId, payload: &[u8]) -> Reception {
        let message = match Message::decode(payload) {
            Ok(message) => message,
            Err(reason) => {
                return Reception {
                    refusals: vec![Refusal { peer, operation: None, reason }],
                    ..Reception::default()
                };
            }
        };

        match message {
            Message::Offer(offer) => self.answer_offer(peer, &offer),
            Message::Transfer(operations) => self.take_operations(peer, &operations),
            Message::Snapshot(bytes) => self.take_snapshot(peer, &bytes),
            Message::Attestation(bytes) => self.take_attestation(peer, &bytes),
        }
    }

    /// Admits an operation authored on this node, and says what to forward.
    ///
    /// The operation is sent whole rather than announced. Announcing would halve
    /// traffic for operations a peer already holds, at the cost of a round trip
    /// on every one it does not — and a revocation is exactly the case where the
    /// round trip is the expensive part.
    pub fn admit_local(&mut self, bytes: &[u8]) -> Result<Option<Message>> {
        let admission = self.roster.offer_bytes(bytes);
        self.settle();
        match admission {
            Admission::Accepted(_) => Ok(Some(Message::Transfer(vec![bytes.to_vec()]))),
            // Held or already known: nothing new to spread.
            Admission::Pending { .. } | Admission::AlreadyHeld(_) => Ok(None),
            Admission::Refused { reason, .. } => Err(Error::Roster(reason)),
        }
    }

    /// Answers a peer's offer with what it lacks.
    fn answer_offer(&mut self, peer: DeviceId, offer: &Offer) -> Reception {
        let mut reception = Reception::default();
        let held = offer.ids.iter().copied().collect::<BTreeSet<_>>();

        // The snapshot goes first. A node far enough behind cannot place the
        // operations that build on a foundation it does not have yet, and would
        // hold every one of them pending — spending its quota on this node to
        // learn nothing.
        if let Some(snapshot) = self.roster.snapshot() {
            let ours = snapshot.body().seq;
            let theirs = offer.snapshot.unwrap_or(0);
            if ours > theirs {
                reception.replies.push(Message::Snapshot(snapshot.to_bytes()));
            } else if ours < theirs {
                // Seen in their offer, so nothing is transferred for it. Their
                // snapshot is ahead of ours, so ours would regress theirs; a
                // well-behaved peer will send us theirs instead.
                reception.refusals.push(Refusal {
                    peer,
                    operation: None,
                    reason: Error::SnapshotWouldRegress { offered: ours, held: theirs },
                });
            }
        }

        // One pass over the verified set, splitting it against what the peer
        // offered: what it lacks is sent, and what it already has is reported.
        // The second half is the evidence a caller needs to know an operation
        // reached that peer, and it costs nothing — the peer named it itself.
        let mut missing: Vec<Vec<u8>> = Vec::new();
        let mut theirs: Vec<OperationId> = Vec::new();
        for operation in self.roster.dag().operations() {
            if held.contains(&operation.id()) {
                theirs.push(operation.id());
            } else {
                // The exact verified bytes. Re-serializing a decoded structure
                // and sending that would risk a peer computing a different id
                // for the same operation.
                missing.push(operation.to_bytes());
            }
        }

        reception.held = Some(Held { peer, ids: theirs });

        if !missing.is_empty() {
            reception.replies.push(Message::Transfer(missing));
        }
        reception
    }

    /// Takes operations a peer sent, subject to its quota.
    fn take_operations(&mut self, peer: DeviceId, operations: &[Vec<u8>]) -> Reception {
        let mut reception = Reception::default();
        let mut accepted: Vec<Vec<u8>> = Vec::new();

        for bytes in operations {
            self.settle();
            match self.admit_from(peer, bytes) {
                Ok(Some(id)) => {
                    reception.admitted.push(id);
                    accepted.push(bytes.clone());
                }
                Ok(None) => {}
                Err((operation, reason)) => {
                    reception.refusals.push(Refusal { peer, operation, reason });
                }
            }
        }

        // Admitting a parent can integrate operations that were waiting on it,
        // so the charges they held are released here rather than at the start of
        // whatever call happens next. A peer that supplies the parents its
        // operations were waiting for gets its room back immediately.
        self.settle();

        if !accepted.is_empty() {
            // Only what newly entered the verified set, and never back to the
            // peer it came from. Both are what make a cycle of nodes terminate.
            reception.forward = Some(Message::Transfer(accepted.clone()));
            reception.accepted = accepted;
        }
        reception
    }

    /// Admits one operation from a peer, charging its quota if it is held.
    ///
    /// Returns the id if it entered the verified set, `None` if it was held or
    /// already known.
    fn admit_from(
        &mut self,
        peer: DeviceId,
        bytes: &[u8],
    ) -> core::result::Result<Option<OperationId>, (Option<OperationId>, Error)> {
        // Whether this will be held is decided before the roster sees it, so a
        // peer over quota is refused at the door. The alternative — offer it and
        // deal with the consequence — would mean evicting something to make
        // room, and the entry displaced might be the revocation.
        let raw = match RawOperation::decode(bytes) {
            Ok(raw) => raw,
            Err(reason) => return Err((None, Error::Malformed(reason))),
        };
        let id = raw.id();
        let would_be_held =
            raw.core().parents.iter().any(|parent| !self.roster.dag().contains(parent));

        if would_be_held && !self.quota.has_room(&peer) {
            return Err((
                Some(id),
                Error::OverQuota { peer, limit: crate::limits::PENDING_PER_PEER },
            ));
        }
        drop(raw);

        match self.roster.offer_bytes(bytes) {
            Admission::Accepted(id) => Ok(Some(id)),
            Admission::Pending { operation, .. } => {
                self.quota.charge(peer, operation);
                Ok(None)
            }
            Admission::AlreadyHeld(_) => Ok(None),
            Admission::Refused { reason, .. } => Err((Some(id), Error::Roster(reason))),
        }
    }

    /// Takes a snapshot a peer sent.
    fn take_snapshot(&mut self, peer: DeviceId, bytes: &[u8]) -> Reception {
        let mut reception = Reception::default();

        // The sequence is read before the roster is asked, so a regression is
        // named as such rather than arriving as a generic refusal. The roster
        // refuses it too; this only makes the reason legible.
        if let Ok(raw) = RawSnapshot::decode(bytes) {
            let offered = raw.body().seq;
            if let Some(held) = self.roster.snapshot().map(|snapshot| snapshot.body().seq)
                && offered < held
            {
                reception.refusals.push(Refusal {
                    peer,
                    operation: None,
                    reason: Error::SnapshotWouldRegress { offered, held },
                });
                return reception;
            }
        }

        let admission = self.roster.offer_snapshot(bytes);
        if let Some(reason) = admission.refusal() {
            reception.refusals.push(Refusal {
                peer,
                operation: None,
                reason: Error::Roster(reason.clone()),
            });
        } else {
            // What arrived, so a caller that keeps it keeps what was signed.
            reception.snapshot = Some(bytes.to_vec());
            // A snapshot can complete operations that were waiting on it.
            self.settle();
        }
        reception
    }

    /// Takes an attestation a peer sent.
    ///
    /// **Never forwarded.** An attestation says what its author knew at a moment;
    /// a node passing on someone else's would be saying it about itself, and the
    /// receiver would date its roster from a device it never heard from. Every
    /// admin sends its own, to every session it has.
    fn take_attestation(&mut self, peer: DeviceId, bytes: &[u8]) -> Reception {
        let mut reception = Reception::default();

        let admission = self.roster.offer_attestation(bytes);
        match admission {
            AttestationAdmission::Accepted { .. } => {
                // What arrived, so a caller that keeps it keeps what was signed
                // — and can restore it with the receipt time it had, which is
                // what makes freshness outlive the process.
                reception.attestation = Some(bytes.to_vec());
            }
            // The author knew more than this node does. Not a refusal: nobody
            // misbehaved, and the answer is to catch up, which reconciliation is
            // already doing.
            AttestationAdmission::HeadsNotHeld { .. } => {}
            AttestationAdmission::Refused { reason } => {
                reception.refusals.push(Refusal {
                    peer,
                    operation: None,
                    reason: Error::Roster(reason),
                });
            }
        }
        reception
    }

    /// Releases quota charges the roster no longer holds pending.
    fn settle(&mut self) {
        let pending: BTreeSet<OperationId> = self.roster.pending_ids().into_iter().collect();
        self.quota.settle(&pending);
    }
}

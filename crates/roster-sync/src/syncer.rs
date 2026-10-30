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
use roster::roster::{Admission, AttestationAdmission, PieceAdmission, Roster};
use roster::sign::RawOperation;

use crate::error::{Error, Result};
use crate::message::{Digest, Holding, Message, Offer, StatePieces};
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
    /// A message to send to every *other* open session, and to the neighbours.
    ///
    /// Carries only what was newly accepted — operations, or an attestation newer
    /// than the one held — so a cycle of nodes terminates: what is already held
    /// produces nothing to forward. It is never sent back to the peer it arrived
    /// from.
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
    /// The exact bytes of batch pieces newly taken, as they arrived.
    ///
    /// Kept for the reason operations are: a batch's entries live in its
    /// pieces, and a node that restarted without them would hold the header
    /// and wait for pieces it once had.
    pub pieces: Vec<Vec<u8>>,
    /// The base this node now rests on, when a state transfer completed: the
    /// root and the state it commits to.
    ///
    /// Kept for the same reason a compacted node keeps its base: the log
    /// replays from it, and holds nothing beneath it.
    pub base: Option<(roster::snapshot::SignedSnapshot, roster::state::RosterState)>,
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
    /// A state being received, when this node asked for one.
    assembling: Option<Assembly>,
}

/// A state this node asked a peer for, as its pieces arrive.
#[derive(Debug)]
struct Assembly {
    /// The peer asked.
    peer: DeviceId,
    /// The root it was asked for, as it arrived.
    snapshot: Vec<u8>,
    /// The pieces so far.
    assembler: roster::transfer::StateAssembler,
}

impl Syncer {
    /// Wraps a roster.
    #[must_use]
    pub fn new(roster: Roster) -> Self {
        Self { roster, quota: Quota::new(), assembling: None }
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
    ///
    /// A batch's header waiting for its pieces is verified, and is offered: a
    /// peer needs it before any piece, and the pieces this node holds of it are
    /// said beside it.
    #[must_use]
    pub fn offer(&self) -> Offer {
        let mut ids: Vec<OperationId> = self
            .roster
            .dag()
            .operations()
            .iter()
            .map(roster::sign::VerifiedOperation::id)
            .collect();
        ids.extend(self.roster.waiting_headers().into_iter().map(|(batch, _)| batch));
        Offer {
            ids,
            snapshot: self.roster.snapshot().map(|held| held.body().generation),
            root: self.roster.snapshot().map(|held| held.body().root),
            partial: self
                .roster
                .partial_batches()
                .into_iter()
                .map(|partial| Holding::of(partial.batch, partial.pieces, &partial.held))
                .collect(),
        }
    }

    /// The digest of what this node holds, as it tells a peer first.
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::of_offer(&self.offer())
    }

    /// Whether a peer is a light member: one sent roots and answers, and never
    /// operations.
    #[must_use]
    pub fn is_light(&self, peer: &DeviceId) -> bool {
        self.roster.mode_of(peer) == Some(roster::leaf::Mode::Light)
    }

    /// `message` as `peer` is to receive it, if at all.
    ///
    /// A full member receives everything. A light member receives roots and
    /// attestations, and never an operation, a piece or an offer of them, and
    /// no digest, which would invite an offer.
    ///
    /// Nor the root this node holds, in place of the digest, as it once was:
    /// the light member already has it from the evidence this node showed as
    /// the session opened, taken there or caught up to (`transport`'s
    /// `CatchingUp`). Sent with every greeting, the same root went to every
    /// light member at every session, about an hour apart, whether anything
    /// had changed or not: at a hundred thousand light members, some 70 MB an
    /// hour from each full member serving half of them. A root a node takes
    /// later still reaches open sessions, as what it forwards.
    ///
    /// Every message a node sends on a roster channel passes here, so the
    /// rule is in one place rather than at each send.
    #[must_use]
    pub fn for_peer(&self, peer: &DeviceId, message: Message) -> Option<Message> {
        if !self.is_light(peer) {
            return Some(message);
        }
        match message {
            Message::Snapshot(_) | Message::Attestation(_) => Some(message),
            Message::Digest(_)
            | Message::Offer(_)
            | Message::Transfer(_)
            | Message::Pieces(_)
            | Message::StateRequest(_)
            | Message::State(_) => None,
        }
    }

    /// The root this node holds, as a message.
    fn root_message(&self) -> Option<Message> {
        self.roster.snapshot().map(|held| Message::Snapshot(held.to_bytes()))
    }

    /// What to send when a session opens, and on every periodic reconciliation.
    ///
    /// Both sides send this immediately, without waiting to be asked. There is
    /// no server: a node that has just joined and the node that founded the
    /// network run the same exchange. A protocol where one side asks and the
    /// other answers has a privileged role in it, and §4.7 says there is none.
    ///
    /// The digest, not the offer: where both sides hold the same operations,
    /// which is almost always, that is the whole exchange.
    #[must_use]
    pub fn greeting(&self) -> Message {
        Message::Digest(self.digest())
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

        // A light member exchanges roots. Operations from it are refused before
        // anything reads them, and its digest is answered with the root.
        if self.is_light(&peer) {
            match message {
                Message::Offer(_)
                | Message::Transfer(_)
                | Message::Pieces(_)
                | Message::StateRequest(_)
                | Message::State(_) => {
                    return Reception {
                        refusals: vec![Refusal {
                            peer,
                            operation: None,
                            reason: Error::FromLightMember { peer },
                        }],
                        ..Reception::default()
                    };
                }
                Message::Digest(_) => {
                    return Reception {
                        replies: self.root_message().into_iter().collect(),
                        ..Reception::default()
                    };
                }
                Message::Snapshot(_) | Message::Attestation(_) => {}
            }
        }

        match message {
            Message::Offer(offer) => self.answer_offer(peer, &offer),
            Message::Transfer(operations) => self.take_operations(peer, &operations),
            Message::Pieces(pieces) => self.take_pieces(peer, &pieces),
            Message::StateRequest(root) => self.answer_state_request(&root),
            Message::State(state) => self.take_state(peer, state),
            Message::Snapshot(bytes) => self.take_snapshot(peer, &bytes),
            Message::Attestation(bytes) => self.take_attestation(peer, &bytes),
            Message::Digest(digest) => self.answer_digest(peer, digest),
        }
    }

    /// Answers a peer's digest.
    ///
    /// Equal: the peer holds exactly what this node holds, and nothing is sent.
    /// That is also evidence, as an offer naming every operation would be — the
    /// peer's own digest commits to its set — so every operation held here is
    /// reported as held by the peer.
    ///
    /// Different: this node's offer, so that the peer can send what this node
    /// lacks. The peer, having seen this node's digest differ from its own, sends
    /// its offer too, and each answers the other's as before.
    fn answer_digest(&self, peer: DeviceId, digest: Digest) -> Reception {
        let mut reception = Reception::default();
        if digest == self.digest() {
            reception.held = Some(Held {
                peer,
                ids: self
                    .roster
                    .dag()
                    .operations()
                    .iter()
                    .map(roster::sign::VerifiedOperation::id)
                    .collect(),
            });
        } else {
            reception.replies.push(Message::Offer(self.offer()));
        }
        reception
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
            // A batch's header spreads with its pieces, which sync carries.
            Admission::AwaitingPieces(_) => Ok(Some(Message::Transfer(vec![bytes.to_vec()]))),
            Admission::Refused { reason, .. } => Err(Error::Roster(reason)),
        }
    }

    /// Admits batch pieces made on this node, and says what to forward.
    ///
    /// # Errors
    ///
    /// When the roster refuses a piece: its header is not held here, or it does
    /// not prove against it.
    pub fn admit_local_pieces(&mut self, pieces: &[Vec<u8>]) -> Result<Vec<Message>> {
        let mut taken = Vec::new();
        for piece in pieces {
            match self.roster.offer_piece(piece) {
                PieceAdmission::Taken { .. } => taken.push(piece.clone()),
                PieceAdmission::AlreadyHeld { .. } => {}
                PieceAdmission::Refused { reason } => return Err(Error::Roster(reason)),
            }
        }
        self.settle();
        Ok(in_messages(taken))
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
            // The heavier of two roots: the higher generation, then the greater
            // root hash, as the roster keeps. Theirs heavier: a well-behaved peer
            // sends us theirs instead.
            let ours = (snapshot.body().generation, Some(snapshot.body().root));
            let theirs = (offer.snapshot.unwrap_or(0), offer.root);
            if offer.snapshot.is_none() || ours > theirs {
                reception.replies.push(Message::Snapshot(snapshot.to_bytes()));
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
        // Headers waiting for their pieces go too: whoever passes on a piece
        // passes on what it is checked against first.
        for (batch, bytes) in self.roster.waiting_headers() {
            if !held.contains(&batch) {
                missing.push(bytes);
            }
        }

        reception.held = Some(Held { peer, ids: theirs });

        if !missing.is_empty() {
            reception.replies.push(Message::Transfer(missing));
        }
        // Pieces after the operations, so the headers they belong to arrive
        // first. Of each batch held here, whole or in part: none where the
        // peer holds it whole, those its bitmap lacks where it holds it in
        // part, and every one where it lacks the header, which went above.
        let batches = self
            .roster
            .whole_batches()
            .into_iter()
            .chain(self.roster.partial_batches().into_iter().map(|partial| partial.batch));
        let mut pieces: Vec<Vec<u8>> = Vec::new();
        for batch in batches {
            let holding = offer.holding(&batch);
            if holding.is_none() && held.contains(&batch) {
                continue;
            }
            for (index, piece) in self.roster.pieces_held(&batch) {
                if !holding.is_some_and(|holding| holding.has(index)) {
                    pieces.push(piece);
                }
            }
        }
        reception.replies.extend(in_messages(pieces));
        reception
    }

    /// Takes batch pieces a peer sent.
    ///
    /// Each piece taken is passed on at once, before its batch is whole, and
    /// reported to be kept. One already held is neither, which is what makes a
    /// cycle of nodes terminate.
    fn take_pieces(&mut self, peer: DeviceId, pieces: &[Vec<u8>]) -> Reception {
        let mut reception = Reception::default();
        let mut taken: Vec<Vec<u8>> = Vec::new();
        for piece in pieces {
            match self.roster.offer_piece(piece) {
                PieceAdmission::Taken { batch, complete } => {
                    taken.push(piece.clone());
                    if complete {
                        reception.admitted.push(batch);
                    }
                }
                PieceAdmission::AlreadyHeld { .. } => {}
                PieceAdmission::Refused { reason } => {
                    reception.refusals.push(Refusal {
                        peer,
                        operation: None,
                        reason: Error::Roster(reason),
                    });
                }
            }
        }
        // A batch completing can integrate operations that were waiting on it.
        self.settle();
        if !taken.is_empty() {
            reception.forward = Some(Message::Pieces(taken.clone()));
            reception.pieces = taken;
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
    ///
    /// A batch's header waiting for its pieces counts as entering: it is
    /// verified, it is passed on, and it is kept, though it takes effect only
    /// once the pieces are in.
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
        let already_waiting = self.roster.waiting_headers().iter().any(|(batch, _)| *batch == id);

        match self.roster.offer_bytes(bytes) {
            Admission::Accepted(id) => Ok(Some(id)),
            Admission::Pending { operation, .. } => {
                self.quota.charge(peer, operation);
                Ok(None)
            }
            Admission::AwaitingPieces(batch) if !already_waiting => Ok(Some(batch)),
            Admission::AlreadyHeld(_) | Admission::AwaitingPieces(_) => Ok(None),
            Admission::Refused { reason, .. } => Err((Some(id), Error::Roster(reason))),
        }
    }

    /// Takes a snapshot a peer sent.
    fn take_snapshot(&mut self, peer: DeviceId, bytes: &[u8]) -> Reception {
        let mut reception = Reception::default();

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
            // A root newly adopted reaches every other session at once, light
            // members' above all: it is all they are given. One already held
            // or lighter goes nowhere, which is what ends a cycle.
            if matches!(
                admission,
                roster::roster::SnapshotAdmission::Accepted { .. }
                    | roster::roster::SnapshotAdmission::AdoptedUnverified { .. }
            ) {
                reception.forward = Some(Message::Snapshot(bytes.to_vec()));
            }
            // A full member holding nothing, given a root it cannot check, asks
            // for the state behind it: the operations beneath it are gone from
            // every peer that compacted, so this is the only way in.
            if matches!(admission, roster::roster::SnapshotAdmission::AdoptedUnverified { .. })
                && self.roster.dag().is_empty()
                && self.assembling.is_none()
                && let (Some(held), Some(network)) =
                    (self.roster.snapshot(), self.roster.snapshot().map(|held| held.body().network))
            {
                let root = held.body().root;
                self.assembling = Some(Assembly {
                    peer,
                    snapshot: bytes.to_vec(),
                    assembler: roster::transfer::StateAssembler::new(
                        network,
                        root,
                        crate::limits::MAX_STATE_DEVICES,
                    ),
                });
                reception.replies.push(Message::StateRequest(root));
            }
        }
        reception
    }

    /// Takes an attestation a peer sent.
    ///
    /// **Forwarded when accepted as newer, and only then.** An attestation says
    /// what its author knew and when it signed it, so a node passing one on is
    /// carrying the admin's word, dated, rather than saying anything itself: the
    /// receiver ages it by the time since it was signed, however late it arrives.
    /// That is what spares an admin on a phone meeting every member in person.
    ///
    /// One already held, one this roster refused, or one naming heads this node
    /// does not hold is not forwarded: the first would echo round a cycle, and
    /// the others are not this node's to vouch for having accepted.
    fn take_attestation(&mut self, peer: DeviceId, bytes: &[u8]) -> Reception {
        let mut reception = Reception::default();

        let admission = self.roster.offer_attestation(bytes);
        match admission {
            AttestationAdmission::Accepted { .. } => {
                // What arrived, so a caller that keeps it keeps what was signed
                // — and can restore it with the receipt time it had, which is
                // what makes freshness outlive the process.
                reception.attestation = Some(bytes.to_vec());
                reception.forward = Some(Message::Attestation(bytes.to_vec()));
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

    /// Answers a request for the state behind a root, where this node holds it.
    ///
    /// The heads the root covers go first, as operations: the asker rests on
    /// them with the state, and keeps them where it keeps operations.
    fn answer_state_request(&self, root: &[u8; 32]) -> Reception {
        let mut reception = Reception::default();
        let Some((snapshot, state)) = self.roster.state_for_root(root) else {
            return reception;
        };
        let heads: Vec<Vec<u8>> = snapshot
            .body()
            .heads
            .iter()
            .filter_map(|head| {
                let index = self.roster.dag().position(head)?;
                self.roster.dag().operation(index).map(roster::sign::VerifiedOperation::to_bytes)
            })
            .collect();
        if !heads.is_empty() {
            reception.replies.push(Message::Transfer(heads));
        }
        let pieces = roster::transfer::pieces_of(&state);
        let chunks: Vec<&[Vec<u8>]> =
            pieces.chunks(crate::limits::MAX_STATE_PIECES_PER_MESSAGE).collect();
        let count = chunks.len();
        for (index, chunk) in chunks.into_iter().enumerate() {
            reception.replies.push(Message::State(StatePieces {
                root: *root,
                pieces: chunk.to_vec(),
                last: index.saturating_add(1) == count,
            }));
        }
        reception
    }

    /// Takes pieces of a state this node asked for, and rests on it once whole.
    fn take_state(&mut self, peer: DeviceId, state: StatePieces) -> Reception {
        let mut reception = Reception::default();
        let Some(assembly) = self.assembling.as_mut() else { return reception };
        if assembly.peer != peer || assembly.assembler_root() != state.root {
            return reception;
        }
        for piece in &state.pieces {
            if let Err(reason) = assembly.assembler.add(piece) {
                self.assembling = None;
                reception.refusals.push(Refusal {
                    peer,
                    operation: None,
                    reason: Error::Roster(reason),
                });
                return reception;
            }
        }
        if !state.last {
            return reception;
        }
        let Some(done) = self.assembling.take() else { return reception };
        let whole = match done.assembler.finish() {
            Ok(whole) => whole,
            Err(reason) => {
                reception.refusals.push(Refusal {
                    peer,
                    operation: None,
                    reason: Error::Roster(reason),
                });
                return reception;
            }
        };
        // The heads the root covers came ahead of the state, and wait pending.
        let heads: Vec<Vec<u8>> = roster::snapshot::RawSnapshot::decode(&done.snapshot)
            .map(|raw| {
                raw.body().heads.iter().filter_map(|head| self.roster.pending_bytes(head)).collect()
            })
            .unwrap_or_default();
        match self.roster.rest_on(&done.snapshot, whole, &heads) {
            Ok(()) => {
                self.settle();
                reception.accepted = heads;
                reception.base =
                    match (self.roster.dag().base_snapshot(), self.roster.dag().base_state()) {
                        (Some(snapshot), Some(state)) => Some((snapshot.clone(), state.clone())),
                        _ => None,
                    };
            }
            Err(reason) => {
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

/// Pieces in as many messages as they need, each within one payload.
fn in_messages(pieces: Vec<Vec<u8>>) -> Vec<Message> {
    pieces
        .chunks(crate::limits::MAX_PIECES_PER_MESSAGE)
        .map(|chunk| Message::Pieces(chunk.to_vec()))
        .collect()
}

impl Assembly {
    /// The root this assembly must make.
    fn assembler_root(&self) -> [u8; 32] {
        roster::snapshot::RawSnapshot::decode(&self.snapshot).map_or([0; 32], |raw| raw.body().root)
    }
}

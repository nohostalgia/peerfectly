//! What crosses a session, and how it is encoded.
//!
//! Six messages, each a canonical CBOR map behind a small envelope: a
//! **digest** of what the sender holds, an **offer** naming it, a **transfer**
//! carrying operations, **pieces** of batches, a **snapshot** and an
//! **attestation**.
//!
//! # These messages are not signed, deliberately
//!
//! The session is already authenticated and bound to a device: the peer proved
//! possession of a transport key the roster names. A signature on the envelope
//! would prove that same thing a second time, and a second signing context is a
//! second place to get domain separation wrong.
//!
//! What is *inside* is signed. Operations and snapshots carry their own
//! signatures and are verified by the roster on receipt, over the exact bytes
//! that arrived. Nothing here is trusted because of where it came from.
//!
//! # Encoding
//!
//! Roster's canonical CBOR encoder, not a second one. Definite lengths, minimal
//! integer widths, length-first map key ordering, no unknown or duplicate or
//! missing keys, no trailing bytes — and rejection rather than repair, so two
//! byte strings that differ never decode to the same message.
//!
//! Growing a private encoder here would mean two sets of canonicity rules in one
//! workspace, drifting apart at exactly the points that are hard to test. The
//! length-first ordering rule alone has already been got wrong once in this
//! codebase, caught only because roster asserts its schemas are canonical.

use roster::cbor::{Reader, Writer};
use roster::id::OperationId;
use roster::limits as roster_limits;

use crate::error::{Error, Result};
use crate::limits;

/// The envelope every message is wrapped in.
///
/// Both keys are four bytes long, so length-first ordering falls through to a
/// byte comparison: `body` precedes `kind`.
const ENVELOPE: &[&str] = &["body", "kind"];

/// An offer's fields. Lengths 3, 4, 7 — strictly increasing, so canonical.
const OFFER: &[&str] = &["ids", "snap", "snapseq"];

/// The fields of an offer that also names the root it holds, or batches it
/// holds in part. `root` and `snap` are four bytes long, and `r` sorts first;
/// `partial` and `snapseq` are seven, and `p` sorts first.
const EXTENDED_OFFER: &[&str] = &["ids", "root", "snap", "partial", "snapseq"];

/// One batch held in part: the bitmap of the pieces held, the batch, and how
/// many pieces it has.
const HOLDING: &[&str] = &["held", "batch", "pieces"];

/// A pieces message's single field.
const PIECES: &[&str] = &["pieces"];

/// A state request's single field.
const STATE_REQUEST: &[&str] = &["root"];

/// A state message's fields: whether it is the last, the root, the pieces.
const STATE: &[&str] = &["last", "root", "pieces"];

/// A transfer's single field.
const TRANSFER: &[&str] = &["ops"];

/// A snapshot message's single field.
const SNAPSHOT: &[&str] = &["snap"];

/// An attestation message's single field.
const ATTESTATION: &[&str] = &["att"];

/// A digest message's single field.
const DIGEST: &[&str] = &["hash"];

/// Which message an envelope carries.
mod kind {
    /// An offer of what the sender holds.
    pub const OFFER: u64 = 1;
    /// Operations the peer's offer did not name.
    pub const TRANSFER: u64 = 2;
    /// A signed snapshot.
    pub const SNAPSHOT: u64 = 3;
    /// A signed attestation.
    pub const ATTESTATION: u64 = 4;
    /// A digest of what the sender holds.
    pub const DIGEST: u64 = 5;
    /// Pieces of batches.
    pub const PIECES: u64 = 6;
    /// An offer naming the root held, or batches held in part.
    ///
    /// A kind of its own rather than fields every offer carries: an offer with
    /// neither encodes to the bytes it always did.
    pub const EXTENDED_OFFER: u64 = 7;
    /// A request for the state behind a root.
    pub const STATE_REQUEST: u64 = 8;
    /// Pieces of the state behind a root.
    pub const STATE: u64 = 9;
}

/// A message crossing a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// What the sender holds: every operation id, and the snapshot sequence it
    /// has, if any.
    Offer(Offer),
    /// Operations the peer's offer did not name, as the exact verified bytes.
    Transfer(Vec<Vec<u8>>),
    /// Pieces of batches the peer's offer showed it lacks, as the exact bytes
    /// their author cut.
    ///
    /// Each proves on its own against its batch's header, so a node passes one
    /// on as soon as it has checked it, before the batch is whole.
    Pieces(Vec<Vec<u8>>),
    /// A request for the state behind a root, from a full member that holds
    /// nothing yet and was given the root.
    StateRequest([u8; 32]),
    /// Pieces of the state behind a root, in answer to a request.
    ///
    /// Nothing in them is believed until the last is in and the leaves make
    /// the root: a sender that lies costs the receiver the download, never a
    /// wrong state.
    State(StatePieces),
    /// A signed snapshot, as the exact bytes.
    Snapshot(Vec<u8>),
    /// A signed attestation, as the exact bytes.
    ///
    /// Produced by an admin's node when its heads change and otherwise on a
    /// period, and relayed by any node whose roster accepted it as newer: it
    /// carries the time its author signed it, so whoever delivers it, it reads as
    /// old as it is.
    Attestation(Vec<u8>),
    /// A digest of what the sender holds, sent first.
    ///
    /// Two nodes that agree — which is almost every time — learn it from 32 bytes
    /// each and send nothing else. Only where the digests differ does each send
    /// its [`Offer`], and the exchange carries on exactly as it did before there
    /// was a digest: one payload each way, no resumption.
    Digest(Digest),
}

/// A hash of the set of operations a node holds verified, and of the snapshot
/// it holds.
///
/// Recomputed from the set rather than updated as operations arrive. A hash
/// kept incrementally — a sum or exclusive-or of per-operation hashes — is
/// linear, and a set of operations chosen to cancel out could make two
/// different sets agree: two nodes, one of them missing a revocation, would each
/// believe the other held everything. Hashing the sorted ids costs a few dozen
/// microseconds for the largest roster there can be, once per contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// The digest of a set of operation ids and a snapshot sequence.
    ///
    /// The order the ids are given in does not matter: they are sorted first, so
    /// two nodes that admitted the same operations in different orders agree.
    #[must_use]
    pub fn of(ids: &[OperationId], snapshot: Option<u64>) -> Self {
        Self::with_partial(ids, snapshot, &[])
    }

    /// The digest of what an offer says, batches held in part included.
    ///
    /// Two nodes holding the same operations but different pieces of a batch
    /// must not agree, or neither would ever send the other what it lacks. With
    /// no batch in part, the digest is the one [`Self::of`] always gave.
    #[must_use]
    pub fn with_partial(ids: &[OperationId], snapshot: Option<u64>, partial: &[Holding]) -> Self {
        Self::of_offer(&Offer {
            ids: ids.to_vec(),
            snapshot,
            root: None,
            partial: partial.to_vec(),
        })
    }

    /// The digest of everything an offer says.
    ///
    /// The root included: two nodes holding sibling roots of one generation,
    /// over the same operations, must not agree, or the heavier would never
    /// reach the other.
    #[must_use]
    pub fn of_offer(offer: &Offer) -> Self {
        let (ids, snapshot, partial) = (&offer.ids, offer.snapshot, &offer.partial);
        let mut sorted: Vec<&OperationId> = ids.iter().collect();
        sorted.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        sorted.dedup();
        let mut hasher = blake3::Hasher::new_derive_key("peerfectly roster digest v1");
        // The snapshot first, flagged, so "no snapshot" and "snapshot 0" differ.
        match snapshot {
            Some(seq) => {
                hasher.update(&[1]);
                hasher.update(&seq.to_be_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
        hasher.update(&(sorted.len() as u64).to_be_bytes());
        for id in sorted {
            hasher.update(id.as_bytes());
        }
        if !partial.is_empty() {
            let mut holdings: Vec<&Holding> = partial.iter().collect();
            holdings.sort_by_key(|holding| holding.batch);
            hasher.update(&(holdings.len() as u64).to_be_bytes());
            for holding in holdings {
                hasher.update(holding.batch.as_bytes());
                hasher.update(&holding.pieces.to_be_bytes());
                hasher.update(&holding.held);
            }
        }
        if let Some(root) = &offer.root {
            hasher.update(b"root");
            hasher.update(root);
        }
        Self(*hasher.finalize().as_bytes())
    }
}

/// What a node holds, as it tells a peer.
///
/// The full id set rather than heads plus a walk-back. A roster holds at most
/// `MAX_OPERATIONS`, so the largest possible offer fits in one payload — which
/// means reconciliation needs no resumption protocol, and a resumption protocol
/// is somewhere to stall. A stalled reconciliation is a revocation that did not
/// arrive.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Offer {
    /// Every operation this node holds verified. Pending ones are absent: a node
    /// offers only what it has checked.
    pub ids: Vec<OperationId>,
    /// The sequence of the snapshot this node holds, if it holds one.
    ///
    /// Carried so the compacted case is a single round trip like every other,
    /// and so a regression is visible before any snapshot bytes are sent. It is
    /// not evidence of anything: the snapshot itself is signed and verified on
    /// receipt, and a lie here costs the liar an exchange.
    pub snapshot: Option<u64>,
    /// The root this node holds, if it holds one.
    ///
    /// With the generation, what decides which of two roots is heavier, so
    /// that siblings of one generation still reach each other.
    pub root: Option<[u8; 32]>,
    /// The batches this node holds the header of and only some pieces.
    ///
    /// A batch named in `ids` and not here is held whole. One named here is
    /// sent the pieces its bitmap lacks; one named nowhere, all of them.
    pub partial: Vec<Holding>,
}

impl Offer {
    /// Whether this offer names an operation.
    #[must_use]
    pub fn names(&self, id: &OperationId) -> bool {
        self.ids.contains(id)
    }

    /// Whether this offer says only what offers always said: no root and no
    /// batch in part.
    #[must_use]
    pub fn is_plain(&self) -> bool {
        self.root.is_none() && self.partial.is_empty()
    }

    /// What this offer says of a batch held in part, if it is.
    #[must_use]
    pub fn holding(&self, batch: &OperationId) -> Option<&Holding> {
        self.partial.iter().find(|holding| holding.batch == *batch)
    }
}

/// Some of the pieces of the state behind a root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePieces {
    /// The root they make, with the rest.
    pub root: [u8; 32],
    /// The pieces, each at most a state piece's size.
    pub pieces: Vec<Vec<u8>>,
    /// Whether these are the last.
    pub last: bool,
}

/// A batch a node holds in part: which of its pieces it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holding {
    /// The batch.
    pub batch: OperationId,
    /// How many pieces it has, as its header says.
    pub pieces: u64,
    /// One bit per piece, the lowest bit of the first byte for piece 0: set
    /// where the piece is held. Exactly as many bytes as the pieces need, with
    /// the bits past the last piece clear, so a holding has one spelling.
    pub held: Vec<u8>,
}

impl Holding {
    /// The holding of the pieces at `indices`, of a batch of `pieces`.
    #[must_use]
    pub fn of(batch: OperationId, pieces: u64, indices: &[u64]) -> Self {
        let mut held = vec![0_u8; bitmap_len(pieces)];
        for index in indices {
            if *index < pieces
                && let Some(byte) = held.get_mut(usize::try_from(index / 8).unwrap_or(usize::MAX))
            {
                *byte |= 1 << (index % 8);
            }
        }
        Self { batch, pieces, held }
    }

    /// Whether piece `index` is held.
    #[must_use]
    pub fn has(&self, index: u64) -> bool {
        usize::try_from(index / 8)
            .ok()
            .and_then(|at| self.held.get(at))
            .is_some_and(|byte| byte & (1 << (index % 8)) != 0)
    }
}

/// How many bytes a bitmap of `pieces` takes.
fn bitmap_len(pieces: u64) -> usize {
    usize::try_from(pieces.div_ceil(8)).unwrap_or(usize::MAX)
}

impl Message {
    /// Encodes a message.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (kind, body) = match self {
            Self::Offer(offer) if offer.is_plain() => (kind::OFFER, encode_offer(offer)),
            Self::Offer(offer) => (kind::EXTENDED_OFFER, encode_offer(offer)),
            Self::Transfer(operations) => (kind::TRANSFER, encode_transfer(operations)),
            Self::Pieces(pieces) => (kind::PIECES, encode_pieces(pieces)),
            Self::StateRequest(root) => (kind::STATE_REQUEST, encode_state_request(root)),
            Self::State(state) => (kind::STATE, encode_state(state)),
            Self::Snapshot(bytes) => (kind::SNAPSHOT, encode_snapshot(bytes)),
            Self::Attestation(bytes) => (kind::ATTESTATION, encode_attestation(bytes)),
            Self::Digest(digest) => (kind::DIGEST, encode_digest(digest)),
        };
        let mut writer = Writer::new();
        writer.map(2);
        writer.key("body").bytes(&body);
        writer.key("kind").u64(kind);
        writer.finish()
    }

    /// Decodes a message, refusing anything non-canonical rather than repairing
    /// it.
    ///
    /// `input` is the payload as received. A declared count is checked against
    /// the bytes that could possibly back it before any of them are read, and
    /// nothing is allocated to a declared size — the two halves of refusing the
    /// "ten gigabyte array".
    pub fn decode(input: &[u8]) -> Result<Self> {
        let available = input.len();
        let mut reader = Reader::new(input);
        let mut envelope = reader.map(ENVELOPE).map_err(Error::Malformed)?;
        let body = envelope
            .key("body")
            .and_then(|value| value.bytes(roster_limits::MAX_OPERATION_SIZE * 64, "body"))
            .map_err(Error::Malformed)?
            .to_vec();
        let kind =
            envelope.key("kind").and_then(roster::cbor::Reader::u64).map_err(Error::Malformed)?;
        envelope.finish().map_err(Error::Malformed)?;
        reader.finish().map_err(Error::Malformed)?;

        match kind {
            kind::OFFER => decode_offer(&body, available, false).map(Self::Offer),
            kind::EXTENDED_OFFER => decode_offer(&body, available, true).map(Self::Offer),
            kind::TRANSFER => decode_transfer(&body, available).map(Self::Transfer),
            kind::PIECES => decode_pieces(&body, available).map(Self::Pieces),
            kind::STATE_REQUEST => decode_state_request(&body).map(Self::StateRequest),
            kind::STATE => decode_state(&body, available).map(Self::State),
            kind::SNAPSHOT => decode_snapshot(&body).map(Self::Snapshot),
            kind::ATTESTATION => decode_attestation(&body).map(Self::Attestation),
            kind::DIGEST => decode_digest(&body).map(Self::Digest),
            // An unknown kind is refused, never skipped. The message we cannot
            // parse might be the one carrying a revocation.
            _ => Err(Error::Malformed(roster::Error::InvalidValue("message kind"))),
        }
    }
}

/// Encodes an offer.
fn encode_offer(offer: &Offer) -> Vec<u8> {
    let mut writer = Writer::new();
    let extended = !offer.is_plain();
    writer.map(if extended { 5 } else { 3 });
    writer.key("ids");
    writer.array(offer.ids.len() as u64);
    for id in &offer.ids {
        writer.bytes(id.as_bytes());
    }
    if extended {
        writer.key("root").bytes(offer.root.as_ref().map_or(&[][..], |root| &root[..]));
    }
    writer.key("snap").bool(offer.snapshot.is_some());
    if extended {
        let mut holdings: Vec<&Holding> = offer.partial.iter().collect();
        holdings.sort_by_key(|holding| holding.batch);
        writer.key("partial").array(holdings.len() as u64);
        for holding in holdings {
            writer.map(3);
            writer.key("held").bytes(&holding.held);
            writer.key("batch").bytes(holding.batch.as_bytes());
            writer.key("pieces").u64(holding.pieces);
        }
    }
    writer.key("snapseq").u64(offer.snapshot.unwrap_or(0));
    writer.finish()
}

/// Reads the batches an offer holds in part.
fn decode_partial(value: &mut Reader<'_>) -> Result<Vec<Holding>> {
    let count = value
        .array(limits::MAX_PARTIAL_BATCHES, "batches held in part")
        .map_err(Error::Malformed)?;
    let mut holdings: Vec<Holding> = Vec::new();
    for _ in 0..count {
        let mut map = value.map(HOLDING).map_err(Error::Malformed)?;
        let held = map
            .key("held")
            .and_then(|field| field.bytes(bitmap_len(roster_limits::MAX_BATCH_ENTRIES), "held"))
            .map_err(Error::Malformed)?
            .to_vec();
        let raw =
            map.key("batch").and_then(|field| field.fixed_bytes(32)).map_err(Error::Malformed)?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(raw);
        let pieces =
            map.key("pieces").and_then(roster::cbor::Reader::u64).map_err(Error::Malformed)?;
        map.finish().map_err(Error::Malformed)?;
        let holding = Holding { batch: OperationId::from_bytes(bytes), pieces, held };
        // One spelling: as many bytes as the pieces need, nothing set past the
        // last, and batches in order.
        let canonical = Holding::of(
            holding.batch,
            pieces,
            &(0..pieces.min(roster_limits::MAX_BATCH_ENTRIES))
                .filter(|index| holding.has(*index))
                .collect::<Vec<_>>(),
        );
        if pieces == 0 || pieces > roster_limits::MAX_BATCH_ENTRIES || canonical != holding {
            return Err(Error::Malformed(roster::Error::NonCanonical));
        }
        if holdings.last().is_some_and(|last| last.batch >= holding.batch) {
            return Err(Error::Malformed(roster::Error::NonCanonical));
        }
        holdings.push(holding);
    }
    Ok(holdings)
}

/// Decodes an offer, of the plain kind or the extended one.
fn decode_offer(body: &[u8], available: usize, extended: bool) -> Result<Offer> {
    let mut reader = Reader::new(body);
    let mut map =
        reader.map(if extended { EXTENDED_OFFER } else { OFFER }).map_err(Error::Malformed)?;

    let ids = {
        let value = map.key("ids").map_err(Error::Malformed)?;
        let declared = value.array(limits::MAX_OFFERED_IDS, "offered ids").map_err(|reason| {
            match reason {
                // A count beyond what a roster may hold describes a roster that
                // cannot exist. Refused on the declared count alone.
                roster::Error::LimitExceeded(_) => {
                    Error::OfferTooLarge { declared: 0, limit: limits::MAX_OFFERED_IDS }
                }
                other => Error::Malformed(other),
            }
        })?;

        // Every id costs at least one byte on the wire, so a count exceeding the
        // whole payload cannot be honest. Checked before reading any of them,
        // and no capacity is reserved for the declared count either way.
        if declared > available {
            return Err(Error::CountExceedsPayload { declared, available });
        }

        let mut ids = Vec::new();
        for _ in 0..declared {
            let raw = value.fixed_bytes(32).map_err(Error::Malformed)?;
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(raw);
            ids.push(OperationId::from_bytes(bytes));
        }
        ids
    };

    let root = if extended {
        match map.key("root").and_then(|field| field.bytes(32, "root")).map_err(Error::Malformed)? {
            [] => None,
            bytes => Some(
                <[u8; 32]>::try_from(bytes)
                    .map_err(|_| Error::Malformed(roster::Error::IdentifierLength))?,
            ),
        }
    } else {
        None
    };
    let held = map.key("snap").and_then(roster::cbor::Reader::bool).map_err(Error::Malformed)?;
    let holdings = if extended {
        decode_partial(map.key("partial").map_err(Error::Malformed)?)?
    } else {
        Vec::new()
    };
    // The plain kind is the spelling of an offer with neither; a root without
    // a snapshot held is not an offer at all.
    if extended && root.is_none() && holdings.is_empty() {
        return Err(Error::Malformed(roster::Error::NonCanonical));
    }
    if root.is_some() && !held {
        return Err(Error::Malformed(roster::Error::InvalidValue("a root without a snapshot")));
    }
    let sequence =
        map.key("snapseq").and_then(roster::cbor::Reader::u64).map_err(Error::Malformed)?;
    map.finish().map_err(Error::Malformed)?;
    reader.finish().map_err(Error::Malformed)?;

    // Two encodings must never mean the same thing. A sequence alongside "no
    // snapshot held" is a second spelling of the same offer.
    if !held && sequence != 0 {
        return Err(Error::Malformed(roster::Error::InvalidValue(
            "snapshot sequence without a snapshot",
        )));
    }

    Ok(Offer { ids, snapshot: held.then_some(sequence), root, partial: holdings })
}

/// Encodes a digest.
fn encode_digest(digest: &Digest) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.map(1);
    writer.key("hash").bytes(&digest.0);
    writer.finish()
}

/// Decodes a digest.
fn decode_digest(body: &[u8]) -> Result<Digest> {
    let mut reader = Reader::new(body);
    let mut map = reader.map(DIGEST).map_err(Error::Malformed)?;
    let raw = map.key("hash").and_then(|value| value.fixed_bytes(32)).map_err(Error::Malformed)?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(raw);
    map.finish().map_err(Error::Malformed)?;
    reader.finish().map_err(Error::Malformed)?;
    Ok(Digest(hash))
}

/// Encodes a transfer.
fn encode_transfer(operations: &[Vec<u8>]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.map(1);
    writer.key("ops");
    writer.array(operations.len() as u64);
    for operation in operations {
        writer.bytes(operation);
    }
    writer.finish()
}

/// Decodes a transfer.
fn decode_transfer(body: &[u8], available: usize) -> Result<Vec<Vec<u8>>> {
    let mut reader = Reader::new(body);
    let mut map = reader.map(TRANSFER).map_err(Error::Malformed)?;
    let operations = {
        let value = map.key("ops").map_err(Error::Malformed)?;
        let declared = value
            .array(limits::MAX_TRANSFERRED, "transferred operations")
            .map_err(Error::Malformed)?;

        if declared > available {
            return Err(Error::CountExceedsPayload { declared, available });
        }

        let mut operations = Vec::new();
        for _ in 0..declared {
            let bytes = value
                .bytes(roster_limits::MAX_OPERATION_SIZE, "operation")
                .map_err(Error::Malformed)?;
            operations.push(bytes.to_vec());
        }
        operations
    };
    map.finish().map_err(Error::Malformed)?;
    reader.finish().map_err(Error::Malformed)?;
    Ok(operations)
}

/// Encodes a pieces message.
fn encode_pieces(pieces: &[Vec<u8>]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.map(1);
    writer.key("pieces");
    writer.array(pieces.len() as u64);
    for piece in pieces {
        writer.bytes(piece);
    }
    writer.finish()
}

/// Decodes a pieces message.
fn decode_pieces(body: &[u8], available: usize) -> Result<Vec<Vec<u8>>> {
    let mut reader = Reader::new(body);
    let mut map = reader.map(PIECES).map_err(Error::Malformed)?;
    let pieces = {
        let value = map.key("pieces").map_err(Error::Malformed)?;
        let declared = value
            .array(limits::MAX_PIECES_PER_MESSAGE, "pieces in a message")
            .map_err(Error::Malformed)?;
        if declared > available {
            return Err(Error::CountExceedsPayload { declared, available });
        }
        let mut pieces = Vec::new();
        for _ in 0..declared {
            let bytes = value
                .bytes(roster_limits::MAX_OPERATION_SIZE, "batch piece")
                .map_err(Error::Malformed)?;
            pieces.push(bytes.to_vec());
        }
        pieces
    };
    map.finish().map_err(Error::Malformed)?;
    reader.finish().map_err(Error::Malformed)?;
    Ok(pieces)
}

/// Encodes a state request.
fn encode_state_request(root: &[u8; 32]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.map(1);
    writer.key("root").bytes(root);
    writer.finish()
}

/// Decodes a state request.
fn decode_state_request(body: &[u8]) -> Result<[u8; 32]> {
    let mut reader = Reader::new(body);
    let mut map = reader.map(STATE_REQUEST).map_err(Error::Malformed)?;
    let root = fixed_32(map.key("root").map_err(Error::Malformed)?)?;
    map.finish().map_err(Error::Malformed)?;
    reader.finish().map_err(Error::Malformed)?;
    Ok(root)
}

/// Encodes a state message.
fn encode_state(state: &StatePieces) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.map(3);
    writer.key("last").bool(state.last);
    writer.key("root").bytes(&state.root);
    writer.key("pieces").array(state.pieces.len() as u64);
    for piece in &state.pieces {
        writer.bytes(piece);
    }
    writer.finish()
}

/// Decodes a state message.
fn decode_state(body: &[u8], available: usize) -> Result<StatePieces> {
    let mut reader = Reader::new(body);
    let mut map = reader.map(STATE).map_err(Error::Malformed)?;
    let last = map.key("last").and_then(roster::cbor::Reader::bool).map_err(Error::Malformed)?;
    let root = fixed_32(map.key("root").map_err(Error::Malformed)?)?;
    let pieces = {
        let value = map.key("pieces").map_err(Error::Malformed)?;
        let declared = value
            .array(limits::MAX_STATE_PIECES_PER_MESSAGE, "state pieces in a message")
            .map_err(Error::Malformed)?;
        if declared > available {
            return Err(Error::CountExceedsPayload { declared, available });
        }
        let mut pieces = Vec::new();
        for _ in 0..declared {
            let bytes = value
                .bytes(roster_limits::MAX_STATE_PIECE_SIZE, "state piece")
                .map_err(Error::Malformed)?;
            pieces.push(bytes.to_vec());
        }
        pieces
    };
    map.finish().map_err(Error::Malformed)?;
    reader.finish().map_err(Error::Malformed)?;
    Ok(StatePieces { root, pieces, last })
}

/// Reads a 32-byte string.
fn fixed_32(value: &mut Reader<'_>) -> Result<[u8; 32]> {
    let raw = value.fixed_bytes(32).map_err(Error::Malformed)?;
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(raw);
    Ok(bytes)
}

/// Encodes a snapshot message.
fn encode_snapshot(bytes: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.map(1);
    writer.key("snap").bytes(bytes);
    writer.finish()
}

/// Encodes an attestation message.
fn encode_attestation(bytes: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.map(1);
    writer.key("att").bytes(bytes);
    writer.finish()
}

/// Decodes an attestation message.
///
/// Bounded by the attestation's own limit and not the snapshot's, which is two
/// orders larger: an attestation carries heads and no state, so anything near a
/// snapshot's size is not one.
fn decode_attestation(body: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Reader::new(body);
    let mut map = reader.map(ATTESTATION).map_err(Error::Malformed)?;
    let bytes = map
        .key("att")
        .and_then(|value| value.bytes(roster_limits::MAX_ATTESTATION_SIZE, "attestation"))
        .map_err(Error::Malformed)?
        .to_vec();
    map.finish().map_err(Error::Malformed)?;
    reader.finish().map_err(Error::Malformed)?;
    Ok(bytes)
}

/// Decodes a snapshot message.
fn decode_snapshot(body: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Reader::new(body);
    let mut map = reader.map(SNAPSHOT).map_err(Error::Malformed)?;
    let bytes = map
        .key("snap")
        .and_then(|value| value.bytes(roster_limits::MAX_SNAPSHOT_SIZE, "snapshot"))
        .map_err(Error::Malformed)?
        .to_vec();
    map.finish().map_err(Error::Malformed)?;
    reader.finish().map_err(Error::Malformed)?;
    Ok(bytes)
}

/// The largest an offer can legitimately be on the wire.
///
/// Every id is a 32-byte string: one header byte plus 32. The array header and
/// the envelope add a fixed handful. Stated as a function so the test that
/// compares it with the transport's payload bound cannot drift from the
/// encoder.
#[must_use]
pub fn largest_offer_size() -> usize {
    let offer = Offer {
        ids: vec![OperationId::from_bytes([0xab; 32]); limits::MAX_OFFERED_IDS],
        snapshot: Some(u64::MAX),
        root: Some([0xef; 32]),
        partial: (0..limits::MAX_PARTIAL_BATCHES)
            .map(|index| {
                let mut batch = [0xcd; 32];
                batch[0] = u8::try_from(index).unwrap_or(u8::MAX);
                Holding {
                    batch: OperationId::from_bytes(batch),
                    pieces: roster_limits::MAX_BATCH_ENTRIES,
                    held: vec![0xff; bitmap_len(roster_limits::MAX_BATCH_ENTRIES)],
                }
            })
            .collect(),
    };
    Message::Offer(offer).encode().len()
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test reports a failed expectation by panicking")]
mod tests {
    use roster::cbor::is_canonical_schema;

    use super::*;

    /// Every schema is in canonical key order. Roster asserts this of its own
    /// schemas because a typo would silently change the wire format; the same
    /// applies here, and the ordering rule is length-first rather than
    /// alphabetical, which is exactly the kind of thing that gets written wrong.
    #[test]
    fn every_schema_is_canonical() {
        for schema in [
            ENVELOPE,
            OFFER,
            EXTENDED_OFFER,
            HOLDING,
            PIECES,
            STATE_REQUEST,
            STATE,
            TRANSFER,
            SNAPSHOT,
            DIGEST,
        ] {
            assert!(is_canonical_schema(schema), "{schema:?} is not in canonical key order");
        }
    }

    /// The largest legal offer fits in one payload, so reconciliation never
    /// needs fragmenting — and so needs no resumption protocol to stall in.
    #[test]
    fn the_largest_offer_fits_one_payload() {
        let largest = largest_offer_size();
        assert!(
            largest < transport::limits::MAX_PAYLOAD,
            "largest offer is {largest} bytes, transport payload bound is {}",
            transport::limits::MAX_PAYLOAD
        );
    }

    #[test]
    fn an_offer_round_trips() {
        let offer = Offer {
            ids: vec![OperationId::from_bytes([1; 32]), OperationId::from_bytes([2; 32])],
            snapshot: Some(7),
            root: None,
            partial: Vec::new(),
        };
        let encoded = Message::Offer(offer.clone()).encode();
        assert_eq!(Message::decode(&encoded), Ok(Message::Offer(offer)));
    }

    #[test]
    fn an_offer_without_a_snapshot_round_trips() {
        let offer = Offer { ids: Vec::new(), snapshot: None, root: None, partial: Vec::new() };
        let encoded = Message::Offer(offer.clone()).encode();
        assert_eq!(Message::decode(&encoded), Ok(Message::Offer(offer)));
    }

    #[test]
    fn an_offer_holding_batches_in_part_round_trips() {
        let offer = Offer {
            ids: vec![OperationId::from_bytes([1; 32])],
            snapshot: None,
            root: None,
            partial: vec![
                Holding::of(OperationId::from_bytes([2; 32]), 11, &[0, 3, 10]),
                Holding::of(OperationId::from_bytes([3; 32]), 1, &[]),
            ],
        };
        let encoded = Message::Offer(offer.clone()).encode();
        assert_eq!(Message::decode(&encoded), Ok(Message::Offer(offer)));
    }

    /// An offer with no batch in part is the bytes it always was, so a peer
    /// that knows nothing of batches reads it as it always did.
    #[test]
    fn an_offer_with_no_batch_in_part_keeps_its_kind() {
        let offer = Offer { ids: Vec::new(), snapshot: None, root: None, partial: Vec::new() };
        let encoded = Message::Offer(offer).encode();
        let mut reader = Reader::new(&encoded);
        let mut envelope = reader.map(ENVELOPE).unwrap_or_else(|_| panic!("an envelope"));
        let _ = envelope.key("body").and_then(|body| body.bytes(usize::MAX, "body"));
        let kind = envelope.key("kind").and_then(roster::cbor::Reader::u64);
        assert_eq!(kind, Ok(kind::OFFER));
    }

    #[test]
    fn a_holding_with_a_bit_past_its_last_piece_is_refused() {
        let mut holding = Holding::of(OperationId::from_bytes([2; 32]), 3, &[0]);
        if let Some(byte) = holding.held.first_mut() {
            *byte |= 0b1000_0000;
        }
        let offer = Offer { ids: Vec::new(), snapshot: None, root: None, partial: vec![holding] };
        assert!(Message::decode(&Message::Offer(offer).encode()).is_err());
    }

    #[test]
    fn an_offer_naming_its_root_round_trips_and_a_root_alone_is_refused() {
        let offer =
            Offer { ids: Vec::new(), snapshot: Some(3), root: Some([4; 32]), partial: Vec::new() };
        let encoded = Message::Offer(offer.clone()).encode();
        assert_eq!(Message::decode(&encoded), Ok(Message::Offer(offer)));
        let orphan =
            Offer { ids: Vec::new(), snapshot: None, root: Some([4; 32]), partial: Vec::new() };
        assert!(Message::decode(&Message::Offer(orphan).encode()).is_err());
    }

    #[test]
    fn sibling_roots_of_one_generation_give_different_digests() {
        let one =
            Offer { ids: Vec::new(), snapshot: Some(3), root: Some([4; 32]), partial: Vec::new() };
        let other = Offer { root: Some([5; 32]), ..one.clone() };
        assert_ne!(Digest::of_offer(&one), Digest::of_offer(&other));
    }

    #[test]
    fn a_state_request_and_its_answer_round_trip() {
        let request = Message::StateRequest([6; 32]);
        assert_eq!(Message::decode(&request.encode()), Ok(request));
        let answer = Message::State(StatePieces {
            root: [6; 32],
            pieces: vec![vec![1, 2], vec![3]],
            last: true,
        });
        assert_eq!(Message::decode(&answer.encode()), Ok(answer));
    }

    #[test]
    fn pieces_round_trip() {
        let message = Message::Pieces(vec![vec![1, 2, 3], vec![4]]);
        assert_eq!(Message::decode(&message.encode()), Ok(message));
    }

    #[test]
    fn a_digest_tells_apart_two_nodes_holding_different_pieces() {
        let batch = OperationId::from_bytes([2; 32]);
        let ids = [batch];
        let some = [Holding::of(batch, 4, &[0])];
        let more = [Holding::of(batch, 4, &[0, 1])];
        assert_ne!(
            Digest::with_partial(&ids, None, &some),
            Digest::with_partial(&ids, None, &more)
        );
        assert_eq!(Digest::with_partial(&ids, None, &[]), Digest::of(&ids, None));
    }

    #[test]
    fn a_transfer_round_trips() {
        let message = Message::Transfer(vec![vec![1, 2, 3], vec![4, 5]]);
        assert_eq!(Message::decode(&message.encode()), Ok(message));
    }

    #[test]
    fn a_snapshot_round_trips() {
        let message = Message::Snapshot(vec![9; 128]);
        assert_eq!(Message::decode(&message.encode()), Ok(message));
    }

    #[test]
    fn an_attestation_round_trips() {
        let message = Message::Attestation(vec![7; 200]);
        assert_eq!(Message::decode(&message.encode()), Ok(message));
    }

    /// Bounded by the attestation's own limit, not the snapshot's. An
    /// attestation carries heads and no state, so anything of a snapshot's size
    /// is not one — and a bound this tight is itself a check.
    #[test]
    fn an_oversized_attestation_is_refused() {
        let message = Message::Attestation(vec![0; roster_limits::MAX_ATTESTATION_SIZE + 1]);
        assert!(matches!(Message::decode(&message.encode()), Err(Error::Malformed(_))));

        // And the same bytes would have fitted a snapshot, which is what makes
        // the separate bound worth having.
        const {
            assert!(roster_limits::MAX_ATTESTATION_SIZE < roster_limits::MAX_SNAPSHOT_SIZE);
        }
    }

    /// The kinds that existed keep their numbers, so a peer running the older
    /// build reads what it always read rather than reading one thing as another.
    #[test]
    fn the_existing_kinds_keep_their_numbers() {
        assert_eq!(kind::OFFER, 1);
        assert_eq!(kind::TRANSFER, 2);
        assert_eq!(kind::SNAPSHOT, 3);
        assert_eq!(kind::ATTESTATION, 4);
    }

    /// Trailing bytes are a refusal, not something to ignore. Two byte strings
    /// that differ must never decode to the same message.
    #[test]
    fn trailing_bytes_are_refused() {
        let mut encoded = Message::Offer(Offer::default()).encode();
        encoded.push(0);
        assert!(matches!(Message::decode(&encoded), Err(Error::Malformed(_))));
    }

    /// An unknown message kind is refused, never skipped.
    #[test]
    fn an_unknown_kind_is_refused() {
        let mut writer = Writer::new();
        writer.map(2);
        writer.key("body").bytes(&[]);
        writer.key("kind").u64(99);
        let encoded = writer.finish();
        assert!(matches!(Message::decode(&encoded), Err(Error::Malformed(_))));
    }

    /// A sequence alongside "no snapshot held" is a second spelling of the same
    /// offer, so it is refused rather than normalized away.
    #[test]
    fn a_sequence_without_a_snapshot_is_refused() {
        let mut body = Writer::new();
        body.map(3);
        body.key("ids").array(0);
        body.key("snap").bool(false);
        body.key("snapseq").u64(5);
        let body = body.finish();

        let mut writer = Writer::new();
        writer.map(2);
        writer.key("body").bytes(&body);
        writer.key("kind").u64(kind::OFFER);
        let encoded = writer.finish();

        assert!(matches!(Message::decode(&encoded), Err(Error::Malformed(_))));
    }

    /// A count larger than the payload could possibly back is refused before any
    /// of it is read, and nothing is allocated to the declared size.
    #[test]
    fn a_count_larger_than_the_payload_is_refused() {
        let mut body = Writer::new();
        body.map(3);
        body.key("ids").array(4000);
        // No ids follow at all.
        body.key("snap").bool(false);
        body.key("snapseq").u64(0);
        let body = body.finish();

        let mut writer = Writer::new();
        writer.map(2);
        writer.key("body").bytes(&body);
        writer.key("kind").u64(kind::OFFER);
        let encoded = writer.finish();

        match Message::decode(&encoded) {
            Err(Error::CountExceedsPayload { declared, .. }) => assert_eq!(declared, 4000),
            other => panic!("expected a count refusal, got {other:?}"),
        }
    }

    /// An offer naming more than a roster may hold describes a roster that
    /// cannot exist.
    #[test]
    fn an_offer_beyond_the_roster_bound_is_refused() {
        let mut body = Writer::new();
        body.map(3);
        body.key("ids").array((limits::MAX_OFFERED_IDS + 1) as u64);
        body.key("snap").bool(false);
        body.key("snapseq").u64(0);
        let body = body.finish();

        let mut writer = Writer::new();
        writer.map(2);
        writer.key("body").bytes(&body);
        writer.key("kind").u64(kind::OFFER);
        let encoded = writer.finish();

        assert!(matches!(Message::decode(&encoded), Err(Error::OfferTooLarge { .. })));
    }

    /// Nothing decodes from noise.
    #[test]
    fn noise_is_refused() {
        for input in [b"".as_slice(), b"\x00".as_slice(), b"not cbor".as_slice()] {
            assert!(Message::decode(input).is_err(), "{input:?} decoded");
        }
    }

    fn id(tag: u8) -> OperationId {
        OperationId::from_bytes([tag; 32])
    }

    #[test]
    fn a_digest_does_not_depend_on_order() {
        assert_eq!(
            Digest::of(&[id(1), id(2), id(3)], Some(4)),
            Digest::of(&[id(3), id(1), id(2)], Some(4))
        );
    }

    #[test]
    fn one_operation_more_changes_the_digest() {
        assert_ne!(Digest::of(&[id(1), id(2)], None), Digest::of(&[id(1), id(2), id(3)], None));
    }

    #[test]
    fn a_different_snapshot_changes_the_digest() {
        let ids = [id(1), id(2)];
        assert_ne!(Digest::of(&ids, Some(1)), Digest::of(&ids, Some(2)));
        assert_ne!(Digest::of(&ids, None), Digest::of(&ids, Some(0)), "none is not zero");
    }

    #[test]
    fn a_digest_round_trips() {
        let digest = Digest::of(&[id(7)], Some(3));
        assert_eq!(Message::decode(&Message::Digest(digest).encode()), Ok(Message::Digest(digest)));
    }

    #[test]
    fn a_digest_of_the_wrong_width_is_refused() {
        let mut writer = Writer::new();
        writer.map(1);
        writer.key("hash").bytes(&[0u8; 31]);
        let body = writer.finish();
        let mut envelope = Writer::new();
        envelope.map(2);
        envelope.key("body").bytes(&body);
        envelope.key("kind").u64(kind::DIGEST);
        assert!(Message::decode(&envelope.finish()).is_err());
    }
}

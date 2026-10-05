//! What crosses a session, and how it is encoded.
//!
//! Three messages, each a canonical CBOR map behind a small envelope: an
//! **offer** naming what the sender holds, a **transfer** carrying operations,
//! and a **snapshot**.
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

/// A transfer's single field.
const TRANSFER: &[&str] = &["ops"];

/// A snapshot message's single field.
const SNAPSHOT: &[&str] = &["snap"];

/// An attestation message's single field.
const ATTESTATION: &[&str] = &["att"];

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
}

/// A message crossing a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// What the sender holds: every operation id, and the snapshot sequence it
    /// has, if any.
    Offer(Offer),
    /// Operations the peer's offer did not name, as the exact verified bytes.
    Transfer(Vec<Vec<u8>>),
    /// A signed snapshot, as the exact bytes.
    Snapshot(Vec<u8>),
    /// A signed attestation, as the exact bytes.
    ///
    /// Sent by an admin's node when its heads change and otherwise on a period,
    /// and never relayed: an attestation says what its author knew, and a node
    /// passing on someone else's would be saying it about itself.
    Attestation(Vec<u8>),
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
}

impl Offer {
    /// Whether this offer names an operation.
    #[must_use]
    pub fn names(&self, id: &OperationId) -> bool {
        self.ids.contains(id)
    }
}

impl Message {
    /// Encodes a message.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (kind, body) = match self {
            Self::Offer(offer) => (kind::OFFER, encode_offer(offer)),
            Self::Transfer(operations) => (kind::TRANSFER, encode_transfer(operations)),
            Self::Snapshot(bytes) => (kind::SNAPSHOT, encode_snapshot(bytes)),
            Self::Attestation(bytes) => (kind::ATTESTATION, encode_attestation(bytes)),
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
            kind::OFFER => decode_offer(&body, available).map(Self::Offer),
            kind::TRANSFER => decode_transfer(&body, available).map(Self::Transfer),
            kind::SNAPSHOT => decode_snapshot(&body).map(Self::Snapshot),
            kind::ATTESTATION => decode_attestation(&body).map(Self::Attestation),
            // An unknown kind is refused, never skipped. The message we cannot
            // parse might be the one carrying a revocation.
            _ => Err(Error::Malformed(roster::Error::InvalidValue("message kind"))),
        }
    }
}

/// Encodes an offer.
fn encode_offer(offer: &Offer) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.map(3);
    writer.key("ids");
    writer.array(offer.ids.len() as u64);
    for id in &offer.ids {
        writer.bytes(id.as_bytes());
    }
    writer.key("snap").bool(offer.snapshot.is_some());
    writer.key("snapseq").u64(offer.snapshot.unwrap_or(0));
    writer.finish()
}

/// Decodes an offer.
fn decode_offer(body: &[u8], available: usize) -> Result<Offer> {
    let mut reader = Reader::new(body);
    let mut map = reader.map(OFFER).map_err(Error::Malformed)?;

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

    let held = map.key("snap").and_then(roster::cbor::Reader::bool).map_err(Error::Malformed)?;
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

    Ok(Offer { ids, snapshot: held.then_some(sequence) })
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
        for schema in [ENVELOPE, OFFER, TRANSFER, SNAPSHOT] {
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
        };
        let encoded = Message::Offer(offer.clone()).encode();
        assert_eq!(Message::decode(&encoded), Ok(Message::Offer(offer)));
    }

    #[test]
    fn an_offer_without_a_snapshot_round_trips() {
        let offer = Offer { ids: Vec::new(), snapshot: None };
        let encoded = Message::Offer(offer.clone()).encode();
        assert_eq!(Message::decode(&encoded), Ok(Message::Offer(offer)));
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
}

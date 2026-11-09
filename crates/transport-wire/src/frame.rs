//! The session protocol carried over a convesso session.
//!
//! convesso keeps one session per pair of peers in a context. The transport
//! interface hands out a session per `connect`, so the sessions it means are
//! carried inside convesso's as frames, each naming the session it belongs to
//! by an id the dialler chose. A frame for a session that has ended is dropped,
//! so nothing in flight from a replaced session reaches the one that replaced
//! it.
//!
//! # The frames
//!
//! ```text
//! OPEN     1 | version: u8 | id: u64 BE | limits | evidence
//! ACCEPT   2 | id | limits | evidence
//! REFUSE   3 | id | reason: u8
//! CLOSE    4 | id | reason: u8
//! PAYLOAD  5 | id | bytes                  (a convesso message)
//! PACKET   6 | id | fragment               (a convesso datagram)
//! BEHIND   7 | id | root: 32 bytes
//! ROOTS    8 | id | roots
//! PART     9 | id | sequence: u32 BE | last: u8 | piece
//!
//! limits = largest message: u32 BE | largest frame: u32 BE
//! ```
//!
//! Every frame but `PACKET` travels as a reliable message: whole where it fits
//! the largest message its receiver takes, else in `PART`s (`crate::parts`).
//! Each end says in `OPEN` or `ACCEPT` the largest convesso message it takes
//! and the largest frame it puts back together: a computer takes a payload of
//! the interface's largest size in one message, a microcontroller 2 KB.
//! Version 4: before it every end took the computer's sizes, and a
//! microcontroller could not.
//!
//! `evidence` is what the sender shows of its membership — its leaf, the
//! proof of it and the hash of the root they rest on, as
//! `roster::membership::Shown` bytes — or nothing, where it holds no root. A
//! peer holding no roster judges the sender by it; one holding a roster judges
//! by that. Version 3: version 2 carried the root itself, which was most of
//! what opening a session cost, and a peer nearly always holds it already.
//!
//! `BEHIND` and `ROOTS` are how a peer holding no roster catches up while a
//! session opens. Shown evidence resting on a root it does not know, it says
//! the root it holds instead of refusing; the other side answers with the
//! roots taken after it, each verified against the one before as it is taken,
//! and the evidence is judged again once they are. `roots` is opaque here: what the serving side's source gives, and
//! what the taking side reads.
//!
//! Decoding never panics: a frame that is truncated or of an unknown kind is
//! refused whole.

use alloc::vec::Vec;

/// The version of this protocol. Carried in `OPEN`, so two ends that disagree
/// say so rather than misreading each other.
pub const VERSION: u8 = 4;

/// The bytes in front of a payload: kind, id.
pub const PAYLOAD_HEADER: usize = 9;

/// The bytes in front of a packet's fragment: kind, id.
pub const PACKET_HEADER: usize = 9;

/// The datagram data a relayed convesso packet carries: 1,380 bytes on the
/// relay (`PROTOCOL.md §6`), less the 31 of convesso's own transport framing.
/// The relay is the narrowest path, so a fragment cut to this fits on every
/// path a session may take.
pub const DATAGRAM_ROOM: usize = 1_380 - 31;

/// The room a packet's fragment has inside a datagram, its own header
/// included.
pub const FRAGMENT_ROOM: usize = DATAGRAM_ROOM - PACKET_HEADER;

/// The bytes in front of a part's piece: kind, id, sequence, last.
pub const PART_HEADER: usize = 14;

/// What an end takes: the largest convesso message, and the largest frame it
/// puts back together from parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The largest convesso message, in bytes.
    pub message: u32,
    /// The largest frame, in bytes, header included.
    pub frame: u32,
}

impl Limits {
    /// What every end takes at least, and what is assumed of a peer until it
    /// says: a convesso message of a microcontroller's largest size, and a
    /// frame holding a root of the largest size (`roster::limits`) and more.
    pub const LEAST: Self = Self { message: 2_048, frame: 72 * 1_024 };

    /// The larger of these and [`Self::LEAST`], field by field: an end saying
    /// less than every end takes is read as taking that.
    #[must_use]
    pub fn at_least_the_least(self) -> Self {
        Self {
            message: self.message.max(Self::LEAST.message),
            frame: self.frame.max(Self::LEAST.frame),
        }
    }

    /// The largest message, as a length.
    #[must_use]
    pub fn message_len(self) -> usize {
        usize::try_from(self.message).unwrap_or(usize::MAX)
    }

    /// The largest frame, as a length.
    #[must_use]
    pub fn frame_len(self) -> usize {
        usize::try_from(self.frame).unwrap_or(usize::MAX)
    }

    fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.message.to_be_bytes());
        out.extend_from_slice(&self.frame.to_be_bytes());
    }

    fn decode(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let (message, rest) = bytes.split_at_checked(4)?;
        let (frame, rest) = rest.split_at_checked(4)?;
        let message = u32::from_be_bytes(message.try_into().ok()?);
        let frame = u32::from_be_bytes(frame.try_into().ok()?);
        Some((Self { message, frame }, rest))
    }
}

/// A session's id, chosen at random by the dialler.
pub type SessionId = u64;

/// Why a session was refused or closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Closed in the ordinary way.
    Ordinary,
    /// The refusing side's roster names no device holding this key.
    NotAMember,
    /// The refusing side's roster records this device as revoked.
    Revoked,
    /// The two ends speak different versions of this protocol.
    Version,
    /// The session was closed because its peer stopped being a member.
    MembershipLost,
    /// The refusing side's access policy does not let the dialler reach it.
    NotAllowed,
    /// A reason this version does not know. Read as an ordinary close.
    Unknown(u8),
}

impl Reason {
    const fn to_byte(self) -> u8 {
        match self {
            Self::Ordinary => 0,
            Self::NotAMember => 1,
            Self::Revoked => 2,
            Self::Version => 3,
            Self::MembershipLost => 4,
            Self::NotAllowed => 5,
            Self::Unknown(byte) => byte,
        }
    }

    const fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Ordinary,
            1 => Self::NotAMember,
            2 => Self::Revoked,
            3 => Self::Version,
            4 => Self::MembershipLost,
            5 => Self::NotAllowed,
            other => Self::Unknown(other),
        }
    }
}

/// One frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A dialler opens a session.
    Open {
        /// The protocol version it speaks.
        version: u8,
        /// The session's id.
        id: SessionId,
        /// What the dialler takes. Read only at this version: an `OPEN` of
        /// another is refused for its version, whatever follows.
        limits: Limits,
        /// What the dialler shows of its membership; empty for nothing.
        evidence: Vec<u8>,
    },
    /// The accepting side took the session.
    Accept {
        /// The session's id.
        id: SessionId,
        /// What the accepting side takes.
        limits: Limits,
        /// What the accepting side shows of its membership; empty for nothing.
        evidence: Vec<u8>,
    },
    /// The accepting side refused the session.
    Refuse {
        /// The session's id.
        id: SessionId,
        /// Why.
        reason: Reason,
    },
    /// Either side closed the session.
    Close {
        /// The session's id.
        id: SessionId,
        /// Why.
        reason: Reason,
    },
    /// A payload, whole.
    Payload {
        /// The session's id.
        id: SessionId,
        /// The payload.
        bytes: Vec<u8>,
    },
    /// A packet's fragment, as `transport::fragment` cut it.
    Packet {
        /// The session's id.
        id: SessionId,
        /// The fragment, its own header included.
        fragment: Vec<u8>,
    },
    /// The side holding no roster cannot place the root the other's evidence
    /// rests on, and asks for the roots taken after the one it holds.
    Behind {
        /// The session's id.
        id: SessionId,
        /// The root it holds.
        root: [u8; 32],
    },
    /// The roots asked for.
    Roots {
        /// The session's id.
        id: SessionId,
        /// The roots, as the answering side's source gives them.
        roots: Vec<u8>,
    },
}

pub(crate) const OPEN: u8 = 1;
const ACCEPT: u8 = 2;
const REFUSE: u8 = 3;
const CLOSE: u8 = 4;
const PAYLOAD: u8 = 5;
const PACKET: u8 = 6;
const BEHIND: u8 = 7;
const ROOTS: u8 = 8;
/// A piece of a frame too large for one message (`crate::parts`).
pub(crate) const PART: u8 = 9;

impl Frame {
    /// The frame's bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Open { version, id, limits, evidence } => {
                out.push(OPEN);
                out.push(*version);
                out.extend_from_slice(&id.to_be_bytes());
                limits.encode(&mut out);
                out.extend_from_slice(evidence);
            }
            Self::Accept { id, limits, evidence } => {
                out.push(ACCEPT);
                out.extend_from_slice(&id.to_be_bytes());
                limits.encode(&mut out);
                out.extend_from_slice(evidence);
            }
            Self::Refuse { id, reason } => {
                out.push(REFUSE);
                out.extend_from_slice(&id.to_be_bytes());
                out.push(reason.to_byte());
            }
            Self::Close { id, reason } => {
                out.push(CLOSE);
                out.extend_from_slice(&id.to_be_bytes());
                out.push(reason.to_byte());
            }
            Self::Payload { id, bytes } => {
                out.reserve(PAYLOAD_HEADER.saturating_add(bytes.len()));
                out.push(PAYLOAD);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(bytes);
            }
            Self::Packet { id, fragment } => {
                out.reserve(PACKET_HEADER.saturating_add(fragment.len()));
                out.push(PACKET);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(fragment);
            }
            Self::Behind { id, root } => {
                out.push(BEHIND);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(root);
            }
            Self::Roots { id, roots } => {
                out.push(ROOTS);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(roots);
            }
        }
        out
    }

    /// Reads a frame, or `None` for anything that is not one.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&kind, rest) = bytes.split_first()?;
        match kind {
            OPEN => {
                let (&version, rest) = rest.split_first()?;
                let (id, rest) = id_and_rest(rest)?;
                if version != VERSION {
                    // Another version: what follows is not read, and the
                    // version alone is answered.
                    return Some(Self::Open {
                        version,
                        id,
                        limits: Limits::LEAST,
                        evidence: Vec::new(),
                    });
                }
                let (limits, evidence) = Limits::decode(rest)?;
                Some(Self::Open { version, id, limits, evidence: evidence.to_vec() })
            }
            ACCEPT => {
                let (id, rest) = id_and_rest(rest)?;
                let (limits, evidence) = Limits::decode(rest)?;
                Some(Self::Accept { id, limits, evidence: evidence.to_vec() })
            }
            REFUSE | CLOSE => {
                let (id, rest) = id_and_rest(rest)?;
                let [reason] = rest else { return None };
                let reason = Reason::from_byte(*reason);
                Some(if kind == REFUSE {
                    Self::Refuse { id, reason }
                } else {
                    Self::Close { id, reason }
                })
            }
            PAYLOAD => {
                let (id, payload) = id_and_rest(rest)?;
                Some(Self::Payload { id, bytes: payload.to_vec() })
            }
            PACKET => {
                let (id, fragment) = id_and_rest(rest)?;
                if fragment.is_empty() {
                    return None;
                }
                Some(Self::Packet { id, fragment: fragment.to_vec() })
            }
            BEHIND => {
                let (id, root) = id_and_rest(rest)?;
                Some(Self::Behind { id, root: root.try_into().ok()? })
            }
            ROOTS => {
                let (id, roots) = id_and_rest(rest)?;
                Some(Self::Roots { id, roots: roots.to_vec() })
            }
            _ => None,
        }
    }
}

/// An id that is all of `bytes`.
fn exact_id(bytes: &[u8]) -> Option<SessionId> {
    let array: [u8; 8] = bytes.try_into().ok()?;
    Some(SessionId::from_be_bytes(array))
}

/// An id at the front of `bytes`, and what follows it.
pub(crate) fn id_and_rest(bytes: &[u8]) -> Option<(SessionId, &[u8])> {
    let (head, rest) = bytes.split_at_checked(8)?;
    Some((exact_id(head)?, rest))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a test reports failure by panicking"
)]
mod tests {
    use alloc::vec;

    use proptest::prelude::*;

    use super::*;

    const SOME: Limits = Limits { message: 300_000, frame: 1_000_000 };

    fn every_kind() -> Vec<Frame> {
        vec![
            Frame::Open { version: VERSION, id: 7, limits: SOME, evidence: Vec::new() },
            Frame::Open { version: VERSION, id: 8, limits: Limits::LEAST, evidence: vec![1, 2, 3] },
            Frame::Accept { id: u64::MAX, limits: SOME, evidence: Vec::new() },
            Frame::Accept { id: 9, limits: Limits::LEAST, evidence: vec![4; 40] },
            Frame::Refuse { id: 1, reason: Reason::Revoked },
            Frame::Close { id: 2, reason: Reason::MembershipLost },
            Frame::Payload { id: 3, bytes: b"bytes".to_vec() },
            Frame::Payload { id: 3, bytes: Vec::new() },
            Frame::Packet { id: 4, fragment: vec![9; 30] },
            Frame::Behind { id: 5, root: [6; 32] },
            Frame::Roots { id: 6, roots: vec![1, 2, 3] },
            Frame::Roots { id: 6, roots: Vec::new() },
        ]
    }

    #[test]
    fn every_kind_reads_back_as_written() {
        for frame in every_kind() {
            assert_eq!(Frame::decode(&frame.encode()), Some(frame.clone()), "{frame:?}");
        }
    }

    #[test]
    fn a_truncated_frame_is_refused() {
        for frame in every_kind() {
            let bytes = frame.encode();
            // A payload may legitimately be empty, and a packet's fragment is
            // its tail: only cuts into the fixed header must fail.
            let header = match frame {
                Frame::Payload { .. } => PAYLOAD_HEADER,
                Frame::Open { .. } => 18,
                Frame::Accept { .. } => 17,
                Frame::Packet { .. } => PACKET_HEADER.saturating_add(1),
                Frame::Roots { .. } => 9,
                _ => bytes.len(),
            };
            for cut in 0..header {
                assert_eq!(Frame::decode(&bytes[..cut]), None, "{frame:?} cut at {cut}");
            }
        }
    }

    #[test]
    fn an_unknown_kind_is_refused() {
        assert_eq!(Frame::decode(&[0, 0, 0, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(Frame::decode(&[10, 0, 0, 0, 0, 0, 0, 0, 0]), None);
        // A part is put back together before it is a frame, never read as one.
        assert_eq!(Frame::decode(&[PART, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), None);
    }

    /// An `OPEN` of another version is read for its version and id alone, so
    /// it can be refused for its version whatever the rest holds.
    #[test]
    fn an_open_of_another_version_is_read_for_its_version() {
        let old = [OPEN, 3, 0, 0, 0, 0, 0, 0, 0, 5, 9, 9];
        assert_eq!(
            Frame::decode(&old),
            Some(Frame::Open { version: 3, id: 5, limits: Limits::LEAST, evidence: Vec::new() })
        );
    }

    #[test]
    fn an_unknown_reason_is_kept() {
        let bytes = [CLOSE, 0, 0, 0, 0, 0, 0, 0, 5, 200];
        assert_eq!(
            Frame::decode(&bytes),
            Some(Frame::Close { id: 5, reason: Reason::Unknown(200) })
        );
    }

    proptest! {
        /// Whatever arrives, decoding answers and does not panic.
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = Frame::decode(&bytes);
        }
    }
}

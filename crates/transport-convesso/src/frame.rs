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
//! OPEN     1 | version: u8 | id: u64 BE
//! ACCEPT   2 | id
//! REFUSE   3 | id | reason: u8
//! CLOSE    4 | id | reason: u8
//! PAYLOAD  5 | id | bytes                  (a convesso message)
//! PACKET   6 | id | fragment               (a convesso datagram)
//! ```
//!
//! Every frame but `PACKET` travels as a reliable message. A payload of the
//! interface's largest size travels in one message with its header: the node
//! runs a stream configuration whose largest message has room for both
//! ([`Stream`]).
//!
//! Decoding never panics: a frame that is truncated or of an unknown kind is
//! refused whole.

use convesso_stream::config::StreamConfig;

/// The version of this protocol. Carried in `OPEN`, so two ends that disagree
/// say so rather than misreading each other.
pub const VERSION: u8 = 1;

/// The bytes in front of a payload: kind, id.
pub const PAYLOAD_HEADER: usize = 9;

/// The bytes in front of a packet's fragment: kind, id.
pub const PACKET_HEADER: usize = 9;

convesso_stream::config! {
    /// The stream configuration every node of this binding runs: the server's,
    /// with a largest message that holds the interface's largest payload and
    /// its header. Both ends run it, so neither refuses what the other sends.
    pub Stream: Server { max_message: transport::limits::MAX_PAYLOAD + PAYLOAD_HEADER }
}

/// The largest convesso message the node carries.
pub const MAX_MESSAGE: usize = <Stream as StreamConfig>::MAX_MESSAGE;

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
    },
    /// The accepting side took the session.
    Accept {
        /// The session's id.
        id: SessionId,
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
}

const OPEN: u8 = 1;
const ACCEPT: u8 = 2;
const REFUSE: u8 = 3;
const CLOSE: u8 = 4;
const PAYLOAD: u8 = 5;
const PACKET: u8 = 6;

impl Frame {
    /// The frame's bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Open { version, id } => {
                out.push(OPEN);
                out.push(*version);
                out.extend_from_slice(&id.to_be_bytes());
            }
            Self::Accept { id } => {
                out.push(ACCEPT);
                out.extend_from_slice(&id.to_be_bytes());
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
                let id = exact_id(rest)?;
                Some(Self::Open { version, id })
            }
            ACCEPT => Some(Self::Accept { id: exact_id(rest)? }),
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
fn id_and_rest(bytes: &[u8]) -> Option<(SessionId, &[u8])> {
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
    use proptest::prelude::*;

    use super::*;

    fn every_kind() -> Vec<Frame> {
        vec![
            Frame::Open { version: VERSION, id: 7 },
            Frame::Accept { id: u64::MAX },
            Frame::Refuse { id: 1, reason: Reason::Revoked },
            Frame::Close { id: 2, reason: Reason::MembershipLost },
            Frame::Payload { id: 3, bytes: b"bytes".to_vec() },
            Frame::Payload { id: 3, bytes: Vec::new() },
            Frame::Packet { id: 4, fragment: vec![9; 30] },
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
                Frame::Packet { .. } => PACKET_HEADER.saturating_add(1),
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
        assert_eq!(Frame::decode(&[7, 0, 0, 0, 0, 0, 0, 0, 0]), None);
    }

    #[test]
    fn an_unknown_reason_is_kept() {
        let bytes = [CLOSE, 0, 0, 0, 0, 0, 0, 0, 5, 200];
        assert_eq!(
            Frame::decode(&bytes),
            Some(Frame::Close { id: 5, reason: Reason::Unknown(200) })
        );
    }

    /// The configuration has room for the largest payload and its header, so a
    /// payload is never split.
    #[test]
    fn a_payload_of_the_largest_size_is_one_message() {
        let payload = vec![7u8; transport::limits::MAX_PAYLOAD];
        let message = Frame::Payload { id: 9, bytes: payload.clone() }.encode();
        assert_eq!(message.len(), MAX_MESSAGE);
        assert_eq!(Frame::decode(&message), Some(Frame::Payload { id: 9, bytes: payload }));
    }

    proptest! {
        /// Whatever arrives, decoding answers and does not panic.
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = Frame::decode(&bytes);
        }
    }
}

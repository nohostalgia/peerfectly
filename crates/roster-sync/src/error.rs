//! What can go wrong reconciling, kept apart.
//!
//! The distinctions here are not cosmetic. "You are over quota" says nothing
//! about the operation and everything about the sender; "this signature does not
//! verify" says the opposite. Collapsing them would make the one refusal that is
//! about traffic shaping indistinguishable from the one that is about a forged
//! operation — and an operator watching a node would have no way to tell a
//! chatty peer from a hostile one.

use core::fmt;

/// The result of a reconciliation step.
pub type Result<T> = core::result::Result<T, Error>;

/// Why a reconciliation step did not do what was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The sender already holds its share of the pending set.
    ///
    /// Says nothing about the operation. The sender keeps it and may offer it
    /// again — after supplying the parents it was waiting for, or at the next
    /// reconciliation. Nothing already pending was displaced to produce this.
    OverQuota {
        /// The device that has reached its share.
        peer: roster::id::DeviceId,
        /// The share, so the reason carries the bound it names.
        limit: usize,
    },

    /// An offer named more operation ids than a roster may hold.
    ///
    /// Refused on the declared count, before anything is read for it.
    OfferTooLarge {
        /// What the offer declared.
        declared: usize,
        /// What a roster may hold.
        limit: usize,
    },

    /// A message did not decode as this protocol.
    ///
    /// Carries roster's decoding reason rather than replacing it, so a
    /// non-canonical encoding stays distinguishable from a truncated one.
    Malformed(roster::Error),

    /// A message declared a count the bytes that follow cannot support.
    ///
    /// Kept apart from [`Error::Malformed`] because this is the shape of the
    /// "ten gigabyte array" refusal: the declared count is the attack, and no
    /// allocation is made for it.
    CountExceedsPayload {
        /// What the message declared.
        declared: usize,
        /// What the remaining bytes could hold at best.
        available: usize,
    },

    /// The peer offered a snapshot sequence lower than the one held.
    ///
    /// Seen in the offer, so no snapshot bytes are transferred for it. The
    /// roster refuses a regression on its own; this is the same refusal one
    /// exchange earlier.
    SnapshotWouldRegress {
        /// What the peer offered.
        offered: u64,
        /// What this node holds.
        held: u64,
    },

    /// The roster refused something received.
    ///
    /// The reason is the roster's, unchanged. "The roster refused this
    /// operation" must stay distinguishable from "reconciliation failed".
    Roster(roster::Error),

    /// The transport failed, or the session ended.
    Transport(transport::Error),
}

impl Error {
    /// Whether this refusal is about the sender rather than about the content.
    ///
    /// The two call for different responses: a peer over quota is behaving
    /// normally and should be left alone, while a peer sending operations that
    /// do not verify is worth reporting. Neither ends a session.
    #[must_use]
    pub const fn is_about_the_sender(&self) -> bool {
        matches!(self, Self::OverQuota { .. })
    }

    /// Whether the content was refused, rather than the sender throttled.
    #[must_use]
    pub const fn is_about_the_content(&self) -> bool {
        matches!(
            self,
            Self::Malformed(_)
                | Self::CountExceedsPayload { .. }
                | Self::OfferTooLarge { .. }
                | Self::Roster(_)
                | Self::SnapshotWouldRegress { .. }
        )
    }

    /// Whether the session has ended.
    ///
    /// The only outcome that stops reconciliation. Every other refusal leaves
    /// the session open, by design — see the crate documentation.
    #[must_use]
    pub fn is_session_over(&self) -> bool {
        matches!(self, Self::Transport(inner) if inner.is_closed())
    }
}

impl From<roster::Error> for Error {
    fn from(value: roster::Error) -> Self {
        Self::Roster(value)
    }
}

impl From<transport::Error> for Error {
    fn from(value: transport::Error) -> Self {
        Self::Transport(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OverQuota { peer, limit } => {
                write!(f, "peer {peer:?} already holds its share of {limit} pending entries")
            }
            Self::OfferTooLarge { declared, limit } => {
                write!(f, "offer names {declared} ids, more than the {limit} a roster may hold")
            }
            Self::Malformed(reason) => write!(f, "message did not decode: {reason}"),
            Self::CountExceedsPayload { declared, available } => {
                write!(f, "message declares {declared} entries but only {available} can follow")
            }
            Self::SnapshotWouldRegress { offered, held } => {
                write!(f, "peer offers snapshot {offered}, behind the {held} held")
            }
            Self::Roster(reason) => write!(f, "the roster refused it: {reason}"),
            Self::Transport(reason) => write!(f, "the session: {reason}"),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use roster::id::DeviceId;

    fn device() -> DeviceId {
        DeviceId::from_bytes([7; 32])
    }

    /// Every outcome is distinguishable from every other. A caller that cannot
    /// tell a throttle from a rejection cannot respond correctly to either.
    #[test]
    fn every_outcome_is_distinct() {
        let all = [
            Error::OverQuota { peer: device(), limit: 32 },
            Error::OfferTooLarge { declared: 9000, limit: 4096 },
            Error::Malformed(roster::Error::TrailingData),
            Error::CountExceedsPayload { declared: 4096, available: 3 },
            Error::SnapshotWouldRegress { offered: 1, held: 4 },
            Error::Roster(roster::Error::SignatureInvalid),
            Error::Transport(transport::Error::ClosedByPeer),
        ];
        for (i, left) in all.iter().enumerate() {
            for (j, right) in all.iter().enumerate() {
                assert_eq!(i == j, left == right, "{left:?} vs {right:?}");
            }
        }
    }

    /// A quota refusal says nothing about the operation; a validity refusal says
    /// everything about it. This is the distinction the specification requires,
    /// and the one an operator reads to tell a chatty peer from a hostile one.
    #[test]
    fn a_quota_refusal_is_not_a_validity_refusal() {
        let quota = Error::OverQuota { peer: device(), limit: 32 };
        let invalid = Error::Roster(roster::Error::SignatureInvalid);

        assert!(quota.is_about_the_sender());
        assert!(!quota.is_about_the_content());

        assert!(invalid.is_about_the_content());
        assert!(!invalid.is_about_the_sender());
    }

    /// A refusal originating in the roster keeps the roster's reason. Replacing
    /// it with "sync failed" would lose the only thing worth knowing.
    #[test]
    fn an_underlying_reason_survives() {
        let converted: Error = roster::Error::UnauthorizedAuthor.into();
        assert_eq!(converted, Error::Roster(roster::Error::UnauthorizedAuthor));
        assert!(converted.to_string().contains("author"), "{converted}");

        let from_transport: Error = transport::Error::NotAMember.into();
        assert_eq!(from_transport, Error::Transport(transport::Error::NotAMember));
    }

    /// Only the session ending stops reconciliation. Every other refusal leaves
    /// it open — the policy the crate documents, pinned here.
    #[test]
    fn only_the_session_ending_stops_reconciliation() {
        assert!(Error::Transport(transport::Error::ClosedByPeer).is_session_over());
        assert!(
            Error::Transport(transport::Error::ClosedOnMembershipLoss).is_session_over(),
            "membership loss ends the session, and it is the transport that ends it"
        );

        for refusal in [
            Error::OverQuota { peer: device(), limit: 32 },
            Error::Malformed(roster::Error::TrailingData),
            Error::Roster(roster::Error::SignatureInvalid),
            Error::OfferTooLarge { declared: 9000, limit: 4096 },
        ] {
            assert!(!refusal.is_session_over(), "{refusal:?} must not end a session");
        }
    }
}

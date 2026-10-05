//! Why a session did not happen, or stopped happening.
//!
//! These are kept apart deliberately. DESIGN.md §3.3 lists the states where a
//! person loses confidence in the product, and they call for entirely different
//! responses: *"your laptop is offline, last seen three hours ago"* and *"that
//! device is no longer in your network"* are not the same sentence, and a
//! generic error can produce neither.
//!
//! A refusal that originated in the roster or in identity carries that reason
//! rather than replacing it, so "the roster refused this device" stays
//! distinguishable from "the network failed".

use core::fmt;

/// Why a session was refused, or ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The peer could not be reached at all.
    ///
    /// Says nothing about whether it is a member — this is the answer before
    /// that question can be asked.
    PeerUnreachable {
        /// What the connectivity layer said, when it had anything to say.
        ///
        /// `None` from an in-process transport, which knows only that nobody was
        /// listening. `Some` from a real one, carrying the layer's own words.
        ///
        /// Added because a dial that failed on a real network reported only that
        /// it had failed. The abstraction is right to keep its error set small
        /// and closed — a caller must not have to know about QUIC — but a closed
        /// set with nothing behind it makes a failure undiagnosable, and somebody
        /// eventually has to diagnose it.
        cause: Option<String>,
    },
    /// The peer was reached, and holds a key no device in the roster names.
    ///
    /// A stranger, not an expelled device.
    NotAMember,
    /// The peer was reached, and its device has been revoked.
    ///
    /// Distinct from [`Self::NotAMember`]: this device *was* in the network and
    /// was removed, which is a different thing to tell someone.
    Revoked,
    /// The peer presented a key it could not prove it holds.
    ///
    /// Nothing about the roster is wrong here; the peer is lying or broken.
    PossessionNotProven,
    /// The session was closed by the far end, in the ordinary way.
    ClosedByPeer,
    /// The session was closed because its peer stopped being a member.
    ///
    /// Reported separately from [`Self::ClosedByPeer`] so a caller can say
    /// "the network expelled this device" rather than "the other end hung up".
    ClosedOnMembershipLoss,
    /// An operation was attempted on a session that is already closed.
    SessionClosed,
    /// A payload exceeded the interface's stated bound.
    ///
    /// Refused at the sender: a truncated payload becomes a decoding failure at
    /// the far end, blamed on the sender, and diagnosed nowhere near where it
    /// went wrong.
    PayloadTooLarge {
        /// How large the payload was.
        len: usize,
        /// The largest that would have been accepted.
        limit: usize,
    },
    /// A packet exceeded the interface's stated packet bound.
    ///
    /// Refused at the sender, whole, as an oversized payload is.
    PacketTooLarge {
        /// How large the packet was.
        len: usize,
        /// The largest that would have been accepted.
        limit: usize,
    },
    /// The peer's end of the session does not accept packets.
    ///
    /// What a peer running a build that predates packets looks like: payloads
    /// still cross, and tunnel traffic cannot. Its own outcome so the difference
    /// is said rather than seen as silent loss.
    PacketsNotAccepted,
    /// A roster check refused the value.
    Roster(roster::Error),
    /// An identity operation failed.
    Identity(identity::Error),
}

impl Error {
    /// A stable, short name for this outcome.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::PeerUnreachable { .. } => "peer_unreachable",
            Self::NotAMember => "not_a_member",
            Self::Revoked => "revoked",
            Self::PossessionNotProven => "possession_not_proven",
            Self::ClosedByPeer => "closed_by_peer",
            Self::ClosedOnMembershipLoss => "closed_on_membership_loss",
            Self::SessionClosed => "session_closed",
            Self::PayloadTooLarge { .. } => "payload_too_large",
            Self::PacketTooLarge { .. } => "packet_too_large",
            Self::PacketsNotAccepted => "packets_not_accepted",
            Self::Roster(_) => "roster",
            Self::Identity(_) => "identity",
        }
    }

    /// Every outcome this capability can report.
    pub const ALL_KINDS: &'static [&'static str] = &[
        "peer_unreachable",
        "not_a_member",
        "revoked",
        "possession_not_proven",
        "closed_by_peer",
        "closed_on_membership_loss",
        "session_closed",
        "payload_too_large",
        "packet_too_large",
        "packets_not_accepted",
        "roster",
        "identity",
    ];

    /// Whether this is a refusal on membership grounds rather than a failure of
    /// connectivity.
    ///
    /// The distinction matters to a caller deciding whether to retry: a network
    /// problem might resolve itself, and a device that is not in the network
    /// will not.
    #[must_use]
    pub const fn is_membership_refusal(&self) -> bool {
        matches!(self, Self::NotAMember | Self::Revoked | Self::ClosedOnMembershipLoss)
    }

    /// Whether the session ended rather than never starting.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self, Self::ClosedByPeer | Self::ClosedOnMembershipLoss | Self::SessionClosed)
    }
}

impl From<roster::Error> for Error {
    fn from(value: roster::Error) -> Self {
        Self::Roster(value)
    }
}

impl From<identity::Error> for Error {
    fn from(value: identity::Error) -> Self {
        Self::Identity(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerUnreachable { cause } => match cause {
                Some(cause) => write!(f, "the peer could not be reached: {cause}"),
                None => f.write_str("the peer could not be reached"),
            },
            Self::NotAMember => f.write_str("the peer is not a member of this network"),
            Self::Revoked => f.write_str("the peer's device was revoked"),
            Self::PossessionNotProven => {
                f.write_str("the peer could not prove it holds the key it presented")
            }
            Self::ClosedByPeer => f.write_str("the peer closed the session"),
            Self::ClosedOnMembershipLoss => {
                f.write_str("the session closed because its peer is no longer a member")
            }
            Self::SessionClosed => f.write_str("the session is closed"),
            Self::PayloadTooLarge { len, limit } => {
                write!(f, "payload of {len} bytes exceeds the {limit}-byte limit")
            }
            Self::PacketTooLarge { len, limit } => {
                write!(f, "packet of {len} bytes exceeds the {limit}-byte limit")
            }
            Self::PacketsNotAccepted => {
                f.write_str("the peer does not accept packets: it may be running an older build")
            }
            Self::Roster(inner) => write!(f, "roster: {inner}"),
            Self::Identity(inner) => write!(f, "identity: {inner}"),
        }
    }
}

impl core::error::Error for Error {}

/// Result alias for transport operations.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;
    use std::collections::BTreeSet;

    /// Every outcome the spec names is its own outcome. Collapsing any two
    /// would make §3.3's required states unbuildable at the layer above.
    #[test]
    fn every_outcome_is_distinct() {
        let samples = [
            Error::PeerUnreachable { cause: None },
            Error::NotAMember,
            Error::Revoked,
            Error::PossessionNotProven,
            Error::ClosedByPeer,
            Error::ClosedOnMembershipLoss,
            Error::SessionClosed,
            Error::PayloadTooLarge { len: 2, limit: 1 },
            Error::PacketTooLarge { len: 2, limit: 1 },
            Error::PacketsNotAccepted,
            Error::Roster(roster::Error::InvalidKey),
            Error::Identity(identity::Error::KeyReuse),
        ];
        let unique: BTreeSet<&str> = samples.iter().map(Error::kind).collect();
        assert_eq!(unique.len(), samples.len(), "two outcomes share a kind string");
        assert_eq!(samples.len(), Error::ALL_KINDS.len());
        for sample in &samples {
            assert!(Error::ALL_KINDS.contains(&sample.kind()), "{} is missing", sample.kind());
        }
    }

    /// The three membership refusals differ from each other and from the
    /// connectivity failures.
    #[test]
    fn membership_refusals_are_separable_from_connectivity() {
        assert!(Error::NotAMember.is_membership_refusal());
        assert!(Error::Revoked.is_membership_refusal());
        assert!(Error::ClosedOnMembershipLoss.is_membership_refusal());

        assert!(!Error::PeerUnreachable { cause: None }.is_membership_refusal());
        assert!(!Error::ClosedByPeer.is_membership_refusal());
        assert!(!Error::PossessionNotProven.is_membership_refusal());

        // And a stranger is not an expelled device.
        assert_ne!(Error::NotAMember, Error::Revoked);
    }

    /// A close caused by revocation is not a hang-up.
    #[test]
    fn a_membership_close_differs_from_a_normal_close() {
        assert_ne!(Error::ClosedByPeer, Error::ClosedOnMembershipLoss);
        assert!(Error::ClosedByPeer.is_closed());
        assert!(Error::ClosedOnMembershipLoss.is_closed());
        assert!(!Error::ClosedByPeer.is_membership_refusal());
    }

    /// An underlying refusal keeps its reason rather than being flattened.
    #[test]
    fn an_underlying_reason_survives() {
        let from_roster: Error = roster::Error::KeyReuse.into();
        assert_eq!(from_roster, Error::Roster(roster::Error::KeyReuse));
        assert!(format!("{from_roster}").contains("key_reuse"));

        let from_identity: Error = identity::Error::Declined.into();
        assert_eq!(from_identity, Error::Identity(identity::Error::Declined));
        assert!(format!("{from_identity}").contains("declined"));
    }
}

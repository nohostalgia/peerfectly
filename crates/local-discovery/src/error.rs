//! Why a packet did not become a candidate address.
//!
//! Most of these are **ordinary**. A listener on a dedicated multicast port
//! shares it with every other network in range, so packets that do not decrypt
//! are the expected background rather than a fault. Reporting them as errors
//! would fill a log with the sound of other people's networks working.
//!
//! The distinction that matters is between *not for us* and *for us and wrong*.

use core::fmt;

/// The result of handling a packet.
pub type Result<T> = core::result::Result<T, Error>;

/// Why a packet produced nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The packet did not decrypt under this network's key.
    ///
    /// **Ordinary.** It belongs to another network, or it is not an
    /// announcement at all. Carries no detail because there is none to have: a
    /// failed AEAD says nothing about what it was.
    NotForThisNetwork,

    /// Too short to be an announcement, or larger than the bound.
    ///
    /// Also ordinary — anything at all may arrive on a UDP port.
    NotAnAnnouncement,

    /// It decrypted, but the bytes inside are not a record.
    ///
    /// Interesting: whoever sent it knew the network id. Carries roster's
    /// decoding reason rather than replacing it.
    Malformed(roster::Error),

    /// It decrypted and decoded, but the signature does not verify.
    ///
    /// The most interesting failure here. Someone who knows the network id sent
    /// a record they could not sign — an impostor announcing a key they do not
    /// hold, or a former member replaying something altered.
    SignatureInvalid,

    /// Its sequence does not exceed what is already cached for that key.
    ///
    /// A replay, or a repeat of an announcement already heard. Repeats are
    /// expected: §8 requires announcements to be sent more than once.
    NotNewer {
        /// What the announcement carried.
        offered: u64,
        /// What is already cached.
        cached: u64,
    },

    /// The cache is full.
    ///
    /// Reported rather than discarding silently: a cache that quietly drops is a
    /// cache that quietly stops making the first path fast.
    CacheFull {
        /// The bound.
        limit: usize,
    },

    /// The socket would not carry it.
    ///
    /// **Not a packet problem at all**, which is the whole reason this variant
    /// exists. A send that fails means this device is announcing to nobody, and
    /// the operating system has already said why. Reporting that as
    /// [`Self::NotAnAnnouncement`] — which is what happened — throws the reason
    /// away at the one moment it is the entire diagnosis, and sends whoever reads
    /// it looking for a malformed packet that was never received.
    ///
    /// It cost a day. `HostUnreachable` here means the announcement left through
    /// an interface that cannot carry it, and the fix is to choose the interface
    /// rather than to look at packets.
    ///
    /// Carries the kind rather than the `io::Error`: this type is `Clone` and
    /// `PartialEq` and the whole crate's tests compare errors by value, while
    /// `io::Error` is neither. The kind is what names the cause.
    NotCarried {
        /// What the operating system said.
        kind: std::io::ErrorKind,
    },
}

impl Error {
    /// Whether this is the ordinary noise of sharing a network.
    ///
    /// True for packets that were never ours. A listener should not report
    /// these; on any real network they are most of what arrives.
    #[must_use]
    pub const fn is_background_noise(&self) -> bool {
        matches!(self, Self::NotForThisNetwork | Self::NotAnAnnouncement)
    }

    /// Whether someone who knew the network id sent something wrong.
    ///
    /// Worth surfacing. It means a party with the roster — a member, or one that
    /// used to be — is announcing something that does not hold up.
    #[must_use]
    pub const fn is_worth_reporting(&self) -> bool {
        matches!(
            self,
            Self::Malformed(_)
                | Self::SignatureInvalid
                | Self::CacheFull { .. }
                | Self::NotCarried { .. }
        )
    }

    /// Whether the socket refused to carry it, as opposed to a packet being
    /// wrong.
    ///
    /// The question a caller has to be able to ask without reading text.
    #[must_use]
    pub const fn is_a_transmission_failure(&self) -> bool {
        matches!(self, Self::NotCarried { .. })
    }
}

impl From<roster::Error> for Error {
    fn from(value: roster::Error) -> Self {
        Self::Malformed(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotForThisNetwork => write!(f, "the packet is not for this network"),
            Self::NotAnAnnouncement => write!(f, "the packet is not an announcement"),
            Self::Malformed(reason) => {
                write!(f, "it decrypted but did not decode: {reason}")
            }
            Self::SignatureInvalid => {
                write!(f, "it decoded but the signature does not verify under the key it names")
            }
            Self::NotNewer { offered, cached } => {
                write!(f, "sequence {offered} does not exceed the cached {cached}")
            }
            Self::CacheFull { limit } => write!(f, "the cache holds its {limit} peers"),
            Self::NotCarried { kind } => {
                write!(f, "the socket would not carry the announcement: {kind}")
            }
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<Error> {
        vec![
            Error::NotForThisNetwork,
            Error::NotAnAnnouncement,
            Error::Malformed(roster::Error::TrailingData),
            Error::SignatureInvalid,
            Error::NotNewer { offered: 1, cached: 2 },
            Error::CacheFull { limit: 256 },
            Error::NotCarried { kind: std::io::ErrorKind::HostUnreachable },
        ]
    }

    #[test]
    fn every_outcome_is_distinct() {
        let all = all();
        for (i, left) in all.iter().enumerate() {
            for (j, right) in all.iter().enumerate() {
                assert_eq!(i == j, left == right, "{left:?} vs {right:?}");
            }
        }
    }

    /// A packet from someone else's network is not a fault. Reporting it would
    /// fill a log with the sound of other people's networks working.
    #[test]
    fn a_foreign_packet_is_not_worth_reporting() {
        assert!(Error::NotForThisNetwork.is_background_noise());
        assert!(!Error::NotForThisNetwork.is_worth_reporting());

        assert!(Error::NotAnAnnouncement.is_background_noise());
        assert!(!Error::NotAnAnnouncement.is_worth_reporting());
    }

    /// Someone who knew the network id sending something that does not verify is
    /// worth knowing about: a member, or a former one, announcing a key it does
    /// not hold.
    #[test]
    fn a_bad_signature_from_inside_is_worth_reporting() {
        assert!(Error::SignatureInvalid.is_worth_reporting());
        assert!(!Error::SignatureInvalid.is_background_noise());
    }

    /// A repeat is neither. §8 requires announcements to be sent more than once,
    /// so hearing one twice is the design working.
    #[test]
    fn a_repeat_is_neither_noise_nor_a_fault() {
        let repeat = Error::NotNewer { offered: 4, cached: 4 };
        assert!(!repeat.is_background_noise());
        assert!(!repeat.is_worth_reporting());
    }

    /// A send that failed is not a packet that was wrong, and a caller must be
    /// able to tell them apart without reading English.
    ///
    /// They were the same variant until two machines on one LAN discovered
    /// nothing for a day while the daemon reported "the packet is not an
    /// announcement" — about a packet it had never received, because the send
    /// had failed with `HostUnreachable`.
    #[test]
    fn a_send_that_failed_is_not_a_malformed_packet() {
        let unsent = Error::NotCarried { kind: std::io::ErrorKind::HostUnreachable };
        let malformed = Error::NotAnAnnouncement;

        assert_ne!(unsent, malformed);
        assert!(unsent.is_a_transmission_failure());
        assert!(!malformed.is_a_transmission_failure());

        // And it is not background: a device announcing to nobody is a fault,
        // while somebody else's packet on a shared port is not.
        assert!(unsent.is_worth_reporting());
        assert!(!unsent.is_background_noise());
    }

    /// The reason the operating system gave survives into the report.
    #[test]
    fn the_cause_of_a_failed_send_is_carried() {
        let unsent = Error::NotCarried { kind: std::io::ErrorKind::HostUnreachable };
        assert!(
            matches!(unsent, Error::NotCarried { kind } if kind == std::io::ErrorKind::HostUnreachable),
            "the kind the operating system gave must survive into the report"
        );
        assert!(unsent.to_string().contains("would not carry"));
    }

    #[test]
    fn an_underlying_decoding_reason_survives() {
        let converted: Error = roster::Error::KeyOrdering.into();
        assert_eq!(converted, Error::Malformed(roster::Error::KeyOrdering));
        assert!(converted.to_string().contains("did not decode"));
    }
}

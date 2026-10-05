//! Why a record was refused.
//!
//! The distinction that matters most is between a refusal about the *publisher*
//! and one about the *record*. A key being rate-limited is behaving normally and
//! will succeed later; a key sending records that do not verify will not,
//! however long it waits. An operator watching this service needs to tell those
//! apart, and so does a client deciding whether to retry.

use core::fmt;

/// The result of handling a record.
pub type Result<T> = core::result::Result<T, Error>;

/// Why a record was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The signature does not verify under the key the record is stored against.
    ///
    /// Covers a forged record, one signed with the wrong key — including a
    /// device's *signing* key rather than its transport key — and one altered
    /// after signing.
    SignatureInvalid,

    /// The sequence does not exceed the one already held.
    ///
    /// Not about the record's contents. The publisher is behind, or something is
    /// replaying an older record at a client.
    SequenceNotNewer {
        /// What the record carried.
        offered: u64,
        /// What is already held.
        held: u64,
    },

    /// Two different records claim the same sequence.
    ///
    /// Both are refused rather than one being chosen. A device that signed two
    /// different records at one sequence has equivocated, and picking a winner
    /// would hide the evidence.
    Equivocation {
        /// The sequence both records claim.
        sequence: u64,
    },

    /// The record belongs to a different network.
    ForeignNetwork,

    /// The record did not decode, or was not canonical.
    ///
    /// Carries roster's reason rather than replacing it, so a non-canonical
    /// encoding stays distinguishable from a truncated one.
    Malformed(roster::Error),

    /// A bound was exceeded. Says nothing about whether the record is valid.
    Limit(Limit),
}

/// Which bound was exceeded.
///
/// Separate from [`Error`] so "you are going too fast" can never be confused
/// with "this record is not valid": the first is recoverable by waiting and the
/// second never is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Limit {
    /// The record is larger than [`crate::limits::MAX_RECORD_SIZE`].
    RecordSize {
        /// The size offered.
        len: usize,
        /// The bound.
        limit: usize,
    },
    /// The record names more addresses than allowed.
    AddressCount {
        /// The count offered.
        count: usize,
        /// The bound.
        limit: usize,
    },
    /// This key published again too soon.
    PublishRate {
        /// The shortest interval accepted, in seconds.
        interval_secs: u64,
    },
    /// This source address has created as many keys as it may.
    KeysPerSource {
        /// The bound.
        limit: usize,
    },
    /// The store holds as many records as it may.
    ///
    /// The one global bound. Reported rather than discarding silently.
    StorageFull {
        /// The bound.
        limit: usize,
    },
}

impl Error {
    /// Whether this refusal is about the publisher rather than the record.
    ///
    /// A publisher refused this way is behaving normally and will succeed later.
    /// One refused any other way will not.
    #[must_use]
    pub const fn is_about_the_publisher(&self) -> bool {
        matches!(self, Self::Limit(_))
    }

    /// Whether the record itself was rejected.
    #[must_use]
    pub const fn is_about_the_record(&self) -> bool {
        matches!(
            self,
            Self::SignatureInvalid
                | Self::SequenceNotNewer { .. }
                | Self::Equivocation { .. }
                | Self::ForeignNetwork
                | Self::Malformed(_)
        )
    }

    /// Whether waiting and retrying the same record could succeed.
    ///
    /// True for exactly two refusals. A client that retried a bad signature
    /// forever would be a client hammering the one piece of shared
    /// infrastructure the project runs.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Limit(Limit::PublishRate { .. } | Limit::StorageFull { .. }))
    }
}

impl From<roster::Error> for Error {
    fn from(value: roster::Error) -> Self {
        Self::Malformed(value)
    }
}

impl From<Limit> for Error {
    fn from(value: Limit) -> Self {
        Self::Limit(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignatureInvalid => {
                write!(f, "the signature does not verify under the key this record is stored under")
            }
            Self::SequenceNotNewer { offered, held } => {
                write!(f, "sequence {offered} does not exceed the {held} already held")
            }
            Self::Equivocation { sequence } => {
                write!(f, "two different records both claim sequence {sequence}")
            }
            Self::ForeignNetwork => write!(f, "the record belongs to a different network"),
            Self::Malformed(reason) => write!(f, "the record did not decode: {reason}"),
            Self::Limit(limit) => write!(f, "{limit}"),
        }
    }
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordSize { len, limit } => {
                write!(f, "the record is {len} bytes, over the {limit} allowed")
            }
            Self::AddressCount { count, limit } => {
                write!(f, "the record names {count} addresses, over the {limit} allowed")
            }
            Self::PublishRate { interval_secs } => {
                write!(f, "this key may publish at most once every {interval_secs} seconds")
            }
            Self::KeysPerSource { limit } => {
                write!(f, "this source has created its {limit} keys")
            }
            Self::StorageFull { limit } => write!(f, "the store holds its {limit} records"),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> Vec<Error> {
        vec![
            Error::SignatureInvalid,
            Error::SequenceNotNewer { offered: 1, held: 2 },
            Error::Equivocation { sequence: 3 },
            Error::ForeignNetwork,
            Error::Malformed(roster::Error::TrailingData),
            Error::Limit(Limit::RecordSize { len: 9000, limit: 8192 }),
            Error::Limit(Limit::AddressCount { count: 20, limit: 16 }),
            Error::Limit(Limit::PublishRate { interval_secs: 5 }),
            Error::Limit(Limit::KeysPerSource { limit: 64 }),
            Error::Limit(Limit::StorageFull { limit: 100_000 }),
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

    /// The distinction the specification requires: a limit says nothing about
    /// the record, and a rejection says nothing about the publisher.
    #[test]
    fn a_limit_refusal_is_not_a_record_refusal() {
        let limited = Error::Limit(Limit::PublishRate { interval_secs: 5 });
        assert!(limited.is_about_the_publisher());
        assert!(!limited.is_about_the_record());

        let invalid = Error::SignatureInvalid;
        assert!(invalid.is_about_the_record());
        assert!(!invalid.is_about_the_publisher());
    }

    #[test]
    fn only_transient_refusals_are_retryable() {
        assert!(Error::Limit(Limit::PublishRate { interval_secs: 5 }).is_retryable());
        assert!(Error::Limit(Limit::StorageFull { limit: 10 }).is_retryable());

        for permanent in [
            Error::SignatureInvalid,
            Error::ForeignNetwork,
            Error::Equivocation { sequence: 1 },
            Error::Limit(Limit::RecordSize { len: 9000, limit: 8192 }),
            Error::Limit(Limit::KeysPerSource { limit: 64 }),
        ] {
            assert!(!permanent.is_retryable(), "{permanent:?} must not invite a retry");
        }
    }

    #[test]
    fn an_underlying_decoding_reason_survives() {
        let converted: Error = roster::Error::KeyOrdering.into();
        assert_eq!(converted, Error::Malformed(roster::Error::KeyOrdering));
        assert!(converted.to_string().contains("did not decode"));
    }

    #[test]
    fn a_sequence_refusal_names_both_numbers() {
        let refusal = Error::SequenceNotNewer { offered: 4, held: 9 };
        let message = refusal.to_string();
        assert!(message.contains('4') && message.contains('9'), "{message}");
    }
}

//! What can go wrong while enrolling, and why each one is its own variant.
//!
//! Enrolment is the moment a person is most likely to be attacked and least
//! likely to be reading carefully. A single "enrolment failed" would leave them
//! unable to tell a mistyped code from a substituted payload, so every refusal
//! here names what was wrong and what a person should do about it.

use core::fmt;

/// The result of an enrolment step.
pub type Result<T> = core::result::Result<T, Error>;

/// Why an enrolment step was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not a payload this version can read.
    ///
    /// Never repaired. A payload that does not decode exactly is refused, so a
    /// person retypes it rather than enrolling on a guess.
    Malformed(&'static str),

    /// A field is longer than its bound.
    TooLong {
        /// Which field.
        field: &'static str,
        /// What it was, in bytes.
        len: usize,
        /// What it may be, in bytes.
        limit: usize,
    },

    /// A field that must not be empty was.
    Empty(&'static str),

    /// The joining device did not prove it holds the signing key it presented.
    ///
    /// The channel proves the transport key; this is the other half. A payload
    /// pairing one device's signing key with another's transport key fails here,
    /// which matters because a device's identity comes from its signing key and
    /// a roster keeps the first admission of a device id for ever.
    PossessionUnproved,

    /// The code entered does not match the code this exchange derived.
    ///
    /// The refusal a person is most likely to see and the one they most need to
    /// understand: either they mistyped, or they are not talking to the machine
    /// they think they are.
    CodeMismatch,

    /// The delivered roster does not admit this device.
    NotAdmitted,

    /// The operation admitting this device was not signed by an admin.
    NotSignedByAdmin,

    /// The delivered roster does not derive to a usable state.
    RosterUnusable(roster::Error),

    /// The network pins a relay certificate other than the one already accepted.
    ///
    /// A relay substituted while this device had no roster to check it against
    /// can prevent an enrolment; it must not survive into membership.
    RelayCertificateChanged,

    /// The exchange did not finish within its deadline.
    ExchangeTimedOut,

    /// This wait has entertained as many exchanges as it will.
    TooManyAttempts {
        /// How many were allowed.
        limit: u32,
    },
    /// This device's own proof of possession was not signed.
    ///
    /// Carries the custody reason whole, because one of them — a person declining
    /// the prompt — is an ordinary outcome and must reach the interface as one.
    NotProved(identity::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(what) => {
                write!(f, "this is not a joining payload: {what}. Copy it again, whole")
            }
            Self::TooLong { field, len, limit } => {
                write!(f, "the {field} is {len} bytes, and at most {limit} are allowed")
            }
            Self::Empty(field) => write!(f, "the {field} is empty, and must not be"),
            Self::PossessionUnproved => f.write_str(
                "the device did not prove it holds the signing key it presented, so the payload \
                 did not come from the device that answered — do not admit it",
            ),
            Self::CodeMismatch => f.write_str(
                "the code does not match this exchange. Either it was mistyped, or the machine \
                 answering is not the one showing you that code",
            ),
            Self::NotAdmitted => f.write_str(
                "the delivered network does not admit this device, so it is not the network that \
                 was being joined",
            ),
            Self::NotSignedByAdmin => {
                f.write_str("the admission was not signed by an admin of that network")
            }
            Self::RosterUnusable(cause) => {
                write!(f, "the delivered network is not usable: {cause}")
            }
            Self::RelayCertificateChanged => f.write_str(
                "the network pins a relay certificate other than the one this device accepted to \
                 reach the exchange",
            ),
            Self::ExchangeTimedOut => {
                f.write_str("the exchange took too long and was abandoned; the wait continues")
            }
            Self::TooManyAttempts { limit } => {
                write!(f, "this wait has already entertained {limit} attempts, and has ended")
            }
            Self::NotProved(cause) => {
                write!(f, "this device's proof that it holds its key was not signed: {cause}")
            }
        }
    }
}

impl core::error::Error for Error {}

impl From<roster::Error> for Error {
    fn from(cause: roster::Error) -> Self {
        Self::RosterUnusable(cause)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// Each of these sends a person somewhere different. A single failure would
    /// send them to the wrong place, and at this moment that is expensive.
    #[test]
    fn every_refusal_is_distinct() {
        let all = [
            Error::Malformed("truncated"),
            Error::TooLong { field: "name", len: 100, limit: 64 },
            Error::Empty("relay"),
            Error::PossessionUnproved,
            Error::CodeMismatch,
            Error::NotAdmitted,
            Error::NotSignedByAdmin,
            Error::RelayCertificateChanged,
            Error::ExchangeTimedOut,
            Error::TooManyAttempts { limit: 10 },
        ];
        for (i, left) in all.iter().enumerate() {
            for (j, right) in all.iter().enumerate() {
                assert_eq!(i == j, left == right, "{left:?} vs {right:?}");
            }
        }
    }

    /// The two refusals a person is most likely to meet must say what to do,
    /// not only what happened.
    #[test]
    fn the_dangerous_refusals_tell_a_person_what_to_do() {
        let mismatch = Error::CodeMismatch.to_string();
        assert!(mismatch.contains("mistyped"), "{mismatch}");
        assert!(mismatch.contains("not the one"), "{mismatch}");

        let unproved = Error::PossessionUnproved.to_string();
        assert!(unproved.contains("do not admit it"), "{unproved}");
    }
}

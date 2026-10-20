//! Why a node could not be built.

use core::fmt;

use roster::types::Algorithm;

/// Why a node could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuildError {
    /// The device's transport key is not ed25519, and a convesso identity is.
    NotEd25519 {
        /// The algorithm it is.
        algorithm: Algorithm,
    },
    /// The network's relay is not one this build can use: not `key@host:port`,
    /// or written for the iroh binding, with a certificate pinned beside it. A
    /// network written for one binding cannot be read by the other.
    UnusableRelay {
        /// What is wrong with it.
        reason: String,
    },
    /// convesso did not start.
    Start(String),
    /// An enrolment exchange failed.
    Exchange(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEd25519 { algorithm } => {
                write!(f, "the transport key is {algorithm:?}, and convesso needs ed25519")
            }
            Self::UnusableRelay { reason } => write!(f, "the network's relay: {reason}"),
            Self::Start(cause) => write!(f, "convesso did not start: {cause}"),
            Self::Exchange(cause) => write!(f, "the enrolment exchange: {cause}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// A build's result.
pub type Result<T> = core::result::Result<T, BuildError>;

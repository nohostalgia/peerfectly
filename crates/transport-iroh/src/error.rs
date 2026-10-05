//! What can go wrong building an endpoint.
//!
//! Session-level failures use `transport::Error`, because a caller above the
//! interface must not be able to tell which implementation it holds. These are
//! the failures that happen *before* there is a session: a key this layer cannot
//! represent, a relay address that is not one, a socket that will not bind.
//!
//! They are separate deliberately. Every one of them is a misconfiguration
//! discoverable at startup, and a node that reported them as "peer unreachable"
//! would send someone hunting for a network fault that does not exist.

use core::fmt;

/// The result of building an endpoint.
pub type Result<T> = core::result::Result<T, BuildError>;

/// Why an endpoint could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuildError {
    /// The device's transport key is not ed25519.
    ///
    /// The connectivity layer identifies endpoints by an ed25519 key, and this
    /// binding makes the device's transport key *be* that identity, so a key of
    /// another algorithm has no representation here.
    ///
    /// DESIGN.md §2.3 settles this: the root key is P-256 because an Apple
    /// enclave imposes it, but device signing and transport keys are ed25519.
    /// Reaching this error means an identity was built outside that rule.
    NotEd25519 {
        /// The algorithm the transport key actually uses.
        algorithm: roster::types::Algorithm,
    },

    /// The network parameters name a relay that is not a usable address.
    ///
    /// The address is signed into the roster, so this is a network-wide
    /// misconfiguration rather than a local one, and every node will hit it.
    UnusableRelay {
        /// The address as the roster carries it.
        address: String,
    },

    /// The network pins a relay certificate that is not one.
    ///
    /// Signed into the roster like the address, so this too is a network-wide
    /// misconfiguration every node will hit. It is refused at bind rather than
    /// at the first connection: a pin that cannot be parsed leaves the trust
    /// store empty, and an empty trust store rejects the real relay as firmly as
    /// an impostor — a failure that would otherwise surface as every peer being
    /// unreachable, with nothing pointing at the certificate.
    UnusableRelayCertificate {
        /// Why the certificate could not be made into a trust anchor.
        reason: String,
    },

    /// The endpoint could not be bound.
    ///
    /// Carries the underlying description rather than discarding it: "the socket
    /// is already in use" and "there is no network" call for different
    /// responses, and neither is this crate's to interpret.
    Bind(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEd25519 { algorithm } => write!(
                f,
                "a transport key must be ed25519 to be an endpoint identity, but this one is {}",
                algorithm.as_str()
            ),
            Self::UnusableRelay { address } => {
                write!(f, "the network's relay address is not usable: {address}")
            }
            Self::UnusableRelayCertificate { reason } => {
                write!(f, "the network's pinned relay certificate is not usable: {reason}")
            }
            Self::Bind(reason) => write!(f, "the endpoint could not be bound: {reason}"),
        }
    }
}

impl core::error::Error for BuildError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each of these sends someone to a different place. A single "could not
    /// start" would send them to the wrong one.
    #[test]
    fn every_build_failure_is_distinct() {
        let all = [
            BuildError::NotEd25519 { algorithm: roster::types::Algorithm::P256 },
            BuildError::UnusableRelay { address: "not a url".to_owned() },
            BuildError::UnusableRelayCertificate { reason: "no anchors".to_owned() },
            BuildError::Bind("address in use".to_owned()),
        ];
        for (i, left) in all.iter().enumerate() {
            for (j, right) in all.iter().enumerate() {
                assert_eq!(i == j, left == right, "{left:?} vs {right:?}");
            }
        }
    }

    /// The message names the algorithm, so the fix is obvious from the log
    /// rather than requiring a debugger.
    #[test]
    fn the_algorithm_refusal_names_the_algorithm() {
        let refusal = BuildError::NotEd25519 { algorithm: roster::types::Algorithm::P256 };
        let message = refusal.to_string();
        assert!(message.contains("p256"), "{message}");
        assert!(message.contains("ed25519"), "{message}");
    }

    /// A pin that will not parse and a relay that will not resolve send someone
    /// to different files on different machines.
    #[test]
    fn a_bad_pin_does_not_read_as_a_bad_address() {
        let pin = BuildError::UnusableRelayCertificate { reason: "no anchors".to_owned() };
        let message = pin.to_string();
        assert!(message.contains("certificate"), "{message}");
        assert!(!message.contains("address"), "{message}");
    }

    #[test]
    fn an_underlying_bind_reason_survives() {
        let refusal = BuildError::Bind("address in use".to_owned());
        assert!(refusal.to_string().contains("address in use"));
    }
}

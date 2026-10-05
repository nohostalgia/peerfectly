//! Why this capability refuses.
//!
//! Distinct from `roster::Error`, because these are failures of *custody* — a
//! key file another user can read, a custodian a person declined — rather than
//! failures of the log's byte-level contract. Where a roster check is the one
//! that failed, its reason is carried through rather than flattened.

use core::fmt;

/// A reason an identity operation did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The operating system would not provide entropy.
    ///
    /// Not something to work around. A node that cannot obtain randomness must
    /// not fall back to anything, because everything else available to it is
    /// predictable.
    NoEntropy,
    /// An identity was assembled with one key value serving two purposes.
    KeyReuse,
    /// A stored identity is readable by a group or by other users.
    ///
    /// Refused rather than read: a check that warns and continues is advice,
    /// not a control.
    PermissiveKeyFile {
        /// The permission bits found, for the message a person will read.
        mode: u32,
    },
    /// A stored identity did not decode, or carried a structurally invalid key.
    CorruptIdentity,
    /// A stored identity is of a version this build does not know.
    UnknownStoredVersion {
        /// The version found.
        found: u64,
    },
    /// The filesystem refused the read or write.
    Storage {
        /// What the operating system reported.
        detail: String,
    },
    /// A supplied signature does not verify over the request it answers.
    ///
    /// Caught here rather than shipped, because an artifact carrying a bad
    /// signature fails on a peer, where the cause is much harder to see.
    SignatureMismatch,
    /// A signature was produced by a key other than the one the request names.
    WrongSigningKey,
    /// A person declined the signing prompt, or it timed out.
    ///
    /// An ordinary outcome the interface must render as such — not a fault to
    /// log and retry.
    Declined,
    /// The custodian could not sign, for a reason that is not a decline.
    CustodianFailed {
        /// What the custodian reported.
        detail: String,
    },
    /// The key is not reachable from this process, and the caller asked anyway.
    ///
    /// A safety net, not a path. Whether a custodian can answer here is asked
    /// before signing, through `detached::KeyCustodian::answers_here` — and a
    /// caller that did not ask reaches this instead of blocking on something that
    /// will never answer.
    SignedElsewhere,
    /// A stored identity names a custodian key that is not there.
    ///
    /// Refused rather than replaced: a new key would make this a different
    /// device, and the roster would still load, so nothing would look wrong until
    /// every peer refused it.
    CustodianKeyMissing {
        /// The name the stored identity knows the key by.
        reference: String,
    },
    /// The custodian holds a key under that name, and it is not the stored one.
    CustodianKeyMismatch {
        /// The name the stored identity knows the key by.
        reference: String,
    },
    /// A key sealed with a passphrase would not open: the passphrase is wrong,
    /// or the stored bytes were changed.
    ///
    /// **One reason, not two.** An authenticated cipher cannot tell them apart,
    /// and naming only one would be a guess presented as a finding.
    WrongPassphraseOrAltered,
    /// A key sealed with a passphrase names stretching parameters below the
    /// floor or above the ceiling, and was refused before anything was derived.
    UnacceptableStretch,
    /// A roster check refused the value.
    Roster(roster::Error),
}

impl Error {
    /// A stable, short name for this reason.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::NoEntropy => "no_entropy",
            Self::KeyReuse => "key_reuse",
            Self::PermissiveKeyFile { .. } => "permissive_key_file",
            Self::CorruptIdentity => "corrupt_identity",
            Self::UnknownStoredVersion { .. } => "unknown_stored_version",
            Self::Storage { .. } => "storage",
            Self::SignatureMismatch => "signature_mismatch",
            Self::WrongSigningKey => "wrong_signing_key",
            Self::Declined => "declined",
            Self::CustodianFailed { .. } => "custodian_failed",
            Self::SignedElsewhere => "signed_elsewhere",
            Self::CustodianKeyMissing { .. } => "custodian_key_missing",
            Self::CustodianKeyMismatch { .. } => "custodian_key_mismatch",
            Self::WrongPassphraseOrAltered => "wrong_passphrase_or_altered",
            Self::UnacceptableStretch => "unacceptable_stretch",
            Self::Roster(_) => "roster",
        }
    }

    /// Every reason this capability can produce.
    pub const ALL_KINDS: &'static [&'static str] = &[
        "no_entropy",
        "key_reuse",
        "permissive_key_file",
        "corrupt_identity",
        "unknown_stored_version",
        "storage",
        "signature_mismatch",
        "wrong_signing_key",
        "declined",
        "custodian_failed",
        "signed_elsewhere",
        "custodian_key_missing",
        "custodian_key_mismatch",
        "wrong_passphrase_or_altered",
        "unacceptable_stretch",
        "roster",
    ];

    /// Whether this is a person declining rather than something going wrong.
    #[must_use]
    pub const fn is_declined(&self) -> bool {
        matches!(self, Self::Declined)
    }
}

impl From<roster::Error> for Error {
    fn from(value: roster::Error) -> Self {
        Self::Roster(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Storage { detail: value.to_string() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEntropy => f.write_str("the system would not provide entropy"),
            Self::KeyReuse => f.write_str("one key value cannot serve both signing and transport"),
            Self::PermissiveKeyFile { mode } => {
                write!(f, "the key file is readable beyond its owner (mode {mode:o})")
            }
            Self::CorruptIdentity => f.write_str("the stored identity did not decode"),
            Self::UnknownStoredVersion { found } => {
                write!(f, "the stored identity is version {found}, which this build cannot read")
            }
            Self::Storage { detail } => write!(f, "storage: {detail}"),
            Self::SignatureMismatch => {
                f.write_str("the signature does not verify over the request it answers")
            }
            Self::WrongSigningKey => {
                f.write_str("the signature was made by a key the request does not name")
            }
            Self::Declined => f.write_str("signing was declined"),
            Self::CustodianFailed { detail } => write!(f, "the key custodian failed: {detail}"),
            Self::SignedElsewhere => f.write_str(
                "this signing key cannot be used from this process; the request must be prepared and signed where the key is",
            ),
            Self::CustodianKeyMissing { reference } => write!(
                f,
                "the signing key `{reference}` this identity is kept under is not in the key \
                 store; it was not replaced, because a new key would be a different device"
            ),
            Self::CustodianKeyMismatch { reference } => write!(
                f,
                "the key store holds a different key under `{reference}` from the one this \
                 identity was stored with"
            ),
            Self::WrongPassphraseOrAltered => f.write_str(
                "the key would not open: the passphrase is wrong, or the stored key was changed",
            ),
            Self::UnacceptableStretch => f.write_str(
                "the stored key names stretching parameters outside what is accepted, and was                  refused before anything was derived",
            ),
            Self::Roster(inner) => write!(f, "roster: {inner}"),
        }
    }
}

impl core::error::Error for Error {}

/// Result alias for identity operations.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;
    use std::collections::BTreeSet;

    /// Each reason this capability refuses is its own reason.
    #[test]
    fn every_reason_is_distinct() {
        let samples = [
            Error::NoEntropy,
            Error::KeyReuse,
            Error::PermissiveKeyFile { mode: 0o644 },
            Error::CorruptIdentity,
            Error::UnknownStoredVersion { found: 9 },
            Error::Storage { detail: "sample".to_owned() },
            Error::SignatureMismatch,
            Error::WrongSigningKey,
            Error::Declined,
            Error::CustodianFailed { detail: "sample".to_owned() },
            Error::SignedElsewhere,
            Error::CustodianKeyMissing { reference: "sample".to_owned() },
            Error::CustodianKeyMismatch { reference: "sample".to_owned() },
            Error::WrongPassphraseOrAltered,
            Error::UnacceptableStretch,
            Error::Roster(roster::Error::InvalidKey),
        ];
        let unique: BTreeSet<&str> = samples.iter().map(Error::kind).collect();
        assert_eq!(unique.len(), samples.len(), "two reasons share a kind string");
        assert_eq!(samples.len(), Error::ALL_KINDS.len());
        for sample in &samples {
            assert!(Error::ALL_KINDS.contains(&sample.kind()), "{} is missing", sample.kind());
        }
    }

    /// A decline is not a failure, and callers must be able to tell.
    #[test]
    fn a_decline_is_distinguishable_from_a_failure() {
        assert!(Error::Declined.is_declined());
        assert!(!Error::CustodianFailed { detail: "hardware".to_owned() }.is_declined());
        assert!(!Error::SignatureMismatch.is_declined());
    }

    #[test]
    fn a_roster_refusal_is_carried_through_rather_than_flattened() {
        let converted: Error = roster::Error::KeyReuse.into();
        assert_eq!(converted, Error::Roster(roster::Error::KeyReuse));
        assert!(format!("{converted}").contains("key_reuse"));
    }
}

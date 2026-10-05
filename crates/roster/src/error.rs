//! The rejection taxonomy.
//!
//! Every way the roster can refuse input has its own variant. This is not
//! decoration: the shared test-vector corpus names an expected error kind for
//! each negative vector, and a second implementation that rejects the same
//! bytes for a different reason is a divergence worth seeing.
//!
//! There is deliberately no "unsupported" or "ignored" outcome. An operation
//! this code cannot parse might be a revocation, so the only options are
//! "understood and accepted" and "rejected with a reason".

use core::fmt;

/// A reason the roster refused to accept some input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Input ended before the current item was complete.
    UnexpectedEof,
    /// Valid CBOR, but not in canonical form: a non-minimal integer width, an
    /// indefinite-length item, or a reserved additional-information value.
    NonCanonical,
    /// An item's CBOR major type was not the one the schema requires here.
    TypeMismatch,
    /// A text string was not valid UTF-8.
    InvalidUtf8,
    /// Map keys were not in canonical order (shorter key first, then bytewise).
    KeyOrdering,
    /// The same map key appeared more than once.
    DuplicateKey,
    /// A map carried a key the schema does not define.
    UnknownField,
    /// A map omitted a key the schema requires. The one optional field, the
    /// network's IPv4 range, is absent only by being left out of a map one
    /// entry shorter; every other absent field is refused, never read as a
    /// default.
    MissingField,
    /// Bytes remained in the buffer after the top-level item ended.
    TrailingData,
    /// A declared or actual size exceeded its documented bound. The payload
    /// names which bound, so an operator can tell a hostile peer from a
    /// legitimately large network.
    LimitExceeded(&'static str),
    /// The `type` field was not one of the seven defined operation types.
    UnknownOperationType,
    /// The body did not match the schema of the declared operation type.
    BodySchema,
    /// The `alg` field named an algorithm this implementation does not know.
    /// Never a reason to skip the operation.
    UnknownAlgorithm,
    /// A field constrained to a fixed set of values carried something else.
    /// The payload names the field.
    InvalidValue(&'static str),
    /// An identifier or key had the wrong length. Identifiers are never
    /// truncated, so a short one is an error rather than a prefix.
    IdentifierLength,
    /// The stated operation id did not match the one recomputed from the
    /// received bytes.
    IdMismatch,
    /// A device reused one key value for two different purposes.
    KeyReuse,
    /// A device record carried no signing key, so it has no derivable id.
    MissingSigningKey,
    /// A device record carried no attestation key, so it could never date the
    /// roster it belongs to.
    MissingAttestationKey,
    /// A public key was structurally invalid, or of small order.
    InvalidKey,
    /// A signature was not in the required fixed-width encoding, or carried a
    /// scalar outside its canonical range.
    SignatureEncoding,
    /// The signature did not verify against the supplied key.
    SignatureInvalid,
    /// The supplied public key does not hash to the operation's `author`.
    AuthorKeyMismatch,
    /// The operation's `network` field names a different network.
    ForeignNetwork,
    /// A second `create_network` was offered; a roster has exactly one.
    DuplicateGenesis,
    /// No `create_network` is present, so no network is established.
    MissingGenesis,
    /// A non-genesis operation named no parents. Only the founding operation
    /// may be parentless.
    ParentlessOperation,
    /// The operation set presents a cycle and cannot be ordered causally.
    CyclicHistory,
    /// The author did not hold the role this operation requires, in the state
    /// derived from the operation's own causal ancestors.
    UnauthorizedAuthor,
    /// The device this operation names is not in the state its own causal
    /// ancestors imply, or is already revoked there.
    ///
    /// Such an operation can never have an effect: derivation ignores one whose
    /// target does not exist, and a second revocation of a revoked device says
    /// nothing the first did not. Refused rather than admitted, because the graph
    /// is bounded and the room kept for revocations must not be fillable with
    /// revocations of devices nobody ever added.
    UnknownTarget,
    /// The operation is causally concurrent with the removal of its author's
    /// authority. Work done before losing authority stays valid; work that
    /// surfaces afterwards does not.
    ConcurrentWithAuthorRemoval,
    /// A `revoke_device` or `demote` targeted a founder, and its author was not
    /// that founder.
    FounderProtected,
    /// The operation's author signed two causally concurrent operations: one
    /// identity, two histories. Neither branch is granted effect, because
    /// choosing between them would be letting the author choose — it decided
    /// what to show to whom.
    Equivocated,
    /// The operation is anchored further behind the local frontier than this
    /// node accepts. Local policy, never a statement about derived state.
    StaleOperation,
    /// A snapshot's sequence number did not advance past the highest accepted.
    /// Refusing it is what blocks a rollback served by a compromised
    /// rendezvous.
    SnapshotSequenceRegressed,
    /// Two snapshots share a sequence number and disagree. Both are refused:
    /// this is either two admins acting at once or an author equivocating, and
    /// picking a winner between them would hide it.
    SnapshotSequenceConflict,
    /// A snapshot's stated state disagrees with what this node derives from the
    /// operations it holds. The node's own derivation wins.
    SnapshotStateMismatch,
    /// A snapshot could not be verified against operations this node holds, and
    /// so cannot be leaned on for anything that discards evidence.
    SnapshotUnverified,
    /// Compaction was asked for but a precondition did not hold.
    CompactionRefused(&'static str),
}

impl Error {
    /// A stable, language-neutral name for this rejection reason.
    ///
    /// The test-vector corpus stores these strings, so other implementations
    /// can assert not just *that* they rejected an input but *why*. Changing
    /// one of these strings is a corpus-visible change.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::UnexpectedEof => "unexpected_eof",
            Self::NonCanonical => "non_canonical",
            Self::TypeMismatch => "type_mismatch",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::KeyOrdering => "key_ordering",
            Self::DuplicateKey => "duplicate_key",
            Self::UnknownField => "unknown_field",
            Self::MissingField => "missing_field",
            Self::TrailingData => "trailing_data",
            Self::LimitExceeded(_) => "limit_exceeded",
            Self::UnknownOperationType => "unknown_operation_type",
            Self::BodySchema => "body_schema",
            Self::UnknownAlgorithm => "unknown_algorithm",
            Self::InvalidValue(_) => "invalid_value",
            Self::IdentifierLength => "identifier_length",
            Self::IdMismatch => "id_mismatch",
            Self::KeyReuse => "key_reuse",
            Self::MissingSigningKey => "missing_signing_key",
            Self::MissingAttestationKey => "missing_attestation_key",
            Self::InvalidKey => "invalid_key",
            Self::SignatureEncoding => "signature_encoding",
            Self::SignatureInvalid => "signature_invalid",
            Self::AuthorKeyMismatch => "author_key_mismatch",
            Self::ForeignNetwork => "foreign_network",
            Self::DuplicateGenesis => "duplicate_genesis",
            Self::MissingGenesis => "missing_genesis",
            Self::ParentlessOperation => "parentless_operation",
            Self::CyclicHistory => "cyclic_history",
            Self::UnauthorizedAuthor => "unauthorized_author",
            Self::UnknownTarget => "unknown_target",
            Self::ConcurrentWithAuthorRemoval => "concurrent_with_author_removal",
            Self::FounderProtected => "founder_protected",
            Self::Equivocated => "equivocated",
            Self::StaleOperation => "stale_operation",
            Self::SnapshotSequenceRegressed => "snapshot_sequence_regressed",
            Self::SnapshotSequenceConflict => "snapshot_sequence_conflict",
            Self::SnapshotStateMismatch => "snapshot_state_mismatch",
            Self::SnapshotUnverified => "snapshot_unverified",
            Self::CompactionRefused(_) => "compaction_refused",
        }
    }

    /// Every rejection reason this implementation can produce.
    ///
    /// The corpus test walks this list and fails if any reason has no negative
    /// vector, so adding a variant without a vector breaks the build.
    pub const ALL_KINDS: &'static [&'static str] = &[
        "unexpected_eof",
        "non_canonical",
        "type_mismatch",
        "invalid_utf8",
        "key_ordering",
        "duplicate_key",
        "unknown_field",
        "missing_field",
        "trailing_data",
        "limit_exceeded",
        "unknown_operation_type",
        "body_schema",
        "unknown_algorithm",
        "invalid_value",
        "identifier_length",
        "id_mismatch",
        "key_reuse",
        "missing_signing_key",
        "missing_attestation_key",
        "invalid_key",
        "signature_encoding",
        "signature_invalid",
        "author_key_mismatch",
        "foreign_network",
        "duplicate_genesis",
        "missing_genesis",
        "parentless_operation",
        "cyclic_history",
        "unauthorized_author",
        "unknown_target",
        "concurrent_with_author_removal",
        "founder_protected",
        "equivocated",
        "stale_operation",
        "snapshot_sequence_regressed",
        "snapshot_sequence_conflict",
        "snapshot_state_mismatch",
        "snapshot_unverified",
        "compaction_refused",
    ];
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded(which) => write!(f, "limit exceeded: {which}"),
            Self::InvalidValue(field) => write!(f, "invalid value for field: {field}"),
            Self::CompactionRefused(why) => write!(f, "compaction refused: {why}"),
            other => f.write_str(other.kind()),
        }
    }
}

impl core::error::Error for Error {}

/// Result alias for roster operations.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;
    use std::collections::BTreeSet;

    /// Every variant the spec names as a rejection reason maps to a distinct
    /// kind string. Two reasons sharing a string would make the corpus unable
    /// to tell them apart.
    #[test]
    fn every_rejection_reason_is_distinct() {
        let unique: BTreeSet<&str> = Error::ALL_KINDS.iter().copied().collect();
        assert_eq!(
            unique.len(),
            Error::ALL_KINDS.len(),
            "two rejection reasons share a kind string"
        );
    }

    /// `ALL_KINDS` is written by hand, so it can drift from the enum. Every
    /// constructible variant must appear in it.
    #[test]
    fn all_kinds_covers_every_variant() {
        let samples = [
            Error::UnexpectedEof,
            Error::NonCanonical,
            Error::TypeMismatch,
            Error::InvalidUtf8,
            Error::KeyOrdering,
            Error::DuplicateKey,
            Error::UnknownField,
            Error::MissingField,
            Error::TrailingData,
            Error::LimitExceeded("sample"),
            Error::UnknownOperationType,
            Error::BodySchema,
            Error::UnknownAlgorithm,
            Error::InvalidValue("sample"),
            Error::IdentifierLength,
            Error::IdMismatch,
            Error::KeyReuse,
            Error::MissingSigningKey,
            Error::MissingAttestationKey,
            Error::InvalidKey,
            Error::SignatureEncoding,
            Error::SignatureInvalid,
            Error::AuthorKeyMismatch,
            Error::ForeignNetwork,
            Error::DuplicateGenesis,
            Error::MissingGenesis,
            Error::ParentlessOperation,
            Error::CyclicHistory,
            Error::UnauthorizedAuthor,
            Error::UnknownTarget,
            Error::ConcurrentWithAuthorRemoval,
            Error::FounderProtected,
            Error::Equivocated,
            Error::StaleOperation,
            Error::SnapshotSequenceRegressed,
            Error::SnapshotSequenceConflict,
            Error::SnapshotStateMismatch,
            Error::SnapshotUnverified,
            Error::CompactionRefused("sample"),
        ];
        assert_eq!(samples.len(), Error::ALL_KINDS.len());
        for sample in &samples {
            assert!(
                Error::ALL_KINDS.contains(&sample.kind()),
                "{} is missing from ALL_KINDS",
                sample.kind()
            );
        }
    }
}

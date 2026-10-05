//! Protocol constants bounding every otherwise-unbounded structure.
//!
//! These are not tuning knobs. A node that raises one of them accepts
//! operations its peers reject, which forks the network as surely as a
//! disagreement about byte order would. They change only together with the
//! `"roster/v1"` domain-separation tag.
//!
//! The point of the bounds is that a compromised admin, who can legitimately
//! sign operations, still cannot make a phone allocate an arbitrary amount of
//! memory. Every bound is therefore checked against the *declared* length
//! before any buffer is reserved, not against the length actually delivered.

/// Maximum size in bytes of one encoded operation, as received.
///
/// An `add_device` carrying three keys and a handful of capabilities sits well
/// under 1 KiB. The headroom covers future body growth without letting a single
/// operation matter to a mobile client's memory.
pub const MAX_OPERATION_SIZE: usize = 8 * 1024;

/// Maximum number of parent ids one operation may name.
///
/// A merge in a network of a few dozen devices needs a handful of parents.
/// Thirty-two is generous for the product's stated scale of one household.
pub const MAX_PARENTS: usize = 32;

/// Maximum number of key entries in one device record.
///
/// A signing key, a transport key, an enclave-held key, and room to rotate.
pub const MAX_KEYS_PER_DEVICE: usize = 8;

/// Maximum length in bytes of a device name.
///
/// The name is rendered in a list on a phone; anything longer is truncated by
/// the UI anyway, and letting it grow only helps an attacker fill storage.
pub const MAX_NAME_LEN: usize = 64;

/// Maximum number of capability strings on one device.
pub const MAX_CAPABILITIES: usize = 16;

/// Maximum length in bytes of a single capability string.
///
/// `lan_exit:` followed by an IPv6 CIDR fits comfortably.
pub const MAX_CAPABILITY_LEN: usize = 128;

/// Maximum length in bytes of a revocation reason.
///
/// The reason is shown to a person deciding whether to trust a device again.
/// It is prose, not a log.
pub const MAX_REASON_LEN: usize = 256;

/// Maximum length in bytes of the network name suffix.
///
/// A DNS suffix under `.internal`; the DNS label limits are far below this.
pub const MAX_SUFFIX_LEN: usize = 64;

/// Length in bytes of every identifier in the format.
///
/// BLAKE3 output, never truncated. DESIGN.md §4.2 is explicit that truncating
/// an operation id is not an option: the id is what fixes an operation's
/// position in the DAG.
pub const ID_LEN: usize = 32;

/// Length in bytes of an encoded signature.
///
/// Both supported algorithms produce 64 bytes: ed25519 natively, and P-256 as
/// fixed-width `r || s` with DER never entering the format.
pub const SIGNATURE_LEN: usize = 64;

/// Maximum length in bytes of a public key value in a key entry.
///
/// ed25519 and P-256 compressed keys are 32 and 33 bytes. The bound exists so
/// an unknown algorithm cannot smuggle in a large blob before the algorithm
/// itself is rejected.
pub const MAX_PUBLIC_KEY_LEN: usize = 64;

/// Maximum length in bytes of the relay address carried in the network
/// parameters.
///
/// A relay URL: a scheme, a host and perhaps a port. Generous against the
/// longest plausible hostname, and bounded because the parameters travel inside
/// an operation whose own size is bounded.
pub const MAX_RELAY_LEN: usize = 128;

/// The longest relay certificate a network may pin, in bytes of DER.
///
/// A certificate is the relay's identity, carried in the signed parameters so
/// the roster authenticates the relay rather than a certificate authority
/// doing it. Ordinary certificates are one to two kilobytes; this leaves room
/// for a chain without letting a parameter become an attachment.
pub const MAX_RELAY_CERT_LEN: usize = 4096;

/// The longest rendezvous address a network may carry, in bytes.
///
/// The same bound as the relay's, for the same reason: it is a URL somebody
/// types once, not a place to hide a payload.
pub const MAX_RENDEZVOUS_LEN: usize = 128;

/// Maximum length in bytes of the ULA prefix carried in the network parameters.
///
/// An IPv6 address is 16 bytes; the prefix is at most that.
pub const MAX_ULA_PREFIX_LEN: usize = 16;

/// Maximum length in bytes of any map key in the format.
///
/// Keys are short text strings. Holding them under CBOR's 24-byte inline
/// threshold means canonical key ordering reduces to comparing
/// `(length, bytes)`, with no header-width special case to get wrong.
pub const MAX_MAP_KEY_LEN: usize = 23;

/// Maximum number of operations one roster may hold.
///
/// Ancestry is stored as a bitset per operation, so the cost is quadratic:
/// 4096 operations is 2 MiB, which a phone can carry. A household producing an
/// operation a week reaches this in eight decades, and compaction arrives long
/// before that.
///
/// Protocol-adjacent: a node that raises this accepts rosters its peers refuse.
pub const MAX_OPERATIONS: usize = 4096;

/// How many of those may be operations that are **not** revocations.
///
/// The rest of the ceiling is kept for revocations, and nothing else may take
/// it. Without the reserve the ceiling is reached by whatever arrives first, and
/// a network that has reached it can no longer revoke the device that filled it
/// — which is the state the security review's finding F-02 described as
/// permanent: nobody can be admitted or revoked again, including the device that
/// did it.
///
/// 512 left for revocations is more than a household-scale network is likely to
/// produce in its whole life, and every one of them must name a device that was
/// really added, so the room cannot be filled with revocations of devices nobody
/// ever created. A network that has honestly revoked 512 devices has reached the
/// ceiling the ordinary way, and compaction is its remedy.
///
/// Protocol-adjacent, like the ceiling itself: a node with a different share
/// admits rosters its peers refuse.
pub const MAX_NON_REVOCATION_OPERATIONS: usize = 3584;

/// Maximum number of operations held awaiting their parents.
///
/// Enough to absorb an out-of-order burst during a sync, small enough that junk
/// from a hostile peer cannot matter on a phone. Operations here have not been
/// signature-verified, because the key that would verify them is derived from
/// the ancestors that are missing.
pub const MAX_PENDING_OPERATIONS: usize = 256;

/// How far behind the local frontier an operation may be anchored, by default.
///
/// This is **not** a protocol constant. It governs local admission only, never
/// derived state, and two nodes running different values must still derive
/// identical rosters from the same operations.
///
/// Deliberately generous: in a network producing a few operations a month, 64
/// of causal depth is years, so a phone that was honestly switched off is never
/// locked out. Tightening it narrows an attacker's window at the cost of
/// refusing real work from devices that were away.
pub const DEFAULT_STALENESS_DEPTH: u64 = 64;

/// Maximum number of heads one snapshot may cover.
///
/// A snapshot attests to everything beneath a set of heads. In a household
/// network the head count is one most of the time and a handful after a merge;
/// the bound is the same order as `MAX_PARENTS` for the same reason.
pub const MAX_SNAPSHOT_HEADS: usize = 32;

/// Maximum size in bytes of an encoded snapshot.
///
/// A snapshot carries the whole derived roster, so it scales with the device
/// count rather than with history. Sixty-four devices with keys, names and
/// capabilities sit far below this.
pub const MAX_SNAPSHOT_SIZE: usize = 64 * 1024;

/// Maximum size in bytes of an encoded attestation.
///
/// Two orders below a snapshot's bound, and deliberately: an attestation carries
/// heads and no state, so its size follows `MAX_SNAPSHOT_HEADS` and nothing
/// else. A bound this tight is itself a check — an attestation that had grown a
/// state field could not fit through it.
pub const MAX_ATTESTATION_SIZE: usize = 4 * 1024;

/// The `snapshot_window` a newly founded network carries, in seconds.
///
/// Seven days. It was thirty because the only device that could date a roster on
/// a phone was one a person had just unlocked, so an admin phone attested only
/// while somebody was holding it — and a window this short made an ordinary
/// network read as stale. An attestation key that needs no person removes that
/// reason, and the shorter window is what bounds the revocation window.
///
/// A **default**, not a rule: the window is a signed network parameter, so this
/// changes what a new network carries and nothing about one that exists.
pub const DEFAULT_SNAPSHOT_WINDOW: u64 = 7 * 24 * 60 * 60;

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin every protocol constant. A change to one of these is a change to
    /// what the network accepts, so it should never pass silently in a diff
    /// that claims to be a refactor.
    #[test]
    fn protocol_constants_are_pinned() {
        assert_eq!(MAX_OPERATION_SIZE, 8192);
        assert_eq!(MAX_PARENTS, 32);
        assert_eq!(MAX_KEYS_PER_DEVICE, 8);
        assert_eq!(MAX_NAME_LEN, 64);
        assert_eq!(MAX_CAPABILITIES, 16);
        assert_eq!(MAX_CAPABILITY_LEN, 128);
        assert_eq!(MAX_REASON_LEN, 256);
        assert_eq!(MAX_SUFFIX_LEN, 64);
        assert_eq!(ID_LEN, 32);
        assert_eq!(SIGNATURE_LEN, 64);
        assert_eq!(MAX_PUBLIC_KEY_LEN, 64);
        assert_eq!(MAX_ULA_PREFIX_LEN, 16);
        assert_eq!(MAX_RELAY_LEN, 128);
        assert_eq!(MAX_MAP_KEY_LEN, 23);
        assert_eq!(MAX_OPERATIONS, 4096);
        assert_eq!(MAX_NON_REVOCATION_OPERATIONS, 3584);
        const {
            assert!(
                MAX_NON_REVOCATION_OPERATIONS < MAX_OPERATIONS,
                "the reserve has to leave room for a revocation"
            );
        }
        assert_eq!(
            MAX_OPERATIONS - MAX_NON_REVOCATION_OPERATIONS,
            512,
            "and the room it leaves is the reserve this bound exists for"
        );
        assert_eq!(MAX_PENDING_OPERATIONS, 256);
        assert_eq!(MAX_SNAPSHOT_HEADS, 32);
        assert_eq!(MAX_SNAPSHOT_SIZE, 65536);
        assert_eq!(MAX_ATTESTATION_SIZE, 4096);
        assert_eq!(DEFAULT_SNAPSHOT_WINDOW, 604_800, "seven days");
        const {
            assert!(
                MAX_ATTESTATION_SIZE < MAX_SNAPSHOT_SIZE,
                "an attestation carries no state, so it cannot need a snapshot's room"
            );
        }
    }

    /// The staleness default is a policy knob rather than a protocol constant,
    /// but pinning it still keeps a silent change out of an unrelated diff.
    #[test]
    fn the_staleness_default_is_pinned() {
        assert_eq!(DEFAULT_STALENESS_DEPTH, 64);
    }

    /// The map-key bound exists to keep canonical ordering free of the
    /// multi-byte-header case. If it ever rose to 24 the ordering rule in
    /// `cbor` would silently become wrong.
    #[test]
    fn map_keys_stay_below_the_cbor_inline_threshold() {
        const { assert!(MAX_MAP_KEY_LEN < 24) };
    }
}

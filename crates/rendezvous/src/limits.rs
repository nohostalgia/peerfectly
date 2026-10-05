//! What one key, and one source, can cost.
//!
//! §2.8 requires these from the first version rather than as a later hardening
//! pass, and the reason is simple: this is the only piece of shared
//! infrastructure the project runs, and the first day it is public is the first
//! day it is a target. A service without limits is a service anyone can fill.
//!
//! Every bound here is per key or per source address. There is exactly one
//! global bound — total stored records — and reaching it is reported rather than
//! silently discarding, because a store that quietly drops is a store that
//! quietly stops working.

/// Maximum encoded size of one record.
///
/// Bounded because the service reads it from a stranger, and large enough to
/// hold a record that fills every other bound — a limit that refused a
/// legitimate publication would be worse than no limit. The same value as
/// roster's operation bound, so there is one size to remember rather than two.
pub const MAX_RECORD_SIZE: usize = 8192;

/// What sealing adds to the contents: a 12-byte nonce and a 16-byte tag.
pub const SEAL_OVERHEAD: usize = 28;

/// Maximum size of a record as it travels, before its signature: what fits in
/// [`MAX_RECORD_SIZE`], sealed, with room for the key and sequence around it.
pub const MAX_WIRE_SIZE: usize = MAX_RECORD_SIZE + SEAL_OVERHEAD + 128;

/// Maximum number of addresses one record may name.
///
/// A device has a handful of paths: a LAN address, a global one, a relay. More
/// than this is not a device describing itself.
pub const MAX_ADDRESSES: usize = 16;

/// Maximum length of one address.
///
/// Addresses are opaque to this crate, so this bounds a string rather than a
/// parsed form. Long enough for a URL with a host and a port.
pub const MAX_ADDRESS_LEN: usize = 256;

/// Minimum interval between accepted publications for one key.
///
/// A device publishes when its addresses change, which is rare. This is loose
/// enough never to inconvenience one and tight enough that a key cannot be used
/// to generate load.
pub const MIN_PUBLISH_INTERVAL_SECS: u64 = 5;

/// Maximum number of distinct keys one source address may create.
///
/// The only bound keyed on something the service observes rather than something
/// a record proves. Without it, one host can fill the store with keys nobody
/// will ever fetch, and every record would verify perfectly.
pub const MAX_KEYS_PER_SOURCE: usize = 64;

/// Maximum number of records stored in total.
///
/// The one global bound. Reaching it is reported.
pub const MAX_RECORDS: usize = 100_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stated_bounds_are_pinned() {
        assert_eq!(MAX_RECORD_SIZE, 8192);
        assert_eq!(MAX_RECORD_SIZE, roster::limits::MAX_OPERATION_SIZE);
        assert_eq!(MAX_ADDRESSES, 16);
        assert_eq!(MAX_ADDRESS_LEN, 256);
        assert_eq!(MIN_PUBLISH_INTERVAL_SECS, 5);
        assert_eq!(MAX_KEYS_PER_SOURCE, 64);
        assert_eq!(MAX_RECORDS, 100_000);
    }

    /// The record bound must actually accommodate the largest record the other
    /// bounds allow, or a legitimate device would be unable to publish.
    #[test]
    fn a_record_at_every_other_bound_still_fits() {
        // Addresses dominate: each is a string plus a short CBOR header.
        let addresses = MAX_ADDRESSES.saturating_mul(MAX_ADDRESS_LEN.saturating_add(3));
        // Key, sequence, network id, and the map and array headers.
        let overhead = 128;
        assert!(
            addresses.saturating_add(overhead) <= MAX_RECORD_SIZE,
            "a record filling every other bound must fit in {MAX_RECORD_SIZE}"
        );
    }
}

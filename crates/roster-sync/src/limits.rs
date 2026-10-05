//! Bounds on what one peer can cause.
//!
//! Every value here exists because something on the other end of a session is
//! not necessarily friendly. They are stated as relations to bounds the roster
//! and the transport already fix, so that changing one of those cannot silently
//! leave this crate inconsistent with it.

/// The most pending entries one peer device may occupy.
///
/// An operation whose parents are absent is held pending, and pending entries
/// are unverified by necessity — the author's key is resolved from state
/// derived from the very ancestors that are missing. The set is bounded. Without
/// per-peer accounting, one peer fills it, and the `revoke_device` that names
/// that peer arrives to find nowhere to wait.
///
/// An eighth of the roster's bound, so at least eight distinct devices can hold
/// pending entries whatever any other peer does. Reserving space for
/// revocations specifically would not work: an attacker labels junk as one.
pub const PENDING_PER_PEER: usize = roster::limits::MAX_PENDING_OPERATIONS / 8;

/// The most operation ids an offer may name.
///
/// A roster holds at most `MAX_OPERATIONS`, so an offer claiming more describes
/// a roster that cannot exist. Refusing at the declared count is what stops a
/// peer making this node allocate on its say-so.
pub const MAX_OFFERED_IDS: usize = roster::limits::MAX_OPERATIONS;

/// The most operations one transfer message may carry.
///
/// A transfer answers an offer, so it can name at most what a roster holds.
pub const MAX_TRANSFERRED: usize = roster::limits::MAX_OPERATIONS;

#[cfg(test)]
mod tests {
    use super::*;

    /// The quota is stated as a relation, not a number typed twice. A test that
    /// only checked the literal would pass while the relation it exists for had
    /// quietly stopped holding.
    #[test]
    fn the_quota_leaves_room_for_eight_peers() {
        assert_eq!(PENDING_PER_PEER, 32);
        assert_eq!(PENDING_PER_PEER * 8, roster::limits::MAX_PENDING_OPERATIONS);
        const { assert!(PENDING_PER_PEER > 0, "a quota of zero would refuse everything") };
    }

    /// An offer may not describe a roster larger than one that can exist.
    #[test]
    fn an_offer_cannot_name_more_than_a_roster_holds() {
        assert_eq!(MAX_OFFERED_IDS, roster::limits::MAX_OPERATIONS);
        assert_eq!(MAX_TRANSFERRED, roster::limits::MAX_OPERATIONS);
    }
}

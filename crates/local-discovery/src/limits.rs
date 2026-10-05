//! Bounds on what arrives from a network anyone can join.
//!
//! A local network is not a trusted place. Everything here is read from a
//! stranger's packet, so every count and length is bounded before anything is
//! reserved for it.

/// Maximum size of an announcement packet, encrypted, as it leaves the socket.
///
/// The payload is a record — a key, a network id, a sequence and a short list of
/// addresses — plus a signature, a nonce and the AEAD's tag. Comfortably under
/// the smallest MTU anyone still runs, because a fragmented multicast datagram
/// on a wireless network is a datagram that does not arrive.
pub const MAX_PACKET_SIZE: usize = 1200;

/// Length of the random nonce prefixed to every packet.
pub const NONCE_LEN: usize = 12;

/// Maximum number of peers held in the cache.
///
/// A personal network, not a directory. Reaching this is reported rather than
/// silently discarding, because a cache that quietly drops is a cache that
/// quietly stops making the first path fast.
pub const MAX_CACHED_PEERS: usize = 256;

/// Maximum addresses remembered for one peer.
///
/// A device has a handful of paths on a local network: one per interface, and
/// rarely more than two of those.
pub const MAX_ADDRESSES_PER_PEER: usize = 8;

/// How often a device repeats its announcement, in seconds.
///
/// §8: multicast on wireless is filtered outright or delivered at the lowest
/// bitrate, so an announcement sent once is an announcement that may never
/// arrive. Repeating is the design, not a retry.
pub const ANNOUNCE_INTERVAL_SECS: u64 = 15;

/// How long a cached entry is offered before it is considered worthless.
///
/// Long enough to survive a laptop lid being closed over lunch. An entry past it
/// is not wrong, only unlikely — and trying it costs one attempt, so the bound
/// is generous rather than cautious.
pub const CACHE_ENTRY_MAX_AGE_SECS: u64 = 3600;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stated_bounds_are_pinned() {
        assert_eq!(MAX_PACKET_SIZE, 1200);
        assert_eq!(NONCE_LEN, 12);
        assert_eq!(MAX_CACHED_PEERS, 256);
        assert_eq!(MAX_ADDRESSES_PER_PEER, 8);
        assert_eq!(ANNOUNCE_INTERVAL_SECS, 15);
        assert_eq!(CACHE_ENTRY_MAX_AGE_SECS, 3600);
    }

    /// A packet must be small enough to cross a wireless network unfragmented.
    /// A fragmented multicast datagram is one that does not arrive, and the
    /// whole point of this crate is the path that works when nothing else does.
    #[test]
    fn a_packet_fits_inside_the_smallest_plausible_mtu() {
        // IPv6 requires links to carry 1280 bytes; headers take some of that.
        const { assert!(MAX_PACKET_SIZE <= 1280 - 48, "a packet must not need fragmenting") };
    }

    /// The bound must hold a real announcement, or a legitimate device could not
    /// announce at all — a limit that refuses honest traffic is worse than none.
    #[test]
    fn a_packet_bound_holds_a_real_announcement() {
        // A key, a network id, a sequence, some addresses, a signature, a nonce
        // and the AEAD tag. Addresses dominate.
        let addresses = MAX_ADDRESSES_PER_PEER.saturating_mul(64);
        let fixed = 32 + 32 + 8 + 64 + NONCE_LEN + 16 + 64;
        assert!(
            addresses.saturating_add(fixed) <= MAX_PACKET_SIZE,
            "an announcement at every other bound must fit in {MAX_PACKET_SIZE}"
        );
    }

    /// Repeating must be frequent enough that a listener starting at a random
    /// moment hears one well inside the time a person waits.
    #[test]
    fn announcements_repeat_often_enough_to_be_heard() {
        const { assert!(ANNOUNCE_INTERVAL_SECS <= 30, "a listener should not wait half a minute") };
        const { assert!(ANNOUNCE_INTERVAL_SECS >= 5, "and the network should not be flooded") };
    }
}

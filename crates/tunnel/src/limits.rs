//! Bounds on what is read from a packet.
//!
//! Everything here is read from bytes a peer chose. A parser that guesses at a
//! truncated header is a parser reading attacker-chosen memory, so every field
//! is bounded before it is touched.

/// The number of bits an IPv6 address has.
pub const ADDRESS_BITS: usize = 128;

/// The shortest prefix a network may use.
///
/// A prefix must leave room for a device part with enough bits that two devices
/// never land on one address. Sixty-four bits of device part is the smallest
/// that keeps birthday collisions out of reach for any plausible network.
pub const MAX_PREFIX_BITS: usize = 64;

/// The fewest bits a device part may have.
///
/// The mirror of [`MAX_PREFIX_BITS`]. Stated separately because it is the one a
/// reader cares about: it is what stops two devices sharing an address.
pub const MIN_DEVICE_BITS: usize = ADDRESS_BITS - MAX_PREFIX_BITS;

/// The smallest packet that can carry an IPv6 source address.
///
/// An IPv6 header is forty bytes, and the source occupies bytes 8 to 24. A
/// packet shorter than that cannot have a source to check, so it is dropped
/// rather than parsed.
pub const MIN_PACKET_LEN: usize = 40;

/// The version an overlay packet must declare.
///
/// The high nibble of the first byte. §2.5 addresses devices with IPv6, so a
/// packet declaring anything else is not a packet this layer can reason about —
/// and reasoning about it anyway is how a source check gets bypassed.
pub const IP_VERSION: u8 = 6;

/// Where the source address begins in an IPv6 header.
pub const SOURCE_OFFSET: usize = 8;

/// Where the destination address begins in an IPv6 header.
pub const DESTINATION_OFFSET: usize = 24;

/// The version an IPv4 packet declares.
pub const IPV4_VERSION: u8 = 4;

/// The shortest IPv4 header: twenty bytes, the header length nibble at five.
///
/// A packet shorter than that cannot carry a source to check. Options make a
/// header longer, never shorter.
pub const IPV4_MIN_HEADER: usize = 20;

/// Where the total length begins in an IPv4 header, two bytes big-endian.
pub const IPV4_TOTAL_LENGTH_OFFSET: usize = 2;

/// Where the source address begins in an IPv4 header.
pub const IPV4_SOURCE_OFFSET: usize = 12;

/// Where the destination address begins in an IPv4 header.
pub const IPV4_DESTINATION_OFFSET: usize = 16;

/// The largest packet this layer will inspect.
///
/// Generous against any plausible MTU, and bounded because the length arrives
/// from outside.
pub const MAX_PACKET_LEN: usize = 65_535;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stated_bounds_are_pinned() {
        assert_eq!(ADDRESS_BITS, 128);
        assert_eq!(MAX_PREFIX_BITS, 64);
        assert_eq!(MIN_DEVICE_BITS, 64);
        assert_eq!(MIN_PACKET_LEN, 40);
        assert_eq!(SOURCE_OFFSET, 8);
        assert_eq!(DESTINATION_OFFSET, 24);
        assert_eq!(MAX_PACKET_LEN, 65_535);
        assert_eq!(IPV4_VERSION, 4);
        assert_eq!(IPV4_MIN_HEADER, 20);
        assert_eq!(IPV4_TOTAL_LENGTH_OFFSET, 2);
        assert_eq!(IPV4_SOURCE_OFFSET, 12);
        assert_eq!(IPV4_DESTINATION_OFFSET, 16);
    }

    /// The device part must be large enough that two devices never collide.
    /// Silently overlapping device parts would put two devices at one address,
    /// which is exactly the confusion this crate exists to prevent.
    #[test]
    fn a_device_part_is_wide_enough_to_avoid_collisions() {
        const { assert!(MIN_DEVICE_BITS >= 64, "a narrower device part invites collisions") };
        const { assert!(MAX_PREFIX_BITS + MIN_DEVICE_BITS == ADDRESS_BITS) };
    }

    /// The offsets must describe a real IPv6 header, or every check reads the
    /// wrong sixteen bytes and passes for the wrong reason.
    #[test]
    fn the_offsets_describe_an_ipv6_header() {
        const { assert!(SOURCE_OFFSET + 16 == DESTINATION_OFFSET, "source precedes destination") };
        const { assert!(DESTINATION_OFFSET + 16 == MIN_PACKET_LEN, "the header is forty bytes") };
    }

    /// The same for IPv4: a wrong offset reads four bytes of something else and
    /// the source check passes or fails for the wrong reason.
    #[test]
    fn the_offsets_describe_an_ipv4_header() {
        const {
            assert!(IPV4_TOTAL_LENGTH_OFFSET + 2 <= IPV4_SOURCE_OFFSET, "length precedes source");
        };
        const {
            assert!(
                IPV4_SOURCE_OFFSET + 4 == IPV4_DESTINATION_OFFSET,
                "source precedes destination"
            );
        };
        const {
            assert!(IPV4_DESTINATION_OFFSET + 4 == IPV4_MIN_HEADER, "the header is twenty bytes");
        };
        const { assert!(IPV4_VERSION != IP_VERSION, "the two families are told apart by version") };
    }
}

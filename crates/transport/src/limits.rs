//! Bounds this interface states, so callers can rely on them.

/// Largest payload a session carries.
///
/// Big enough for any roster operation (bounded at 8 KiB) and for a snapshot
/// (bounded at 64 KiB), with room for whatever framing `roster-sync` puts around
/// them. Refused at the sender rather than truncated.
pub const MAX_PAYLOAD: usize = 256 * 1024;

/// Largest packet a session carries.
///
/// A packet is a tunnel packet: the overlay's MTU is 1,280, and this leaves room
/// for an IPv4 path of ordinary size without inviting anything a datagram
/// transport would have to cut into many pieces. Refused at the sender rather
/// than truncated, like a payload.
pub const MAX_PACKET: usize = 1_500;

/// Packets a session will hold for a reader before it drops.
///
/// A packet is best effort: a reader that falls this far behind is not coming
/// back soon, and packets that wait longer are not worth delivering. Dropping
/// is what a router does, and the traffic inside the tunnel recovers from it.
pub const PACKET_QUEUE: usize = 256;

/// Payloads a session will hold before a sender waits.
///
/// Backpressure rather than unbounded buffering: a peer that stops reading
/// should slow its sender down, not consume this node's memory.
pub const SESSION_QUEUE: usize = 64;

/// Dials a node will queue before refusing.
///
/// Only the in-memory transport uses this; a real one gets its own limit from
/// the connectivity layer.
pub const MAX_PENDING_DIALS: usize = 32;

#[cfg(test)]
mod tests {
    use super::{MAX_PACKET, MAX_PAYLOAD, MAX_PENDING_DIALS, PACKET_QUEUE, SESSION_QUEUE};

    /// Pin the stated bounds: a caller may rely on them, so a change should be
    /// visible in a diff rather than silent.
    #[test]
    fn stated_bounds_are_pinned() {
        assert_eq!(MAX_PAYLOAD, 262_144);
        assert_eq!(SESSION_QUEUE, 64);
        assert_eq!(MAX_PENDING_DIALS, 32);
        assert_eq!(MAX_PACKET, 1_500);
        assert_eq!(PACKET_QUEUE, 256);
    }

    /// The overlay requires 1,280 on its link, so a packet bound below it could
    /// not carry a full-size tunnel packet at all.
    #[test]
    fn a_packet_can_carry_a_full_size_ipv6_packet() {
        const { assert!(MAX_PACKET >= 1_280) };
        const { assert!(MAX_PACKET < MAX_PAYLOAD) };
    }

    /// A payload must be able to carry the largest artifact the roster defines,
    /// or the transport would be unable to move a snapshot.
    #[test]
    fn a_payload_can_carry_the_largest_roster_artifact() {
        const { assert!(MAX_PAYLOAD > roster::limits::MAX_OPERATION_SIZE) };
        const { assert!(MAX_PAYLOAD > roster::limits::MAX_SNAPSHOT_SIZE) };
    }
}

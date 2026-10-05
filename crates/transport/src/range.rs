//! A block of addresses a transport must not route a session through.
//!
//! The one thing this crate needs to say about addressing, and it says it from
//! the outside in: a caller that runs tunnels knows which addresses its tunnels
//! serve, and a transport has no way to work that out. The addresses of a tunnel
//! adapter look exactly like any other address of the machine — which is how a
//! connectivity layer comes to offer one as a candidate, reach it through the
//! very tunnel it is carrying, and conclude it has found a path.
//!
//! Deliberately not an address: a range is stable while the roster changes under
//! it, and "this block belongs to a tunnel of mine" stays true when a peer is
//! admitted, revoked or renumbered inside it.

use core::fmt;
use std::net::IpAddr;

/// A block of addresses, as a base address and a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Range {
    /// The block's base address. Bits below the prefix are not read.
    address: IpAddr,
    /// How many leading bits of `address` name the block.
    prefix_len: u8,
}

impl Range {
    /// A range, or `None` when the prefix is longer than the address has bits.
    ///
    /// Host bits set in `address` are accepted rather than refused: a caller
    /// naming the block by an address inside it means the same block, and
    /// refusing would turn a harmless way of saying it into a failure on a path
    /// that cannot report one usefully.
    #[must_use]
    pub const fn new(address: IpAddr, prefix_len: u8) -> Option<Self> {
        let bits = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > bits {
            return None;
        }
        Some(Self { address, prefix_len })
    }

    /// Whether `address` falls inside this block.
    ///
    /// Always false across families: an IPv4 address is not inside an IPv6
    /// block, whatever the bits would say if they were compared.
    #[must_use]
    pub fn contains(&self, address: &IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(base), IpAddr::V4(other)) => {
                matching(u32::from(base).into(), u32::from(*other).into(), self.prefix_len, 32)
            }
            (IpAddr::V6(base), IpAddr::V6(other)) => {
                matching(u128::from(base), u128::from(*other), self.prefix_len, 128)
            }
            _ => false,
        }
    }

    /// The block's base address, as it was given.
    #[must_use]
    pub const fn address(&self) -> IpAddr {
        self.address
    }

    /// How many leading bits name the block.
    #[must_use]
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
}

impl fmt::Display for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

/// Whether two addresses agree on their first `prefix_len` bits.
///
/// A prefix of zero matches everything, which is the honest reading of "no bits
/// have to agree" and the case a shift by the full width would otherwise make
/// undefined.
fn matching(left: u128, right: u128, prefix_len: u8, bits: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let Some(shift) = bits.checked_sub(prefix_len) else {
        return false;
    };
    let Some(mask) = u128::MAX.checked_shl(u32::from(shift)) else {
        return false;
    };
    // The mask is built for the full 128 bits either way; for IPv4 both sides
    // carry zeros above bit 32, so the extra high bits agree trivially.
    left & mask == right & mask
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a test that cannot construct its own fixtures proves less than it costs"
)]
mod tests {
    use super::*;

    fn v4(text: &str) -> IpAddr {
        IpAddr::V4(text.parse().unwrap())
    }

    fn v6(text: &str) -> IpAddr {
        IpAddr::V6(text.parse().unwrap())
    }

    #[test]
    fn an_address_inside_an_ipv4_block_is_inside_it() {
        let range = Range::new(v4("100.64.0.0"), 10).unwrap();
        assert!(range.contains(&v4("100.64.0.1")));
        assert!(range.contains(&v4("100.117.31.3")));
        assert!(range.contains(&v4("100.127.255.255")));
    }

    #[test]
    fn an_address_outside_an_ipv4_block_is_outside_it() {
        let range = Range::new(v4("100.64.0.0"), 10).unwrap();
        assert!(!range.contains(&v4("100.128.0.1")));
        assert!(!range.contains(&v4("192.168.1.9")));
        assert!(!range.contains(&v4("100.63.255.255")));
    }

    #[test]
    fn a_ula_prefix_holds_its_own_addresses_and_no_others() {
        let range = Range::new(v6("fd12:3456:789a:bcde::"), 64).unwrap();
        assert!(range.contains(&v6("fd12:3456:789a:bcde::53")));
        assert!(!range.contains(&v6("fd12:3456:789a:bcdf::1")));
        assert!(!range.contains(&v6("2a01:820:145:119d::1")));
    }

    /// The two families never answer for each other, whatever their bits say.
    #[test]
    fn a_range_of_one_family_never_holds_the_other() {
        let four = Range::new(v4("0.0.0.0"), 0).unwrap();
        let six = Range::new(v6("::"), 0).unwrap();
        assert!(!four.contains(&v6("fd00::1")));
        assert!(!six.contains(&v4("100.64.0.1")));
    }

    /// Nothing is excluded by a prefix of zero bits *within* its own family, and
    /// the shift that would be undefined at the full width is not taken.
    #[test]
    fn a_prefix_of_zero_holds_every_address_of_its_family() {
        assert!(Range::new(v4("0.0.0.0"), 0).unwrap().contains(&v4("8.8.8.8")));
        assert!(Range::new(v6("::"), 0).unwrap().contains(&v6("2a01::1")));
    }

    #[test]
    fn a_full_length_prefix_holds_exactly_one_address() {
        let range = Range::new(v4("100.99.120.85"), 32).unwrap();
        assert!(range.contains(&v4("100.99.120.85")));
        assert!(!range.contains(&v4("100.99.120.86")));

        let one = Range::new(v6("fd00::1"), 128).unwrap();
        assert!(one.contains(&v6("fd00::1")));
        assert!(!one.contains(&v6("fd00::2")));
    }

    #[test]
    fn a_prefix_longer_than_the_family_is_refused() {
        assert!(Range::new(v4("100.64.0.0"), 33).is_none());
        assert!(Range::new(v6("fd00::"), 129).is_none());
        assert!(Range::new(v4("100.64.0.0"), 32).is_some());
        assert!(Range::new(v6("fd00::"), 128).is_some());
    }

    /// Host bits in the base address name the same block.
    #[test]
    fn a_block_named_by_an_address_inside_it_is_that_block() {
        let named = Range::new(v4("100.117.31.3"), 10).unwrap();
        assert!(named.contains(&v4("100.99.120.85")));
        assert!(!named.contains(&v4("192.168.1.9")));
    }

    #[test]
    fn a_range_reads_as_an_address_and_a_prefix() {
        let range = Range::new(v4("100.64.0.0"), 10).unwrap();
        assert_eq!(range.to_string(), "100.64.0.0/10");
        assert_eq!(range.address(), v4("100.64.0.0"));
        assert_eq!(range.prefix_len(), 10);
    }
}

//! Where a device lives on the overlay.
//!
//! # Derived from the device id, not the transport key
//!
//! DESIGN.md §2.5 says a device's `/128` derives from "its public key" and that
//! a packet is dropped unless its source matches "the hash of the key of the
//! session". This uses the **device id** instead. That is a deliberate
//! reading of what §2.5 is *for* rather than of its letter, and the reasoning
//! belongs here so a later reader meets a decision rather than a contradiction.
//!
//! **On the threat the rule exists for, the two are identical.** That threat is
//! not an outsider — the transport refuses a peer the roster does not name
//! before a packet flows. It is a *member* claiming another member's source
//! address inside its own legitimate session. Under either derivation a member
//! can present only the one address its session resolves to, and cannot forge
//! another's without holding a key the roster names for it.
//!
//! **They differ on stability.** Deriving from the transport key would move a
//! device's address whenever that key rotated — and transport keys are the ones
//! most likely to rotate, being software-held and used constantly. Every name,
//! cached route and address-shaped access rule pointing at the old address would
//! dangle. §3.2 has a person typing `name.<suffix>`; an address that moves
//! under a name is a broken name.
//!
//! **And on cost.** [`transport::session::Session`] exposes an authenticated
//! `DeviceId` and no key. Deriving from the transport key would mean adding an
//! accessor to the shared interface that every transport implementation and the
//! behavioural suite must carry, for a derivation that can use what is already
//! there.
//!
//! An address is stable while a device's *identity* is. Rotating a **signing**
//! key changes the device id, so the address moves — but that is already a
//! re-enrolment: the roster sees a different device.

use std::net::{Ipv4Addr, Ipv6Addr};

use roster::id::{DeviceId, NetworkId};
use roster::types::Ipv4Range;

use crate::limits;
use crate::outcome::{Error, Result};

/// The context the device part is derived under.
///
/// A keyed derivation rather than a plain hash, so an address cannot collide
/// with any other value derived in this system, and so a change to the scheme is
/// a change to this string.
const ADDRESS_CONTEXT: &str = "peerfectly tunnel address v1";

/// The context a founder derives a network prefix under.
const PREFIX_CONTEXT: &str = "peerfectly tunnel prefix v1";

/// The context a device's IPv4 candidate is derived under.
const IPV4_CONTEXT: &str = "peerfectly tunnel ipv4 v1";

/// A network's address range on the overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    /// The leading bytes, zero-padded to sixteen.
    bytes: [u8; 16],
    /// How many leading bits belong to the network.
    bits: usize,
}

impl Prefix {
    /// Reads a prefix from the bytes the network parameters carry.
    ///
    /// The parameters hold the prefix as bytes; each byte is eight bits of
    /// network. A prefix long enough to leave no room for a device part is an
    /// **error**, not a truncation: overlapping device parts would put two
    /// devices at one address, which is the confusion this crate exists to
    /// prevent.
    ///
    /// What remains must be a unique local `/64`, by the roster's own rule
    /// rather than a restatement of it. The length complaints come first, so a
    /// prefix that is wrong in one of the ways this crate has always named is
    /// still reported that way.
    ///
    /// # Errors
    ///
    /// [`Error::PrefixMalformed`] or [`Error::PrefixTooLong`] for a length this
    /// crate cannot use, and [`Error::PrefixNotPrivate`] for one outside
    /// `fd00::/8` or of any length but eight bytes.
    pub fn from_parameter(ula: &[u8]) -> Result<Self> {
        if ula.is_empty() || ula.len() > 16 {
            return Err(Error::PrefixMalformed { len: ula.len() });
        }
        let bits = ula.len().saturating_mul(8);
        if bits > limits::MAX_PREFIX_BITS {
            return Err(Error::PrefixTooLong { bits, limit: limits::MAX_PREFIX_BITS });
        }
        match roster::params::unique_local_prefix(ula) {
            Ok(()) => {}
            Err(roster::Error::InvalidValue(reason) | roster::Error::LimitExceeded(reason)) => {
                return Err(Error::PrefixNotPrivate { reason });
            }
            // The rule names its refusals in those two; a refusal this crate
            // cannot quote is still a refusal.
            Err(_) => return Err(Error::PrefixNotPrivate { reason: "prefix refused" }),
        }

        let mut bytes = [0u8; 16];
        for (slot, byte) in bytes.iter_mut().zip(ula.iter()) {
            *slot = *byte;
        }
        Ok(Self { bytes, bits })
    }

    /// The prefix a founder would derive for a network.
    ///
    /// §2.5 says the prefix descends from the network's root key. Offered so a
    /// founder can compute a well-distributed one; a network may still carry a
    /// prefix nobody derived, as long as it is a unique local `/64` — the roster
    /// is the authority on which prefix the network uses, and this layer only
    /// holds it to the shape both agree on. Two networks choosing the same
    /// prefix within that shape collide, which matters only on a host in both
    /// and is a misconfiguration to warn about rather than a packet to drop.
    ///
    /// The first byte is `0xfd`, the locally assigned half of the unique local
    /// range, and the result is a `/64`, so a derived prefix always satisfies
    /// [`Self::from_parameter`].
    #[must_use]
    pub fn derive_for(network: &roster::id::NetworkId) -> Self {
        let derived = blake3::derive_key(PREFIX_CONTEXT, network.as_bytes());
        let mut bytes = [0u8; 16];
        if let Some(first) = bytes.first_mut() {
            *first = 0xfd;
        }
        // Seven derived bytes after the 0xfd marker: a /64 with the low half
        // left for devices.
        for (slot, byte) in bytes.iter_mut().skip(1).take(7).zip(derived.iter()) {
            *slot = *byte;
        }
        Self { bytes, bits: limits::MAX_PREFIX_BITS }
    }

    /// The bytes a founder would put in the network parameters.
    #[must_use]
    pub fn to_parameter(self) -> Vec<u8> {
        let bytes = self.bits.saturating_div(8);
        self.bytes.iter().take(bytes).copied().collect()
    }

    /// How many leading bits belong to the network.
    #[must_use]
    pub const fn bits(&self) -> usize {
        self.bits
    }

    /// Whether an address falls inside this prefix.
    #[must_use]
    pub fn contains(&self, address: Ipv6Addr) -> bool {
        let octets = address.octets();
        let whole = self.bits.saturating_div(8);
        let leftover = self.bits.saturating_sub(whole.saturating_mul(8));

        for index in 0..whole {
            match (octets.get(index), self.bytes.get(index)) {
                (Some(left), Some(right)) if left == right => {}
                _ => return false,
            }
        }
        if leftover == 0 {
            return true;
        }
        // The partial byte, compared only on the bits the prefix claims.
        let mask = 0xffu8
            .checked_shl(u32::try_from(8usize.saturating_sub(leftover)).unwrap_or(8))
            .unwrap_or(0);
        match (octets.get(whole), self.bytes.get(whole)) {
            (Some(left), Some(right)) => (left & mask) == (right & mask),
            _ => false,
        }
    }
}

/// The address a device holds on this network.
///
/// A pure function of the device id and the prefix: two nodes computing it agree
/// without coordination, a lookup service, or any state beyond the roster.
#[must_use]
pub fn address_of(device: &DeviceId, prefix: &Prefix) -> Ipv6Addr {
    let derived = blake3::derive_key(ADDRESS_CONTEXT, device.as_bytes());

    let mut octets = prefix.bytes;
    let whole = prefix.bits.saturating_div(8);
    // The device part fills everything the prefix does not claim.
    for (index, slot) in octets.iter_mut().enumerate().skip(whole) {
        *slot = derived.get(index.saturating_sub(whole)).copied().unwrap_or(0);
    }
    Ipv6Addr::from(octets)
}

/// The IPv4 address a device would hold in a network, if no other device
/// derives the same one.
///
/// A keyed hash of the network id and the device id, reduced into the range
/// with its first and last addresses left out, so nothing a person might read as
/// a network or broadcast address is handed out.
///
/// The network id is an input because one device holding two networks would
/// otherwise present one IPv4 address in both, and be linkable by it. IPv6 needs
/// no such care: the prefix already differs.
///
/// A candidate is not yet an address. Thirty-two bits cannot hold every device
/// id apart, so whether a device holds its candidate is decided by
/// [`crate::Ipv4Holdings`], against every other device of the network.
#[must_use]
pub fn ipv4_candidate(network: &NetworkId, device: &DeviceId, range: &Ipv4Range) -> Ipv4Addr {
    let mut input = [0u8; 64];
    for (slot, byte) in input.iter_mut().zip(network.as_bytes().iter().chain(device.as_bytes())) {
        *slot = *byte;
    }
    let derived = blake3::derive_key(IPV4_CONTEXT, &input);
    let head = derived.first_chunk::<8>().copied().unwrap_or_default();
    // A range is at most a `/28`, so there are always fourteen or more.
    let assignable = range.size().saturating_sub(2).max(1);
    let offset = u64::from_be_bytes(head).checked_rem(assignable).unwrap_or(0);
    let first = u32::from_be_bytes(range.address());
    let host = first.saturating_add(1).saturating_add(u32::try_from(offset).unwrap_or(0));
    Ipv4Addr::from(host)
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test reports a failed expectation by panicking")]
mod tests {
    use roster::id::NetworkId;

    use super::*;

    fn device(tag: u8) -> DeviceId {
        DeviceId::from_bytes([tag; 32])
    }

    fn prefix() -> Prefix {
        Prefix::from_parameter(&[0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).expect("valid")
    }

    /// The property everything rests on: no coordination, no lookup service.
    #[test]
    fn two_nodes_derive_the_same_address() {
        assert_eq!(address_of(&device(1), &prefix()), address_of(&device(1), &prefix()));
    }

    #[test]
    fn different_devices_get_different_addresses() {
        assert_ne!(address_of(&device(1), &prefix()), address_of(&device(2), &prefix()));
    }

    #[test]
    fn an_address_lies_inside_its_prefix() {
        let prefix = prefix();
        assert!(prefix.contains(address_of(&device(1), &prefix)));
    }

    /// One device in two networks is two addresses, and neither strays into the
    /// other network's range.
    #[test]
    fn the_same_device_in_another_network_gets_another_address() {
        let ours = prefix();
        let theirs = Prefix::from_parameter(&[0xfd, 0x11, 0x22, 0x33, 0x00, 0x00, 0x00, 0x00])
            .expect("valid");

        let here = address_of(&device(1), &ours);
        let there = address_of(&device(1), &theirs);

        assert_ne!(here, there);
        assert!(!theirs.contains(here));
        assert!(!ours.contains(there));
    }

    /// The reason for deriving from the device id: a transport key can rotate
    /// without a device moving. The device id is the input, so a key change
    /// simply does not enter the calculation.
    #[test]
    fn an_address_depends_only_on_the_device_id() {
        let prefix = prefix();
        let before = address_of(&device(3), &prefix);
        // Nothing about a transport key is an input here; that is the point.
        let after = address_of(&DeviceId::from_bytes(*device(3).as_bytes()), &prefix);
        assert_eq!(before, after);
    }

    /// An error, never a truncation: two devices sharing an address is the
    /// confusion this crate exists to prevent.
    #[test]
    fn a_prefix_leaving_no_room_is_refused() {
        let too_long = vec![0xfd; 12];
        match Prefix::from_parameter(&too_long) {
            Err(Error::PrefixTooLong { bits, limit }) => {
                assert_eq!(bits, 96);
                assert_eq!(limit, limits::MAX_PREFIX_BITS);
            }
            other => panic!("expected a bound refusal naming the prefix, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_or_oversized_prefix_is_refused() {
        assert!(matches!(Prefix::from_parameter(&[]), Err(Error::PrefixMalformed { .. })));
        assert!(matches!(Prefix::from_parameter(&[0xfd; 17]), Err(Error::PrefixMalformed { .. })));
    }

    #[test]
    fn a_prefix_at_the_bound_is_accepted() {
        let exact = vec![0xfd; limits::MAX_PREFIX_BITS / 8];
        assert!(Prefix::from_parameter(&exact).is_ok(), "the bound is inclusive");
    }

    /// A founder can derive a prefix, and this crate still reads one nobody
    /// derived — as long as it is a unique local `/64`. The roster is the
    /// authority on *which* prefix; both agree on the shape.
    #[test]
    fn a_derived_prefix_is_offered_but_any_unique_local_64_is_read() {
        let derived = Prefix::derive_for(&NetworkId::from_bytes([9; 32]));
        assert_eq!(derived.to_parameter().first().copied(), Some(0xfd), "a valid ULA");
        assert_eq!(derived.bits(), limits::MAX_PREFIX_BITS);
        assert!(
            Prefix::from_parameter(&derived.to_parameter()).is_ok(),
            "what a founder derives is what this reads"
        );

        let chosen = Prefix::from_parameter(&[0xfd, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x01])
            .expect("a unique local /64 nobody derived");
        assert!(chosen.contains(address_of(&device(1), &chosen)));
    }

    /// A prefix in global space would route real hosts into the tunnel: a
    /// network's admin could make most of the public IPv6 internet unreachable
    /// on every member's machine.
    #[test]
    fn a_prefix_outside_the_unique_local_range_is_refused() {
        for first in [0x20, 0x2a, 0xfc, 0xfe, 0x00] {
            assert_eq!(
                Prefix::from_parameter(&[first, 0, 0, 0, 0, 0, 0, 0]),
                Err(Error::PrefixNotPrivate { reason: "prefix not unique local" }),
                "{first:#04x}"
            );
        }
    }

    /// A network's addresses fill a `/64`. Anything shorter routes more of the
    /// unique local space than the network uses — including the prefixes home
    /// routers assign themselves.
    #[test]
    fn a_prefix_that_is_not_a_slash_64_is_refused() {
        for len in [1_usize, 2, 4, 7] {
            let mut ula = vec![0u8; len];
            if let Some(first) = ula.first_mut() {
                *first = 0xfd;
            }
            assert_eq!(
                Prefix::from_parameter(&ula),
                Err(Error::PrefixNotPrivate { reason: "prefix not a /64" }),
                "{len} bytes"
            );
        }
    }

    #[test]
    fn two_networks_derive_different_prefixes() {
        let one = Prefix::derive_for(&NetworkId::from_bytes([1; 32]));
        let two = Prefix::derive_for(&NetworkId::from_bytes([2; 32]));
        assert_ne!(one.to_parameter(), two.to_parameter());
    }

    fn range(text: &str) -> Ipv4Range {
        text.parse().expect("an allowed range")
    }

    fn network(tag: u8) -> NetworkId {
        NetworkId::from_bytes([tag; 32])
    }

    #[test]
    fn two_nodes_derive_the_same_ipv4_candidate() {
        let range = Ipv4Range::DEFAULT;
        assert_eq!(
            ipv4_candidate(&network(1), &device(1), &range),
            ipv4_candidate(&network(1), &device(1), &range)
        );
    }

    /// One device in two networks is not linkable by its IPv4 address.
    #[test]
    fn two_networks_give_one_device_different_ipv4_candidates() {
        let range = Ipv4Range::DEFAULT;
        assert_ne!(
            ipv4_candidate(&network(1), &device(1), &range),
            ipv4_candidate(&network(2), &device(1), &range)
        );
    }

    #[test]
    fn a_candidate_is_inside_the_range_and_never_its_first_or_last_address() {
        let range = range("192.168.7.0/28");
        for tag in 0..=255 {
            let candidate = u32::from(ipv4_candidate(&network(1), &device(tag), &range));
            assert!(range.contains(Ipv4Addr::from(candidate).octets()));
            assert_ne!(candidate, 0xc0a8_0700, "the first address");
            assert_ne!(candidate, 0xc0a8_070f, "the last address");
        }
    }

    #[test]
    fn a_prefix_round_trips_through_the_parameter() {
        let derived = Prefix::derive_for(&NetworkId::from_bytes([4; 32]));
        let read = Prefix::from_parameter(&derived.to_parameter()).expect("valid");
        assert_eq!(read, derived);
    }

    #[test]
    fn an_address_outside_the_prefix_is_not_contained() {
        let prefix = prefix();
        assert!(!prefix.contains("2001:db8::1".parse().expect("valid")));
        assert!(!prefix.contains(Ipv6Addr::LOCALHOST));
    }

    /// A prefix whose length is not a whole number of bytes still compares only
    /// the bits it claims.
    #[test]
    fn a_partial_byte_prefix_compares_only_its_bits() {
        let prefix =
            Prefix { bytes: [0xfd, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], bits: 9 };
        assert!(prefix.contains("fdff::1".parse().expect("valid")), "the ninth bit is set");
        assert!(!prefix.contains("fd00::1".parse().expect("valid")), "the ninth bit is clear");
    }
}

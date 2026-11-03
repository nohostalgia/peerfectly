//! Which device holds which IPv4 address.
//!
//! # An offset in the network's block
//!
//! A device holds the address its offset names in the network's block: the
//! block's base plus the offset an admin assigned it at admission
//! (`roster::leaf::Ipv4Offset`), where that is one of the block's hosts —
//! neither its first address nor its last. A device with no offset, or with one
//! the block does not hold, holds no IPv4 address and is reached by IPv6.
//!
//! Nothing is derived from a device's id any more. A derived candidate
//! collided as a network grew — a million devices in the default `/10` left a
//! fifth of them without one — and no rule keeping an address from moving
//! could settle it, the state keeping no admission order (`scalable-membership`
//! 19). An admin who admits knows which offsets are taken, and gives the next.
//!
//! Two claims on one offset are settled by derivation, as any other claim on an
//! address: the latest keeps it, and every device a later claim overruled has
//! lost it for good (`roster::state`). So a state holds each offset once at
//! most, and the holdings read it as it is.
//!
//! The rule reads only what a roster state keeps — the devices present, their
//! settings, the network's block — and never an order or the set of revoked
//! devices: a node resting on a root and one holding the history agree.
//!
//! # Of a state, read as asked
//!
//! The holdings of a state are a view of it: what a device holds is read from
//! its leaf, and who holds an address from the state's index of offsets. Not
//! maps of every device, which held 649 bytes a device at a fleet's size and
//! were decided again whole at every change (`scalable-membership` 16.6).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use roster::id::DeviceId;
use roster::leaf::Ipv4Offset;
use roster::state::RosterState;
use roster::types::Ipv4Range;

/// The IPv4 addresses a network's devices hold, in both directions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Holdings(Holdings);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Holdings {
    /// Of a list of devices, decided as given: what the tests and the
    /// in-process doubles want.
    Listed {
        range: Ipv4Range,
        by_device: BTreeMap<DeviceId, Ipv4Addr>,
        by_address: BTreeMap<Ipv4Addr, DeviceId>,
    },
    /// Of a roster state, read from it.
    Of(Box<View>),
}

/// The holdings of one roster state.
#[derive(Clone)]
struct View {
    state: RosterState,
    range: Ipv4Range,
}

impl core::fmt::Debug for View {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("View")
            .field("network", &self.state.network)
            .field("range", &self.range)
            .field("devices", &self.state.devices.root())
            .finish_non_exhaustive()
    }
}

/// Two views are equal where their states hold the same devices, settings and
/// all, in the same network and block: the holdings are a function of those.
impl PartialEq for View {
    fn eq(&self, other: &Self) -> bool {
        self.state.network == other.state.network
            && self.range == other.range
            && self.state.devices.root() == other.state.devices.root()
    }
}

impl Eq for View {}

impl Default for Ipv4Holdings {
    /// No device holds anything, in the default block.
    fn default() -> Self {
        Self::empty(Ipv4Range::DEFAULT)
    }
}

impl Ipv4Holdings {
    /// Holdings in which no device holds anything.
    #[must_use]
    pub fn empty(range: Ipv4Range) -> Self {
        Self(Holdings::Listed { range, by_device: BTreeMap::new(), by_address: BTreeMap::new() })
    }

    /// The holdings of devices given consecutive offsets in `range`, the first
    /// device the first of its hosts, in the order given: as an admin admitting
    /// them one after another would.
    #[must_use]
    pub fn from<'a>(range: Ipv4Range, devices: impl IntoIterator<Item = &'a DeviceId>) -> Self {
        Self::assigned(
            range,
            devices
                .into_iter()
                .zip(1_u32..)
                .map(|(device, offset)| (*device, Some(offset.to_be_bytes()))),
        )
    }

    /// The holdings of devices each with the offset it was assigned, if any.
    ///
    /// An offset the block does not hold is as good as none. Two devices given
    /// one offset — which a derived state never holds — both hold nothing.
    #[must_use]
    pub fn assigned(
        range: Ipv4Range,
        devices: impl IntoIterator<Item = (DeviceId, Option<Ipv4Offset>)>,
    ) -> Self {
        let mut claims: BTreeMap<Ipv4Addr, Vec<DeviceId>> = BTreeMap::new();
        for (device, offset) in devices {
            if let Some(address) = offset.and_then(|offset| range.address_at(offset)) {
                claims.entry(Ipv4Addr::from(address)).or_default().push(device);
            }
        }
        let mut by_device = BTreeMap::new();
        let mut by_address = BTreeMap::new();
        for (address, claimants) in claims {
            if let [device] = claimants.as_slice() {
                by_device.insert(*device, address);
                by_address.insert(address, *device);
            }
        }
        Self(Holdings::Listed { range, by_device, by_address })
    }

    /// The holdings a roster state implies: a view of it, which costs what
    /// copying the state costs.
    #[must_use]
    pub fn of_state(state: &RosterState) -> Self {
        Self(Holdings::Of(Box::new(View {
            state: state.clone(),
            range: state.params.ipv4_range(),
        })))
    }

    /// The holdings `state` implies, where these are the holdings `previous`
    /// implied: a view of `state`, as [`Self::of_state`].
    #[must_use]
    pub fn updated(&self, _previous: &RosterState, state: &RosterState) -> Self {
        Self::of_state(state)
    }

    /// The block addresses are in.
    #[must_use]
    pub fn range(&self) -> Ipv4Range {
        match &self.0 {
            Holdings::Listed { range, .. } => *range,
            Holdings::Of(view) => view.range,
        }
    }

    /// The address a device holds.
    #[must_use]
    pub fn of(&self, device: &DeviceId) -> Option<Ipv4Addr> {
        match &self.0 {
            Holdings::Listed { by_device, .. } => by_device.get(device).copied(),
            Holdings::Of(view) => {
                let leaf = view.state.devices.get(device)?;
                leaf.settings
                    .ipv4
                    .and_then(|offset| view.range.address_at(offset))
                    .map(Ipv4Addr::from)
            }
        }
    }

    /// The device holding an address.
    #[must_use]
    pub fn holder(&self, address: Ipv4Addr) -> Option<DeviceId> {
        match &self.0 {
            Holdings::Listed { by_address, .. } => by_address.get(&address).copied(),
            Holdings::Of(view) => {
                let offset = view.range.offset_of(address.octets())?;
                // Settled to one by derivation; of two, which a state never
                // holds, neither.
                match view.state.devices.holding_address(offset).as_slice() {
                    [device] => Some(*device),
                    _ => None,
                }
            }
        }
    }

    /// Every held address, by device. Of a state, a walk over every device.
    pub fn held(&self) -> Box<dyn Iterator<Item = (DeviceId, Ipv4Addr)> + '_> {
        match &self.0 {
            Holdings::Listed { by_device, .. } => {
                Box::new(by_device.iter().map(|(device, address)| (*device, *address)))
            }
            Holdings::Of(view) => Box::new(
                view.state
                    .devices
                    .keys()
                    .filter_map(|device| self.of(&device).map(|address| (device, address))),
            ),
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test reports a failed expectation by panicking")]
mod tests {
    use super::*;

    fn device(tag: u8) -> DeviceId {
        DeviceId::from_bytes([tag; 32])
    }

    fn range(text: &str) -> Ipv4Range {
        text.parse().expect("an allowed range")
    }

    #[test]
    fn consecutive_offsets_hold_consecutive_addresses_from_the_first_host() {
        let holdings = Ipv4Holdings::from(range("10.0.0.0/28"), &[device(1), device(2), device(3)]);
        assert_eq!(holdings.of(&device(1)), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(holdings.of(&device(3)), Some(Ipv4Addr::new(10, 0, 0, 3)));
        assert_eq!(holdings.holder(Ipv4Addr::new(10, 0, 0, 2)), Some(device(2)));
        assert_eq!(holdings.holder(Ipv4Addr::new(10, 0, 0, 4)), None);
    }

    #[test]
    fn an_offset_the_block_does_not_hold_is_as_good_as_none() {
        // A /28 holds hosts 1 to 14: 0 is its network, 15 its broadcast.
        let holdings = Ipv4Holdings::assigned(
            range("10.0.0.0/28"),
            [
                (device(1), Some(0_u32.to_be_bytes())),
                (device(2), Some(15_u32.to_be_bytes())),
                (device(3), Some(16_u32.to_be_bytes())),
                (device(4), None),
                (device(5), Some(14_u32.to_be_bytes())),
            ],
        );
        for tag in 1..=4 {
            assert_eq!(holdings.of(&device(tag)), None, "device {tag}");
        }
        assert_eq!(holdings.of(&device(5)), Some(Ipv4Addr::new(10, 0, 0, 14)));
    }

    #[test]
    fn two_devices_given_one_offset_both_hold_nothing() {
        let one = Some(3_u32.to_be_bytes());
        let holdings =
            Ipv4Holdings::assigned(range("10.0.0.0/28"), [(device(1), one), (device(2), one)]);
        assert_eq!(holdings.of(&device(1)), None);
        assert_eq!(holdings.of(&device(2)), None);
        assert_eq!(holdings.holder(Ipv4Addr::new(10, 0, 0, 3)), None);
    }

    #[test]
    fn moving_the_block_moves_every_address_and_no_offset() {
        let devices = [device(1), device(2)];
        let before = Ipv4Holdings::from(range("10.0.0.0/24"), &devices);
        let after = Ipv4Holdings::from(range("10.9.0.0/22"), &devices);
        assert_eq!(before.of(&device(2)), Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(after.of(&device(2)), Some(Ipv4Addr::new(10, 9, 0, 2)));
    }
}

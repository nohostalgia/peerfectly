//! Which device holds which IPv4 address.
//!
//! # Assigned, or derived and unique among present devices
//!
//! A device holds the address an admin **assigned** it, where that address is
//! one of the range's hosts. Otherwise it holds its derived
//! [`crate::ipv4_candidate`], but only where no other present device holds or
//! derives the same address: thirty-two bits cannot keep every device id apart,
//! and where two devices derive one candidate, **neither holds it**. An assigned
//! address beats a derived one: the device deriving it holds nothing, and an
//! admin may assign it a free one.
//!
//! The rule reads only what a roster state keeps — the devices present, their
//! settings, the network's range — and never an order or the set of revoked
//! devices. Admission order is gone once a roster is compacted, and so is a
//! revocation a checkpoint absorbed: a rule reading either would give a node
//! resting on a root different addresses from a node holding the history. A
//! revoked device therefore reserves nothing once it is gone, and a later
//! device may hold the address it held.
//!
//! Two devices are never assigned one address in a state: derivation settles
//! concurrent assignments by last writer, and the loser falls back to its
//! derived candidate.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use roster::id::{DeviceId, NetworkId};
use roster::state::RosterState;
use roster::types::Ipv4Range;

use crate::address::ipv4_candidate;

/// Why a present device holds no IPv4 address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collision {
    /// The address it would have held.
    pub candidate: Ipv4Addr,
    /// The other present devices that hold or derive the same one.
    pub with: BTreeSet<DeviceId>,
}

/// The IPv4 addresses a network's devices hold, in both directions.
///
/// Computed whole from a roster state and replaced whole when the roster
/// changes; nothing updates it in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Holdings {
    /// The range addresses were derived in.
    range: Ipv4Range,
    /// Each present device holding an address.
    by_device: BTreeMap<DeviceId, Ipv4Addr>,
    /// Each held address, and the device holding it.
    by_address: BTreeMap<Ipv4Addr, DeviceId>,
    /// Each present device without an address, and why.
    colliding: BTreeMap<DeviceId, Collision>,
}

impl Default for Ipv4Holdings {
    /// No device holds anything, in the default range.
    fn default() -> Self {
        Self::empty(Ipv4Range::DEFAULT)
    }
}

/// Whether `address` is one of `range`'s hosts: inside it, and neither its
/// first address nor its last.
fn assignable(range: &Ipv4Range, address: [u8; 4]) -> bool {
    let first = u32::from_be_bytes(range.address());
    let last = u64::from(first).saturating_add(range.size()).saturating_sub(1);
    let value = u32::from_be_bytes(address);
    range.contains(address) && value != first && u64::from(value) != last
}

impl Ipv4Holdings {
    /// Holdings in which no device holds anything.
    #[must_use]
    pub fn empty(range: Ipv4Range) -> Self {
        Self {
            range,
            by_device: BTreeMap::new(),
            by_address: BTreeMap::new(),
            colliding: BTreeMap::new(),
        }
    }

    /// The holdings of devices none of which was assigned an address.
    #[must_use]
    pub fn from<'a>(
        network: &NetworkId,
        range: Ipv4Range,
        devices: impl IntoIterator<Item = &'a DeviceId>,
    ) -> Self {
        Self::assigned(network, range, devices.into_iter().map(|device| (device, None)))
    }

    /// Decides the holdings of a network: each present device, with the
    /// address it was assigned, if any.
    ///
    /// An assigned address that is not one of the range's hosts is as good as
    /// none: the device falls back to its derived candidate.
    #[must_use]
    pub fn assigned<'a>(
        network: &NetworkId,
        range: Ipv4Range,
        devices: impl IntoIterator<Item = (&'a DeviceId, Option<[u8; 4]>)>,
    ) -> Self {
        // Every address claimed, by whom: those assigned it, those deriving it.
        let mut claims: BTreeMap<Ipv4Addr, (BTreeSet<DeviceId>, BTreeSet<DeviceId>)> =
            BTreeMap::new();
        for (device, assigned) in devices {
            match assigned.filter(|address| assignable(&range, *address)) {
                Some(address) => {
                    claims.entry(Ipv4Addr::from(address)).or_default().0.insert(*device);
                }
                None => {
                    claims
                        .entry(ipv4_candidate(network, device, &range))
                        .or_default()
                        .1
                        .insert(*device);
                }
            }
        }

        let mut holdings = Self::empty(range);
        for (address, (assigned, derived)) in claims {
            let everyone: BTreeSet<DeviceId> = assigned.union(&derived).copied().collect();
            // One device assigned it holds it, whoever derives it; failing that,
            // one device deriving it, alone.
            let holder = match (assigned.len(), derived.len()) {
                (1, _) => assigned.first().copied(),
                (0, 1) => derived.first().copied(),
                _ => None,
            };
            for device in &everyone {
                if Some(*device) == holder {
                    holdings.by_device.insert(*device, address);
                    holdings.by_address.insert(address, *device);
                } else {
                    let with = everyone.iter().filter(|other| *other != device).copied().collect();
                    holdings.colliding.insert(*device, Collision { candidate: address, with });
                }
            }
        }
        holdings
    }

    /// The holdings a roster state implies.
    #[must_use]
    pub fn of_state(state: &RosterState) -> Self {
        Self::assigned(
            &state.network,
            state.params.ipv4_range(),
            state.devices.keys().map(|device| {
                (device, state.settings.get(device).and_then(|settings| settings.ipv4))
            }),
        )
    }

    /// The range addresses were derived in.
    #[must_use]
    pub const fn range(&self) -> Ipv4Range {
        self.range
    }

    /// The address a device holds.
    #[must_use]
    pub fn of(&self, device: &DeviceId) -> Option<Ipv4Addr> {
        self.by_device.get(device).copied()
    }

    /// The device holding an address.
    #[must_use]
    pub fn holder(&self, address: Ipv4Addr) -> Option<DeviceId> {
        self.by_address.get(&address).copied()
    }

    /// Why a present device holds no address, when it collides.
    #[must_use]
    pub fn collision(&self, device: &DeviceId) -> Option<&Collision> {
        self.colliding.get(device)
    }

    /// Every held address, by device.
    pub fn held(&self) -> impl Iterator<Item = (DeviceId, Ipv4Addr)> + '_ {
        self.by_device.iter().map(|(device, address)| (*device, *address))
    }

    /// Every present device without an address, and why.
    pub fn colliding(&self) -> impl Iterator<Item = (&DeviceId, &Collision)> {
        self.colliding.iter()
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test reports a failed expectation by panicking")]
mod tests {
    use super::*;

    fn device(tag: u8) -> DeviceId {
        DeviceId::from_bytes([tag; 32])
    }

    fn network() -> NetworkId {
        NetworkId::from_bytes([7; 32])
    }

    /// The narrowest range holds fourteen addresses, so a few dozen devices are
    /// sure to collide somewhere. Finds the first pair that does.
    fn a_colliding_pair(range: Ipv4Range) -> (DeviceId, DeviceId) {
        let mut seen: BTreeMap<Ipv4Addr, DeviceId> = BTreeMap::new();
        for tag in 0..=255 {
            let candidate = ipv4_candidate(&network(), &device(tag), &range);
            if let Some(earlier) = seen.insert(candidate, device(tag)) {
                return (earlier, device(tag));
            }
        }
        panic!("sixteen addresses cannot hold 256 devices apart");
    }

    fn narrow() -> Ipv4Range {
        "10.0.0.0/28".parse().expect("allowed")
    }

    #[test]
    fn a_device_alone_holds_its_candidate_in_both_directions() {
        let range = Ipv4Range::DEFAULT;
        let holdings = Ipv4Holdings::from(&network(), range, &[device(1)]);
        let candidate = ipv4_candidate(&network(), &device(1), &range);

        assert_eq!(holdings.of(&device(1)), Some(candidate));
        assert_eq!(holdings.holder(candidate), Some(device(1)));
        assert_eq!(holdings.collision(&device(1)), None);
    }

    #[test]
    fn a_collision_leaves_both_without_ipv4() {
        let (one, two) = a_colliding_pair(narrow());
        let holdings = Ipv4Holdings::from(&network(), narrow(), &[one, two]);
        let candidate = ipv4_candidate(&network(), &one, &narrow());

        assert_eq!(holdings.of(&one), None);
        assert_eq!(holdings.of(&two), None);
        assert_eq!(holdings.holder(candidate), None);
        let collision = holdings.collision(&one).expect("the reason is kept");
        assert_eq!(collision.candidate, candidate);
        assert_eq!(collision.with, BTreeSet::from([two]), "and names the other device");
        assert_eq!(holdings.collision(&two).map(|c| c.with.clone()), Some(BTreeSet::from([one])));
    }

    #[test]
    fn an_assigned_address_beats_a_derived_one() {
        let (assigned, deriving) = a_colliding_pair(narrow());
        let address = ipv4_candidate(&network(), &deriving, &narrow());
        let other = device(250);
        let holdings = Ipv4Holdings::assigned(
            &network(),
            narrow(),
            [(&assigned, Some(address.octets())), (&deriving, None), (&other, None)],
        );
        assert_eq!(holdings.of(&assigned), Some(address));
        assert_eq!(holdings.holder(address), Some(assigned));
        assert_eq!(holdings.of(&deriving), None, "the derived candidate loses");
        assert_eq!(
            holdings.collision(&deriving).map(|c| c.with.clone()),
            Some(BTreeSet::from([assigned]))
        );
    }

    #[test]
    fn an_address_outside_the_hosts_falls_back_to_the_candidate() {
        let range = narrow();
        let first = range.address();
        let holdings = Ipv4Holdings::assigned(&network(), range, [(&device(1), Some(first))]);
        assert_eq!(holdings.of(&device(1)), Some(ipv4_candidate(&network(), &device(1), &range)));
        let elsewhere =
            Ipv4Holdings::assigned(&network(), range, [(&device(1), Some([192, 168, 1, 1]))]);
        assert_eq!(elsewhere.of(&device(1)), Some(ipv4_candidate(&network(), &device(1), &range)));
    }

    #[test]
    fn the_result_is_independent_of_iteration_order() {
        let devices: Vec<DeviceId> = (0..40).map(device).collect();
        let forward = Ipv4Holdings::from(&network(), narrow(), &devices);

        let mut backward_devices = devices.clone();
        backward_devices.reverse();
        let backward = Ipv4Holdings::from(&network(), narrow(), &backward_devices);

        assert_eq!(forward, backward);
        assert!(forward.colliding().next().is_some(), "the fixture exercises collisions");
    }

    #[test]
    fn empty_holdings_hold_nothing() {
        let holdings = Ipv4Holdings::default();
        assert_eq!(holdings.range(), Ipv4Range::DEFAULT);
        assert_eq!(holdings.held().count(), 0);
        assert_eq!(holdings.holder(Ipv4Addr::new(100, 64, 0, 1)), None);
    }
}

//! Which device holds which IPv4 address.
//!
//! # Held only when unique among present and revoked devices
//!
//! Thirty-two bits cannot keep every device id apart, so two devices of one
//! network can derive the same [`crate::ipv4_candidate`]. When they do, **neither
//! holds it**. The rule reads only sets — the devices present and the devices
//! revoked — and never an order, because admission order is gone once a roster
//! is compacted: a rule reading it would give a node fed a snapshot different
//! addresses from a node fed the whole history.
//!
//! Revoked devices count. A present device never holds the address a revoked
//! one derives, so a revoked device's address is never reused, with nothing to
//! reserve or expire — including in the window where one node has seen the
//! revocation and another still routes to the revoked device.
//!
//! What it gives up: two admissions made apart that derive one candidate leave
//! both devices without IPv4. Admission refuses every collision it can see, so
//! only concurrent ones get this far; they are reported by name, and IPv6 and
//! the name keep working.

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
    /// The other devices, present or revoked, that derive the same one.
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

    /// Decides the holdings of a network.
    ///
    /// `devices` are the devices present, `revoked` those revoked. A device in
    /// both is counted once. Only present devices hold addresses.
    #[must_use]
    pub fn from<'a>(
        network: &NetworkId,
        range: Ipv4Range,
        devices: impl IntoIterator<Item = &'a DeviceId>,
        revoked: impl IntoIterator<Item = &'a DeviceId>,
    ) -> Self {
        let present: BTreeSet<DeviceId> = devices.into_iter().copied().collect();
        let everyone: BTreeSet<DeviceId> =
            present.iter().copied().chain(revoked.into_iter().copied()).collect();

        let mut by_candidate: BTreeMap<Ipv4Addr, BTreeSet<DeviceId>> = BTreeMap::new();
        for device in &everyone {
            by_candidate
                .entry(ipv4_candidate(network, device, &range))
                .or_default()
                .insert(*device);
        }

        let mut holdings = Self::empty(range);
        for (candidate, devices) in by_candidate {
            for device in devices.iter().filter(|device| present.contains(device)) {
                if devices.len() == 1 {
                    holdings.by_device.insert(*device, candidate);
                    holdings.by_address.insert(candidate, *device);
                } else {
                    let with = devices.iter().filter(|other| *other != device).copied().collect();
                    holdings.colliding.insert(*device, Collision { candidate, with });
                }
            }
        }
        holdings
    }

    /// The holdings a roster state implies.
    #[must_use]
    pub fn of_state(state: &RosterState) -> Self {
        Self::from(
            &state.network,
            state.params.ipv4_range(),
            state.devices.keys(),
            state.revoked.iter(),
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
        let holdings = Ipv4Holdings::from(&network(), range, &[device(1)], &[]);
        let candidate = ipv4_candidate(&network(), &device(1), &range);

        assert_eq!(holdings.of(&device(1)), Some(candidate));
        assert_eq!(holdings.holder(candidate), Some(device(1)));
        assert_eq!(holdings.collision(&device(1)), None);
    }

    #[test]
    fn a_collision_leaves_both_without_ipv4() {
        let (one, two) = a_colliding_pair(narrow());
        let holdings = Ipv4Holdings::from(&network(), narrow(), &[one, two], &[]);
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
    fn a_revoked_devices_candidate_is_never_held_by_a_present_one() {
        let (revoked, present) = a_colliding_pair(narrow());
        let holdings = Ipv4Holdings::from(&network(), narrow(), &[present], &[revoked]);

        assert_eq!(holdings.of(&present), None);
        assert_eq!(holdings.of(&revoked), None, "a revoked device holds nothing");
        assert_eq!(
            holdings.collision(&present).map(|c| c.with.clone()),
            Some(BTreeSet::from([revoked]))
        );
        assert!(holdings.colliding().all(|(device, _)| *device != revoked));
    }

    #[test]
    fn a_device_both_present_and_revoked_does_not_collide_with_itself() {
        let holdings = Ipv4Holdings::from(&network(), narrow(), &[device(1)], &[device(1)]);
        assert!(holdings.of(&device(1)).is_some());
    }

    #[test]
    fn the_result_is_independent_of_iteration_order() {
        let devices: Vec<DeviceId> = (0..40).map(device).collect();
        let revoked: Vec<DeviceId> = (40..50).map(device).collect();
        let forward = Ipv4Holdings::from(&network(), narrow(), &devices, &revoked);

        let mut backward_devices = devices.clone();
        backward_devices.reverse();
        let mut backward_revoked = revoked.clone();
        backward_revoked.reverse();
        let backward =
            Ipv4Holdings::from(&network(), narrow(), &backward_devices, &backward_revoked);

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

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
//!
//! # Following a roster's changes
//!
//! Each address is decided by the devices claiming it and nothing else, so a
//! change decides again only the addresses its devices claimed before and
//! claim now: [`Ipv4Holdings::updated`]. And holdings are copied to whatever
//! routes by them, so they are kept as a shared base and the changes on top,
//! as the roster keeps its devices: a copy costs the changes.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

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

/// A map shared between copies, and what changed on top of it: a value, or
/// `None` where one was removed.
#[derive(Debug, Clone)]
struct Layered<K: Ord + Clone, V: Clone> {
    base: Arc<BTreeMap<K, V>>,
    over: BTreeMap<K, Option<V>>,
}

impl<K: Ord + Clone, V: Clone> Default for Layered<K, V> {
    fn default() -> Self {
        Self { base: Arc::new(BTreeMap::new()), over: BTreeMap::new() }
    }
}

impl<K: Ord + Clone, V: Clone + PartialEq> PartialEq for Layered<K, V> {
    fn eq(&self, other: &Self) -> bool {
        // Copies of one base differ only where their changes do.
        if Arc::ptr_eq(&self.base, &other.base) {
            let keys: BTreeSet<&K> = self.over.keys().chain(other.over.keys()).collect();
            return keys.into_iter().all(|key| self.get(key) == other.get(key));
        }
        self.iter().eq(other.iter())
    }
}

impl<K: Ord + Clone, V: Clone + PartialEq> Eq for Layered<K, V> {}

impl<K: Ord + Clone, V: Clone> Layered<K, V> {
    fn of(map: BTreeMap<K, V>) -> Self {
        Self { base: Arc::new(map), over: BTreeMap::new() }
    }

    fn get(&self, key: &K) -> Option<&V> {
        match self.over.get(key) {
            Some(changed) => changed.as_ref(),
            None => self.base.get(key),
        }
    }

    fn insert(&mut self, key: K, value: V) {
        self.over.insert(key, Some(value));
    }

    fn remove(&mut self, key: &K) {
        if self.base.contains_key(key) {
            self.over.insert(key.clone(), None);
        } else {
            self.over.remove(key);
        }
    }

    /// Every entry, in key order: the base and the changes merged.
    fn iter(&self) -> impl Iterator<Item = (&K, &V)> + '_ {
        let mut base = self.base.iter().peekable();
        let mut over = self.over.iter().peekable();
        std::iter::from_fn(move || {
            loop {
                let take_over = match (base.peek(), over.peek()) {
                    (None, None) => return None,
                    (Some(_), None) => false,
                    (None, Some(_)) => true,
                    (Some((base_key, _)), Some((over_key, _))) => over_key <= base_key,
                };
                if take_over {
                    let (key, changed) = over.next()?;
                    if base.peek().is_some_and(|(base_key, _)| *base_key == key) {
                        base.next();
                    }
                    if let Some(value) = changed {
                        return Some((key, value));
                    }
                } else {
                    return base.next();
                }
            }
        })
    }

    /// Folds the changes into a new base once they are a good part of it, so
    /// that copying stays cheap and reading stays one lookup or two.
    fn settle(&mut self) {
        if self.over.len() <= (self.base.len() / 8).saturating_add(64) {
            return;
        }
        let merged: BTreeMap<K, V> =
            self.iter().map(|(key, value)| (key.clone(), value.clone())).collect();
        self.base = Arc::new(merged);
        self.over.clear();
    }
}

/// The devices claiming an address: those assigned it, those deriving it.
type Claim = (BTreeSet<DeviceId>, BTreeSet<DeviceId>);

/// The IPv4 addresses a network's devices hold, in both directions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Holdings {
    /// The network addresses were derived for.
    network: NetworkId,
    /// The range addresses were derived in.
    range: Ipv4Range,
    /// Every address claimed, by whom.
    claims: Layered<Ipv4Addr, Claim>,
    /// What each present device claims, and whether it was assigned it.
    claim_of: Layered<DeviceId, (Ipv4Addr, bool)>,
    /// Each present device holding an address.
    by_device: Layered<DeviceId, Ipv4Addr>,
    /// Each held address, and the device holding it.
    by_address: Layered<Ipv4Addr, DeviceId>,
    /// Each present device without an address, and why.
    colliding: Layered<DeviceId, Collision>,
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
            network: NetworkId::from_bytes([0; 32]),
            range,
            claims: Layered::default(),
            claim_of: Layered::default(),
            by_device: Layered::default(),
            by_address: Layered::default(),
            colliding: Layered::default(),
        }
    }

    /// The holdings of devices none of which was assigned an address.
    #[must_use]
    pub fn from<'a>(
        network: &NetworkId,
        range: Ipv4Range,
        devices: impl IntoIterator<Item = &'a DeviceId>,
    ) -> Self {
        Self::assigned(network, range, devices.into_iter().map(|device| (*device, None)))
    }

    /// Decides the holdings of a network: each present device, with the
    /// address it was assigned, if any.
    ///
    /// An assigned address that is not one of the range's hosts is as good as
    /// none: the device falls back to its derived candidate.
    #[must_use]
    pub fn assigned(
        network: &NetworkId,
        range: Ipv4Range,
        devices: impl IntoIterator<Item = (DeviceId, Option<[u8; 4]>)>,
    ) -> Self {
        let mut claims: BTreeMap<Ipv4Addr, Claim> = BTreeMap::new();
        let mut claim_of: BTreeMap<DeviceId, (Ipv4Addr, bool)> = BTreeMap::new();
        for (device, assigned) in devices {
            let (address, was_assigned) = Self::claimed(network, &range, &device, assigned);
            let claim = claims.entry(address).or_default();
            if was_assigned {
                claim.0.insert(device);
            } else {
                claim.1.insert(device);
            }
            claim_of.insert(device, (address, was_assigned));
        }

        let mut by_device = BTreeMap::new();
        let mut by_address = BTreeMap::new();
        let mut colliding = BTreeMap::new();
        for (address, claim) in &claims {
            let (holder, everyone) = Self::decided(claim);
            for device in &everyone {
                if Some(*device) == holder {
                    by_device.insert(*device, *address);
                    by_address.insert(*address, *device);
                } else {
                    let with = everyone.iter().filter(|other| *other != device).copied().collect();
                    colliding.insert(*device, Collision { candidate: *address, with });
                }
            }
        }
        Self {
            network: *network,
            range,
            claims: Layered::of(claims),
            claim_of: Layered::of(claim_of),
            by_device: Layered::of(by_device),
            by_address: Layered::of(by_address),
            colliding: Layered::of(colliding),
        }
    }

    /// The address a device claims, and whether it was assigned it.
    fn claimed(
        network: &NetworkId,
        range: &Ipv4Range,
        device: &DeviceId,
        assigned: Option<[u8; 4]>,
    ) -> (Ipv4Addr, bool) {
        match assigned.filter(|address| assignable(range, *address)) {
            Some(address) => (Ipv4Addr::from(address), true),
            None => (ipv4_candidate(network, device, range), false),
        }
    }

    /// Who holds an address its claimants contend for, and all of them.
    ///
    /// One device assigned it holds it, whoever derives it; failing that, one
    /// device deriving it, alone.
    fn decided((assigned, derived): &Claim) -> (Option<DeviceId>, BTreeSet<DeviceId>) {
        let everyone: BTreeSet<DeviceId> = assigned.union(derived).copied().collect();
        let holder = match (assigned.len(), derived.len()) {
            (1, _) => assigned.first().copied(),
            (0, 1) => derived.first().copied(),
            _ => None,
        };
        (holder, everyone)
    }

    /// The holdings a roster state implies.
    #[must_use]
    pub fn of_state(state: &RosterState) -> Self {
        Self::assigned(
            &state.network,
            state.params.ipv4_range(),
            state.devices.iter().map(|(device, leaf)| (device, leaf.settings.ipv4)),
        )
    }

    /// The holdings `state` implies, where these are the holdings `previous`
    /// implied: only the addresses the devices that changed claimed, or claim
    /// now, are decided again. Where the two states share no base, or the
    /// network or its range changed, decided whole.
    #[must_use]
    pub fn updated(&self, previous: &RosterState, state: &RosterState) -> Self {
        let range = state.params.ipv4_range();
        if state.network != self.network
            || previous.network != self.network
            || range != self.range
            || previous.params.ipv4_range() != self.range
        {
            return Self::of_state(state);
        }
        let Some(changed) = state.devices.differing(&previous.devices) else {
            return Self::of_state(state);
        };
        let mut next = self.clone();
        let mut unsettled: BTreeSet<Ipv4Addr> = BTreeSet::new();
        for device in changed {
            if let Some((address, was_assigned)) = next.claim_of.get(&device).copied() {
                next.unclaim(&device, address, was_assigned);
                unsettled.insert(address);
            }
            if let Some(leaf) = state.devices.get(&device) {
                let (address, was_assigned) =
                    Self::claimed(&self.network, &range, &device, leaf.settings.ipv4);
                next.claim(device, address, was_assigned);
                unsettled.insert(address);
            }
        }
        for address in unsettled {
            next.decide(address);
        }
        next.claims.settle();
        next.claim_of.settle();
        next.by_device.settle();
        next.by_address.settle();
        next.colliding.settle();
        next
    }

    fn unclaim(&mut self, device: &DeviceId, address: Ipv4Addr, was_assigned: bool) {
        if let Some(mut claim) = self.claims.get(&address).cloned() {
            if was_assigned {
                claim.0.remove(device);
            } else {
                claim.1.remove(device);
            }
            self.claims.insert(address, claim);
        }
        self.claim_of.remove(device);
        self.by_device.remove(device);
        self.colliding.remove(device);
        if self.by_address.get(&address) == Some(device) {
            self.by_address.remove(&address);
        }
    }

    fn claim(&mut self, device: DeviceId, address: Ipv4Addr, was_assigned: bool) {
        let mut claim = self.claims.get(&address).cloned().unwrap_or_default();
        if was_assigned {
            claim.0.insert(device);
        } else {
            claim.1.insert(device);
        }
        self.claims.insert(address, claim);
        self.claim_of.insert(device, (address, was_assigned));
    }

    /// Decides `address` again, from the devices claiming it now.
    fn decide(&mut self, address: Ipv4Addr) {
        let claim = self.claims.get(&address).cloned().unwrap_or_default();
        if claim.0.is_empty() && claim.1.is_empty() {
            self.claims.remove(&address);
            self.by_address.remove(&address);
            return;
        }
        let (holder, everyone) = Self::decided(&claim);
        match holder {
            Some(holder) => self.by_address.insert(address, holder),
            None => self.by_address.remove(&address),
        }
        for device in &everyone {
            if Some(*device) == holder {
                self.by_device.insert(*device, address);
                self.colliding.remove(device);
            } else {
                self.by_device.remove(device);
                let with = everyone.iter().filter(|other| *other != device).copied().collect();
                self.colliding.insert(*device, Collision { candidate: address, with });
            }
        }
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
            [(assigned, Some(address.octets())), (deriving, None), (other, None)],
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
        let holdings = Ipv4Holdings::assigned(&network(), range, [(device(1), Some(first))]);
        assert_eq!(holdings.of(&device(1)), Some(ipv4_candidate(&network(), &device(1), &range)));
        let elsewhere =
            Ipv4Holdings::assigned(&network(), range, [(device(1), Some([192, 168, 1, 1]))]);
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

    /// A state over a narrow range, every device in it assigned what `assigned`
    /// says of it.
    fn state_of(devices: &BTreeMap<u8, Option<u8>>, base: Option<&RosterState>) -> RosterState {
        let mut state = base.cloned().unwrap_or_else(|| {
            let mut params = roster::types::NetworkParams::new(
                vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
                "example.internal",
                0,
            )
            .expect("parameters");
            params.ipv4 = Some(narrow());
            RosterState::empty(network(), params)
        });
        let held: Vec<DeviceId> = state.devices.keys().collect();
        for device in held {
            if !devices.keys().any(|tag| self::device(*tag) == device) {
                state.devices.remove(&device);
            }
        }
        for (tag, last) in devices {
            let leaf = roster::leaf::DeviceLeaf {
                record: roster::types::DeviceRecord {
                    id: device(*tag),
                    keys: Vec::new(),
                    name: format!("d{tag}"),
                    role: roster::types::Role::Member,
                    founder: false,
                    added_by: roster::id::OperationId::from_bytes([1; 32]),
                    capabilities: Vec::new(),
                },
                settings: roster::leaf::DeviceSettings::new(
                    roster::leaf::Mode::Full,
                    Vec::new(),
                    last.map(|last| [10, 0, 0, last % 16]),
                    None,
                )
                .expect("settings"),
            };
            state.devices.insert_leaf(leaf);
        }
        state
    }

    proptest::proptest! {
        #[test]
        fn following_changes_is_deciding_whole(
            steps in proptest::collection::vec(
                proptest::collection::btree_map(0u8..24, proptest::option::of(0u8..16), 0..20),
                1..8,
            ),
        ) {
            let mut previous = state_of(&BTreeMap::new(), None);
            previous.devices.flatten();
            let mut holdings = Ipv4Holdings::of_state(&previous);
            for devices in &steps {
                let next = state_of(devices, Some(&previous));
                holdings = holdings.updated(&previous, &next);
                let whole = Ipv4Holdings::of_state(&next);
                proptest::prop_assert_eq!(&holdings, &whole);
                proptest::prop_assert_eq!(
                    holdings.held().collect::<Vec<_>>(),
                    whole.held().collect::<Vec<_>>()
                );
                previous = next;
            }
        }
    }
}

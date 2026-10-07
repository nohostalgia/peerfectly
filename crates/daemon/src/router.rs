//! Which session a packet leaving the machine belongs to.
//!
//! `tunnel` left the reverse lookup open, noting the derivation does not invert.
//! It does not need to. The daemon only ever routes to devices it has a session
//! with, so it derives each of those addresses **forwards** and keeps the result.
//! A hash that cannot be inverted is not a problem when the set of inputs worth
//! asking about is small and already known.
//!
//! # Nothing a peer said gets in here
//!
//! Entries come from two places: the device identity the transport authenticated
//! when a session was established, and the prefix in the signed network
//! parameters. Neither is something a peer can choose.
//!
//! That is the whole security property of this module. A map that could be
//! extended by an address a peer announced would let one member receive another
//! member's traffic — the outbound mirror of the spoofing `tunnel` refuses on the
//! way in, and a good deal quieter, because nothing would look wrong.
//!
//! IPv4 is the same, with one more input that no peer chooses either: the
//! holdings the roster state implies. A device with a session is routable at its
//! IPv4 address only while the holdings say it holds one.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use roster::id::DeviceId;
use tunnel::{Ipv4Holdings, Prefix, address_of};

/// Where a packet for an overlay address should go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Router {
    /// The network's prefix, from the signed parameters.
    prefix: Prefix,
    /// Address to device, for devices with a live session.
    live: BTreeMap<Ipv6Addr, DeviceId>,
    /// Which device holds which IPv4 address, from the roster state.
    holdings: Ipv4Holdings,
    /// IPv4 address to device, for devices with a live session that hold one.
    live_v4: BTreeMap<Ipv4Addr, DeviceId>,
    /// Address to device, for every member, session or not.
    ///
    /// What lets a packet for a member with no session open one: the router has
    /// to know whose address it is before anyone can be asked to answer at it.
    /// Derived from the roster's members, never supplied.
    members: BTreeMap<Ipv6Addr, DeviceId>,
    /// The same for IPv4, from the holdings.
    members_v4: BTreeMap<Ipv4Addr, DeviceId>,
}

impl Router {
    /// An empty router for a network, in which no device holds IPv4 yet.
    #[must_use]
    pub fn new(prefix: Prefix) -> Self {
        Self {
            prefix,
            live: BTreeMap::new(),
            holdings: Ipv4Holdings::default(),
            live_v4: BTreeMap::new(),
            members: BTreeMap::new(),
            members_v4: BTreeMap::new(),
        }
    }

    /// Replaces the members a packet may open a session to.
    ///
    /// Each address is derived here from the device id, as [`Self::opened`]
    /// derives a live one; the caller names devices, never addresses.
    pub fn set_members(&mut self, devices: impl IntoIterator<Item = DeviceId>) {
        self.members =
            devices.into_iter().map(|device| (address_of(&device, &self.prefix), device)).collect();
        self.members_v4 = self
            .members
            .values()
            .filter_map(|device| self.holdings.of(device).map(|address| (address, *device)))
            .collect();
    }

    /// The member whose address this is, whether or not a session to it is open.
    ///
    /// `None` for an address no member holds.
    #[must_use]
    pub fn member_at(&self, destination: impl Into<IpAddr>) -> Option<DeviceId> {
        match destination.into() {
            IpAddr::V6(address) => self.members.get(&address).copied(),
            IpAddr::V4(address) => self.members_v4.get(&address).copied(),
        }
    }

    /// Records that a session to a device is established.
    ///
    /// The address is derived here, from the device identity the transport
    /// authenticated. The caller cannot supply one.
    pub fn opened(&mut self, device: DeviceId) {
        let address = address_of(&device, &self.prefix);
        self.live.insert(address, device);
        if let Some(address) = self.holdings.of(&device) {
            self.live_v4.insert(address, device);
        }
    }

    /// Records that a session has gone.
    pub fn closed(&mut self, device: &DeviceId) {
        let address = address_of(device, &self.prefix);
        self.live.remove(&address);
        self.live_v4.retain(|_, holder| holder != device);
    }

    /// Replaces the IPv4 holdings, and with them every live IPv4 entry.
    ///
    /// A device that lost its address stops being routable at it, and one that
    /// gained one becomes routable, without its session changing.
    pub fn set_holdings(&mut self, holdings: Ipv4Holdings) {
        self.live_v4 = self
            .live
            .values()
            .filter_map(|device| holdings.of(device).map(|address| (address, *device)))
            .collect();
        self.members_v4 = self
            .members
            .values()
            .filter_map(|device| holdings.of(device).map(|address| (address, *device)))
            .collect();
        self.holdings = holdings;
    }

    /// The device a packet for this address should go to.
    ///
    /// `None` for an address on the network with no session, which is the
    /// ordinary case for a device that is switched off. It is not an error and
    /// not a refusal — there is simply nowhere to send it yet.
    #[must_use]
    pub fn route(&self, destination: impl Into<IpAddr>) -> Option<DeviceId> {
        match destination.into() {
            IpAddr::V6(address) => self.live.get(&address).copied(),
            IpAddr::V4(address) => self.live_v4.get(&address).copied(),
        }
    }

    /// The address this router would use for a device.
    #[must_use]
    pub fn address_of(&self, device: &DeviceId) -> Ipv6Addr {
        address_of(device, &self.prefix)
    }

    /// How many sessions are live.
    #[must_use]
    pub fn len(&self) -> usize {
        self.live.len()
    }

    /// Whether any session is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    fn prefix() -> Prefix {
        Prefix::from_parameter(&[0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).expect("valid")
    }

    fn device(tag: u8) -> DeviceId {
        DeviceId::from_bytes([tag; 32])
    }

    #[test]
    fn a_packet_goes_to_the_session_for_its_destination() {
        let mut router = Router::new(prefix());
        router.opened(device(1));
        router.opened(device(2));

        assert_eq!(router.route(router.address_of(&device(1))), Some(device(1)));
        assert_eq!(router.route(router.address_of(&device(2))), Some(device(2)));
    }

    /// A device with no session is not routable. Not an error — it is switched
    /// off — but there is nowhere to send it.
    #[test]
    fn an_address_with_no_session_is_not_routable() {
        let mut router = Router::new(prefix());
        router.opened(device(1));

        assert_eq!(router.route(router.address_of(&device(2))), None);
    }

    #[test]
    fn a_closed_session_stops_being_routable() {
        let mut router = Router::new(prefix());
        router.opened(device(1));
        router.closed(&device(1));

        assert_eq!(router.route(router.address_of(&device(1))), None);
        assert!(router.is_empty());
    }

    #[test]
    fn an_address_off_the_network_is_not_routable() {
        let mut router = Router::new(prefix());
        router.opened(device(1));

        let elsewhere: Ipv6Addr = "2001:db8::1".parse().expect("valid");
        assert_eq!(router.route(elsewhere), None);
    }

    /// The map is built forwards from authenticated identities. There is no way
    /// to put an address in it directly, and this is what stops one member
    /// receiving another's traffic.
    #[test]
    fn nothing_can_insert_an_address_of_its_own_choosing() {
        let code = crate::code_of(include_str!("router.rs"));

        assert!(
            !code.contains("pub fn insert") && !code.contains("pub fn learn_address"),
            "an entry must derive from an authenticated device, never be supplied"
        );
        assert!(code.contains("address_of(&device"), "every entry is derived here");
    }

    /// The router follows the signed parameters: the same device in a different
    /// network is a different address.
    #[test]
    fn the_router_follows_the_prefix() {
        let mut ours = Router::new(prefix());
        let mut theirs = Router::new(
            Prefix::from_parameter(&[0xfd, 0x11, 0x22, 0x33, 0x00, 0x00, 0x00, 0x00])
                .expect("valid"),
        );
        ours.opened(device(1));
        theirs.opened(device(1));

        assert_ne!(ours.address_of(&device(1)), theirs.address_of(&device(1)));
        assert_eq!(ours.route(theirs.address_of(&device(1))), None);
    }

    fn holdings(devices: &[DeviceId]) -> Ipv4Holdings {
        Ipv4Holdings::from(
            &roster::id::NetworkId::from_bytes([3; 32]),
            roster::types::Ipv4Range::DEFAULT,
            devices,
            &[],
        )
    }

    #[test]
    fn an_ipv4_packet_goes_to_the_session_holding_its_destination() {
        let mut router = Router::new(prefix());
        router.set_holdings(holdings(&[device(1), device(2)]));
        router.opened(device(1));
        router.opened(device(2));

        let one = holdings(&[device(1), device(2)]).of(&device(1)).expect("held");
        let two = holdings(&[device(1), device(2)]).of(&device(2)).expect("held");
        assert_eq!(router.route(one), Some(device(1)));
        assert_eq!(router.route(two), Some(device(2)));
        assert_eq!(router.route(Ipv4Addr::from(u32::from(one) ^ 1)), None, "held by nobody");
    }

    /// Holdings arriving after a session opened still make it routable, and a
    /// device losing its address stops being routable at it.
    #[test]
    fn new_holdings_apply_to_sessions_already_open() {
        let mut router = Router::new(prefix());
        router.opened(device(1));
        let address = holdings(&[device(1)]).of(&device(1)).expect("held");
        assert_eq!(router.route(address), None, "nothing held yet");

        router.set_holdings(holdings(&[device(1)]));
        assert_eq!(router.route(address), Some(device(1)));

        router.set_holdings(holdings(&[]));
        assert_eq!(router.route(address), None);
        assert_eq!(router.route(router.address_of(&device(1))), Some(device(1)), "IPv6 stays");
    }

    #[test]
    fn a_closed_session_stops_being_routable_over_ipv4() {
        let mut router = Router::new(prefix());
        router.set_holdings(holdings(&[device(1)]));
        router.opened(device(1));
        router.closed(&device(1));

        assert_eq!(router.route(holdings(&[device(1)]).of(&device(1)).expect("held")), None);
    }

    #[test]
    fn reopening_a_session_does_not_duplicate_it() {
        let mut router = Router::new(prefix());
        router.opened(device(1));
        router.opened(device(1));
        assert_eq!(router.len(), 1);
    }
}

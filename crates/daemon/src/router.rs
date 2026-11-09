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
    /// Which device holds which IPv4 address, from the roster state: an IPv4
    /// address is routed to its holder, where the holder is routable at its
    /// IPv6 one.
    holdings: Ipv4Holdings,
    /// Who is at an address, for every member, session or not.
    ///
    /// What lets a packet for a member with no session open one: the router has
    /// to know whose address it is before anyone can be asked to answer at it.
    /// Derived from the roster's members, never supplied.
    members: Members,
}

/// The members a packet may open a session to: a list, or a roster state asked
/// by its index of the addresses its devices derive. Not a map of every
/// member's address: 50 bytes a device at a fleet's size, made again at every
/// change (`scalable-membership` 16.6).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Members {
    Listed(BTreeMap<Ipv6Addr, DeviceId>),
    Of { state: Box<roster::state::RosterState>, me: DeviceId },
}

/// Names the derivation the index of interface identifiers is built for.
const INTERFACE_TAG: [u8; 32] = *b"peerfectly ipv6 interface ids v1";

impl Members {
    /// The member at `address`, under `prefix`.
    fn at(&self, address: Ipv6Addr, prefix: &Prefix) -> Option<DeviceId> {
        match self {
            Self::Listed(listed) => listed.get(&address).copied(),
            Self::Of { state, me } => {
                // The first four bytes of the device's part, which a /64 prefix
                // leaves alone: the same whatever the prefix, so the index
                // outlives a change of it. Every hit is held to the whole
                // address again.
                let interface = |device: &DeviceId| {
                    let octets = address_of(device, prefix).octets();
                    [octets[8], octets[9], octets[10], octets[11]]
                };
                let octets = address.octets();
                let value = [octets[8], octets[9], octets[10], octets[11]];
                let derivation = roster::members::Derivation { tag: INTERFACE_TAG, of: &interface };
                state
                    .devices
                    .deriving(&derivation, value)
                    .into_iter()
                    .find(|device| device != me && address_of(device, prefix) == address)
            }
        }
    }

    /// Whether `device` is one of them.
    fn holds(&self, device: &DeviceId, prefix: &Prefix) -> bool {
        match self {
            Self::Listed(listed) => listed.contains_key(&address_of(device, prefix)),
            Self::Of { state, me } => device != me && state.devices.contains_key(device),
        }
    }
}

impl Router {
    /// An empty router for a network, in which no device holds IPv4 yet.
    #[must_use]
    pub fn new(prefix: Prefix) -> Self {
        Self {
            prefix,
            live: BTreeMap::new(),
            holdings: Ipv4Holdings::default(),
            members: Members::Listed(BTreeMap::new()),
        }
    }

    /// Replaces the members a packet may open a session to.
    ///
    /// Each address is derived here from the device id, as [`Self::opened`]
    /// derives a live one; the caller names devices, never addresses.
    pub fn set_members(&mut self, devices: impl IntoIterator<Item = DeviceId>) {
        self.members = Members::Listed(
            devices.into_iter().map(|device| (address_of(&device, &self.prefix), device)).collect(),
        );
    }

    /// Takes every member of `state` but `me` as the members a packet may open
    /// a session to: a copy of the state, asked as packets come, which costs
    /// what copying a state costs.
    pub fn follow_state(&mut self, state: &roster::state::RosterState, me: &DeviceId) {
        self.members = Members::Of { state: Box::new(state.clone()), me: *me };
    }

    /// The member whose address this is, whether or not a session to it is open.
    ///
    /// `None` for an address no member holds.
    #[must_use]
    pub fn member_at(&self, destination: impl Into<IpAddr>) -> Option<DeviceId> {
        match destination.into() {
            IpAddr::V6(address) => self.members.at(address, &self.prefix),
            IpAddr::V4(address) => self
                .holdings
                .holder(address)
                .filter(|device| self.members.holds(device, &self.prefix)),
        }
    }

    /// The holder of an IPv4 address, where it has a live session.
    fn holder_in(
        &self,
        address: Ipv4Addr,
        routable: &BTreeMap<Ipv6Addr, DeviceId>,
    ) -> Option<DeviceId> {
        self.holdings
            .holder(address)
            .filter(|device| routable.contains_key(&address_of(device, &self.prefix)))
    }

    /// Records that a session to a device is established.
    ///
    /// The address is derived here, from the device identity the transport
    /// authenticated. The caller cannot supply one.
    pub fn opened(&mut self, device: DeviceId) {
        let address = address_of(&device, &self.prefix);
        self.live.insert(address, device);
    }

    /// Records that a session has gone.
    pub fn closed(&mut self, device: &DeviceId) {
        let address = address_of(device, &self.prefix);
        self.live.remove(&address);
    }

    /// Replaces the IPv4 holdings.
    ///
    /// A device that lost its address stops being routable at it, and one that
    /// gained one becomes routable, without its session changing.
    pub fn set_holdings(&mut self, holdings: Ipv4Holdings) {
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
            IpAddr::V4(address) => self.holder_in(address, &self.live),
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

    /// A state of these devices, some in its base and some laid by a batch.
    fn state_of(base: &[u8], batch: &[u8]) -> roster::state::RosterState {
        let params = roster::types::NetworkParams::new(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            "example.internal",
            0,
        )
        .unwrap();
        let entry = |tag: &u8| {
            let key = |purpose, name: &str| {
                roster::types::KeyEntry::new(
                    roster::types::Algorithm::Ed25519,
                    purpose,
                    blake3::hash(format!("{name}{tag}").as_bytes()).as_bytes().to_vec(),
                )
                .unwrap()
            };
            let mut keys = vec![
                key(roster::types::KeyPurpose::Signing, "s"),
                key(roster::types::KeyPurpose::Transport, "t"),
                key(roster::types::KeyPurpose::Attestation, "a"),
            ];
            keys.sort_by_key(roster::types::KeyEntry::order_key);
            roster::batch::BatchEntry {
                keys,
                name: format!("d{tag}"),
                serial: vec![*tag],
                ipv4: None,
            }
        };
        let layer = |tags: &[u8]| {
            roster::members::Layer::new(
                roster::id::OperationId::from_bytes([9; 32]),
                roster::leaf::Mode::Full,
                Vec::new(),
                tags.iter().map(entry).collect(),
            )
        };
        let mut state =
            roster::state::RosterState::empty(roster::id::NetworkId::from_bytes([7; 32]), params);
        let mut held = roster::members::Members::new();
        held.lay(std::sync::Arc::new(layer(base)), std::sync::Arc::default());
        state.devices = held.values().map(|leaf| (*leaf).clone()).collect();
        state.devices.lay(std::sync::Arc::new(layer(batch)), std::sync::Arc::default());
        state
    }

    /// Of a state, the members are asked of its index of addresses: each found
    /// at its own, a batch's as well as the base's, this device and a stranger
    /// not.
    #[test]
    fn of_a_state_every_member_is_found_at_its_address() {
        let state = state_of(&[1, 2, 3], &[4, 5, 6]);
        let me = state.devices.keys().next().unwrap();
        let mut router = Router::new(prefix());
        router.follow_state(&state, &me);
        for device in state.devices.keys() {
            let expected = (device != me).then_some(device);
            assert_eq!(router.member_at(router.address_of(&device)), expected);
        }
        assert_eq!(router.member_at(router.address_of(&device(200))), None, "a stranger is not");
        assert_eq!(
            router.route(router.address_of(&state.devices.keys().nth(4).unwrap())),
            None,
            "nor routed without a session"
        );
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
        Ipv4Holdings::from(roster::types::Ipv4Range::DEFAULT, devices)
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

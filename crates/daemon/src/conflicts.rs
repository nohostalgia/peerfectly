//! Which peers' IPv4 addresses this device withholds, and why.
//!
//! A peer's IPv4 address is fine in the network and may still be unusable here:
//! a printer on this Wi-Fi might hold the same address, or the gateway every
//! connection depends on, or a device of another network this device holds. A
//! route for it would take the address away from whatever already uses it.
//!
//! So it is decided on this device, from this device's own networks, and
//! re-decided when they change. A withheld peer gets no host route and no `A`
//! record; its IPv6 address and its name keep working. The same peer is fine on
//! a device somewhere else.
//!
//! Pure: every input is handed in, so the rule is exercised with no adapter and
//! the same function serves the desktop and the phone.
//!
//! **Not by range.** Withholding a whole network's range whenever a local subnet
//! overlaps it would withhold every peer on every phone behind carrier-grade NAT,
//! which is inside `100.64.0.0/10`. Only the addresses that actually collide are
//! withheld.

use core::fmt;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use roster::id::DeviceId;

use crate::connectivity::{LocalInterface, Subnet};

/// What a withheld peer's address conflicts with on this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conflict {
    /// An address this device holds on one of its own interfaces.
    LocalAddress,
    /// A subnet one of this device's interfaces is on.
    LocalSubnet(Subnet),
    /// A gateway this device routes through.
    Gateway,
    /// A resolver this device uses.
    Resolver,
    /// The relay this network's transport reaches.
    Relay,
    /// The rendezvous this network's transport reaches.
    Rendezvous,
    /// This device's own IPv4 address in another network.
    OwnAddressIn {
        /// That network's local label.
        network: String,
    },
    /// A peer of another network, whose label sorts earlier and so keeps the
    /// address.
    PeerOf {
        /// That network's local label.
        network: String,
        /// The peer routed to it there.
        device: DeviceId,
    },
}

impl fmt::Display for Conflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalAddress => write!(f, "an address of this device"),
            Self::LocalSubnet(subnet) => {
                let mask = u32::MAX
                    .checked_shl(32_u32.saturating_sub(u32::from(subnet.prefix_len.min(32))))
                    .unwrap_or(0);
                let network = Ipv4Addr::from(u32::from(subnet.address) & mask);
                write!(f, "the local subnet {network}/{}", subnet.prefix_len)
            }
            Self::Gateway => write!(f, "a gateway of this device"),
            Self::Resolver => write!(f, "a resolver of this device"),
            Self::Relay => write!(f, "the relay"),
            Self::Rendezvous => write!(f, "the rendezvous"),
            Self::OwnAddressIn { network } => {
                write!(f, "this device's address in network {network}")
            }
            Self::PeerOf { network, device } => {
                write!(f, "device [{}] of network {network}", crate::control::short_id(device))
            }
        }
    }
}

/// Another network this device holds, as far as conflicts need to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtherNetwork {
    /// Its local label. Labels decide which of two networks keeps an address.
    pub label: String,
    /// This device's own IPv4 address there, if it holds one and the network is
    /// up.
    pub own: Option<Ipv4Addr>,
    /// The peers routed to there, after that network's own withholding.
    pub routed: Vec<(DeviceId, Ipv4Addr)>,
}

/// The infrastructure this network's transport reaches, by IPv4 address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Infrastructure {
    /// The relay's addresses: a literal one, or those it resolved to.
    pub relay: Vec<Ipv4Addr>,
    /// The rendezvous's addresses, the same way.
    pub rendezvous: Vec<Ipv4Addr>,
}

impl Infrastructure {
    /// The addresses written literally in the relay and rendezvous URLs.
    ///
    /// A name is not resolved here: resolving is traffic, and this is called
    /// whenever anything changes. Resolved addresses join when the transport
    /// resolves them.
    #[must_use]
    pub fn literal(relay: Option<&str>, rendezvous: Option<&str>) -> Self {
        Self {
            relay: relay.and_then(literal_ipv4).into_iter().collect(),
            rendezvous: rendezvous.and_then(literal_ipv4).into_iter().collect(),
        }
    }
}

/// The IPv4 address a URL names literally, if it names one.
#[must_use]
pub fn literal_ipv4(url: &str) -> Option<Ipv4Addr> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let host = host.split_once(':').map_or(host, |(host, _)| host);
    host.parse().ok()
}

/// The peers of one network withheld on this device, and what each conflicts
/// with.
///
/// `this` is the network's own label; a peer colliding with a peer of a network
/// whose label sorts **earlier** is withheld here, and one colliding with a later
/// network's peer is not — that network withholds its own. The order of labels
/// is the same after every restart, so the same peer stays withheld.
#[must_use]
pub fn withheld(
    this: &str,
    local: &[LocalInterface],
    infrastructure: &Infrastructure,
    others: &[OtherNetwork],
    peers: impl IntoIterator<Item = (DeviceId, Ipv4Addr)>,
) -> BTreeMap<DeviceId, Conflict> {
    peers
        .into_iter()
        .filter_map(|(device, address)| {
            conflict(this, local, infrastructure, others, address).map(|why| (device, why))
        })
        .collect()
}

/// The first conflict one address has, in the order a person would look.
fn conflict(
    this: &str,
    local: &[LocalInterface],
    infrastructure: &Infrastructure,
    others: &[OtherNetwork],
    address: Ipv4Addr,
) -> Option<Conflict> {
    let usable = || local.iter().filter(|interface| !interface.loopback);
    if usable().any(|interface| interface.ipv4.contains(&address)) {
        return Some(Conflict::LocalAddress);
    }
    if usable().any(|interface| interface.gateways.contains(&address)) {
        return Some(Conflict::Gateway);
    }
    if usable().any(|interface| interface.resolvers.contains(&address)) {
        return Some(Conflict::Resolver);
    }
    if infrastructure.relay.contains(&address) {
        return Some(Conflict::Relay);
    }
    if infrastructure.rendezvous.contains(&address) {
        return Some(Conflict::Rendezvous);
    }
    for other in others.iter().filter(|other| other.label != this) {
        if other.own == Some(address) {
            return Some(Conflict::OwnAddressIn { network: other.label.clone() });
        }
        if other.label.as_str() < this
            && let Some((device, _)) = other.routed.iter().find(|(_, routed)| *routed == address)
        {
            return Some(Conflict::PeerOf { network: other.label.clone(), device: *device });
        }
    }
    usable()
        .flat_map(|interface| interface.subnets.iter())
        // A host subnet is the address itself, already checked; a `/0` would be
        // everything and is not a subnet anybody is on.
        .find(|subnet| subnet.prefix_len > 0 && subnet.contains(address))
        .map(|subnet| Conflict::LocalSubnet(*subnet))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    fn device(tag: u8) -> DeviceId {
        DeviceId::from_bytes([tag; 32])
    }

    fn wifi() -> LocalInterface {
        LocalInterface {
            index: 3,
            ipv4: vec![Ipv4Addr::new(192, 168, 1, 40)],
            subnets: vec![Subnet { address: Ipv4Addr::new(192, 168, 1, 40), prefix_len: 24 }],
            gateways: vec![Ipv4Addr::new(192, 168, 1, 1)],
            resolvers: vec![Ipv4Addr::new(192, 168, 1, 53)],
            up: true,
            running: true,
            multicast: true,
            loopback: false,
        }
    }

    fn only(
        address: Ipv4Addr,
        local: &[LocalInterface],
        others: &[OtherNetwork],
    ) -> Option<Conflict> {
        withheld(
            "casa",
            local,
            &Infrastructure::literal(
                Some("https://203.0.113.9:4433"),
                Some("https://198.51.100.7"),
            ),
            others,
            [(device(1), address)],
        )
        .remove(&device(1))
    }

    #[test]
    fn a_peer_elsewhere_is_not_withheld() {
        assert_eq!(only(Ipv4Addr::new(100, 64, 7, 9), &[wifi()], &[]), None);
    }

    #[test]
    fn a_peer_equal_to_a_local_address_is_withheld() {
        let mut vpn = wifi();
        vpn.ipv4 = vec![Ipv4Addr::new(100, 64, 7, 9)];
        vpn.subnets = Vec::new();
        assert_eq!(
            only(Ipv4Addr::new(100, 64, 7, 9), &[wifi(), vpn], &[]),
            Some(Conflict::LocalAddress)
        );
    }

    #[test]
    fn a_peer_inside_a_local_subnet_is_withheld_naming_it() {
        let conflict = only(Ipv4Addr::new(192, 168, 1, 77), &[wifi()], &[]).unwrap();
        assert_eq!(
            conflict,
            Conflict::LocalSubnet(Subnet {
                address: Ipv4Addr::new(192, 168, 1, 40),
                prefix_len: 24
            })
        );
        assert_eq!(conflict.to_string(), "the local subnet 192.168.1.0/24");
    }

    #[test]
    fn a_peer_equal_to_a_gateway_or_resolver_is_withheld() {
        let mut routed_elsewhere = wifi();
        routed_elsewhere.subnets = Vec::new();
        assert_eq!(
            only(Ipv4Addr::new(192, 168, 1, 1), &[routed_elsewhere.clone()], &[]),
            Some(Conflict::Gateway)
        );
        assert_eq!(
            only(Ipv4Addr::new(192, 168, 1, 53), &[routed_elsewhere], &[]),
            Some(Conflict::Resolver)
        );
    }

    #[test]
    fn a_peer_equal_to_the_relay_or_rendezvous_is_withheld() {
        assert_eq!(only(Ipv4Addr::new(203, 0, 113, 9), &[], &[]), Some(Conflict::Relay));
        assert_eq!(only(Ipv4Addr::new(198, 51, 100, 7), &[], &[]), Some(Conflict::Rendezvous));
    }

    /// Between two networks the earlier label keeps the address, whichever
    /// network was loaded first.
    #[test]
    fn a_peer_of_an_earlier_network_keeps_the_address() {
        let address = Ipv4Addr::new(100, 64, 1, 1);
        let alpha = OtherNetwork {
            label: "alpha".to_owned(),
            own: None,
            routed: vec![(device(9), address)],
        };
        let zeta = OtherNetwork {
            label: "zeta".to_owned(),
            own: None,
            routed: vec![(device(9), address)],
        };

        match only(address, &[], &[alpha]) {
            Some(Conflict::PeerOf { network, device: other }) => {
                assert_eq!(network, "alpha");
                assert_eq!(other, device(9));
            }
            other => panic!("the later network withholds its peer, got {other:?}"),
        }
        assert_eq!(only(address, &[], &[zeta]), None, "the earlier network keeps it");
    }

    #[test]
    fn a_peer_equal_to_this_devices_address_in_another_network_is_withheld() {
        let address = Ipv4Addr::new(100, 64, 1, 1);
        let zeta =
            OtherNetwork { label: "zeta".to_owned(), own: Some(address), routed: Vec::new() };
        assert_eq!(
            only(address, &[], &[zeta]),
            Some(Conflict::OwnAddressIn { network: "zeta".to_owned() })
        );
    }

    /// The reason not to withhold by range: a phone behind carrier-grade NAT
    /// holds an address inside `100.64.0.0/10`, and every peer elsewhere in that
    /// block is still reachable.
    #[test]
    fn a_cgnat_phone_address_does_not_withhold_peers_elsewhere_in_the_block() {
        let cellular = LocalInterface {
            index: 9,
            ipv4: vec![Ipv4Addr::new(100, 72, 5, 9)],
            subnets: vec![Subnet { address: Ipv4Addr::new(100, 72, 5, 9), prefix_len: 30 }],
            gateways: vec![Ipv4Addr::new(100, 72, 5, 10)],
            resolvers: Vec::new(),
            up: true,
            running: true,
            multicast: false,
            loopback: false,
        };
        assert_eq!(only(Ipv4Addr::new(100, 64, 7, 9), std::slice::from_ref(&cellular), &[]), None);
        assert_eq!(only(Ipv4Addr::new(100, 127, 0, 1), std::slice::from_ref(&cellular), &[]), None);
        assert!(only(Ipv4Addr::new(100, 72, 5, 11), &[cellular], &[]).is_some(), "its own /30 is");
    }

    #[test]
    fn the_loopback_interface_withholds_nothing() {
        let loopback = LocalInterface {
            ipv4: vec![Ipv4Addr::LOCALHOST],
            subnets: vec![Subnet { address: Ipv4Addr::LOCALHOST, prefix_len: 8 }],
            loopback: true,
            ..wifi()
        };
        assert_eq!(only(Ipv4Addr::new(127, 0, 0, 1), &[loopback], &[]), None);
    }

    #[test]
    fn a_literal_address_is_read_from_a_url_and_a_name_is_not() {
        assert_eq!(literal_ipv4("https://203.0.113.10"), Some(Ipv4Addr::new(203, 0, 113, 10)));
        assert_eq!(literal_ipv4("https://10.0.0.2:4433/path"), Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(literal_ipv4("https://relay.example.com:4433"), None);
        assert_eq!(literal_ipv4("https://[2001:db8::1]:4433"), None);
        assert_eq!(literal_ipv4("192.0.2.1"), Some(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn only_the_peers_that_conflict_are_returned() {
        let result = withheld(
            "casa",
            &[wifi()],
            &Infrastructure::default(),
            &[],
            [(device(1), Ipv4Addr::new(192, 168, 1, 9)), (device(2), Ipv4Addr::new(100, 64, 0, 9))],
        );
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&device(1)));
    }
}

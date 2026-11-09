//! Which parts of a network's IPv4 block this device does not route, and why.
//!
//! A peer's IPv4 address is fine in the network and may still be unusable here:
//! a printer on this Wi-Fi might hold the same address, or the gateway every
//! connection depends on, or a device of another network this device holds. A
//! route for it would take the address away from whatever already uses it.
//!
//! So it is decided on this device, from this device's own networks, and
//! re-decided when they change. The network's block is routed whole, less
//! **holes**: the addresses and subnets it would take from something here. A
//! peer whose address falls in a hole is withheld: no route, no `A` record; its
//! IPv6 address and its name keep working. The same peer is fine on a device
//! somewhere else (`scalable-membership` 19.6).
//!
//! Holes are few — an interface's addresses and subnets, its gateways and
//! resolvers, the relay, another network — so this asks nothing of the roster:
//! no member's address is gathered to decide it, and whether one peer is
//! withheld is asked of the holes when it is wanted.
//!
//! A hole is as wide as what it protects and no wider. A phone behind
//! carrier-grade NAT on a `/30` inside `100.64.0.0/10` makes a `/30` hole; every
//! peer elsewhere in the block is still routed.
//!
//! Pure: every input is handed in, so the rule is exercised with no adapter and
//! the same function serves the desktop and the phone.

use core::fmt;
use std::net::Ipv4Addr;

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
    /// This device's own IPv4 address in another network.
    OwnAddressIn {
        /// That network's local label.
        network: String,
    },
    /// The block of another network that is up, whose label sorts earlier and
    /// so keeps the addresses both blocks hold.
    BlockOf {
        /// That network's local label.
        network: String,
    },
    /// Excluded by a person: on this device alone (`route exclude`), or by
    /// the network's admins for every device (`route exclude --everywhere`).
    Excluded {
        /// Whether the network's admins excluded it.
        everywhere: bool,
    },
}

/// A part of a network's block this device does not route: an address, or a
/// range of them, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hole {
    /// Its first address.
    pub address: Ipv4Addr,
    /// Its prefix length.
    pub prefix_len: u8,
    /// What it protects.
    pub why: Conflict,
}

impl Hole {
    /// Whether `address` is in it.
    #[must_use]
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        u32::from(address) & mask(self.prefix_len) == u32::from(self.address)
    }
}

/// The netmask of a prefix length.
fn mask(prefix_len: u8) -> u32 {
    u32::MAX.checked_shl(32_u32.saturating_sub(u32::from(prefix_len.min(32)))).unwrap_or(0)
}

/// The conflict of the first hole `address` falls in, if any: whether a peer at
/// that address is withheld here, and why.
#[must_use]
pub fn withheld_by(holes: &[Hole], address: Ipv4Addr) -> Option<&Conflict> {
    holes.iter().find(|hole| hole.contains(address)).map(|hole| &hole.why)
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
            Self::OwnAddressIn { network } => {
                write!(f, "this device's address in network {network}")
            }
            Self::BlockOf { network } => write!(f, "the IPv4 block of network {network}"),
            Self::Excluded { everywhere: false } => write!(f, "a block excluded on this device"),
            Self::Excluded { everywhere: true } => {
                write!(f, "a block the network's admins excluded")
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
    /// Its IPv4 block, where the network is up.
    pub block: Option<roster::types::Ipv4Range>,
}

/// The infrastructure this network's transport reaches, by IPv4 address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Infrastructure {
    /// The relay's addresses: a literal one, or those it resolved to.
    pub relay: Vec<Ipv4Addr>,
}

impl Infrastructure {
    /// The address written literally in the relay, `key@host:port`.
    ///
    /// A name is not resolved here: resolving is traffic, and this is called
    /// whenever anything changes. Resolved addresses join when the transport
    /// resolves them.
    #[must_use]
    pub fn literal(relay: Option<&str>) -> Self {
        Self { relay: relay.and_then(literal_ipv4).into_iter().collect() }
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

/// The holes in one network's `block` on this device, in the order a person
/// would look for what each protects.
///
/// `this` is the network's own label. Where another network that is up holds
/// some of the same addresses, the network whose label sorts **earlier** keeps
/// them and the later one has the hole; the order of labels is the same after
/// every restart, so the same addresses stay with the same network. Bringing a
/// network up over another is refused before it comes to that
/// ([`overlapping`]); this is what holds while both are up regardless.
#[must_use]
pub fn holes(
    this: &str,
    block: roster::types::Ipv4Range,
    local: &[LocalInterface],
    infrastructure: &Infrastructure,
    others: &[OtherNetwork],
) -> Vec<Hole> {
    holes_excluding(this, block, local, infrastructure, others, &Excluded::default())
}

/// What a person excluded from a network's route: on this device, and for
/// every device by the network's admins (`scalable-membership` 19.7).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Excluded {
    /// Excluded on this device alone.
    pub here: Vec<roster::types::Excluded>,
    /// Excluded by the network's admins, as its parameters say.
    pub everywhere: Vec<roster::types::Excluded>,
}

/// [`holes`], and what a person excluded, each a hole of its own after those
/// that protect something on this machine.
#[must_use]
pub fn holes_excluding(
    this: &str,
    block: roster::types::Ipv4Range,
    local: &[LocalInterface],
    infrastructure: &Infrastructure,
    others: &[OtherNetwork],
    excluded: &Excluded,
) -> Vec<Hole> {
    let base = u32::from_be_bytes(block.address());
    let len = block.prefix_len();
    // The part of `address/prefix_len` inside the block: the narrower of the
    // two, where they overlap at all, as two aligned blocks only can.
    let within = |address: Ipv4Addr, prefix_len: u8| -> Option<(Ipv4Addr, u8)> {
        let shorter = prefix_len.min(len);
        if u32::from(address) & mask(shorter) != base & mask(shorter) {
            return None;
        }
        Some(if prefix_len >= len {
            (Ipv4Addr::from(u32::from(address) & mask(prefix_len)), prefix_len)
        } else {
            (Ipv4Addr::from(base), len)
        })
    };
    let mut holes = Vec::new();
    let mut hole = |address: Ipv4Addr, prefix_len: u8, why: Conflict| {
        if let Some((address, prefix_len)) = within(address, prefix_len)
            && !holes
                .iter()
                .any(|held: &Hole| held.prefix_len <= prefix_len && held.contains(address))
        {
            holes.push(Hole { address, prefix_len, why });
        }
    };
    let usable = || local.iter().filter(|interface| !interface.loopback);
    for address in usable().flat_map(|interface| interface.ipv4.iter()) {
        hole(*address, 32, Conflict::LocalAddress);
    }
    for address in usable().flat_map(|interface| interface.gateways.iter()) {
        hole(*address, 32, Conflict::Gateway);
    }
    for address in usable().flat_map(|interface| interface.resolvers.iter()) {
        hole(*address, 32, Conflict::Resolver);
    }
    for address in &infrastructure.relay {
        hole(*address, 32, Conflict::Relay);
    }
    for other in others.iter().filter(|other| other.label != this) {
        if let Some(own) = other.own {
            hole(own, 32, Conflict::OwnAddressIn { network: other.label.clone() });
        }
        if other.label.as_str() < this
            && let Some(theirs) = other.block
        {
            hole(
                Ipv4Addr::from(theirs.address()),
                theirs.prefix_len(),
                Conflict::BlockOf { network: other.label.clone() },
            );
        }
    }
    // A host subnet is the address itself, already a hole; a `/0` would be
    // everything and is not a subnet anybody is on.
    for subnet in usable().flat_map(|interface| interface.subnets.iter()) {
        if subnet.prefix_len > 0 {
            hole(subnet.address, subnet.prefix_len, Conflict::LocalSubnet(*subnet));
        }
    }
    for (blocks, everywhere) in [(&excluded.everywhere, true), (&excluded.here, false)] {
        for excluded in blocks {
            hole(
                Ipv4Addr::from(excluded.address()),
                excluded.prefix_len(),
                Conflict::Excluded { everywhere },
            );
        }
    }
    holes
}

/// The networks up on this device whose blocks overlap `block`: what bringing
/// a network up in `block` would take addresses from.
#[must_use]
pub fn overlapping<'a>(
    this: &str,
    block: roster::types::Ipv4Range,
    others: &'a [OtherNetwork],
) -> Vec<&'a OtherNetwork> {
    others
        .iter()
        .filter(|other| other.label != this)
        .filter(|other| {
            other.block.is_some_and(|theirs| {
                let shorter = theirs.prefix_len().min(block.prefix_len());
                u32::from_be_bytes(theirs.address()) & mask(shorter)
                    == u32::from_be_bytes(block.address()) & mask(shorter)
            })
        })
        .collect()
}

/// `block` less `holes`, as the fewest aligned blocks that cover exactly the
/// rest: the routes a network's IPv4 takes on this device. One, the block
/// itself, where there is no hole; a few dozen at most for a few holes.
#[must_use]
pub fn routed(block: roster::types::Ipv4Range, holes: &[Hole]) -> Vec<(Ipv4Addr, u8)> {
    fn cover(base: u32, len: u8, holes: &[Hole], out: &mut Vec<(Ipv4Addr, u8)>) {
        let overlaps = |hole: &Hole| {
            let shorter = hole.prefix_len.min(len);
            u32::from(hole.address) & mask(shorter) == base & mask(shorter)
        };
        if holes.iter().any(|hole| hole.prefix_len <= len && overlaps(hole)) {
            // A hole as wide as this part, or wider: none of it is routed.
            return;
        }
        if !holes.iter().any(overlaps) {
            out.push((Ipv4Addr::from(base), len));
            return;
        }
        // A hole inside: each half on its own. A hole narrower than this part
        // means it is wider than a single address, so `len` is below 32.
        let next = len.saturating_add(1);
        let half = 1_u32.checked_shl(32_u32.saturating_sub(u32::from(next))).unwrap_or(0);
        cover(base, next, holes, out);
        cover(base | half, next, holes, out);
    }
    let mut out = Vec::new();
    cover(u32::from_be_bytes(block.address()), block.prefix_len(), holes, &mut out);
    out
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

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

    fn block(text: &str) -> roster::types::Ipv4Range {
        text.parse().unwrap()
    }

    fn relay() -> Infrastructure {
        Infrastructure::literal(Some(
            "0000000000000000000000000000000000000000000000000000000000000000@203.0.113.9:8443",
        ))
    }

    /// What a peer at `address` in `in_block` conflicts with here, if anything.
    fn only(
        address: Ipv4Addr,
        in_block: &str,
        local: &[LocalInterface],
        others: &[OtherNetwork],
    ) -> Option<Conflict> {
        let holes = holes("casa", block(in_block), local, &relay(), others);
        withheld_by(&holes, address).cloned()
    }

    #[test]
    fn a_block_away_from_everything_has_no_hole_and_one_route() {
        let holes = holes("casa", block("100.83.0.0/16"), &[wifi()], &relay(), &[]);
        assert!(holes.is_empty(), "{holes:?}");
        assert_eq!(routed(block("100.83.0.0/16"), &holes), [(Ipv4Addr::new(100, 83, 0, 0), 16)]);
    }

    #[test]
    fn a_local_address_gateway_resolver_or_relay_in_the_block_is_a_hole() {
        let mut vpn = wifi();
        vpn.ipv4 = vec![Ipv4Addr::new(100, 64, 7, 9)];
        vpn.subnets = Vec::new();
        vpn.gateways = vec![Ipv4Addr::new(100, 64, 7, 1)];
        vpn.resolvers = vec![Ipv4Addr::new(100, 64, 7, 53)];
        let at = |address| only(address, "100.64.0.0/10", std::slice::from_ref(&vpn), &[]);
        assert_eq!(at(Ipv4Addr::new(100, 64, 7, 9)), Some(Conflict::LocalAddress));
        assert_eq!(at(Ipv4Addr::new(100, 64, 7, 1)), Some(Conflict::Gateway));
        assert_eq!(at(Ipv4Addr::new(100, 64, 7, 53)), Some(Conflict::Resolver));
        assert_eq!(at(Ipv4Addr::new(100, 64, 7, 10)), None, "its neighbour is routed");
        let relay = Infrastructure { relay: vec![Ipv4Addr::new(10, 0, 0, 9)] };
        let holes = holes("casa", block("10.0.0.0/16"), &[], &relay, &[]);
        assert_eq!(withheld_by(&holes, Ipv4Addr::new(10, 0, 0, 9)), Some(&Conflict::Relay));
    }

    #[test]
    fn a_local_subnet_in_the_block_is_a_hole_naming_it() {
        let conflict =
            only(Ipv4Addr::new(192, 168, 1, 77), "192.168.0.0/16", &[wifi()], &[]).unwrap();
        assert_eq!(
            conflict,
            Conflict::LocalSubnet(Subnet {
                address: Ipv4Addr::new(192, 168, 1, 40),
                prefix_len: 24
            })
        );
        assert_eq!(conflict.to_string(), "the local subnet 192.168.1.0/24");
        assert_eq!(only(Ipv4Addr::new(192, 168, 2, 77), "192.168.0.0/16", &[wifi()], &[]), None);
    }

    /// A subnet wider than the block takes the whole block: nothing is routed.
    #[test]
    fn a_local_subnet_wider_than_the_block_takes_it_all() {
        let holes = holes("casa", block("192.168.1.0/28"), &[wifi()], &relay(), &[]);
        assert!(routed(block("192.168.1.0/28"), &holes).is_empty(), "{holes:?}");
    }

    /// The reason holes are as wide as what they protect: a phone behind
    /// carrier-grade NAT holds a `/30` inside `100.64.0.0/10`, and every peer
    /// elsewhere in the block is still routed.
    #[test]
    fn a_cgnat_phone_makes_a_small_hole() {
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
        let local = std::slice::from_ref(&cellular);
        assert_eq!(only(Ipv4Addr::new(100, 64, 7, 9), "100.64.0.0/10", local, &[]), None);
        assert!(only(Ipv4Addr::new(100, 72, 5, 11), "100.64.0.0/10", local, &[]).is_some());
        let holes = holes("casa", block("100.64.0.0/10"), local, &relay(), &[]);
        let routes = routed(block("100.64.0.0/10"), &holes);
        // Its address and its gateway, each named for what it is, inside the /30.
        assert_eq!(holes.len(), 3, "{holes:?}");
        assert_eq!(routes.len(), 20, "a /10 less a /30 is twenty blocks: {routes:?}");
        assert!(routes.iter().all(|(address, _)| withheld_by(&holes, *address).is_none()));
    }

    /// Between two networks the earlier label keeps the addresses both blocks
    /// hold, whichever was loaded first.
    #[test]
    fn an_earlier_network_keeps_the_addresses_both_blocks_hold() {
        let other = |label: &str| OtherNetwork {
            label: label.to_owned(),
            own: None,
            block: Some(block("100.64.0.0/16")),
        };
        let address = Ipv4Addr::new(100, 64, 1, 1);
        assert_eq!(
            only(address, "100.64.0.0/10", &[], &[other("alpha")]),
            Some(Conflict::BlockOf { network: "alpha".to_owned() })
        );
        assert_eq!(only(address, "100.64.0.0/10", &[], &[other("zeta")]), None);
        assert_eq!(overlapping("casa", block("100.64.0.0/10"), &[other("zeta")]).len(), 1);
        assert!(overlapping("casa", block("10.0.0.0/16"), &[other("zeta")]).is_empty());
    }

    #[test]
    fn this_devices_address_in_another_network_is_a_hole() {
        let address = Ipv4Addr::new(100, 64, 1, 1);
        let zeta = OtherNetwork { label: "zeta".to_owned(), own: Some(address), block: None };
        assert_eq!(
            only(address, "100.64.0.0/10", &[], &[zeta]),
            Some(Conflict::OwnAddressIn { network: "zeta".to_owned() })
        );
    }

    #[test]
    fn the_loopback_interface_makes_no_hole() {
        let loopback = LocalInterface {
            ipv4: vec![Ipv4Addr::new(10, 0, 0, 1)],
            subnets: vec![Subnet { address: Ipv4Addr::new(10, 0, 0, 1), prefix_len: 8 }],
            loopback: true,
            ..wifi()
        };
        assert_eq!(only(Ipv4Addr::new(10, 0, 0, 1), "10.0.0.0/16", &[loopback], &[]), None);
    }

    /// What is routed and what is a hole cover the block exactly, once.
    #[test]
    fn the_routes_and_the_holes_cover_the_block_exactly() {
        let mut vpn = wifi();
        vpn.ipv4 = vec![Ipv4Addr::new(10, 1, 2, 3), Ipv4Addr::new(10, 1, 200, 7)];
        vpn.subnets = vec![Subnet { address: Ipv4Addr::new(10, 1, 64, 1), prefix_len: 20 }];
        vpn.gateways = Vec::new();
        vpn.resolvers = Vec::new();
        let whole = block("10.1.0.0/16");
        let holes = holes("casa", whole, &[vpn], &Infrastructure::default(), &[]);
        let routes = routed(whole, &holes);
        let size = |len: u8| 1_u64 << (32 - u32::from(len));
        let covered: u64 = routes.iter().map(|(_, len)| size(*len)).sum::<u64>()
            + holes.iter().map(|hole| size(hole.prefix_len)).sum::<u64>();
        assert_eq!(covered, size(16), "{routes:?} {holes:?}");
        for probe in
            [[10, 1, 2, 3], [10, 1, 2, 4], [10, 1, 70, 9], [10, 1, 200, 7], [10, 1, 255, 254]]
        {
            let probe = Ipv4Addr::from(probe);
            let in_route = routes
                .iter()
                .filter(|(address, len)| u32::from(probe) & mask(*len) == u32::from(*address));
            assert_eq!(
                in_route.count() + usize::from(withheld_by(&holes, probe).is_some()),
                1,
                "{probe} is in exactly one"
            );
        }
    }

    /// What a person excluded is a hole, here or everywhere, and says which.
    #[test]
    fn an_excluded_block_is_a_hole_saying_who_excluded_it() {
        let excluded = Excluded {
            here: vec!["100.64.9.0/24".parse().unwrap()],
            everywhere: vec!["100.64.12.7".parse().unwrap()],
        };
        let holes = holes_excluding("casa", block("100.64.0.0/10"), &[], &relay(), &[], &excluded);
        assert_eq!(
            withheld_by(&holes, Ipv4Addr::new(100, 64, 9, 77)),
            Some(&Conflict::Excluded { everywhere: false })
        );
        let everywhere = withheld_by(&holes, Ipv4Addr::new(100, 64, 12, 7)).unwrap();
        assert_eq!(everywhere.to_string(), "a block the network's admins excluded");
        assert_eq!(withheld_by(&holes, Ipv4Addr::new(100, 64, 12, 8)), None);
        let outside =
            Excluded { here: vec!["192.168.1.0/24".parse().unwrap()], ..Excluded::default() };
        let none = holes_excluding("casa", block("100.64.0.0/10"), &[], &relay(), &[], &outside);
        assert!(none.is_empty(), "a block outside the network's is nothing to exclude");
    }

    #[test]
    fn a_literal_address_is_read_from_a_url_and_a_name_is_not() {
        assert_eq!(literal_ipv4("https://203.0.113.10"), Some(Ipv4Addr::new(203, 0, 113, 10)));
        assert_eq!(literal_ipv4("https://10.0.0.2:4433/path"), Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(literal_ipv4("https://relay.example.com:4433"), None);
        assert_eq!(literal_ipv4("https://[2001:db8::1]:4433"), None);
        assert_eq!(literal_ipv4("192.0.2.1"), Some(Ipv4Addr::new(192, 0, 2, 1)));
    }
}

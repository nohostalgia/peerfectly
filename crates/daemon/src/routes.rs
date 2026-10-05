//! Which routes should exist, decided before anything is written.
//!
//! This is a pure function of the signed network parameters and the adapter the
//! daemon is using. Nothing here touches the routing table; [`crate::platform`]
//! does that, and does nothing else.
//!
//! The separation is the point. §2.6 says the tunnel carries the network's prefix
//! and never a default route, and that is the single most consequential thing
//! this daemon does to a machine — get it wrong and every packet the computer
//! sends goes through the overlay. Deciding it here means it can be tested
//! exhaustively, on any machine, without Administrator and without an adapter.
//! Deciding it inside the call that writes the table would mean it could only be
//! tested by a person watching a routing table on Windows.
//!
//! # IPv4 is routed per peer, never per range
//!
//! A route for a network's whole IPv4 range would capture every address in it,
//! including hosts on the machine's own networks that happen to fall inside —
//! `100.64.0.0/10` is where every phone behind carrier-grade NAT lives. A host
//! route captures only the peer. There is no way to express a range route here:
//! the only IPv4 destination a [`Route`] can hold is one address.

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use roster::types::NetworkParams;
use tunnel::Prefix;

use crate::error::{Error, Result};

/// The adapter a route points at.
///
/// Opaque on purpose: the core does not care what a Windows interface index is,
/// only that routes belong to one and that one can go away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Interface(u32);

impl Interface {
    /// Names an interface by the number the platform gave it.
    #[must_use]
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// The number the platform gave it.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "interface {}", self.0)
    }
}

/// What a route covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// A network's IPv6 prefix.
    Prefix(Prefix),
    /// One IPv4 address: a peer's, as a `/32`.
    Host(Ipv4Addr),
}

/// One route: a destination, and the adapter it goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// What this route covers.
    destination: Destination,
    /// Where it sends packets.
    interface: Interface,
}

impl Route {
    /// A route for an IPv6 prefix through an adapter.
    #[must_use]
    pub const fn new(prefix: Prefix, interface: Interface) -> Self {
        Self { destination: Destination::Prefix(prefix), interface }
    }

    /// A host route for one peer's IPv4 address through an adapter.
    #[must_use]
    pub const fn host(address: Ipv4Addr, interface: Interface) -> Self {
        Self { destination: Destination::Host(address), interface }
    }

    /// What it covers.
    #[must_use]
    pub const fn destination(&self) -> Destination {
        self.destination
    }

    /// The IPv6 prefix it covers, when it covers one.
    #[must_use]
    pub const fn prefix(&self) -> Option<Prefix> {
        match self.destination {
            Destination::Prefix(prefix) => Some(prefix),
            Destination::Host(_) => None,
        }
    }

    /// The IPv4 address it covers, when it is a host route.
    #[must_use]
    pub const fn ipv4_host(&self) -> Option<Ipv4Addr> {
        match self.destination {
            Destination::Host(address) => Some(address),
            Destination::Prefix(_) => None,
        }
    }

    /// The adapter it points at.
    #[must_use]
    pub const fn interface(&self) -> Interface {
        self.interface
    }

    /// Whether this route would capture traffic for the whole internet.
    ///
    /// A zero-length prefix matches every address. Nothing in this crate may
    /// produce one, and this exists so that claim can be checked rather than
    /// asserted in prose. A host route is one address and never a default.
    #[must_use]
    pub const fn is_default_route(&self) -> bool {
        match self.destination {
            Destination::Prefix(prefix) => prefix.bits() == 0,
            Destination::Host(_) => false,
        }
    }

    /// The IPv6 prefix's sixteen octets, zero-padded past its length.
    ///
    /// All zero for a host route, which has no IPv6 prefix; read
    /// [`Self::destination`] to tell the two apart.
    #[must_use]
    pub fn octets(&self) -> [u8; 16] {
        let mut octets = [0u8; 16];
        if let Destination::Prefix(prefix) = self.destination {
            for (slot, byte) in octets.iter_mut().zip(prefix.to_parameter()) {
                *slot = byte;
            }
        }
        octets
    }

    /// The prefix length, as the platform wants it.
    #[must_use]
    pub fn prefix_length(&self) -> u8 {
        match self.destination {
            Destination::Prefix(prefix) => u8::try_from(prefix.bits()).unwrap_or(u8::MAX),
            Destination::Host(_) => 32,
        }
    }

    /// The destination in the usual `address/length` form.
    #[must_use]
    pub fn prefix_text(&self) -> String {
        match self.destination {
            Destination::Prefix(prefix) => {
                format!("{}/{}", Ipv6Addr::from(self.octets()), prefix.bits())
            }
            Destination::Host(address) => format!("{address}/32"),
        }
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} via {}", self.prefix_text(), self.interface)
    }
}

/// The routes and addresses that should exist while the tunnel is up.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    /// In the order they should be installed: the prefix first, then one host
    /// route per peer, in address order.
    routes: Vec<Route>,
    /// This device's own addresses on the adapter.
    addresses: Vec<IpAddr>,
}

impl Plan {
    /// The plan for a network's prefix alone, as its signed parameters describe
    /// it.
    ///
    /// Exactly one route: the network's prefix, through the adapter.
    ///
    /// # Errors
    ///
    /// When the parameters do not describe a usable prefix.
    pub fn for_network(params: &NetworkParams, interface: Interface) -> Result<Self> {
        Self::wanted(params, interface, None, None, [])
    }

    /// Everything a network that is up should have on this device.
    ///
    /// The prefix route; this device's IPv6 address, when given; its IPv4
    /// address, when it holds one; and one host route for each peer IPv4 address
    /// given — which the caller has already cut down to the peers that hold one
    /// and are not withheld here. There is no argument, flag, environment
    /// variable or configuration file that adds anything else — every input is
    /// derived from the roster.
    ///
    /// # Errors
    ///
    /// When the parameters do not describe a usable prefix.
    pub fn wanted(
        params: &NetworkParams,
        interface: Interface,
        own: Option<Ipv6Addr>,
        own_ipv4: Option<Ipv4Addr>,
        peers: impl IntoIterator<Item = Ipv4Addr>,
    ) -> Result<Self> {
        // The second line. The roster refuses a prefix outside `fd00::/8`, or of
        // any length but a `/64`, where the parameters are decoded; this refuses
        // it again where it would become a route, so parameters that reached
        // this device another way — an older build's, a state assembled in
        // memory — still cannot widen the tunnel. The rule is the roster's own,
        // called rather than restated, and the message names the value, which
        // the roster's cannot.
        if let Err(refusal) = roster::params::unique_local_prefix(&params.ula) {
            let reason = match refusal {
                roster::Error::InvalidValue(reason) | roster::Error::LimitExceeded(reason) => {
                    reason
                }
                _ => "outside what a network may claim",
            };
            return Err(Error::Parameters {
                cause: format!(
                    "{} is not a usable network prefix: {reason}",
                    parameter_text(&params.ula)
                ),
            });
        }

        let prefix = Prefix::from_parameter(&params.ula)
            .map_err(|cause| Error::Parameters { cause: cause.to_string() })?;

        if prefix.bits() == 0 {
            return Err(Error::Parameters {
                cause: "a zero-length prefix would route the whole internet through the tunnel"
                    .to_owned(),
            });
        }

        let range = params.ipv4_range();
        let mut hosts: Vec<Ipv4Addr> = peers
            .into_iter()
            // This device's own address is assigned, not routed; and an address
            // outside the range is nothing the holdings could have produced.
            .filter(|address| Some(*address) != own_ipv4 && range.contains(address.octets()))
            .collect();
        hosts.sort_unstable();
        hosts.dedup();

        let routes = core::iter::once(Route::new(prefix, interface))
            .chain(hosts.into_iter().map(|address| Route::host(address, interface)))
            .collect();
        let addresses = own.map(IpAddr::V6).into_iter().chain(own_ipv4.map(IpAddr::V4)).collect();
        Ok(Self { routes, addresses })
    }

    /// The routes, in the order they should be installed.
    #[must_use]
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// This device's own addresses on the adapter.
    #[must_use]
    pub fn own_addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// This device's own IPv4 address on the adapter, when it holds one.
    #[must_use]
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.addresses.iter().find_map(|address| match address {
            IpAddr::V4(address) => Some(*address),
            IpAddr::V6(_) => None,
        })
    }

    /// The IPv4 host routes, in address order.
    pub fn hosts(&self) -> impl Iterator<Item = Route> + '_ {
        self.routes.iter().filter(|route| route.ipv4_host().is_some()).copied()
    }

    /// Whether this plan would capture traffic for the whole internet.
    ///
    /// Always false, and checked rather than trusted.
    #[must_use]
    pub fn claims_a_default_route(&self) -> bool {
        self.routes.iter().any(Route::is_default_route)
    }

    /// The plan with routes through departed adapters dropped.
    ///
    /// A route pointing at an interface that no longer exists is a route to
    /// nowhere, and on a laptop that changes networks it is the ordinary case
    /// rather than the exceptional one.
    #[must_use]
    pub fn on_live_interfaces(&self, live: &[Interface]) -> Self {
        Self {
            routes: self
                .routes
                .iter()
                .filter(|route| live.contains(&route.interface))
                .copied()
                .collect(),
            addresses: self.addresses.clone(),
        }
    }
}

/// The prefix bytes as a person reads them, so a refusal can name the value.
///
/// The roster's own refusals carry the rule and not the value — a roster error
/// has no room for one — so naming what was refused is this layer's job.
fn parameter_text(ula: &[u8]) -> String {
    let mut bytes = [0u8; 16];
    for (slot, byte) in bytes.iter_mut().zip(ula.iter()) {
        *slot = *byte;
    }
    format!("{}/{}", Ipv6Addr::from(bytes), ula.len().saturating_mul(8))
}

/// Which of the routes now on the machine this daemon should remove.
///
/// The intersection of what it installed with what is present — never everything
/// that looks similar. A route somebody else put there for the same prefix is
/// theirs, and removing it would be this daemon reaching outside its own
/// footprint.
#[must_use]
pub fn removals(installed: &[Route], present: &[Route]) -> Vec<Route> {
    present.iter().filter(|route| installed.contains(route)).copied().collect()
}

/// The blocks of addresses a network's tunnel actually carries.
///
/// Its overlay prefix, which is routed whole, and one block per IPv4 address
/// that has a host route into the adapter: this device's own, and each peer's
/// that is not withheld. The connectivity layer is told these so it never
/// carries a session over a path that runs through the tunnel that session
/// carries — the addresses of a tunnel adapter look like any other address of
/// the machine, so nobody below can tell.
///
/// **What is routed, not what is declared.** A network may declare an IPv4 range
/// that overlaps the house's own network; every address in it that would collide
/// is then withheld and has no route, so a path to such an address goes out of
/// the machine's real interface and is an ordinary path. Avoiding the declared
/// range would refuse the local network itself — measured, on a device holding a
/// network whose range covers `192.168.1.0/24`: every direct path to a peer on
/// the same Wi-Fi was refused and the session stayed on the relay.
#[must_use]
pub fn served(
    params: &NetworkParams,
    own_ipv4: Option<Ipv4Addr>,
    peers: impl IntoIterator<Item = Ipv4Addr>,
) -> Vec<transport::Range> {
    let mut served = Vec::new();

    // The parameter carries the prefix as its leading bytes; each byte is eight
    // bits of network. Zero-padded to an address, which is what a range is named
    // by. The whole prefix, because the whole prefix is one route.
    let mut bytes = [0u8; 16];
    for (slot, byte) in bytes.iter_mut().zip(params.ula.iter()) {
        *slot = *byte;
    }
    let bits = u8::try_from(params.ula.len().saturating_mul(8)).unwrap_or(u8::MAX);
    if let Some(range) = transport::Range::new(IpAddr::V6(Ipv6Addr::from(bytes)), bits) {
        served.push(range);
    }

    // One address at a time on the IPv4 side, exactly as the routes are: a host
    // route captures one address, and so does this.
    for address in own_ipv4.into_iter().chain(peers) {
        if let Some(range) = transport::Range::new(IpAddr::V4(address), 32) {
            served.push(range);
        }
    }

    served
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// A prefix of the shape the roster requires.
    const DERIVED: &[u8] = &[0xfd, 0x00, 0x11, 0x22, 0x00, 0x00, 0x00, 0x00];

    /// Parameters carrying a chosen prefix.
    ///
    /// The prefix is written into the field rather than passed to the
    /// constructor, because the roster refuses anything outside its grammar
    /// and these tests need a state that did not come through decoding — an
    /// older build's parameters, or a state assembled in memory. That is
    /// exactly the case the check here exists for.
    fn params(ula: Vec<u8>) -> NetworkParams {
        let mut params =
            NetworkParams::new(DERIVED.to_vec(), "example.internal", 2_592_000).expect("valid");
        params.ula = ula;
        params
    }

    fn adapter() -> Interface {
        Interface::new(7)
    }

    /// What the connectivity layer is told to keep away from: the whole overlay
    /// prefix, and one block per IPv4 address that has a route into the adapter.
    #[test]
    fn a_network_serves_its_prefix_and_every_address_it_routes() {
        let served = served(
            &params(vec![0xfd, 0x01, 0, 0, 0, 0, 0, 0]),
            Some("100.117.31.3".parse().unwrap()),
            ["100.99.120.85".parse().unwrap()],
        );
        let told: Vec<String> = served.iter().map(ToString::to_string).collect();
        assert_eq!(told, vec!["fd01::/64", "100.117.31.3/32", "100.99.120.85/32"]);
    }

    /// A range a network declares is not what its tunnel carries. Every address
    /// in it may be withheld — because it collides with the house's own network
    /// — and then nothing of it is routed and nothing of it is refused. Avoiding
    /// the declared range instead would refuse the local network itself.
    #[test]
    fn a_declared_range_that_routes_nothing_is_not_served() {
        let mut collides = params(vec![0xfd, 0x01, 0, 0, 0, 0, 0, 0]);
        collides.ipv4 = Some(roster::types::Ipv4Range::new([192, 168, 1, 0], 24).unwrap());
        let served = served(&collides, None, []);
        let told: Vec<String> = served.iter().map(ToString::to_string).collect();
        assert_eq!(told, vec!["fd01::/64"], "the prefix alone: no IPv4 address is routed");

        let range = transport::Range::new("192.168.1.0".parse().unwrap(), 24).unwrap();
        assert!(!served.contains(&range), "a path to a peer on the house's Wi-Fi is a path");
    }

    /// The addresses a tunnel does hand out are covered exactly.
    #[test]
    fn an_address_a_tunnel_routes_is_served_and_its_neighbours_are_not() {
        let served = served(
            &params(vec![0xfd, 0x01, 0, 0, 0, 0, 0, 0]),
            Some("100.117.31.3".parse().unwrap()),
            ["100.99.120.85".parse().unwrap()],
        );
        let own = served.get(1).unwrap();
        assert!(own.contains(&"100.117.31.3".parse().unwrap()));
        assert!(!own.contains(&"100.117.31.4".parse().unwrap()));

        let prefix = served.first().unwrap();
        assert!(prefix.contains(&"fd01::7".parse().unwrap()));
        assert!(!prefix.contains(&"2a01:820::1".parse().unwrap()));
    }

    #[test]
    fn the_plan_is_the_networks_prefix() {
        let plan =
            Plan::for_network(&params(DERIVED.to_vec()), adapter()).expect("a usable prefix");

        assert_eq!(plan.routes().len(), 1, "one route, and only one");
        let route = plan.routes().first().copied().expect("present");
        assert_eq!(route.interface(), adapter());
        assert_eq!(route.prefix_text(), "fd00:1122::/64");
    }

    fn at(text: &str) -> Ipv4Addr {
        text.parse().expect("valid")
    }

    /// One `/32` per peer, the prefix first, and this device's own addresses
    /// assigned rather than routed.
    #[test]
    fn the_wanted_plan_routes_each_peer_and_assigns_this_devices_addresses() {
        let own: Ipv6Addr = "fd00::1".parse().expect("valid");
        let plan = Plan::wanted(
            &params(DERIVED.to_vec()),
            adapter(),
            Some(own),
            Some(at("100.64.0.9")),
            [at("100.64.3.4"), at("100.64.0.9"), at("100.64.1.2"), at("100.64.1.2")],
        )
        .expect("usable");

        let texts: Vec<String> = plan.routes().iter().map(Route::prefix_text).collect();
        assert_eq!(texts, vec!["fd00:1122::/64", "100.64.1.2/32", "100.64.3.4/32"]);
        assert_eq!(plan.own_addresses(), &[IpAddr::V6(own), IpAddr::V4(at("100.64.0.9"))]);
        assert_eq!(plan.ipv4(), Some(at("100.64.0.9")));
        assert_eq!(plan.hosts().count(), 2);
    }

    /// Never a default route of either family, and never the range as a whole:
    /// an IPv4 route is always one address.
    #[test]
    fn no_ipv4_route_is_ever_wider_than_one_address() {
        let plan = Plan::wanted(
            &params(vec![0xfd, 0, 0, 0, 0, 0, 0, 0]),
            adapter(),
            None,
            None,
            [at("100.64.0.0"), at("100.127.255.255"), at("192.168.1.1")],
        )
        .expect("usable");

        assert!(!plan.claims_a_default_route());
        for route in plan.hosts() {
            assert_eq!(route.prefix_length(), 32, "{route}");
        }
        assert!(
            plan.hosts().all(|route| route.ipv4_host() != Some(at("192.168.1.1"))),
            "an address outside the range is not routed"
        );
    }

    /// The single most consequential thing this daemon does to a machine.
    #[test]
    fn no_plan_ever_claims_a_default_route() {
        for ula in [vec![0xfd, 0x00, 0, 0, 0, 0, 0, 0], vec![0xfd; 8], DERIVED.to_vec()] {
            let plan = Plan::for_network(&params(ula), adapter()).expect("usable");
            assert!(!plan.claims_a_default_route());
            assert!(plan.routes().iter().all(|route| !route.is_default_route()));
        }
    }

    /// A prefix that would match everything is refused rather than installed.
    ///
    /// The roster refuses an empty prefix at decoding now, so no signed
    /// parameters can carry one. The guard stays: a state that reached this
    /// device another way — an older build's parameters, a state assembled in
    /// memory — must not be able to route the whole internet through the tunnel
    /// either. The fixture writes the field directly, which is the only way such
    /// a value exists at all.
    #[test]
    fn a_prefix_that_matches_everything_is_refused() {
        assert!(
            NetworkParams::new(Vec::new(), "example.internal", 2_592_000).is_err(),
            "the roster refuses it first"
        );
        let empty = params(Vec::new());

        match Plan::for_network(&empty, adapter()) {
            Err(Error::Parameters { cause }) => {
                assert!(!cause.is_empty(), "the refusal says what is wrong: {cause}");
            }
            Ok(plan) => panic!("a prefix matching everything must never plan a route: {plan:?}"),
            Err(other) => panic!("expected a parameter refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_unusable_prefix_is_refused_with_a_reason() {
        let long = params(vec![0xfd; 12]);
        match Plan::for_network(&long, adapter()) {
            Err(Error::Parameters { cause }) => {
                assert!(!cause.is_empty(), "the refusal says what is wrong");
            }
            other => panic!("expected a refusal naming the parameters, got {other:?}"),
        }
    }

    /// A prefix in global space would route most of the public IPv6 internet
    /// into the tunnel, where the gateway drops it. No route is planned for one,
    /// and the refusal names the prefix — the roster's own refusal cannot.
    #[test]
    fn a_prefix_outside_the_unique_local_range_plans_no_route() {
        let global = params(vec![0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00]);

        match Plan::wanted(&global, adapter(), None, None, []) {
            Err(Error::Parameters { cause }) => {
                assert!(cause.contains("2001:db8::/64"), "the refusal names the prefix: {cause}");
                assert!(cause.contains("not unique local"), "and the rule it broke: {cause}");
            }
            other => panic!("a prefix in global space must plan no route, got {other:?}"),
        }
    }

    /// Shorter than a `/64` claims more of the unique local space than the
    /// network uses — including the prefixes home routers give themselves.
    #[test]
    fn a_prefix_shorter_than_a_slash_64_plans_no_route() {
        match Plan::wanted(&params(vec![0xfd, 0x00]), adapter(), None, None, []) {
            Err(Error::Parameters { cause }) => {
                assert!(cause.contains("fd00::/16"), "the refusal names the prefix: {cause}");
                assert!(cause.contains("not a /64"), "and the rule it broke: {cause}");
            }
            other => panic!("expected a refusal naming the prefix, got {other:?}"),
        }
    }

    #[test]
    fn the_plan_follows_the_signed_parameters() {
        let one = Plan::for_network(&params(vec![0xfd, 0x00, 0, 0, 0, 0, 0, 0]), adapter())
            .expect("usable");
        let two = Plan::for_network(&params(vec![0xfd, 0x11, 0, 0, 0, 0, 0, 0]), adapter())
            .expect("usable");
        assert_ne!(one, two, "different parameters, different plan");
    }

    #[test]
    fn a_route_through_a_departed_interface_is_dropped() {
        let plan = Plan::for_network(&params(DERIVED.to_vec()), adapter()).expect("usable");

        assert_eq!(plan.on_live_interfaces(&[adapter()]), plan, "still there while live");
        assert!(
            plan.on_live_interfaces(&[Interface::new(9)]).routes().is_empty(),
            "a route to a departed interface is a route to nowhere"
        );
    }

    /// The daemon's footprint is its own. A route it did not install is not its
    /// to remove, however much it looks like one.
    #[test]
    fn removal_touches_only_what_the_daemon_installed() {
        let prefix = Prefix::from_parameter(DERIVED).expect("valid");
        let ours = Route::new(prefix, adapter());
        let theirs = Route::new(prefix, Interface::new(3));
        let unrelated = Route::new(
            Prefix::from_parameter(&[0xfd, 0x99, 0, 0, 0, 0, 0, 0]).expect("valid"),
            Interface::new(3),
        );

        let present = [ours, theirs, unrelated];
        let removing = removals(&[ours], &present);

        assert_eq!(removing, vec![ours]);
        assert!(!removing.contains(&theirs), "same prefix, another interface, not ours");
        assert!(!removing.contains(&unrelated));
    }

    /// The roster is the only input. Not a claim in prose: a configuration file,
    /// an environment variable or a flag that added a route would be a way to
    /// widen the tunnel without changing anything anybody signed.
    #[test]
    fn nothing_outside_the_signed_parameters_can_widen_the_plan() {
        let code = crate::code_of(include_str!("routes.rs"));

        for forbidden in ["env::var", "env!", "read_to_string", "Config", "from_args"] {
            assert!(!code.contains(forbidden), "`{forbidden}` would be a second source of routes");
        }
        assert_eq!(
            code.matches("Ok(Self { routes").count(),
            1,
            "one place builds the plan, and it builds it from the parameters"
        );
        assert!(
            !code.contains("pub fn push") && !code.contains("pub fn add"),
            "a plan that could be appended to is a plan that could grow a default route"
        );
    }

    #[test]
    fn removing_nothing_installed_removes_nothing() {
        let prefix = Prefix::from_parameter(DERIVED).expect("valid");
        let present = [Route::new(prefix, adapter())];
        assert!(removals(&[], &present).is_empty());
    }
}

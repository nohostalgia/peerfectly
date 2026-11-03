//! Bringing the tunnel up, and taking it down.
//!
//! # It stays up until a person takes it down
//!
//! DESIGN.md §13.7 asked whether the tunnel should switch itself off after a
//! period of inactivity. It does not, and this module contains no timer that
//! could.
//!
//! Automatic shutdown adds a second way for the network to stop working that the
//! person did not choose — and the first way, them turning it off, is the one the
//! whole product is built around (§2.6b). The battery argument that motivates it
//! on a phone is much weaker on a desktop that is plugged in. If a timer is ever
//! added it should follow a measurement of what the tunnel actually costs, not
//! precede one.
//!
//! A test asserts no shutdown path here is driven by elapsed time, because the
//! easiest way for this decision to be quietly reversed is for somebody to add
//! "just an idle timeout" without noticing it was decided.
//!
//! # A failed bring-up undoes itself
//!
//! Each step is undone in reverse when a later one fails, and what could not be
//! undone is named in the error. A route left behind after a failed bring-up
//! blackholes the network's prefix for the whole machine, which is worse than
//! never having tried — so the interesting path here is not the happy one.
//!
//! # While up, only IPv4 moves
//!
//! Peers are admitted and revoked, and the machine moves between networks where
//! a peer's IPv4 address does or does not conflict, all while the tunnel stays
//! up. [`Lifecycle::reconcile`] adds and removes the host routes and this
//! device's IPv4 address to match, and never touches the prefix route, the IPv6
//! address or the rule: those change only by coming down and up again.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use roster::state::RosterState;

use crate::error::{Error, Residue, Result, Step};
use crate::machine::Machine;
use crate::routes::{Interface, Plan, Route};
use crate::rule::Rule;
use crate::state::Choice;

/// What the daemon has installed while the tunnel is up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Up {
    /// The adapter's interface.
    interface: Interface,
    /// This device's own address, as given to the adapter.
    address: Ipv6Addr,
    /// This device's own IPv4 address on the adapter, while it holds one here.
    ipv4: Option<Ipv4Addr>,
    /// The routes installed, in the order they went in.
    routes: Vec<Route>,
    /// The resolution rule installed.
    rule: Rule,
}

impl Up {
    /// The adapter's interface.
    #[must_use]
    pub const fn interface(&self) -> Interface {
        self.interface
    }

    /// This device's own address on the adapter.
    #[must_use]
    pub const fn address(&self) -> Ipv6Addr {
        self.address
    }

    /// This device's own IPv4 address on the adapter, while it holds one here.
    #[must_use]
    pub const fn ipv4(&self) -> Option<Ipv4Addr> {
        self.ipv4
    }

    /// The routes installed.
    #[must_use]
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// The resolution rule installed.
    #[must_use]
    pub const fn rule(&self) -> &Rule {
        &self.rule
    }
}

/// Brings the tunnel up and takes it down.
pub struct Lifecycle {
    /// What the daemon acts on.
    machine: Arc<dyn Machine>,
}

impl Lifecycle {
    /// A lifecycle over a machine.
    #[must_use]
    pub fn new(machine: Arc<dyn Machine>) -> Self {
        Self { machine }
    }

    /// Removes anything an earlier run left behind.
    ///
    /// Called before bringing up, and worth calling even when nothing is about
    /// to be brought up: a rule from a crashed run is breaking name resolution
    /// for the suffix right now.
    ///
    /// # Errors
    ///
    /// When a leftover was found and could not be removed.
    pub async fn sweep(&self) -> Result<bool> {
        self.machine.sweep_rules().await
    }

    /// Brings the tunnel up.
    ///
    /// Each step is undone if a later one fails. The error names the step that
    /// failed and anything that could not be undone.
    ///
    /// # Errors
    ///
    /// When any step fails.
    pub async fn up(
        &self,
        network: &str,
        state: &RosterState,
        resolver: Ipv6Addr,
    ) -> Result<(Up, std::sync::Arc<dyn tunnel::Packets>)> {
        // Decided before anything is touched. A plan that cannot be computed is a
        // network that cannot be brought up, and finding that out after creating
        // an adapter would mean tearing one down for nothing.
        let rule = Rule::for_network(network, state, resolver)?;

        // This network's own leftover, and only it. A sweep of everything the
        // daemon ever wrote would remove the rule of a network that is up and
        // carrying traffic, which is exactly what bringing a second one up would
        // otherwise do. The whole-daemon sweep still runs once, at startup, where
        // nothing is up to be disturbed.
        let _leftover = self.machine.remove_rule(&rule).await;

        let (interface, device) = self
            .machine
            .create_adapter(
                &crate::limits::adapter_name(network),
                crate::limits::adapter_guid(&state.network),
            )
            .await?;

        // Before any route. Until the machine holds this address, it does not
        // know the address is its own: a packet it sends to itself goes into the
        // tunnel, and nothing — the resolver included — can bind to it.
        if let Err(failure) = self.machine.assign_address(interface, resolver.into()).await {
            let left = self.undo(interface, &[], &[], None).await;
            return Err(Self::wrap(failure, Step::CreatingAdapter, left));
        }

        let plan = Plan::for_network(&state.params, interface)?;

        let mut installed: Vec<Route> = Vec::new();
        for route in plan.routes() {
            if let Err(failure) = self.machine.install_route(route).await {
                let left = self.undo(interface, &[resolver.into()], &installed, None).await;
                return Err(Self::wrap(failure, Step::InstallingRoutes, left));
            }
            installed.push(*route);
        }

        if let Err(failure) = self.machine.install_rule(&rule).await {
            let left = self.undo(interface, &[resolver.into()], &installed, None).await;
            return Err(Self::wrap(failure, Step::InstallingRule, left));
        }

        Ok((Up { interface, address: resolver, ipv4: None, routes: installed, rule }, device))
    }

    /// Brings what is installed while up in line with what is wanted.
    ///
    /// Only IPv4 moves: IPv4 routes no longer wanted come out first, then this
    /// device's IPv4 address changes if it must, then new IPv4 routes go in —
    /// the block, or its parts around a hole. The prefix route, the IPv6
    /// address and the rule are never touched, and anything in `wanted` that is
    /// not an IPv4 route or address is ignored.
    ///
    /// Every step is attempted even after one fails, and `up` records what is
    /// actually installed afterwards, so the next reconciliation starts from the
    /// truth.
    ///
    /// # Errors
    ///
    /// When something could not be added or removed. The error names what is
    /// left behind.
    pub async fn reconcile(&self, up: &mut Up, wanted: &Plan) -> Result<()> {
        let wanted_blocks: Vec<Route> = wanted
            .ipv4_routes()
            .filter_map(|route| route.ipv4_block())
            .map(|(address, prefix_len)| Route::ipv4(address, prefix_len, up.interface))
            .collect();
        let mut left = Vec::new();
        let mut failed = None;

        let stale: Vec<Route> = up
            .routes
            .iter()
            .filter(|route| route.ipv4_block().is_some() && !wanted_blocks.contains(route))
            .copied()
            .collect();
        let fresh: Vec<Route> =
            wanted_blocks.into_iter().filter(|route| !up.routes.contains(route)).collect();

        // **The address off before any route covering it moves, and on again
        // after.** Windows, asked to remove an IPv4 route covering this
        // device's `/32` while the address was held, left the address half
        // there: in no table, nothing reaching it, and every attempt to make it
        // again answered "already there" until the adapter itself was made
        // again (2026-11-02, a person's PC, `route include` after `route
        // exclude`). Taken off cleanly first, as a move of the block always
        // did, it comes back whole.
        let wanted_ipv4 = wanted.ipv4();
        let routes_move = !stale.is_empty() || !fresh.is_empty();
        if (routes_move || up.ipv4 != wanted_ipv4)
            && let Some(old) = up.ipv4.take()
        {
            // Not residue on its own, as in `undo`: it goes with the adapter.
            let _removed = self.machine.remove_address(up.interface, old.into()).await;
        }

        for route in stale {
            match self.machine.remove_route(&route).await {
                Ok(()) => up.routes.retain(|held| *held != route),
                Err(failure) => {
                    left.push(Residue::Route { prefix: route.prefix_text() });
                    failed.get_or_insert(failure);
                }
            }
        }

        if up.ipv4.is_none()
            && let Some(new) = wanted_ipv4
        {
            match self.machine.assign_address(up.interface, new.into()).await {
                Ok(()) => up.ipv4 = Some(new),
                Err(failure) => {
                    failed.get_or_insert(failure);
                }
            }
        }

        for route in fresh {
            match self.machine.install_route(&route).await {
                Ok(()) => up.routes.push(route),
                Err(failure) => {
                    failed.get_or_insert(failure);
                }
            }
        }

        match failed {
            None => Ok(()),
            Some(failure) => Err(Self::wrap(failure, Step::InstallingRoutes, left)),
        }
    }

    /// Gives the adapter this device's IPv4 address back where the machine says
    /// it no longer holds it. `Ok(true)` when it was given back.
    ///
    /// # Errors
    ///
    /// When it could not be given back.
    pub async fn keep_ipv4(&self, up: &Up) -> Result<bool> {
        let Some(held) = up.ipv4 else { return Ok(false) };
        if self.machine.holds_address(up.interface, held.into()).await != Some(false) {
            return Ok(false);
        }
        self.machine.assign_address(up.interface, held.into()).await?;
        Ok(true)
    }

    /// Takes the tunnel down, removing everything it installed.
    ///
    /// # Errors
    ///
    /// When something could not be removed. The error names what is still there.
    pub async fn down(&self, up: &Up) -> Result<()> {
        let addresses: Vec<IpAddr> =
            core::iter::once(up.address.into()).chain(up.ipv4.map(IpAddr::V4)).collect();
        let left = self.undo(up.interface, &addresses, &up.routes, Some(&up.rule)).await;

        if left.is_empty() {
            Ok(())
        } else {
            Err(Error::BringUp {
                step: Step::InstallingRoutes,
                cause: "taking the tunnel down did not remove everything".to_owned(),
                left,
            })
        }
    }

    /// Removes what was installed, in reverse, and reports what would not go.
    ///
    /// Every step is attempted even after one fails. Stopping at the first
    /// failure would leave more behind than necessary, and the whole reason to
    /// undo is to leave as little as possible.
    async fn undo(
        &self,
        interface: Interface,
        addresses: &[IpAddr],
        routes: &[Route],
        rule: Option<&Rule>,
    ) -> Vec<Residue> {
        let mut left = Vec::new();

        if let Some(rule) = rule
            && self.machine.remove_rule(rule).await.is_err()
        {
            left.push(Residue::ResolutionRule { suffix: rule.suffix().to_owned() });
        }

        for route in routes.iter().rev() {
            if self.machine.remove_route(route).await.is_err() {
                left.push(Residue::Route { prefix: route.prefix_text() });
            }
        }

        for address in addresses.iter().rev() {
            // Not reported as residue on its own: the address goes with the
            // adapter, and an adapter that is gone cannot be holding one.
            let _removed = self.machine.remove_address(interface, *address).await;
        }

        if self.machine.remove_adapter(interface).await.is_err() {
            left.push(Residue::Adapter);
        }
        left
    }

    /// Rewrites a failure with the step it belongs to and what is still there.
    fn wrap(failure: Error, step: Step, left: Vec<Residue>) -> Error {
        let cause = match &failure {
            Error::BringUp { cause, .. } => cause.clone(),
            other => other.to_string(),
        };
        Error::BringUp { step, cause, left }
    }
}

/// What the daemon should do on start, given what the person last chose.
///
/// Restored rather than defaulted. A daemon that comes back down after a reboot
/// when the person left it up has quietly overruled them; one that comes back up
/// when they left it down has done something worse.
#[must_use]
pub const fn resume(choice: Choice) -> bool {
    matches!(choice, Choice::Up)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use roster::id::NetworkId;
    use roster::types::NetworkParams;

    use super::*;
    use crate::machine::testing::{Fail, Recording};

    fn state() -> RosterState {
        RosterState::from_parts(
            NetworkId::from_bytes([1; 32]),
            NetworkParams::new(
                vec![0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                "example.internal",
                2_592_000,
            )
            .expect("valid"),
            BTreeMap::new(),
            BTreeSet::new(),
            Default::default(),
        )
    }

    fn resolver() -> Ipv6Addr {
        "fd00::1".parse().expect("valid")
    }

    #[tokio::test]
    async fn bringing_up_installs_the_prefix_and_the_rule() {
        let machine = Arc::new(Recording::new());
        let lifecycle = Lifecycle::new(Arc::clone(&machine) as Arc<dyn Machine>);

        let (up, _device) = lifecycle.up("test", &state(), resolver()).await.expect("comes up");

        let installed = machine.installed();
        assert!(!installed.adapters.is_empty());
        assert_eq!(installed.routes.len(), 1);
        assert_eq!(installed.rules.len(), 1);
        assert_eq!(up.routes().len(), 1);
        assert!(!up.routes().iter().any(Route::is_default_route), "never a default route");
    }

    /// A leftover is removed before anything is installed, not only on the way
    /// out — but only **this network's**.
    ///
    /// This used to sweep every rule the daemon had ever written, which was
    /// harmless while a device held one network and destructive the moment it
    /// held two: bringing the second up would have removed the first's rule
    /// while it was carrying traffic, and nothing would have said so. The
    /// whole-daemon sweep still exists and still runs, once, at startup, where
    /// nothing is up to be disturbed.
    #[tokio::test]
    async fn bringing_one_network_up_leaves_another_networks_rule_alone() {
        let machine = Arc::new(Recording::new());
        let lifecycle = Lifecycle::new(Arc::clone(&machine) as Arc<dyn Machine>);

        let (first, _device) = lifecycle.up("casa", &state(), resolver()).await.expect("comes up");

        let elsewhere = "fd22::1".parse().expect("valid");
        let (second, _second_device) =
            lifecycle.up("lavoro", &other_state(), elsewhere).await.expect("comes up");

        let rules = machine.installed().rules;
        assert_eq!(rules.len(), 2, "two networks, two rules: {rules:?}");
        assert!(rules.contains(first.rule()), "the first network's rule survived the second");
        assert!(rules.contains(second.rule()));
        assert_ne!(first.rule().key_name(), second.rule().key_name(), "and under its own key");

        let adapters = machine.installed().adapters;
        assert_eq!(adapters.len(), 2, "each network has its own adapter");
        assert_eq!(
            machine.installed().named,
            vec!["peerfectly casa".to_owned(), "peerfectly lavoro".to_owned()],
            "named so a person can tell them apart"
        );
        assert_eq!(
            machine.installed().guids,
            vec![
                crate::limits::adapter_guid(&state().network),
                crate::limits::adapter_guid(&other_state().network)
            ],
            "and each given its own network's GUID, so a rule bound to it outlives a raise"
        );
    }

    /// A second network, with its own prefix and its own suffix.
    fn other_state() -> RosterState {
        RosterState::from_parts(
            roster::id::NetworkId::from_bytes([2; 32]),
            roster::types::NetworkParams::new(
                vec![0xfd, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                "lavoro.internal",
                2_592_000,
            )
            .expect("valid"),
            std::collections::BTreeMap::new(),
            std::collections::BTreeSet::new(),
            Default::default(),
        )
    }

    #[tokio::test]
    async fn taking_down_removes_everything() {
        let machine = Arc::new(Recording::new());
        let lifecycle = Lifecycle::new(Arc::clone(&machine) as Arc<dyn Machine>);

        let (up, _device) = lifecycle.up("test", &state(), resolver()).await.expect("comes up");
        lifecycle.down(&up).await.expect("goes down");

        let installed = machine.installed();
        assert!(installed.routes.is_empty(), "no route left");
        assert!(installed.rules.is_empty(), "no rule left");
        assert!(installed.adapters.is_empty(), "no adapter left");
    }

    /// The path that matters. A failure after a route is installed must not
    /// leave the route: it would blackhole the prefix for the whole machine.
    #[tokio::test]
    async fn a_failure_installing_the_rule_leaves_no_route_behind() {
        let machine = Arc::new(Recording::failing_at(Fail::Rule));
        let lifecycle = Lifecycle::new(Arc::clone(&machine) as Arc<dyn Machine>);

        let Err(failure) = lifecycle.up("test", &state(), resolver()).await else {
            panic!("expected the rule fails");
        };

        assert_eq!(failure.step(), Some(Step::InstallingRule), "the error names the step");
        assert!(failure.left_behind().is_empty(), "and nothing was left: {failure}");

        let installed = machine.installed();
        assert!(installed.routes.is_empty(), "the route was taken back out");
        assert!(installed.adapters.is_empty(), "and so was the adapter");
    }

    #[tokio::test]
    async fn a_failure_installing_a_route_leaves_no_adapter_behind() {
        let machine = Arc::new(Recording::failing_at(Fail::Route));
        let lifecycle = Lifecycle::new(Arc::clone(&machine) as Arc<dyn Machine>);

        let Err(failure) = lifecycle.up("test", &state(), resolver()).await else {
            panic!("expected the route fails");
        };

        assert_eq!(failure.step(), Some(Step::InstallingRoutes));
        assert!(machine.installed().adapters.is_empty(), "the adapter was taken back out");
    }

    #[tokio::test]
    async fn a_failure_creating_the_adapter_changes_nothing() {
        let machine = Arc::new(Recording::failing_at(Fail::Adapter));
        let lifecycle = Lifecycle::new(Arc::clone(&machine) as Arc<dyn Machine>);

        let Err(failure) = lifecycle.up("test", &state(), resolver()).await else {
            panic!("expected the adapter fails");
        };

        assert_eq!(failure.step(), Some(Step::CreatingAdapter));
        // Nothing at all, and `swept` is no longer among the exceptions: bringing
        // one network up removes that network's own leftover rule rather than
        // sweeping every rule the daemon ever wrote.
        assert_eq!(machine.installed(), crate::machine::testing::Installed::default());
    }

    /// What could not be undone is named, so a person knows what the machine
    /// looks like rather than being told only that something failed.
    #[tokio::test]
    async fn what_could_not_be_undone_is_named() {
        let machine = Arc::new(Recording::failing_at(Fail::RemovingRoute));
        let lifecycle = Lifecycle::new(Arc::clone(&machine) as Arc<dyn Machine>);

        // Install by hand, since bring-up would fail at the same step.
        let route = Route::new(
            tunnel::Prefix::from_parameter(&[0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .expect("valid"),
            Interface::new(7),
        );
        let rule = Rule::for_network("test", &state(), resolver()).expect("usable");
        let up = Up {
            interface: Interface::new(7),
            address: resolver(),
            ipv4: None,
            routes: vec![route],
            rule,
        };

        let failure = lifecycle.down(&up).await.expect_err("the route will not go");
        let left = failure.left_behind();

        assert!(
            left.iter().any(|item| matches!(item, Residue::Route { .. })),
            "the route that would not go is named: {failure}"
        );
        assert!(failure.to_string().contains("fd00::/64"), "{failure}");
    }

    fn at(text: &str) -> Ipv4Addr {
        text.parse().expect("valid")
    }

    /// The plan a reconciliation is handed: this device at `own`, and the
    /// network's block less these holes, each `a.b.c.d/len`.
    fn wanted(own: Option<&str>, holes: &[&str]) -> Plan {
        let holes: Vec<crate::conflicts::Hole> = holes
            .iter()
            .map(|text| {
                let (address, prefix_len) = text.split_once('/').expect("a block");
                crate::conflicts::Hole {
                    address: at(address),
                    prefix_len: prefix_len.parse().expect("a length"),
                    why: crate::conflicts::Conflict::Gateway,
                }
            })
            .collect();
        Plan::wanted(
            &state().params,
            Interface::new(7),
            Some(resolver()),
            own.map(at),
            Some(&holes),
        )
        .expect("usable")
    }

    fn ipv4_routes(machine: &Recording) -> Vec<String> {
        let mut routes: Vec<String> = machine
            .installed()
            .routes
            .iter()
            .filter(|route| route.ipv4_block().is_some())
            .map(Route::prefix_text)
            .collect();
        routes.sort();
        routes
    }

    async fn brought_up() -> (Arc<Recording>, Lifecycle, Up) {
        let machine = Arc::new(Recording::new());
        let lifecycle = Lifecycle::new(Arc::clone(&machine) as Arc<dyn Machine>);
        let (up, _device) = lifecycle.up("test", &state(), resolver()).await.expect("comes up");
        (machine, lifecycle, up)
    }

    #[tokio::test]
    async fn reconciling_assigns_this_devices_ipv4_address_and_routes_the_block() {
        let (machine, lifecycle, mut up) = brought_up().await;

        lifecycle.reconcile(&mut up, &wanted(Some("100.64.0.1"), &[])).await.expect("reconciles");

        assert_eq!(ipv4_routes(&machine), vec!["100.64.0.0/10"], "one route, whatever the size");
        assert!(machine.installed().addresses.contains(&IpAddr::V4(at("100.64.0.1"))));
        assert_eq!(up.ipv4(), Some(at("100.64.0.1")));

        // An admission or a revocation is the same plan: nothing moves.
        let before = machine.installed();
        lifecycle.reconcile(&mut up, &wanted(Some("100.64.0.1"), &[])).await.expect("again");
        assert_eq!(machine.installed().routes, before.routes);
    }

    /// A hole appearing takes its part out of the route, and its going gives the
    /// block back whole — the caller hands a plan with it, then without.
    #[tokio::test]
    async fn a_hole_appearing_splits_the_route_and_disappearing_restores_it() {
        let (machine, lifecycle, mut up) = brought_up().await;
        let own = Some("100.64.0.1");
        lifecycle.reconcile(&mut up, &wanted(own, &[])).await.expect("ok");
        let prefix_before = machine.installed().routes.first().copied();

        lifecycle.reconcile(&mut up, &wanted(own, &["100.64.0.0/11"])).await.expect("a hole");
        assert_eq!(ipv4_routes(&machine), vec!["100.96.0.0/11"]);

        lifecycle.reconcile(&mut up, &wanted(own, &[])).await.expect("restored");
        assert_eq!(ipv4_routes(&machine), vec!["100.64.0.0/10"]);

        assert_eq!(machine.installed().routes.first().copied(), prefix_before, "the prefix stays");
        assert_eq!(
            machine.installed().routes.iter().filter(|route| route.prefix().is_some()).count(),
            1,
            "and is never added twice"
        );
    }

    /// A machine that loses this device's IPv4 address whenever a route is
    /// removed, as Windows did when the block's route was split and joined.
    struct Forgetful(Arc<Recording>);

    #[async_trait::async_trait]
    impl Machine for Forgetful {
        async fn create_adapter(
            &self,
            name: &str,
            guid: [u8; 16],
        ) -> Result<(Interface, Arc<dyn tunnel::Packets>)> {
            self.0.create_adapter(name, guid).await
        }
        async fn remove_adapter(&self, interface: Interface) -> Result<()> {
            self.0.remove_adapter(interface).await
        }
        async fn assign_address(&self, interface: Interface, address: IpAddr) -> Result<()> {
            self.0.assign_address(interface, address).await
        }
        async fn remove_address(&self, interface: Interface, address: IpAddr) -> Result<()> {
            self.0.remove_address(interface, address).await
        }
        async fn holds_address(&self, _interface: Interface, address: IpAddr) -> Option<bool> {
            Some(self.0.installed().addresses.contains(&address))
        }
        async fn install_route(&self, route: &Route) -> Result<()> {
            self.0.install_route(route).await
        }
        async fn remove_route(&self, route: &Route) -> Result<()> {
            for address in self.0.installed().addresses {
                if address.is_ipv4() {
                    self.0.remove_address(route.interface(), address).await?;
                }
            }
            self.0.remove_route(route).await
        }
        async fn install_rule(&self, rule: &Rule) -> Result<()> {
            self.0.install_rule(rule).await
        }
        async fn remove_rule(&self, rule: &Rule) -> Result<()> {
            self.0.remove_rule(rule).await
        }
        async fn sweep_rules(&self) -> Result<bool> {
            self.0.sweep_rules().await
        }
    }

    /// An address the machine dropped when a route moved is given back in the
    /// same pass: splitting the block around a hole, and joining it again,
    /// leave this device's address on the adapter.
    #[tokio::test]
    async fn an_address_the_machine_dropped_when_a_route_moved_is_given_back() {
        let machine = Arc::new(Recording::new());
        let lifecycle =
            Lifecycle::new(Arc::new(Forgetful(Arc::clone(&machine))) as Arc<dyn Machine>);
        let (mut up, _device) = lifecycle.up("test", &state(), resolver()).await.expect("comes up");
        let own = Some("100.64.0.1");
        lifecycle.reconcile(&mut up, &wanted(own, &[])).await.expect("ok");
        for holes in [&["100.64.0.2/32"][..], &[]] {
            lifecycle.reconcile(&mut up, &wanted(own, holes)).await.expect("ok");
            assert!(
                machine.installed().addresses.contains(&IpAddr::V4(at("100.64.0.1"))),
                "still on the adapter after {holes:?}"
            );
        }
    }

    /// A machine that, as Windows did, leaves an address half there when a
    /// route covering it is removed while it is held: gone from the adapter,
    /// and refused as "already there" from then on.
    struct Haunted {
        machine: Arc<Recording>,
        ghosts: std::sync::Mutex<Vec<IpAddr>>,
    }

    #[async_trait::async_trait]
    impl Machine for Haunted {
        async fn create_adapter(
            &self,
            name: &str,
            guid: [u8; 16],
        ) -> Result<(Interface, Arc<dyn tunnel::Packets>)> {
            self.machine.create_adapter(name, guid).await
        }
        async fn remove_adapter(&self, interface: Interface) -> Result<()> {
            self.machine.remove_adapter(interface).await
        }
        async fn assign_address(&self, interface: Interface, address: IpAddr) -> Result<()> {
            if self.ghosts.lock().expect("not poisoned").contains(&address) {
                return Err(Error::Parameters { cause: "already there, and nowhere".to_owned() });
            }
            self.machine.assign_address(interface, address).await
        }
        async fn remove_address(&self, interface: Interface, address: IpAddr) -> Result<()> {
            self.machine.remove_address(interface, address).await
        }
        async fn install_route(&self, route: &Route) -> Result<()> {
            self.machine.install_route(route).await
        }
        async fn remove_route(&self, route: &Route) -> Result<()> {
            if let Some((base, len)) = route.ipv4_block() {
                let mask = u32::MAX.checked_shl(32_u32.saturating_sub(u32::from(len))).unwrap_or(0);
                for address in self.machine.installed().addresses {
                    if let IpAddr::V4(held) = address
                        && u32::from(held) & mask == u32::from(base) & mask
                    {
                        self.machine.remove_address(route.interface(), address).await?;
                        self.ghosts.lock().expect("not poisoned").push(address);
                    }
                }
            }
            self.machine.remove_route(route).await
        }
        async fn install_rule(&self, rule: &Rule) -> Result<()> {
            self.machine.install_rule(rule).await
        }
        async fn remove_rule(&self, rule: &Rule) -> Result<()> {
            self.machine.remove_rule(rule).await
        }
        async fn sweep_rules(&self) -> Result<bool> {
            self.machine.sweep_rules().await
        }
    }

    /// Splitting the block around a hole and joining it again never removes a
    /// route covering this device's address while the address is held, so the
    /// address comes through both, on a machine that would otherwise lose it.
    #[tokio::test]
    async fn a_route_covering_the_address_moves_only_with_the_address_off() {
        let machine = Arc::new(Recording::new());
        let haunted =
            Haunted { machine: Arc::clone(&machine), ghosts: std::sync::Mutex::default() };
        let lifecycle = Lifecycle::new(Arc::new(haunted) as Arc<dyn Machine>);
        let (mut up, _device) = lifecycle.up("test", &state(), resolver()).await.expect("comes up");
        let own = Some("100.64.0.1");
        lifecycle.reconcile(&mut up, &wanted(own, &[])).await.expect("ok");
        for holes in [&["100.64.0.2/32"][..], &[], &["100.64.0.0/11"], &[]] {
            lifecycle.reconcile(&mut up, &wanted(own, holes)).await.expect("no ghost made");
            assert!(
                machine.installed().addresses.contains(&IpAddr::V4(at("100.64.0.1"))),
                "on the adapter after {holes:?}"
            );
        }
    }

    /// An address the machine says it no longer holds is given back by the
    /// check that runs every second, and one it holds is left alone.
    #[tokio::test]
    async fn an_address_the_machine_says_it_lost_is_given_back() {
        let machine = Arc::new(Recording::new());
        let lifecycle =
            Lifecycle::new(Arc::new(Forgetful(Arc::clone(&machine))) as Arc<dyn Machine>);
        let (mut up, _device) = lifecycle.up("test", &state(), resolver()).await.expect("comes up");
        lifecycle.reconcile(&mut up, &wanted(Some("100.64.0.1"), &[])).await.expect("ok");
        assert!(!lifecycle.keep_ipv4(&up).await.expect("asked"), "held: nothing to do");

        let own = IpAddr::V4(at("100.64.0.1"));
        machine.remove_address(up.interface(), own).await.expect("dropped behind its back");
        assert!(lifecycle.keep_ipv4(&up).await.expect("given back"));
        assert!(machine.installed().addresses.contains(&own));
    }

    /// The prefix route, the IPv6 address and the rule are never touched while
    /// up, whatever the plan says — even a plan built for another adapter.
    #[tokio::test]
    async fn the_prefix_route_is_never_touched_while_up() {
        let (machine, lifecycle, mut up) = brought_up().await;
        let before = machine.installed();

        let nothing = Plan::default();
        lifecycle.reconcile(&mut up, &nothing).await.expect("reconciles");
        lifecycle.reconcile(&mut up, &wanted(None, &["100.64.9.0/24"])).await.expect("ok");
        lifecycle.reconcile(&mut up, &nothing).await.expect("reconciles");

        let after = machine.installed();
        assert_eq!(after.routes, before.routes, "the prefix route is exactly as it was");
        assert_eq!(after.addresses, before.addresses, "and the IPv6 address");
        assert_eq!(after.rules, before.rules, "and the rule");
    }

    /// Never a default route of either family, and no IPv4 route wider than the
    /// network's block.
    #[tokio::test]
    async fn no_default_route_and_nothing_wider_than_the_block_ever_appear() {
        let (machine, lifecycle, mut up) = brought_up().await;
        lifecycle
            .reconcile(&mut up, &wanted(Some("100.64.0.1"), &["100.64.0.0/30", "100.127.255.0/24"]))
            .await
            .expect("reconciles");

        for route in machine.installed().routes {
            assert!(!route.is_default_route(), "{route}");
            if route.ipv4_block().is_some() {
                assert!(route.prefix_length() >= 10, "{route}");
            }
        }
    }

    /// This device's IPv4 address moves when it must, and the old one goes.
    #[tokio::test]
    async fn this_devices_ipv4_address_moves_and_the_old_one_goes() {
        let (machine, lifecycle, mut up) = brought_up().await;
        lifecycle.reconcile(&mut up, &wanted(Some("100.64.0.1"), &[])).await.expect("ok");
        lifecycle.reconcile(&mut up, &wanted(Some("100.64.0.7"), &[])).await.expect("ok");

        let addresses = machine.installed().addresses;
        assert!(addresses.contains(&IpAddr::V4(at("100.64.0.7"))));
        assert!(!addresses.contains(&IpAddr::V4(at("100.64.0.1"))));

        lifecycle.reconcile(&mut up, &wanted(None, &[])).await.expect("ok");
        assert!(machine.installed().addresses.iter().all(IpAddr::is_ipv6), "withheld here");
    }

    /// Taking down after reconciling removes the IPv4 routes and the IPv4
    /// address too.
    #[tokio::test]
    async fn taking_down_removes_what_reconciling_added() {
        let (machine, lifecycle, mut up) = brought_up().await;
        lifecycle
            .reconcile(&mut up, &wanted(Some("100.64.0.1"), &["100.64.0.2/32"]))
            .await
            .expect("ok");
        lifecycle.down(&up).await.expect("goes down");

        let installed = machine.installed();
        assert!(installed.routes.is_empty());
        assert!(installed.addresses.is_empty());
        assert!(installed.adapters.is_empty());
    }

    /// Unusable parameters are found before anything is touched, so a bad roster
    /// does not cost an adapter created and torn down.
    #[tokio::test]
    async fn unusable_parameters_are_refused_before_anything_is_touched() {
        let machine = Arc::new(Recording::new());
        let lifecycle = Lifecycle::new(Arc::clone(&machine) as Arc<dyn Machine>);

        // Written into the field, because the roster refuses an empty suffix
        // where parameters are decoded. What is left is the case this check is
        // for: a state that reached the device another way.
        let mut broken = state();
        broken.params.suffix = String::new();

        assert!(lifecycle.up("test", &broken, resolver()).await.is_err());
        assert_eq!(machine.installed(), crate::machine::testing::Installed::default());
    }

    /// §13.7, resolved: nothing here switches the tunnel off on its own.
    #[test]
    fn no_shutdown_path_is_driven_by_time() {
        let code = crate::code_of(include_str!("lifecycle.rs"));

        for forbidden in ["Instant", "Duration", "sleep", "interval", "elapsed", "timeout"] {
            assert!(
                !code.contains(forbidden),
                "`{forbidden}` in the lifecycle would be the idle timeout §13.7 decided against"
            );
        }
    }

    /// The reasoning is recorded where a later reader meets it, so the decision
    /// reads as a decision rather than an omission.
    #[test]
    fn the_reason_the_tunnel_has_no_timer_is_recorded() {
        let source = include_str!("lifecycle.rs");
        assert!(source.contains("§13.7"), "the source names the decision it settles");
        assert!(source.contains("2.6b"), "and the constraint it follows from");
        assert!(
            source.contains("did not choose"),
            "and why: a second way for the network to stop working"
        );
    }

    #[test]
    fn the_last_choice_is_restored_rather_than_defaulted() {
        assert!(resume(Choice::Up));
        assert!(!resume(Choice::Down));
    }
}

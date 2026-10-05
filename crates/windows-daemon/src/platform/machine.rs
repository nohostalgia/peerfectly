//! The real machine.
//!
//! Wires [`daemon::machine::Machine`] to the adapter, the routing table and the
//! registry. Glue and nothing else: the order these calls happen in, and what is
//! undone when one fails, is [`daemon::lifecycle`]'s, where it is tested against a
//! machine that can be told to fail at any step.
//!
//! # What is not tested here
//!
//! All of it needs Administrator. `VERIFICATION.md` records what was run on a
//! real machine; nothing below is covered by the automated suite.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tunnel::Packets;

use crate::platform::{adapter::Adapter, nrpt, route_table};
use daemon::error::{Error, Result, Step};
use daemon::machine::Machine;
use daemon::routes::{Interface, Route};
use daemon::rule::Rule;

/// The machine this daemon is running on.
#[derive(Default)]
pub struct Windows {
    /// One adapter per network that is up, by the interface it presented.
    ///
    /// Each is held so it lives exactly as long as its own network's tunnel:
    /// dropping it removes the adapter, and the routes go with it. That is what
    /// makes an unclean exit safe, and it is a property of Windows rather than of
    /// our shutdown path — which is the only kind of cleanup guarantee worth
    /// relying on. It is also why an exit takes every network's adapter with it
    /// however many there are, without the daemon having to walk them.
    adapters: Mutex<BTreeMap<Interface, Arc<Adapter>>>,
}

impl Windows {
    /// A handle to this machine.
    #[must_use]
    pub fn new() -> Self {
        Self { adapters: Mutex::new(BTreeMap::new()) }
    }
}

#[async_trait]
impl Machine for Windows {
    async fn create_adapter(
        &self,
        name: &str,
        guid: [u8; 16],
    ) -> Result<(Interface, Arc<dyn Packets>)> {
        let adapter = Arc::new(Adapter::create(name, Some(guid))?);
        let interface = adapter.interface()?;
        // Before anything else touches it, so its automatic routes never outrank
        // the machine's own — including when this device holds no IPv4 address
        // here and Windows gives the adapter a link-local one. Best effort: a
        // network that will not come up for want of a metric is worse than one
        // whose multicast is demoted when its IPv4 address is assigned.
        let _weighed = route_table::weigh_ipv4_interface(interface);

        let mut held = self.adapters.lock().map_err(|_| Error::BringUp {
            step: Step::CreatingAdapter,
            cause: "the adapter handles are poisoned".to_owned(),
            left: Vec::new(),
        })?;
        held.insert(interface, Arc::clone(&adapter));
        Ok((interface, adapter as Arc<dyn Packets>))
    }

    async fn remove_adapter(&self, interface: Interface) -> Result<()> {
        if let Ok(mut held) = self.adapters.lock() {
            // Dropping it removes that adapter and its routes, and leaves every
            // other network's alone.
            held.remove(&interface);
        }
        Ok(())
    }

    async fn assign_address(&self, interface: Interface, address: IpAddr) -> Result<()> {
        route_table::assign_address(interface, address)?;
        if address.is_ipv4() {
            // Known to be accepted once the adapter holds an IPv4 address, which
            // covers an adapter the attempt at creation could not weigh.
            route_table::weigh_ipv4_interface(interface)?;
        }
        Ok(())
    }

    async fn remove_address(&self, interface: Interface, address: IpAddr) -> Result<()> {
        route_table::remove_address(interface, address)
    }

    async fn install_route(&self, route: &Route) -> Result<()> {
        route_table::install(route)
    }

    async fn remove_route(&self, route: &Route) -> Result<()> {
        // Only what this daemon put there. A route somebody else installed for
        // the same prefix is theirs.
        let present = route_table::present()?;
        if present.contains(route) { route_table::remove(route) } else { Ok(()) }
    }

    async fn install_rule(&self, rule: &Rule) -> Result<()> {
        nrpt::install(rule)
    }

    async fn remove_rule(&self, rule: &Rule) -> Result<()> {
        nrpt::remove(rule)
    }

    async fn sweep_rules(&self) -> Result<bool> {
        nrpt::sweep()
    }
}

#[cfg(test)]
mod tests {
    /// This module decides nothing; it forwards. A decision here would be one no
    /// test could reach, because none of it runs without Administrator.
    #[test]
    fn the_machine_decides_nothing() {
        let code = crate::code_of(include_str!("machine.rs"));

        for forbidden in ["Plan::", "if route.is_default", "params", "RosterState"] {
            assert!(!code.contains(forbidden), "`{forbidden}` is a decision, and belongs in core");
        }
    }

    /// Removal consults what is present, so the daemon removes its own footprint
    /// rather than everything that looks like it.
    #[test]
    fn removal_checks_what_is_actually_present() {
        let code = crate::code_of(include_str!("machine.rs"));
        assert!(code.contains("route_table::present()"), "removal must not act blind");
    }
}

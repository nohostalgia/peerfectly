//! The real machine.
//!
//! Wires [`daemon::machine::Machine`] to the TUN device, netlink and
//! systemd-resolved. Glue and nothing else: the order these calls happen in, and
//! what is undone when one fails, is `daemon::lifecycle`'s, tested there against
//! a machine that can be told to fail at any step.
//!
//! # What is not tested here
//!
//! All of it needs `CAP_NET_ADMIN`. The testbed runs it; `VERIFICATION.md`
//! records what was run.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tunnel::Packets;

use crate::{ifname, netlink, resolved, tun::Tun};
use daemon::error::{Error, Result, Step};
use daemon::machine::Machine;
use daemon::routes::{Interface, Route};
use daemon::rule::Rule;

/// One network's interface, held for exactly as long as its tunnel is up.
struct Held {
    /// The device. Dropping it removes the interface, and everything on it.
    tun: Arc<Tun>,
    /// What the portable half named it, which is how a rule finds it.
    asked_as: String,
}

/// The machine this daemon is running on.
pub struct Linux {
    /// One device per network that is up, by the interface it presented.
    held: Mutex<BTreeMap<Interface, Held>>,
    /// The firewall, written whole before any interface exists.
    firewall: crate::firewall::Nftables,
}

impl Linux {
    /// A handle to this machine, with its firewall.
    #[must_use]
    pub fn new(firewall: crate::firewall::Nftables) -> Self {
        Self { held: Mutex::new(BTreeMap::new()), firewall }
    }

    /// The kernel's name for an interface this machine holds.
    fn name_of(&self, interface: Interface) -> Option<String> {
        let held = self.held.lock().ok()?;
        held.get(&interface).map(|held| held.tun.name().to_owned())
    }

    /// The kernel's name for the interface a network's rule belongs to.
    fn name_for_rule(&self, rule: &Rule) -> Option<String> {
        let asked_as = daemon::limits::adapter_name(rule.network());
        let held = self.held.lock().ok()?;
        held.values().find(|held| held.asked_as == asked_as).map(|held| held.tun.name().to_owned())
    }
}

/// Runs a blocking netlink call off the runtime's threads.
async fn blocking<T: Send + 'static>(
    step: Step,
    call: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> Result<T> {
    let failed = |cause: String| Error::BringUp { step, cause, left: Vec::new() };
    tokio::task::spawn_blocking(call)
        .await
        .map_err(|cause| failed(cause.to_string()))?
        .map_err(|cause| failed(cause.to_string()))
}

#[async_trait]
impl Machine for Linux {
    async fn create_adapter(
        &self,
        name: &str,
        guid: [u8; 16],
    ) -> Result<(Interface, Arc<dyn Packets>)> {
        // **No table, no tunnel.** Every new connection arriving on the
        // interface is refused by the firewall table unless exposed; a tunnel
        // without it would make every service on this machine reachable from
        // the network. Rewritten here, before the interface exists, so it is in
        // place — and current — for every bring-up, not only the first.
        let firewall = self.firewall.clone();
        blocking(Step::CreatingAdapter, move || firewall.ensure().map_err(std::io::Error::other))
            .await?;

        // Named from the GUID, not from `name`: the label a person chose may not
        // be an interface name at all. See `ifname`.
        let kernel_name = ifname::from_guid(&guid);
        let opened = kernel_name.clone();
        let tun = Arc::new(blocking(Step::CreatingAdapter, move || Tun::open(&opened)).await?);

        let looked_up = kernel_name.clone();
        let index = blocking(Step::CreatingAdapter, move || netlink::index_of(&looked_up)).await?;
        let mtu = u32::try_from(daemon::limits::MTU).unwrap_or(1_280);
        blocking(Step::CreatingAdapter, move || netlink::link_up(index, mtu)).await?;

        let interface = Interface::new(index);
        let mut held = self.held.lock().map_err(|_| Error::BringUp {
            step: Step::CreatingAdapter,
            cause: "the interface handles are poisoned".to_owned(),
            left: Vec::new(),
        })?;
        held.insert(interface, Held { tun: Arc::clone(&tun), asked_as: name.to_owned() });
        Ok((interface, tun as Arc<dyn Packets>))
    }

    async fn remove_adapter(&self, interface: Interface) -> Result<()> {
        if let Ok(mut held) = self.held.lock() {
            // Dropping the device removes that interface, its addresses, its
            // routes and its resolver setting, and leaves every other network's
            // alone. The packet pump holds a clone until it stops; the interface
            // goes when the last one does.
            held.remove(&interface);
        }
        Ok(())
    }

    async fn assign_address(&self, interface: Interface, address: IpAddr) -> Result<()> {
        blocking(Step::CreatingAdapter, move || netlink::add_address(interface.index(), address))
            .await
    }

    async fn remove_address(&self, interface: Interface, address: IpAddr) -> Result<()> {
        blocking(Step::CreatingAdapter, move || netlink::remove_address(interface.index(), address))
            .await
    }

    async fn install_route(&self, route: &Route) -> Result<()> {
        let route = *route;
        blocking(Step::InstallingRoutes, move || netlink::add_route(&route)).await
    }

    async fn remove_route(&self, route: &Route) -> Result<()> {
        // An interface already gone took its routes with it.
        if self.name_of(route.interface()).is_none() {
            return Ok(());
        }
        let route = *route;
        blocking(Step::InstallingRoutes, move || netlink::remove_route(&route)).await
    }

    async fn install_rule(&self, rule: &Rule) -> Result<()> {
        let Some(interface) = self.name_for_rule(rule) else {
            return Err(Error::BringUp {
                step: Step::InstallingRule,
                cause: format!("no interface is up for the network `{}`", rule.network()),
                left: Vec::new(),
            });
        };
        let (nameserver, suffix) = (rule.nameserver(), rule.suffix().to_owned());
        blocking(Step::InstallingRule, move || {
            resolved::install(&interface, nameserver, &suffix)
                .map(|_| ())
                .map_err(std::io::Error::other)
        })
        .await
    }

    async fn remove_rule(&self, rule: &Rule) -> Result<()> {
        // Before bring-up there is no interface yet, and nothing to undo.
        let Some(interface) = self.name_for_rule(rule) else { return Ok(()) };
        blocking(Step::InstallingRule, move || {
            resolved::revert(&interface).map_err(std::io::Error::other)
        })
        .await
    }

    async fn sweep_rules(&self) -> Result<bool> {
        // The settings belong to interfaces that die with this process, so an
        // earlier run cannot have left one.
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    /// This module decides nothing; it forwards. A decision here would be one
    /// only the testbed could reach.
    #[test]
    fn the_machine_decides_nothing() {
        let code: String = include_str!("machine.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect();
        for forbidden in ["Plan::", "is_default", "params", "RosterState"] {
            assert!(!code.contains(forbidden), "`{forbidden}` is a decision, and belongs in core");
        }
        assert!(
            code.find("firewall.ensure()") < code.find("Tun::open("),
            "the firewall table is in place before the interface exists"
        );
    }
}

//! What the daemon does *to* the machine, behind an interface.
//!
//! Creating an adapter, writing a route, installing a resolution rule. Each is
//! one call to the platform and needs Administrator; none of them decides
//! anything.
//!
//! The interface exists so the **order** those calls happen in, and what happens
//! when one of them fails halfway, can be tested. That sequence is the part most
//! likely to be wrong in a way a person would notice — a failed bring-up that
//! leaves a route behind blackholes the prefix for the whole machine — and it is
//! also the part that cannot be exercised at all if it is welded to calls that
//! need elevation.
//!
//! [`Recording`] is the implementation the tests use: it can be told to fail at
//! any step, and it remembers what is installed, so "the route was removed after
//! the rule failed" is a thing a test can assert rather than a thing a person has
//! to check by hand on a real machine.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tunnel::Packets;

use crate::error::Result;
use crate::routes::{Interface, Route};
use crate::rule::Rule;

/// The machine, as far as this daemon is concerned.
#[async_trait]
pub trait Machine: Send + Sync {
    /// Creates the packet adapter, and hands back both the interface routes
    /// point at and the device packets move over.
    ///
    /// The device comes back rather than being held here because it does not
    /// exist until the tunnel comes up. A daemon holding one for its whole life
    /// would have a live adapter with the tunnel down.
    ///
    /// Named, because a device may hold several networks and each gets its own.
    /// An unnamed adapter would mean the second network created something the
    /// machine could not tell apart from the first's.
    ///
    /// And given its GUID, the same every time for the same network — see
    /// [`crate::limits::adapter_guid`]. A platform with no such notion ignores it.
    async fn create_adapter(
        &self,
        name: &str,
        guid: [u8; 16],
    ) -> Result<(Interface, Arc<dyn Packets>)>;

    /// Removes one packet adapter, named by the interface it presented.
    async fn remove_adapter(&self, interface: Interface) -> Result<()>;

    /// Gives the adapter one of this device's own overlay addresses: its IPv6
    /// address as a `/128`, or its IPv4 address as a `/32`.
    ///
    /// Without it the address lives only in the roster. The machine does not
    /// recognise it as local, so a packet it sends to itself is routed into the
    /// tunnel and dropped for want of a session, and nothing can bind to it —
    /// including the resolver, which listens there. Both were true of the first
    /// version, and both looked like the network simply not working.
    async fn assign_address(&self, interface: Interface, address: IpAddr) -> Result<()>;

    /// Takes the address back off the adapter.
    async fn remove_address(&self, interface: Interface, address: IpAddr) -> Result<()>;

    /// Adds a route.
    async fn install_route(&self, route: &Route) -> Result<()>;

    /// Removes a route.
    async fn remove_route(&self, route: &Route) -> Result<()>;

    /// Writes the name-resolution rule.
    async fn install_rule(&self, rule: &Rule) -> Result<()>;

    /// Removes the name-resolution rule.
    async fn remove_rule(&self, rule: &Rule) -> Result<()>;

    /// Removes any resolution rule left by an earlier run.
    ///
    /// Returns whether anything was found. Runs on startup, which is the only
    /// time it can help: the case that leaves a rule behind is the case where
    /// shutdown did not run.
    async fn sweep_rules(&self) -> Result<bool>;
}

#[cfg(test)]
pub(crate) mod testing {
    //! A machine that remembers what was done to it.

    use std::sync::Mutex;

    use super::{Interface, Machine, Result, Route, Rule};
    use crate::error::{Error, Step};

    /// A step this machine can be told to fail at.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Fail {
        Adapter,
        Address,
        Route,
        Rule,
        RemovingRoute,
    }

    /// What is currently installed.
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    pub(crate) struct Installed {
        /// The interfaces whose adapters exist, one per network that is up.
        pub adapters: Vec<Interface>,
        pub addresses: Vec<std::net::IpAddr>,
        /// The names those adapters were asked for, in the order they were made.
        pub named: Vec<String>,
        /// And the GUIDs, in the same order.
        pub guids: Vec<[u8; 16]>,
        pub routes: Vec<Route>,
        pub rules: Vec<Rule>,
        pub swept: bool,
    }

    /// A machine that records rather than acts.
    pub(crate) struct Recording {
        installed: Mutex<Installed>,
        fail_at: Option<Fail>,
    }

    impl Recording {
        pub(crate) fn new() -> Self {
            Self { installed: Mutex::new(Installed::default()), fail_at: None }
        }

        pub(crate) fn failing_at(step: Fail) -> Self {
            Self { installed: Mutex::new(Installed::default()), fail_at: Some(step) }
        }

        pub(crate) fn installed(&self) -> Installed {
            self.installed.lock().expect("not poisoned").clone()
        }

        fn refuse(step: Step, what: &str) -> Error {
            Error::BringUp { step, cause: what.to_owned(), left: Vec::new() }
        }
    }

    #[async_trait::async_trait]
    impl Machine for Recording {
        async fn create_adapter(
            &self,
            name: &str,
            guid: [u8; 16],
        ) -> Result<(Interface, std::sync::Arc<dyn tunnel::Packets>)> {
            if self.fail_at == Some(Fail::Adapter) {
                return Err(Self::refuse(Step::CreatingAdapter, "told to fail"));
            }
            let mut installed = self.installed.lock().expect("not poisoned");
            // A distinct interface each time, as a real machine gives. Handing
            // the same one back twice would let a test pass while two networks
            // shared an adapter.
            let interface = Interface::new(
                7u32.saturating_add(u32::try_from(installed.adapters.len()).unwrap_or(0)),
            );
            installed.adapters.push(interface);
            installed.named.push(name.to_owned());
            installed.guids.push(guid);
            Ok((interface, std::sync::Arc::new(tunnel::MemoryDevice::new())))
        }

        async fn remove_adapter(&self, interface: Interface) -> Result<()> {
            let mut installed = self.installed.lock().expect("not poisoned");
            installed.adapters.retain(|held| *held != interface);
            Ok(())
        }

        async fn assign_address(
            &self,
            _interface: Interface,
            address: std::net::IpAddr,
        ) -> Result<()> {
            if self.fail_at == Some(Fail::Address) {
                return Err(Self::refuse(Step::CreatingAdapter, "told to fail"));
            }
            self.installed.lock().expect("not poisoned").addresses.push(address);
            Ok(())
        }

        async fn remove_address(
            &self,
            _interface: Interface,
            address: std::net::IpAddr,
        ) -> Result<()> {
            self.installed.lock().expect("not poisoned").addresses.retain(|held| *held != address);
            Ok(())
        }

        async fn install_route(&self, route: &Route) -> Result<()> {
            if self.fail_at == Some(Fail::Route) {
                return Err(Self::refuse(Step::InstallingRoutes, "told to fail"));
            }
            self.installed.lock().expect("not poisoned").routes.push(*route);
            Ok(())
        }

        async fn remove_route(&self, route: &Route) -> Result<()> {
            if self.fail_at == Some(Fail::RemovingRoute) {
                return Err(Self::refuse(Step::InstallingRoutes, "told to fail"));
            }
            self.installed.lock().expect("not poisoned").routes.retain(|held| held != route);
            Ok(())
        }

        async fn install_rule(&self, rule: &Rule) -> Result<()> {
            if self.fail_at == Some(Fail::Rule) {
                return Err(Self::refuse(Step::InstallingRule, "told to fail"));
            }
            self.installed.lock().expect("not poisoned").rules.push(rule.clone());
            Ok(())
        }

        async fn remove_rule(&self, rule: &Rule) -> Result<()> {
            self.installed.lock().expect("not poisoned").rules.retain(|held| held != rule);
            Ok(())
        }

        async fn sweep_rules(&self) -> Result<bool> {
            self.installed.lock().expect("not poisoned").swept = true;
            Ok(false)
        }
    }
}

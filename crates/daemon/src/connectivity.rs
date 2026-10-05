//! Where a transport comes from, and when.
//!
//! A one-method interface, for one reason: §2.6c requires that the daemon reach
//! no infrastructure while the network is off, and a transport that exists is a
//! transport that has already contacted its relay. So one is *made* when the
//! person turns the network on, and dropped when they turn it off.
//!
//! Behind a trait so the whole lifecycle — up, down, up again — is testable
//! against the in-process transport. Without it, the property §2.6c cares about
//! could only be checked with a packet capture on a real machine, and a property
//! that can only be checked that way is one that gets broken between checks.

use std::sync::Arc;

use async_trait::async_trait;
use identity::NodeIdentity;
use roster::state::RosterState;
use transport::session::Transport;

use crate::error::Result;

/// Makes a transport when the network is turned on.
#[async_trait]
pub trait Connectivity: Send + Sync {
    /// Starts a transport for this device on this network.
    ///
    /// Called on bring-up, never before. Anything this does — binding a socket,
    /// contacting a relay, learning an address — is traffic the person has just
    /// asked for.
    async fn start(
        &self,
        identity: &Arc<NodeIdentity>,
        state: RosterState,
    ) -> Result<Arc<dyn Transport>>;
}

/// One network interface this device is on, as far as discovery and IPv4
/// conflicts need to know.
///
/// Platform-neutral on purpose. A desktop reads these from the operating system;
/// Android does not let an app enumerate interfaces that way, so its edge reads
/// them from the connectivity service and hands them over in this shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalInterface {
    /// The platform's index for it.
    pub index: u32,
    /// Its IPv4 addresses, first preferred.
    pub ipv4: Vec<std::net::Ipv4Addr>,
    /// The IPv4 subnets it is on: each address with its prefix length.
    ///
    /// A peer whose IPv4 address falls inside one of these would take that
    /// address away from whatever holds it on this network — a printer, a
    /// television — so it is withheld on this device.
    pub subnets: Vec<Subnet>,
    /// The IPv4 gateways it routes through.
    pub gateways: Vec<std::net::Ipv4Addr>,
    /// The IPv4 resolvers it uses.
    pub resolvers: Vec<std::net::Ipv4Addr>,
    /// Administratively up.
    pub up: bool,
    /// Actually carrying traffic.
    pub running: bool,
    /// Able to carry multicast.
    pub multicast: bool,
    /// The loopback interface.
    pub loopback: bool,
}

/// An IPv4 address with the prefix length of the subnet it is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Subnet {
    /// The address this interface holds.
    pub address: std::net::Ipv4Addr,
    /// The subnet's prefix length, 0 to 32.
    pub prefix_len: u8,
}

impl Subnet {
    /// Whether an address lies inside this subnet.
    #[must_use]
    pub fn contains(&self, address: std::net::Ipv4Addr) -> bool {
        let mask = u32::MAX
            .checked_shl(32_u32.saturating_sub(u32::from(self.prefix_len.min(32))))
            .unwrap_or(0);
        u32::from(address) & mask == u32::from(self.address) & mask
    }
}

/// Where the list of interfaces comes from.
pub trait Interfaces: Send + Sync {
    /// The interfaces this device is on right now.
    fn list(&self) -> Vec<LocalInterface>;
}

/// The operating system's own list, as a desktop reads it.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemInterfaces;

impl Interfaces for SystemInterfaces {
    fn list(&self) -> Vec<LocalInterface> {
        netdev::get_interfaces().iter().map(LocalInterface::from).collect()
    }
}

impl From<&netdev::Interface> for LocalInterface {
    fn from(interface: &netdev::Interface) -> Self {
        Self {
            index: interface.index,
            ipv4: interface.ipv4.iter().map(|net| net.addr()).collect(),
            subnets: interface
                .ipv4
                .iter()
                .map(|net| Subnet { address: net.addr(), prefix_len: net.prefix_len() })
                .collect(),
            gateways: interface
                .gateway
                .as_ref()
                .map(|gateway| gateway.ipv4.clone())
                .unwrap_or_default(),
            resolvers: interface
                .dns_servers
                .iter()
                .filter_map(|server| match server {
                    std::net::IpAddr::V4(address) => Some(*address),
                    std::net::IpAddr::V6(_) => None,
                })
                .collect(),
            up: interface.is_up(),
            running: interface.is_running(),
            multicast: interface.is_multicast(),
            loopback: interface.is_loopback(),
        }
    }
}

/// Connectivity over the real network, through iroh.
///
/// Portable: nothing here knows which platform it runs on. It lived in the Windows
/// edge only because that was the one edge there was, and a phone would otherwise
/// have had to copy it or depend on Windows.
///
/// Binding an endpoint is not a passive act: it contacts the relay named in the
/// signed parameters and begins learning this device's observed addresses. That is
/// traffic to infrastructure, which is why it is only ever reached through
/// [`Connectivity::start`] at bring-up.
#[derive(Debug, Default, Clone, Copy)]
pub struct Iroh;

#[async_trait]
impl Connectivity for Iroh {
    async fn start(
        &self,
        identity: &Arc<NodeIdentity>,
        state: RosterState,
    ) -> Result<Arc<dyn Transport>> {
        let transport =
            transport_iroh::IrohTransport::bind(identity, state).await.map_err(|cause| {
                crate::error::Error::BringUp {
                    step: crate::error::Step::StartingTransport,
                    cause: cause.to_string(),
                    left: Vec::new(),
                }
            })?;
        Ok(Arc::new(transport))
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    /// Addresses with their prefix lengths, the gateway and the IPv4 resolvers
    /// are all carried over; an IPv6 resolver is not an IPv4 conflict.
    #[test]
    fn a_supplied_interface_carries_subnets_gateways_and_resolvers() {
        let mut interface = netdev::Interface::dummy();
        interface.index = 7;
        interface.ipv4 = vec![
            netdev::ipnet::Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 40), 24).unwrap(),
            netdev::ipnet::Ipv4Net::new(Ipv4Addr::new(10, 1, 2, 3), 8).unwrap(),
        ];
        let mut gateway = netdev::NetworkDevice::new();
        gateway.ipv4 = vec![Ipv4Addr::new(192, 168, 1, 1)];
        interface.gateway = Some(gateway);
        interface.dns_servers =
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), IpAddr::V6(Ipv6Addr::LOCALHOST)];

        let local = LocalInterface::from(&interface);

        assert_eq!(local.ipv4, vec![Ipv4Addr::new(192, 168, 1, 40), Ipv4Addr::new(10, 1, 2, 3)]);
        assert_eq!(
            local.subnets,
            vec![
                Subnet { address: Ipv4Addr::new(192, 168, 1, 40), prefix_len: 24 },
                Subnet { address: Ipv4Addr::new(10, 1, 2, 3), prefix_len: 8 },
            ]
        );
        assert_eq!(local.gateways, vec![Ipv4Addr::new(192, 168, 1, 1)]);
        assert_eq!(local.resolvers, vec![Ipv4Addr::new(192, 168, 1, 1)]);
    }

    #[test]
    fn a_subnet_contains_exactly_its_addresses() {
        let lan = Subnet { address: Ipv4Addr::new(192, 168, 1, 40), prefix_len: 24 };
        assert!(lan.contains(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(lan.contains(Ipv4Addr::new(192, 168, 1, 255)));
        assert!(!lan.contains(Ipv4Addr::new(192, 168, 2, 1)));

        let host = Subnet { address: Ipv4Addr::new(100, 64, 3, 4), prefix_len: 32 };
        assert!(host.contains(Ipv4Addr::new(100, 64, 3, 4)));
        assert!(!host.contains(Ipv4Addr::new(100, 64, 3, 5)));

        let everything = Subnet { address: Ipv4Addr::new(1, 2, 3, 4), prefix_len: 0 };
        assert!(everything.contains(Ipv4Addr::new(8, 8, 8, 8)));
    }

    /// The machine this runs on has a way out, and the list says which. A
    /// desktop with no gateway at all would withhold nothing for gateways, and
    /// the reading here would never have been tried on a real adapter.
    #[cfg(windows)]
    #[test]
    fn the_running_machine_reports_at_least_one_gateway() {
        let listed = SystemInterfaces.list();
        assert!(
            listed.iter().any(|interface| !interface.gateways.is_empty()),
            "no interface reported a gateway: {listed:?}"
        );
        assert!(
            listed.iter().any(|interface| !interface.subnets.is_empty()),
            "no interface reported a subnet: {listed:?}"
        );
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! A connectivity that hands out in-process transports.

    use std::sync::{Arc, Mutex};

    use identity::NodeIdentity;
    use roster::state::RosterState;
    use transport::session::Transport;
    use transport::{MemoryFabric, MemoryTransport};

    use super::Connectivity;
    use crate::error::Result;

    /// Counts how many times a transport was asked for.
    pub(crate) struct InProcess {
        fabric: MemoryFabric,
        started: Mutex<usize>,
    }

    impl InProcess {
        pub(crate) fn new() -> Self {
            Self { fabric: MemoryFabric::new(), started: Mutex::new(0) }
        }

        /// How many transports have been started.
        pub(crate) fn started(&self) -> usize {
            *self.started.lock().expect("not poisoned")
        }
    }

    /// An in-process transport that remembers what it was told to avoid.
    ///
    /// Everything else is the in-memory transport's: this wraps it rather than
    /// reimplementing it, so a test about ranges cannot pass because the double
    /// behaves differently from a transport in every other respect.
    pub(crate) struct Watched {
        inner: MemoryTransport,
        avoided: Mutex<Vec<transport::Range>>,
    }

    impl Watched {
        /// The ranges it was last told, in the order they were given.
        pub(crate) fn avoided(&self) -> Vec<transport::Range> {
            self.avoided.lock().expect("not poisoned").clone()
        }
    }

    #[async_trait::async_trait]
    impl Transport for Watched {
        async fn connect(
            &self,
            peer: &roster::sign::PublicKey,
        ) -> transport::Result<Box<dyn transport::Session>> {
            self.inner.connect(peer).await
        }

        async fn accept(&self) -> transport::Result<Box<dyn transport::Session>> {
            self.inner.accept().await
        }

        fn addresses(&self) -> Vec<String> {
            self.inner.addresses()
        }

        fn learned(&self, peer: &roster::sign::PublicKey, addresses: &[String]) {
            self.inner.learned(peer, addresses);
        }

        async fn update_state(&self, state: RosterState) {
            self.inner.update_state(state).await;
        }

        fn avoid(&self, ranges: &[transport::Range]) {
            let mut held = self.avoided.lock().expect("not poisoned");
            held.clear();
            held.extend_from_slice(ranges);
        }

        async fn path_to(&self, peer: &roster::id::DeviceId) -> Option<transport::Path> {
            self.inner.path_to(peer).await
        }
    }

    /// A connectivity handing out [`Watched`] transports, kept by network order.
    pub(crate) struct Watching {
        fabric: MemoryFabric,
        handed: Mutex<Vec<Arc<Watched>>>,
    }

    impl Watching {
        pub(crate) fn new() -> Self {
            Self { fabric: MemoryFabric::new(), handed: Mutex::new(Vec::new()) }
        }

        /// The transports handed out so far, oldest first.
        pub(crate) fn handed(&self) -> Vec<Arc<Watched>> {
            self.handed.lock().expect("not poisoned").clone()
        }
    }

    #[async_trait::async_trait]
    impl Connectivity for Watching {
        async fn start(
            &self,
            identity: &Arc<NodeIdentity>,
            state: RosterState,
        ) -> Result<Arc<dyn Transport>> {
            let inner = MemoryTransport::join(&self.fabric, Arc::clone(identity), state).await;
            let watched = Arc::new(Watched { inner, avoided: Mutex::new(Vec::new()) });
            self.handed.lock().expect("not poisoned").push(Arc::clone(&watched));
            Ok(watched as Arc<dyn Transport>)
        }
    }

    #[async_trait::async_trait]
    impl Connectivity for InProcess {
        async fn start(
            &self,
            identity: &Arc<NodeIdentity>,
            state: RosterState,
        ) -> Result<Arc<dyn Transport>> {
            {
                let mut count = self.started.lock().expect("not poisoned");
                *count = count.saturating_add(1);
            }
            let transport = MemoryTransport::join(&self.fabric, Arc::clone(identity), state).await;
            Ok(Arc::new(transport))
        }
    }
}

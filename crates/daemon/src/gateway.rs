//! Between a session and the machine's networking stack.
//!
//! Everything a packet passes through on its way in or out, and every reason it
//! might not. In the core, over [`tunnel::Packets`], so the whole path is
//! exercised with an in-memory device and no privileges — the real adapter
//! implements the same interface and inherits these expectations unchanged.
//!
//! # `tunnel` decides, this obeys
//!
//! There is no second source check here. Whether a packet's source may be what it
//! claims is [`tunnel`]'s question, it has already been answered, and asking it
//! again in a second place is how two answers start to differ. A scan asserts
//! this module contains no such check.
//!
//! The one bound this adds is the adapter's: a packet larger than the link will
//! carry. That is a statement about the wire and not about who sent it, and it is
//! the reason the two are kept distinguishable in the outcome.
//!
//! # There is no device while the tunnel is down
//!
//! The device is attached when the tunnel comes up and dropped when it goes down,
//! rather than held for the life of the daemon. Section 2.6b says the tunnel
//! exists because a person switched it on; a gateway holding a live adapter with
//! the tunnel down would be a tunnel in every sense but the name.
//!
//! So a packet offered while down is refused with [`crate::Error::NotUp`]. That
//! is not a verdict about the packet — it is an answer about the daemon.

use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use roster::id::DeviceId;
use tunnel::{Inbound, Ipv4Holdings, Outbound, Packets, Tunnel};

use crate::limits;
use crate::router::Router;

/// What became of a packet the host wanted to send.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Departure {
    /// Carry it to this device.
    To {
        /// Where it goes.
        device: DeviceId,
        /// The packet, unchanged.
        packet: Vec<u8>,
    },

    /// The tunnel refused it — most often a destination off the network.
    ///
    /// §2.6's split routing. A caller addressed the wrong place; nobody lied.
    Refused(Outbound),

    /// On the network, but no session to send it over.
    ///
    /// The ordinary state of a device that is switched off. Not an error and not
    /// a refusal: there is simply nowhere to send it yet.
    Unreachable {
        /// Where it was addressed.
        destination: IpAddr,
    },

    /// Larger than the link will carry.
    ///
    /// Refused whole. No prefix of it is judged or sent, because judging the
    /// first part of something as though it were the whole is how a truncated
    /// packet becomes a plausible-looking lie.
    TooLarge {
        /// How many bytes the host offered.
        len: usize,
        /// What the link carries.
        limit: usize,
    },
}

impl Departure {
    /// Whether this packet is going anywhere.
    #[must_use]
    pub const fn is_carried(&self) -> bool {
        matches!(self, Self::To { .. })
    }
}

/// The path between sessions and the machine.
pub struct Gateway {
    /// The rules. Not reimplemented here.
    ///
    /// Behind a lock only so the IPv4 holdings can be replaced when the roster
    /// changes; nothing is held across a wait.
    tunnel: RwLock<Tunnel>,
    /// The device packets move over, while the tunnel is up.
    device: tokio::sync::Mutex<Option<Arc<dyn Packets>>>,
}

impl Gateway {
    /// A gateway with no device yet.
    ///
    /// The tunnel is down until something attaches one.
    #[must_use]
    pub fn new(tunnel: Tunnel) -> Self {
        Self { tunnel: RwLock::new(tunnel), device: tokio::sync::Mutex::new(None) }
    }

    /// Attaches the device. This is what makes the tunnel up.
    pub async fn attach(&self, device: Arc<dyn Packets>) {
        *self.device.lock().await = Some(device);
    }

    /// Drops the device. This is what makes the tunnel down.
    ///
    /// Returns whether there was one, so a caller can tell an idempotent
    /// take-down from a real one.
    pub async fn detach(&self) -> bool {
        self.device.lock().await.take().is_some()
    }

    /// Whether a device is attached.
    pub async fn is_up(&self) -> bool {
        self.device.lock().await.is_some()
    }

    /// The device, if the tunnel is up.
    async fn device(&self) -> crate::Result<Arc<dyn Packets>> {
        self.device.lock().await.clone().ok_or(crate::Error::NotUp)
    }

    /// The rules this gateway obeys, as they are now.
    #[must_use]
    pub fn tunnel(&self) -> Tunnel {
        self.tunnel
            .read()
            .map_or_else(|poisoned| poisoned.into_inner().clone(), |tunnel| tunnel.clone())
    }

    /// Replaces the IPv4 holdings the rules judge against.
    ///
    /// Called from `Node::enforce_roster`, the one place roster changes reach
    /// the layers below, beside the transport's own update.
    pub fn set_holdings(&self, holdings: Ipv4Holdings) {
        match self.tunnel.write() {
            Ok(mut tunnel) => tunnel.set_holdings(holdings),
            Err(poisoned) => poisoned.into_inner().set_holdings(holdings),
        }
    }

    /// A packet that arrived on a session.
    ///
    /// Delivered to the machine only if [`tunnel`] accepts it. There is exactly
    /// one call that writes to the device, on exactly one branch: a refusal
    /// cannot reach the machine by an error path, a fast path, or a buffer that
    /// outlived its check, because there is no other path.
    /// # Errors
    ///
    /// When the packet was accepted and the machine would not take it. A
    /// delivery failure is not a verdict about the packet, so it is reported
    /// separately rather than dressed up as one.
    pub async fn inbound(&self, session: DeviceId, packet: &[u8]) -> crate::Result<Inbound> {
        if packet.len() > limits::MAX_PACKET {
            return Ok(Inbound::TooLong { len: packet.len(), limit: limits::MAX_PACKET });
        }

        let verdict = self.tunnel().inbound(session, packet);
        if verdict.is_accepted() {
            // The only write in this function, and it needs a device — so with
            // the tunnel down nothing reaches the machine by construction rather
            // than by a check somebody has to remember.
            let device = self.device().await?;
            device.deliver(packet).await.map_err(|cause| crate::Error::Refused {
                cause: format!("the machine would not take a packet: {cause}"),
            })?;
        }
        Ok(verdict)
    }

    /// The next packet the machine wants to send, and where it goes.
    ///
    /// # Errors
    ///
    /// When the device cannot be read.
    /// The next packet the machine wants to send.
    ///
    /// Separate from [`Self::route`] because this waits, possibly for a long
    /// time — a machine with nothing to send sends nothing — and whatever a
    /// caller holds while waiting is held for exactly that long. Holding the
    /// router across it deadlocked every new session against an idle read.
    ///
    /// # Errors
    ///
    /// When the tunnel is down, or the device cannot be read.
    pub async fn take(&self) -> crate::Result<Vec<u8>> {
        let device = self.device().await?;
        device.take().await.map_err(|cause| crate::Error::Refused {
            cause: format!("the machine would not give up a packet: {cause}"),
        })
    }

    /// Where a packet the machine offered should go.
    ///
    /// Synchronous, and quick: the router is consulted here and nowhere that
    /// waits.
    #[must_use]
    pub fn route(&self, packet: &[u8], router: &Router) -> Departure {
        let packet = packet.to_vec();

        if packet.len() > limits::MAX_PACKET {
            return Departure::TooLarge { len: packet.len(), limit: limits::MAX_PACKET };
        }

        match self.tunnel().outbound(&packet) {
            Outbound::Carried => {}
            refusal => return Departure::Refused(refusal),
        }

        let Some(destination) = tunnel::destination_of(&packet) else {
            return Departure::Refused(Outbound::TooShort {
                len: packet.len(),
                needed: tunnel::limits::MIN_PACKET_LEN,
            });
        };

        match router.route(destination) {
            Some(device) => Departure::To { device, packet },
            None => Departure::Unreachable { destination },
        }
    }

    /// Takes a packet and says where it goes.
    ///
    /// # Errors
    ///
    /// When the tunnel is down, or the device cannot be read.
    pub async fn outbound(&self, router: &Router) -> crate::Result<Departure> {
        let packet = self.take().await?;
        Ok(self.route(&packet, router))
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use roster::types::Ipv4Range;
    use tunnel::{MemoryDevice, Prefix};

    use super::*;

    fn prefix() -> Prefix {
        Prefix::from_parameter(&[0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).expect("valid")
    }

    fn device(tag: u8) -> DeviceId {
        DeviceId::from_bytes([tag; 32])
    }

    /// The device these gateways belong to, distinct from every peer below.
    fn me() -> DeviceId {
        device(0)
    }

    fn packet(source: Ipv6Addr, destination: Ipv6Addr, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len.max(tunnel::limits::MIN_PACKET_LEN)];
        if let Some(first) = out.first_mut() {
            *first = 0x60;
        }
        out.splice(8..24, source.octets().iter().copied());
        out.splice(24..40, destination.octets().iter().copied());
        out
    }

    async fn gateway() -> (Gateway, Arc<MemoryDevice>) {
        let machine = Arc::new(MemoryDevice::new());
        let gateway = Gateway::new(Tunnel::new(prefix(), me()));
        gateway.attach(Arc::clone(&machine) as Arc<dyn Packets>).await;
        (gateway, machine)
    }

    #[tokio::test]
    async fn an_accepted_packet_reaches_the_machine() {
        let (gateway, machine) = gateway().await;
        let peer = device(1);
        let theirs = gateway.tunnel().address_of(&peer);
        let here = gateway.tunnel().own_address();
        let inbound = packet(theirs, here, 40);

        assert!(gateway.inbound(peer, &inbound).await.expect("delivers").is_accepted());
        assert_eq!(machine.delivered().await, vec![inbound], "unchanged");
    }

    /// The case the whole layer exists for, checked at the point where a packet
    /// would otherwise reach the machine.
    #[tokio::test]
    async fn a_spoofed_packet_reaches_the_machine_by_no_path() {
        let (gateway, machine) = gateway().await;
        let peer = device(1);
        let not_theirs = gateway.tunnel().address_of(&device(2));

        let outcome = gateway
            .inbound(peer, &packet(not_theirs, gateway.tunnel().own_address(), 40))
            .await
            .expect("no delivery");

        assert!(outcome.is_spoofed_source());
        assert_eq!(outcome.session(), Some(peer));
        assert!(machine.delivered().await.is_empty(), "nothing reached the machine");
    }

    #[tokio::test]
    async fn a_malformed_packet_reaches_the_machine_by_no_path() {
        let (gateway, machine) = gateway().await;

        for bytes in [vec![], vec![0u8; 39], vec![0xff; 20]] {
            let outcome = gateway.inbound(device(1), &bytes).await.expect("no delivery");
            assert!(outcome.is_malformed(), "{bytes:?}");
        }
        assert!(machine.delivered().await.is_empty());
    }

    /// Refused whole. Judging a prefix of something as though it were the whole
    /// is how a truncated packet becomes a plausible-looking lie.
    #[tokio::test]
    async fn an_oversized_packet_is_refused_without_being_judged() {
        let (gateway, machine) = gateway().await;
        let peer = device(1);
        let theirs = gateway.tunnel().address_of(&peer);

        // Otherwise perfectly valid, and one byte too long for the link.
        let huge = packet(theirs, theirs, limits::MAX_PACKET.saturating_add(1));
        let outcome = gateway.inbound(peer, &huge).await.expect("no delivery");

        match outcome {
            Inbound::TooLong { len, limit } => {
                assert_eq!(limit, limits::MAX_PACKET);
                assert!(len > limit);
            }
            other => panic!("expected a length refusal, got {other:?}"),
        }
        assert!(machine.delivered().await.is_empty(), "not even a prefix of it");
    }

    #[tokio::test]
    async fn a_packet_for_a_peer_is_routed_to_its_session() {
        let (gateway, machine) = gateway().await;
        let peer = device(1);
        let mut router = Router::new(prefix());
        router.opened(peer);

        let outgoing = packet(Ipv6Addr::UNSPECIFIED, gateway.tunnel().address_of(&peer), 40);
        machine.queue(outgoing.clone()).await;

        match gateway.outbound(&router).await.expect("takes") {
            Departure::To { device: to, packet } => {
                assert_eq!(to, peer);
                assert_eq!(packet, outgoing, "unchanged");
            }
            other => panic!("expected it to be carried, got {other:?}"),
        }
    }

    /// §2.6: a packet for the wider internet does not leave through the tunnel.
    #[tokio::test]
    async fn a_packet_for_the_internet_is_refused() {
        let (gateway, machine) = gateway().await;
        let router = Router::new(prefix());

        let elsewhere: Ipv6Addr = "2001:db8::1".parse().expect("valid");
        machine.queue(packet(Ipv6Addr::UNSPECIFIED, elsewhere, 40)).await;

        match gateway.outbound(&router).await.expect("takes") {
            Departure::Refused(Outbound::DestinationOffNetwork { destination }) => {
                assert_eq!(destination, IpAddr::V6(elsewhere));
            }
            other => panic!("expected a destination refusal, got {other:?}"),
        }
    }

    /// A device that is switched off is not an error.
    #[tokio::test]
    async fn a_packet_for_a_device_with_no_session_is_unreachable() {
        let (gateway, machine) = gateway().await;
        let router = Router::new(prefix());
        let absent = gateway.tunnel().address_of(&device(9));

        machine.queue(packet(Ipv6Addr::UNSPECIFIED, absent, 40)).await;

        match gateway.outbound(&router).await.expect("takes") {
            Departure::Unreachable { destination } => assert_eq!(destination, IpAddr::V6(absent)),
            other => panic!("expected unreachable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_oversized_outbound_packet_is_refused_whole() {
        let (gateway, machine) = gateway().await;
        let mut router = Router::new(prefix());
        let peer = device(1);
        router.opened(peer);

        let huge = packet(
            Ipv6Addr::UNSPECIFIED,
            gateway.tunnel().address_of(&peer),
            limits::MAX_PACKET.saturating_add(1),
        );
        machine.queue(huge.clone()).await;

        match gateway.outbound(&router).await.expect("takes") {
            Departure::TooLarge { len, limit } => {
                assert_eq!(limit, limits::MAX_PACKET);
                assert!(len > limit);
            }
            other => panic!("expected a length refusal, got {other:?}"),
        }
    }

    /// A refusal on the way out and a drop on the way in stay different things,
    /// so an application mistake does not read as an attack.
    #[tokio::test]
    async fn a_wrong_destination_is_not_a_spoofing_report() {
        let (gateway, machine) = gateway().await;
        let router = Router::new(prefix());
        machine
            .queue(packet(Ipv6Addr::UNSPECIFIED, "2001:db8::1".parse().expect("valid"), 40))
            .await;

        let departure = gateway.outbound(&router).await.expect("takes");
        assert!(!departure.is_carried());
        assert!(!matches!(departure, Departure::To { .. }));
    }

    fn holdings(devices: &[DeviceId]) -> Ipv4Holdings {
        Ipv4Holdings::from(
            &roster::id::NetworkId::from_bytes([3; 32]),
            Ipv4Range::DEFAULT,
            devices,
            &[],
        )
    }

    fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        let mut out = vec![0x45, 0, 0, 28];
        out.resize(12, 0);
        out.extend_from_slice(&source.octets());
        out.extend_from_slice(&destination.octets());
        out.resize(28, 0);
        out
    }

    #[tokio::test]
    async fn an_ipv4_packet_is_routed_to_the_session_holding_its_destination() {
        let (gateway, machine) = gateway().await;
        let peer = device(1);
        let held = holdings(&[peer]);
        let theirs = held.of(&peer).expect("held");
        gateway.set_holdings(held.clone());
        let mut router = Router::new(prefix());
        router.set_holdings(held);
        router.opened(peer);

        let outgoing = ipv4_packet(Ipv4Addr::new(100, 64, 0, 9), theirs);
        machine.queue(outgoing.clone()).await;

        match gateway.outbound(&router).await.expect("takes") {
            Departure::To { device: to, packet } => {
                assert_eq!(to, peer);
                assert_eq!(packet, outgoing, "unchanged");
            }
            other => panic!("expected it to be carried, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_ipv4_packet_to_an_unheld_address_is_refused() {
        let (gateway, machine) = gateway().await;
        let peer = device(1);
        let held = holdings(&[peer]);
        let nobody = Ipv4Addr::from(u32::from(held.of(&peer).expect("held")) ^ 1);
        gateway.set_holdings(held.clone());
        let mut router = Router::new(prefix());
        router.set_holdings(held);
        router.opened(peer);

        machine.queue(ipv4_packet(Ipv4Addr::new(100, 64, 0, 9), nobody)).await;

        match gateway.outbound(&router).await.expect("takes") {
            Departure::Refused(Outbound::DestinationHeldByNobody { destination }) => {
                assert_eq!(destination, nobody);
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// Holdings set on the gateway reach the rules it obeys: an IPv4 packet from
    /// a device is refused before, and accepted after.
    #[tokio::test]
    async fn holdings_set_on_the_gateway_reach_its_rules() {
        let (gateway, machine) = gateway().await;
        let peer = device(1);
        // This device holds one too: without that the packet would be refused
        // for its destination, and the test would pass for the wrong reason.
        let held = holdings(&[me(), peer]);
        let theirs = held.of(&peer).expect("held");
        let here = held.of(&me()).expect("held");
        let inbound = ipv4_packet(theirs, here);

        let before = gateway.inbound(peer, &inbound).await.expect("judged");
        assert!(!before.is_accepted(), "{before:?}");
        gateway.set_holdings(held);
        assert!(gateway.inbound(peer, &inbound).await.expect("delivers").is_accepted());
        assert_eq!(machine.delivered().await, vec![inbound]);
    }

    /// There is one write to the device, on one branch. Not a claim in prose: a
    /// second one would be a second way for a refused packet to arrive.
    #[test]
    fn there_is_exactly_one_way_to_reach_the_machine() {
        let code = crate::code_of(include_str!("gateway.rs"));
        assert_eq!(
            code.matches("device.deliver(").count(),
            1,
            "one delivery call, so a refusal has no other path to the machine"
        );
    }

    /// Section 2.6b and 2.6c: with the tunnel down there is no device, so nothing
    /// can pass in either direction. Not a check that could be forgotten — there
    /// is nothing to pass through.
    #[tokio::test]
    async fn nothing_passes_while_the_tunnel_is_down() {
        let gateway = Gateway::new(Tunnel::new(prefix(), me()));
        assert!(!gateway.is_up().await);

        let peer = device(1);
        let theirs = gateway.tunnel().address_of(&peer);

        assert!(matches!(
            gateway.inbound(peer, &packet(theirs, gateway.tunnel().own_address(), 40)).await,
            Err(crate::Error::NotUp)
        ));
        assert!(matches!(gateway.outbound(&Router::new(prefix())).await, Err(crate::Error::NotUp)));
    }

    #[tokio::test]
    async fn attaching_and_detaching_moves_the_tunnel_up_and_down() {
        let gateway = Gateway::new(Tunnel::new(prefix(), me()));
        let machine = Arc::new(MemoryDevice::new());

        assert!(!gateway.is_up().await);
        gateway.attach(machine as Arc<dyn Packets>).await;
        assert!(gateway.is_up().await);

        assert!(gateway.detach().await, "there was a device");
        assert!(!gateway.is_up().await);
        assert!(!gateway.detach().await, "and detaching twice is not a second one");
    }

    /// `tunnel` decides what a packet may claim. A second check here is how two
    /// answers start to differ.
    #[test]
    fn there_is_no_second_source_check() {
        let code = crate::code_of(include_str!("gateway.rs"));
        for forbidden in ["SOURCE_OFFSET", "source_of", "address_of(&session"] {
            assert!(!code.contains(forbidden), "`{forbidden}` would be a second source check");
        }
        assert!(code.contains("self.tunnel().inbound"), "the rules come from `tunnel`");
    }
}

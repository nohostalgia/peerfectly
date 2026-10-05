//! The socket: a dedicated multicast group and port.
//!
//! §8 requires a **dedicated UDP multicast port**, and explicitly **not mDNS
//! with names**. The name is already in the roster; all that is needed is to
//! discover that a key is present and where. Using mDNS would also collide with
//! the Bonjour and Avahi responders already present on most networks, which own
//! port 5353 and would answer for us.
//!
//! # Announcements repeat
//!
//! Not a retry — the design. §8 warns that multicast on wireless networks is
//! filtered by the access point outright, or delivered at the lowest available
//! bitrate. One announcement is one that may never arrive, so a caller sends on
//! an interval and a listener that starts late still learns of a device.
//!
//! # This crate opens a socket and nothing else
//!
//! When to announce, how often, and on which interfaces is `windows-daemon`'s.
//! What is here is the send, the receive, and the group to join.
//!
//! The interfaces are **taken, never inferred**. Leaving them out is refused
//! rather than defaulted: see [`name_an_interface`] for why both available
//! defaults are wrong, one of them dangerously.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use roster::id::NetworkId;
use tokio::net::UdpSocket;

use crate::announce::{self, Announcement};
use crate::error::{Error, Result};
use crate::limits;

/// The multicast group announcements are sent to.
///
/// In the administratively scoped block reserved for local use, so it is not
/// forwarded beyond the local network by any correctly configured router — which
/// is the whole intent, since an announcement is only meaningful to something on
/// the same network.
pub const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 61, 41);

/// The port announcements are sent to.
///
/// Deliberately not 5353: mDNS owns that, and a responder already running would
/// answer for us. §8 says to avoid exactly that collision.
pub const PORT: u16 = 41641;

/// The address announcements are sent to.
#[must_use]
pub fn destination() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(GROUP, PORT))
}

/// A socket that announces and listens.
#[derive(Debug)]
pub struct Multicast {
    /// The sockets. One for a listener, joined to the group on every interface
    /// it was given; one **per interface** for a sender, because a socket has
    /// exactly one outgoing multicast interface and a device on a wired and a
    /// wireless network is on two local networks at once.
    sockets: Vec<UdpSocket>,
    /// The network whose announcements this will open.
    network: NetworkId,
}

/// The refusal when a caller names no interface.
///
/// Not an oversight to paper over with a good default. Leaving the choice to the
/// host means the routing table picks by interface metric, and a device running
/// this system acquires a tunnel adapter that can rank first — so announcements
/// leave through the tunnel, where no peer is listening, and local discovery
/// fails on exactly the network it exists to serve.
///
/// Defaulting to *every* interface would fail the other way, and worse: the
/// payload is confidential without the network id but its existence is not, so a
/// packet on a fixed group and port announces that a device of this system is
/// here — on the guest VLAN and the hotel Wi-Fi too. Which networks a person is
/// on is the daemon's to know. Refusing fails closed.
fn name_an_interface(what: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "{what} needs the interfaces to use: naming none would leave the choice to the \
             routing table, and defaulting to all of them would announce this device on every \
             network it is attached to"
        ),
    )
}

impl Multicast {
    /// Binds and joins the group on each interface given.
    ///
    /// `interfaces` are local addresses, one per local network to listen on.
    /// Choosing them is the daemon's job; this takes the answer. An empty list is
    /// refused — see [`name_an_interface`].
    ///
    /// A join that fails on one interface does not fail the rest: an adapter that
    /// cannot carry multicast should not cost a device the networks that can.
    /// Failing every one of them is refused, because then nothing is listening.
    pub async fn join(interfaces: &[Ipv4Addr], network: NetworkId) -> std::io::Result<Self> {
        if interfaces.is_empty() {
            return Err(name_an_interface("listening"));
        }

        // `SO_REUSEADDR` before binding, so several listeners can join one
        // group and port on a host. That is not a test convenience: two nodes
        // side by side on one machine must both hear announcements, and without
        // it the second to start simply fails to bind.
        let raw = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        raw.set_reuse_address(true)?;
        raw.set_nonblocking(true)?;
        // Bound on every address, so an announcement arrives whichever
        // interface carried it.
        raw.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT)).into())?;

        let socket = UdpSocket::from_std(std::net::UdpSocket::from(raw))?;

        let mut joined = 0usize;
        let mut refusal = None;
        for interface in interfaces {
            match socket.join_multicast_v4(GROUP, *interface) {
                Ok(()) => joined = joined.saturating_add(1),
                Err(cause) => refusal = Some(cause),
            }
        }
        if joined == 0 {
            return Err(refusal.unwrap_or_else(|| name_an_interface("listening")));
        }

        // On, so two nodes on one host — and every test in this crate — can hear
        // each other.
        socket.set_multicast_loop_v4(true)?;
        Ok(Self { sockets: vec![socket], network })
    }

    /// Binds a sender per interface, each with its outgoing interface named.
    ///
    /// **Naming it is the point.** A socket that does not sends where the routing
    /// table says, which is chosen by interface metric for reasons that have
    /// nothing to do with local discovery.
    pub async fn sender(interfaces: &[Ipv4Addr], network: NetworkId) -> std::io::Result<Self> {
        if interfaces.is_empty() {
            return Err(name_an_interface("announcing"));
        }

        let mut sockets = Vec::with_capacity(interfaces.len());
        for interface in interfaces {
            let raw = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            raw.set_nonblocking(true)?;
            raw.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).into())?;
            // The one line this whole defect was missing.
            raw.set_multicast_if_v4(interface)?;
            raw.set_multicast_loop_v4(true)?;
            sockets.push(UdpSocket::from_std(std::net::UdpSocket::from(raw))?);
        }
        Ok(Self { sockets, network })
    }

    /// The address the first socket is bound to.
    ///
    /// # Errors
    ///
    /// When the socket cannot say.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.one()?.local_addr()
    }

    /// The single socket a listener has.
    fn one(&self) -> std::io::Result<&UdpSocket> {
        self.sockets.first().ok_or_else(|| name_an_interface("this socket"))
    }

    /// Seals and sends one announcement, on every interface this was built with.
    ///
    /// Callers send on an interval rather than once; see the module
    /// documentation for why that is the design and not a retry.
    ///
    /// One interface failing does not fail the announcement: the others carried
    /// it, and a device on two networks should still be found on the one that
    /// works. Every interface failing is reported, with what the last of them
    /// said — it means this device is announcing to nobody.
    pub async fn announce(&self, announcement: &Announcement) -> Result<()> {
        let packet = announce::seal(announcement, &self.network)?;

        let mut carried = false;
        let mut refusal = None;
        for socket in &self.sockets {
            match socket.send_to(&packet, destination()).await {
                Ok(_) => carried = true,
                Err(cause) => refusal = Some(cause.kind()),
            }
        }

        if carried {
            return Ok(());
        }
        Err(Error::NotCarried { kind: refusal.unwrap_or(std::io::ErrorKind::NotConnected) })
    }

    /// Waits for the next packet and opens it.
    ///
    /// Returns the announcement and where it came from. Most of what arrives on
    /// a shared port is not ours; those come back as
    /// [`Error::NotForThisNetwork`], which a caller should treat as the
    /// background it is rather than as a fault.
    pub async fn receive(&self) -> Result<(Announcement, SocketAddr)> {
        let mut buffer = [0u8; limits::MAX_PACKET_SIZE];
        let socket = self.one().map_err(|cause| Error::NotCarried { kind: cause.kind() })?;
        let (len, from) = socket
            .recv_from(&mut buffer)
            .await
            .map_err(|cause| Error::NotCarried { kind: cause.kind() })?;

        let packet = buffer.get(..len).ok_or(Error::NotAnAnnouncement)?;
        let announcement = announce::open(packet, &self.network)?;
        Ok((announcement, from))
    }
}

#[cfg(test)]
mod tests {
    /// Naming no interface is refused, in both directions.
    ///
    /// Not defaulted to "the host decides", which sends announcements out
    /// whichever adapter ranks first by metric — the tunnel this system creates,
    /// on the machine where this was found. Not defaulted to "all of them"
    /// either: the payload is confidential without the network id but its
    /// existence is not, so that would announce this device on every network it
    /// is attached to, guest Wi-Fi included.
    #[tokio::test]
    async fn naming_no_interface_is_refused() {
        let network = NetworkId::from_bytes([7; 32]);

        let listening = Multicast::join(&[], network).await;
        let announcing = Multicast::sender(&[], network).await;

        for outcome in [listening, announcing] {
            let refusal = outcome.expect_err("naming no interface must be refused");
            assert_eq!(refusal.kind(), std::io::ErrorKind::InvalidInput);
            assert!(
                refusal.to_string().contains("routing table"),
                "and it must say why, since a caller will be tempted to pass nothing: {refusal}"
            );
        }
    }

    /// A sender names its outgoing interface rather than inheriting one.
    ///
    /// The whole defect in one line: without this, the kernel picks by interface
    /// metric, and the adapter this system creates outranked the local network.
    #[test]
    fn the_sender_names_its_outgoing_interface() {
        let source = include_str!("multicast.rs");
        let sender = source
            .split_once("pub async fn sender")
            .map(|(_, rest)| rest.split("pub fn local_addr").next().unwrap_or(rest))
            .expect("the sender exists");
        assert!(
            sender.contains("set_multicast_if_v4"),
            "the sender must name its outgoing interface, not leave it to the routing table"
        );
    }

    /// One dead interface does not silence the ones that work.
    #[tokio::test]
    async fn an_announcement_goes_out_every_interface_it_was_given() {
        let network = NetworkId::from_bytes([9; 32]);
        let sender = Multicast::sender(&[Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST], network)
            .await
            .expect("binds one socket per interface");
        assert_eq!(sender.sockets.len(), 2, "one socket per interface, since each has one");
    }

    use super::*;

    /// mDNS owns 5353, and a responder already running would answer for us. §8
    /// says to avoid exactly that collision.
    #[test]
    fn the_port_is_not_mdns() {
        assert_ne!(PORT, 5353, "5353 belongs to mDNS");
        assert_eq!(PORT, 41641);
    }

    /// Administratively scoped, so a correctly configured router does not
    /// forward it off the local network — which is the entire intent.
    #[test]
    fn the_group_is_locally_scoped() {
        let [first, ..] = GROUP.octets();
        assert_eq!(first, 239, "239.0.0.0/8 is the administratively scoped block");
        assert_ne!(GROUP, Ipv4Addr::new(224, 0, 0, 251), "224.0.0.251 belongs to mDNS");
    }

    #[test]
    fn the_destination_is_the_group_and_port() {
        assert_eq!(destination(), SocketAddr::V4(SocketAddrV4::new(GROUP, PORT)));
    }
}

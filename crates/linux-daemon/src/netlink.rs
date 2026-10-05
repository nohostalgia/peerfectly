//! Addresses, routes and the link, through netlink.
//!
//! One request, one acknowledgement, on a socket opened for that request and
//! closed after it. Nothing here is long-lived, so there is nothing to reconnect
//! and nothing shared between networks. The calls block, and the machine runs
//! them off the async runtime's threads.
//!
//! What is asked for is [`daemon`]'s: which addresses, which routes, in which
//! order. This module turns each into the message the kernel reads, and the
//! kernel's refusal into an error that names what was being done and the errno.
//!
//! # `IFA_F_NODAD`
//!
//! An IPv6 address added without it is *tentative* for about a second while the
//! kernel checks nobody else holds it, and a socket cannot bind it meanwhile — so
//! the resolver would fail to start with `EADDRNOTAVAIL`, the symptom Windows
//! retries around. On a point-to-point tunnel there is nobody to collide with,
//! and the address is the network's to give.

use std::io;
use std::net::IpAddr;

use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, NLM_F_REQUEST, NetlinkHeader,
    NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::address::{AddressAttribute, AddressFlags, AddressMessage};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::{Socket, SocketAddr};

use daemon::routes::{Destination, Route};

/// The index the kernel gave an interface, read from sysfs.
///
/// # Errors
///
/// When there is no such interface.
pub fn index_of(name: &str) -> io::Result<u32> {
    let path = format!("/sys/class/net/{name}/ifindex");
    let text = std::fs::read_to_string(&path)
        .map_err(|cause| io::Error::new(cause.kind(), format!("reading {path}: {cause}")))?;
    text.trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("{path} holds `{text}`")))
}

/// Brings the link up, with the MTU the daemon states.
///
/// # Errors
///
/// When the kernel refuses, naming the errno.
pub fn link_up(index: u32, mtu: u32) -> io::Result<()> {
    let mut link = LinkMessage::default();
    link.header.index = index;
    link.header.flags = LinkFlags::Up;
    link.header.change_mask = LinkFlags::Up;
    link.attributes.push(LinkAttribute::Mtu(mtu));
    ask(RouteNetlinkMessage::SetLink(link), 0)
        .map_err(|cause| named(cause, format!("bringing interface {index} up with MTU {mtu}")))
}

/// Gives the interface one of this device's addresses: IPv6 as a `/128`, with
/// no duplicate detection, or IPv4 as a `/32`.
///
/// # Errors
///
/// When the kernel refuses, naming the errno.
pub fn add_address(index: u32, address: IpAddr) -> io::Result<()> {
    // Replacing, not exclusive: the same address given twice is the same state,
    // and the reconciliation that moves IPv4 may ask again.
    ask(
        RouteNetlinkMessage::NewAddress(address_message(index, address)),
        NLM_F_CREATE | NLM_F_REPLACE,
    )
    .map_err(|cause| named(cause, format!("adding {address} to interface {index}")))
}

/// Takes an address back off the interface.
///
/// # Errors
///
/// When the kernel refuses, naming the errno.
pub fn remove_address(index: u32, address: IpAddr) -> io::Result<()> {
    ask(RouteNetlinkMessage::DelAddress(address_message(index, address)), 0)
        .map_err(|cause| named(cause, format!("removing {address} from interface {index}")))
}

/// Adds a route through its interface.
///
/// **Exclusive.** A route for the same destination that is already there is
/// somebody else's, or a leftover; replacing it would take it from them, so the
/// kernel's refusal is reported instead.
///
/// # Errors
///
/// When the kernel refuses, naming the errno.
pub fn add_route(route: &Route) -> io::Result<()> {
    ask(RouteNetlinkMessage::NewRoute(route_message(route)), NLM_F_CREATE | NLM_F_EXCL)
        .map_err(|cause| named(cause, format!("adding the route {route}")))
}

/// Removes a route — only through its own interface, so a route somebody else
/// has for the same destination is left alone.
///
/// # Errors
///
/// When the kernel refuses, naming the errno.
pub fn remove_route(route: &Route) -> io::Result<()> {
    ask(RouteNetlinkMessage::DelRoute(route_message(route)), 0)
        .map_err(|cause| named(cause, format!("removing the route {route}")))
}

/// The message for one of this device's addresses.
fn address_message(index: u32, address: IpAddr) -> AddressMessage {
    let mut message = AddressMessage::default();
    message.header.index = index;
    match address {
        IpAddr::V6(_) => {
            message.header.family = AddressFamily::Inet6;
            message.header.prefix_len = 128;
            message.attributes.push(AddressAttribute::Flags(AddressFlags::Nodad));
        }
        IpAddr::V4(_) => {
            message.header.family = AddressFamily::Inet;
            message.header.prefix_len = 32;
        }
    }
    message.attributes.push(AddressAttribute::Local(address));
    message.attributes.push(AddressAttribute::Address(address));
    message
}

/// The message for one route: its destination, through its interface, in the
/// main table.
fn route_message(route: &Route) -> RouteMessage {
    let mut message = RouteMessage::default();
    message.header.table = RouteHeader::RT_TABLE_MAIN;
    message.header.protocol = RouteProtocol::Static;
    // Reached directly through the interface, with no gateway: what `ip route
    // add ... dev` gives.
    message.header.scope = RouteScope::Link;
    message.header.kind = RouteType::Unicast;
    message.header.destination_prefix_length = route.prefix_length();
    match route.destination() {
        Destination::Prefix(_) => {
            message.header.address_family = AddressFamily::Inet6;
            message.attributes.push(RouteAttribute::Destination(RouteAddress::Inet6(
                std::net::Ipv6Addr::from(route.octets()),
            )));
        }
        Destination::Host(address) => {
            message.header.address_family = AddressFamily::Inet;
            message.attributes.push(RouteAttribute::Destination(RouteAddress::Inet(address)));
        }
    }
    message.attributes.push(RouteAttribute::Oif(route.interface().index()));
    message
}

/// Sends one request and waits for the kernel's acknowledgement.
fn ask(request: RouteNetlinkMessage, flags: u16) -> io::Result<()> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_ACK | flags;
    header.sequence_number = 1;
    let mut message = NetlinkMessage::new(header, NetlinkPayload::InnerMessage(request));
    message.finalize();
    let mut buffer = vec![0_u8; message.buffer_len()];
    message.serialize(&mut buffer);
    socket.send(&buffer, 0)?;

    loop {
        let (received, _) = socket.recv_from_full()?;
        let mut rest = received.as_slice();
        while !rest.is_empty() {
            let answer = NetlinkMessage::<RouteNetlinkMessage>::deserialize(rest)
                .map_err(|cause| io::Error::new(io::ErrorKind::InvalidData, cause.to_string()))?;
            match answer.payload {
                NetlinkPayload::Error(error) => {
                    return match error.code {
                        None => Ok(()),
                        Some(_) => Err(error.to_io()),
                    };
                }
                NetlinkPayload::Done(_) => return Ok(()),
                _ => {}
            }
            let length = usize::try_from(answer.header.length).unwrap_or(usize::MAX);
            if length == 0 {
                break;
            }
            rest = rest.get(length..).unwrap_or_default();
        }
    }
}

/// An error carrying what was being done, with the kernel's words kept.
fn named(cause: io::Error, doing: String) -> io::Error {
    io::Error::new(cause.kind(), format!("{doing}: {cause}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// **The IPv6 address is never tentative.** Without `IFA_F_NODAD` the
    /// resolver cannot bind for a second after every raise.
    #[test]
    fn the_ipv6_address_skips_duplicate_detection() {
        let message = address_message(7, "fd00::1".parse().unwrap());
        assert_eq!(128, message.header.prefix_len);
        assert!(
            message.attributes.contains(&AddressAttribute::Flags(AddressFlags::Nodad)),
            "{message:?}"
        );
        let ipv4 = address_message(7, "100.64.0.2".parse().unwrap());
        assert_eq!(32, ipv4.header.prefix_len);
    }

    /// A route names its interface, so removing it can only remove ours.
    #[test]
    fn a_route_names_its_interface() {
        let route = Route::host("100.64.0.9".parse().unwrap(), daemon::routes::Interface::new(12));
        let message = route_message(&route);
        assert!(message.attributes.contains(&RouteAttribute::Oif(12)));
        assert_eq!(32, message.header.destination_prefix_length);
        assert_eq!(RouteHeader::RT_TABLE_MAIN, message.header.table);
    }
}

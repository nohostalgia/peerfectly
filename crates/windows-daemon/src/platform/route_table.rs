//! Writing routes into the machine's routing table.
//!
//! **The only `unsafe` in this crate.** The IP Helper API has no safe wrapper,
//! and the alternative — running `netsh interface ipv6 add route` and reading
//! its console output — would mean parsing localized text to learn whether a
//! security-relevant operation succeeded, and spawning processes with
//! Administrator rights to do it. Three FFI calls are a much smaller thing to
//! review than that.
//!
//! This module decides nothing. Which routes should exist is [`daemon::routes`]'s
//! answer, computed from the signed network parameters and testable on any
//! machine; this only carries it out. If a rule about routing appears in this
//! file, it is in the wrong file.
//!
//! # What is not tested here
//!
//! Nothing below runs without Administrator on Windows, so no automated test
//! covers it. `VERIFICATION.md` records what was checked by hand and against
//! which build. Treat an untested branch here as untested, because it is.

#![allow(
    unsafe_code,
    reason = "the IP Helper API is a Win32 API with no safe wrapper; the unsafe surface is \
              confined to this module and is four calls wide"
)]

use core::mem;
use core::ptr;

use std::net::{IpAddr, Ipv4Addr};

use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
    DeleteUnicastIpAddressEntry, FreeMibTable, GetIpForwardTable2, GetIpInterfaceEntry,
    InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
    SetIpInterfaceEntry,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, IpDadStatePreferred};

use daemon::error::{Error, Residue, Result, Step};
use daemon::routes::{Destination, Interface, Route};
use tunnel::Prefix;

/// Windows says a call worked by returning this.
const NO_ERROR: u32 = 0;

/// Builds the row describing a route.
///
/// Zeroed and then filled through `InitializeIpForwardEntry`, which is how the
/// API asks to be used: the structure has fields whose defaults matter and which
/// are not documented as zero.
fn row_for(route: &Route) -> MIB_IPFORWARD_ROW2 {
    // SAFETY: `MIB_IPFORWARD_ROW2` is a plain-old-data structure of integers and
    // unions of integers, for which an all-zero bit pattern is valid, and
    // `InitializeIpForwardEntry` is the documented way to prepare one.
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { mem::zeroed() };
    // SAFETY: `row` is a valid, writable, correctly aligned allocation of
    // exactly this type, which is the function's whole requirement.
    unsafe { InitializeIpForwardEntry(&raw mut row) };

    row.InterfaceIndex = route.interface().index();
    row.DestinationPrefix.PrefixLength = route.prefix_length();
    match route.destination() {
        Destination::Prefix(_) => {
            row.DestinationPrefix.Prefix.si_family = AF_INET6;
            row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
            row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte = route.octets();
            // An on-link route: the next hop stays zeroed, which is how the API
            // spells "delivered directly on this interface" rather than "via a
            // gateway".
            row.NextHop.si_family = AF_INET6;
            row.NextHop.Ipv6.sin6_family = AF_INET6;
        }
        Destination::Host(address) => {
            // A `/32` for one peer, on-link the same way.
            row.DestinationPrefix.Prefix.si_family = AF_INET;
            row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
            row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = in_addr(address);
            row.NextHop.si_family = AF_INET;
            row.NextHop.Ipv4.sin_family = AF_INET;
        }
    }
    row
}

/// An IPv4 address as the API holds it: the four octets in network order, read
/// as a native integer.
fn in_addr(address: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(address.octets())
}

/// Reads a row back into the crate's own type, if it is one we could have made.
///
/// A row this daemon could have written is an IPv6 prefix of whole bytes or an
/// IPv4 `/32`. Anything else is not this daemon's.
fn route_from(row: &MIB_IPFORWARD_ROW2) -> Option<Route> {
    // SAFETY: reading `si_family` from the union is what the API defines as the
    // way to learn which arm is populated; every arm begins with it.
    let family = unsafe { row.DestinationPrefix.Prefix.si_family };
    if family == AF_INET {
        if row.DestinationPrefix.PrefixLength != 32 {
            // Never a range: this daemon writes one address per peer, and a
            // wider IPv4 route cannot have come from here.
            return None;
        }
        // SAFETY: `si_family` said IPv4, so the `Ipv4` arm is the populated one.
        let raw = unsafe { row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr };
        return Some(Route::host(
            Ipv4Addr::from(raw.to_ne_bytes()),
            Interface::new(row.InterfaceIndex),
        ));
    }
    if family != AF_INET6 {
        return None;
    }
    // SAFETY: `si_family` said IPv6, so the `Ipv6` arm is the populated one.
    let octets = unsafe { row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte };
    let bits = usize::from(row.DestinationPrefix.PrefixLength);
    let bytes = bits.checked_div(8)?;
    if bits.checked_rem(8) != Some(0) {
        // The overlay's prefixes are whole bytes. One that is not did not come
        // from this daemon, and guessing at it would risk removing it.
        return None;
    }

    let prefix = Prefix::from_parameter(octets.get(..bytes)?).ok()?;
    Some(Route::new(prefix, Interface::new(row.InterfaceIndex)))
}

/// Adds a route.
///
/// # Errors
///
/// When Windows refuses, most often for want of Administrator.
pub fn install(route: &Route) -> Result<()> {
    let row = row_for(route);
    // SAFETY: `row` is a fully initialised value of the expected type, and the
    // call borrows it for its duration only.
    let status = unsafe { CreateIpForwardEntry2(&raw const row) };

    if status == NO_ERROR {
        Ok(())
    } else {
        Err(Error::BringUp {
            step: Step::InstallingRoutes,
            cause: format!("the routing table refused {route}: error {status}"),
            left: Vec::new(),
        })
    }
}

/// Removes a route.
///
/// # Errors
///
/// When Windows refuses. A route that is already gone is not an error: the
/// caller wanted it absent and it is.
pub fn remove(route: &Route) -> Result<()> {
    let row = row_for(route);
    // SAFETY: as `install`.
    let status = unsafe { DeleteIpForwardEntry2(&raw const row) };

    // ERROR_NOT_FOUND. Removing a route that is not there is the outcome asked
    // for, and treating it as a failure would make cleanup fail on the path
    // where cleanup matters most — the one that runs twice.
    const NOT_FOUND: u32 = 1_168;

    if status == NO_ERROR || status == NOT_FOUND {
        Ok(())
    } else {
        Err(Error::BringUp {
            step: Step::InstallingRoutes,
            cause: format!("the routing table would not drop {route}: error {status}"),
            left: vec![Residue::Route { prefix: route.prefix_text() }],
        })
    }
}

/// Every route of either family currently in the table that this crate could
/// have written.
///
/// Used to work out what is actually present before removing anything, so the
/// daemon removes its own footprint rather than everything that looks like it.
///
/// # Errors
///
/// When the table cannot be read.
pub fn present() -> Result<Vec<Route>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    // SAFETY: `table` is a valid pointer to a pointer, which the call fills in
    // on success and leaves alone otherwise.
    let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &raw mut table) };

    if status != NO_ERROR {
        return Err(Error::BringUp {
            step: Step::InstallingRoutes,
            cause: format!("the routing table could not be read: error {status}"),
            left: Vec::new(),
        });
    }
    if table.is_null() {
        return Ok(Vec::new());
    }

    let mut found = Vec::new();
    // SAFETY: the call succeeded and returned a non-null table, so `NumEntries`
    // rows follow `Table` contiguously. Both reads stay inside that run.
    unsafe {
        let count = (*table).NumEntries;
        let first = (&raw const (*table).Table).cast::<MIB_IPFORWARD_ROW2>();
        for index in 0..count {
            let row = &*first.offset(isize::try_from(index).unwrap_or(0));
            if let Some(route) = route_from(row) {
                found.push(route);
            }
        }
        FreeMibTable(table.cast());
    }
    Ok(found)
}

/// The IPv4 interface metric a peerfectly adapter carries.
///
/// Windows gives every adapter holding an IPv4 address its own multicast
/// (`224.0.0.0/4`) and broadcast (`255.255.255.255`) routes, weighted by the
/// adapter's metric. Left automatic, a tunnel adapter's metric is lower than a
/// Wi-Fi card's — found on a real machine, 261 against 291 — so an application
/// sending mDNS, SSDP or a broadcast without naming an interface would send it
/// into the tunnel, where it is refused, and stop seeing the local network while
/// a peerfectly network is on.
///
/// Well above any physical adapter's, so those routes lose to the machine's own
/// networks. The peers' host routes are unaffected: a `/32` wins on its length
/// before any metric is compared.
pub const IPV4_INTERFACE_METRIC: u32 = 9_000;

/// Weighs the adapter's IPv4 interface so its automatic multicast and broadcast
/// routes never win over the machine's own networks. See
/// [`IPV4_INTERFACE_METRIC`].
///
/// Done when the adapter is created, not only when it gets an IPv4 address. An
/// adapter whose device holds none here — withheld, or colliding — is given a
/// `169.254.0.0/16` address by Windows, and at the automatic metric that brought
/// back, on a real machine, the routes the metric exists to demote. Turning the
/// link-local address off in the same call was refused (error 87), so it stays,
/// weighed like the rest: its routes lose to every physical adapter's.
///
/// # Errors
///
/// When Windows refuses to read or write the interface, with its error code.
pub fn weigh_ipv4_interface(interface: Interface) -> Result<()> {
    // SAFETY: a plain-old-data structure of integers and unions of integers, for
    // which an all-zero bit pattern is valid, prepared by the documented call.
    let mut row: MIB_IPINTERFACE_ROW = unsafe { mem::zeroed() };
    // SAFETY: `row` is a valid, writable, correctly aligned allocation of the
    // expected type.
    unsafe { InitializeIpInterfaceEntry(&raw mut row) };
    row.Family = AF_INET;
    row.InterfaceIndex = interface.index();

    // SAFETY: `row` names the interface by family and index, which is all the
    // call reads; it fills in the rest.
    let status = unsafe { GetIpInterfaceEntry(&raw mut row) };
    if status != NO_ERROR {
        return Err(Error::BringUp {
            step: Step::CreatingAdapter,
            cause: format!("the adapter's IPv4 interface could not be read: error {status}"),
            left: Vec::new(),
        });
    }

    row.UseAutomaticMetric = false;
    row.Metric = IPV4_INTERFACE_METRIC;
    // The call refuses an IPv4 row that carries a site prefix length.
    row.SitePrefixLength = 0;
    // SAFETY: as above; the row is the one the system just returned, changed in
    // fields documented as writable here.
    let status = unsafe { SetIpInterfaceEntry(&raw mut row) };
    if status == NO_ERROR {
        Ok(())
    } else {
        Err(Error::BringUp {
            step: Step::CreatingAdapter,
            cause: format!("the adapter's IPv4 interface could not be weighed: error {status}"),
            left: Vec::new(),
        })
    }
}

/// Gives the adapter one of this device's own overlay addresses.
///
/// Without it the address exists only in the roster: Windows does not recognise
/// it as local, so a packet the machine sends to itself is routed *into* the
/// tunnel and dropped for want of a session, and the resolver cannot bind to it
/// at all. Both were true of the first version, and both looked like the network
/// simply not working.
///
/// Assigned as a `/128`, which is what §2.5 says a device holds, or as a `/32`
/// for IPv4. The prefix's own route and each peer's host route are installed
/// separately, so reaching peers does not depend on the address's on-link
/// length.
///
/// # Errors
///
/// When Windows refuses, most often for want of Administrator.
pub fn assign_address(interface: Interface, address: IpAddr) -> Result<()> {
    let row = address_row(interface, address);
    // SAFETY: `row` is a fully initialised value of the expected type, borrowed
    // for the duration of the call only.
    let status = unsafe { CreateUnicastIpAddressEntry(&raw const row) };

    // ERROR_OBJECT_ALREADY_EXISTS. Asking for an address the adapter already has
    // is the outcome wanted, and failing here would make a retry after a partial
    // bring-up impossible.
    const ALREADY: u32 = 5_010;

    if status == NO_ERROR || status == ALREADY {
        Ok(())
    } else {
        Err(Error::BringUp {
            step: Step::CreatingAdapter,
            cause: format!("the adapter would not take the address {address}: error {status}"),
            left: Vec::new(),
        })
    }
}

/// Takes the address back off the adapter.
///
/// # Errors
///
/// When Windows refuses to remove an address that is present.
pub fn remove_address(interface: Interface, address: IpAddr) -> Result<()> {
    let row = address_row(interface, address);
    // SAFETY: as `assign_address`.
    let status = unsafe { DeleteUnicastIpAddressEntry(&raw const row) };

    // ERROR_NOT_FOUND, and ERROR_FILE_NOT_FOUND when the adapter has already
    // gone. Either way the address is absent, which is what was asked for.
    const NOT_FOUND: u32 = 1_168;
    const NO_SUCH_FILE: u32 = 2;

    if status == NO_ERROR || status == NOT_FOUND || status == NO_SUCH_FILE {
        Ok(())
    } else {
        Err(Error::BringUp {
            step: Step::CreatingAdapter,
            cause: format!("the adapter would not drop the address {address}: error {status}"),
            left: Vec::new(),
        })
    }
}

/// Builds the row describing an address on an interface.
fn address_row(interface: Interface, address: IpAddr) -> MIB_UNICASTIPADDRESS_ROW {
    // SAFETY: a plain-old-data structure of integers and unions of integers, for
    // which an all-zero bit pattern is valid, prepared by the documented call.
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { mem::zeroed() };
    // SAFETY: `row` is a valid, writable, correctly aligned allocation of the
    // expected type.
    unsafe { InitializeUnicastIpAddressEntry(&raw mut row) };

    row.InterfaceIndex = interface.index();
    match address {
        IpAddr::V6(address) => {
            row.Address.si_family = AF_INET6;
            row.Address.Ipv6.sin6_family = AF_INET6;
            row.Address.Ipv6.sin6_addr.u.Byte = address.octets();
            // A /128: this device holds one address, not the network's range.
            // The route for the prefix is installed separately.
            row.OnLinkPrefixLength = 128;
        }
        IpAddr::V4(address) => {
            row.Address.si_family = AF_INET;
            row.Address.Ipv4.sin_family = AF_INET;
            row.Address.Ipv4.sin_addr.S_un.S_addr = in_addr(address);
            // A /32, never the range: an on-link range would route every address
            // in it into the tunnel, including hosts on the machine's own
            // networks that happen to fall inside.
            row.OnLinkPrefixLength = 32;
        }
    }

    // Skip duplicate address detection.
    //
    // A new IPv6 address is Tentative until DAD finishes, and a tentative address
    // cannot be bound to: the resolver got WSAEADDRNOTAVAIL trying, which reads as
    // "the address is not valid in its context" and looks like the address was
    // never assigned at all.
    //
    // DAD asks whether anyone else on the link already holds this address. On a
    // point-to-point tunnel adapter there is no one else on the link, and the
    // address is derived from a key nobody else holds, so the question has no
    // meaning here. WireGuard's Windows client does the same, for the same reason.
    row.DadState = IpDadStatePreferred;
    row
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    fn route() -> Route {
        Route::new(
            Prefix::from_parameter(&[0xfd, 0x00, 0x11, 0x22, 0x00, 0x00, 0x00, 0x00])
                .expect("valid"),
            Interface::new(7),
        )
    }

    /// Building the row is pure and can be checked without touching the table.
    /// Actually installing it cannot — see `VERIFICATION.md`.
    #[test]
    fn the_row_carries_the_prefix_and_the_interface() {
        let route = route();
        let row = row_for(&route);

        assert_eq!(row.InterfaceIndex, 7);
        assert_eq!(row.DestinationPrefix.PrefixLength, 64);
        // SAFETY: the row was built for IPv6 by `row_for`.
        unsafe {
            assert_eq!(row.DestinationPrefix.Prefix.si_family, AF_INET6);
            assert_eq!(row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte, route.octets());
        }
    }

    /// The next hop stays zero: this is an on-link route, not one via a gateway.
    #[test]
    fn the_route_is_on_link() {
        let row = row_for(&route());
        // SAFETY: the row was built for IPv6 by `row_for`, so the `Ipv6` arm is
        // the populated one.
        unsafe {
            assert_eq!(row.NextHop.Ipv6.sin6_addr.u.Byte, [0u8; 16], "no gateway");
        }
    }

    #[test]
    fn a_row_round_trips_through_the_crates_own_type() {
        let route = route();
        assert_eq!(route_from(&row_for(&route)), Some(route));
    }

    /// A row this daemon could not have written is left alone rather than
    /// guessed at — removing somebody else's route is worse than missing ours.
    #[test]
    fn a_row_that_is_not_ours_is_not_claimed() {
        let mut row = row_for(&route());
        row.DestinationPrefix.PrefixLength = 33;
        assert_eq!(route_from(&row), None, "a partial-byte prefix is not one of ours");

        // Writing a union field needs no `unsafe`; only reading one can observe
        // an arm that was never written.
        row.DestinationPrefix.Prefix.si_family = 24; // neither AF_INET (2) nor AF_INET6 (23)
        assert_eq!(route_from(&row), None, "a route of another family is not ours");
    }

    fn host() -> Route {
        Route::host(Ipv4Addr::new(100, 64, 3, 4), Interface::new(7))
    }

    /// An IPv4 host route is a `/32` for the peer's address, on-link.
    #[test]
    fn an_ipv4_row_carries_the_address_as_a_host_route() {
        let row = row_for(&host());

        assert_eq!(row.InterfaceIndex, 7);
        assert_eq!(row.DestinationPrefix.PrefixLength, 32, "one address, not a range");
        // SAFETY: the row was built for IPv4 by `row_for`.
        unsafe {
            assert_eq!(row.DestinationPrefix.Prefix.si_family, AF_INET);
            assert_eq!(
                row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_un_b.s_b1, 100,
                "the first octet first: network order"
            );
            assert_eq!(row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_un_b.s_b4, 4);
            assert_eq!(row.NextHop.si_family, AF_INET);
            assert_eq!(row.NextHop.Ipv4.sin_addr.S_un.S_addr, 0, "no gateway");
        }
    }

    #[test]
    fn an_ipv4_row_round_trips_through_the_crates_own_type() {
        assert_eq!(route_from(&row_for(&host())), Some(host()));
    }

    /// An IPv4 route wider than one address is not this daemon's: it writes a
    /// `/32` per peer and never a range.
    #[test]
    fn an_ipv4_range_row_is_not_claimed() {
        let mut row = row_for(&host());
        row.DestinationPrefix.PrefixLength = 10;
        assert_eq!(route_from(&row), None);
        row.DestinationPrefix.PrefixLength = 0;
        assert_eq!(route_from(&row), None, "and never an IPv4 default route");
    }

    /// The metric has to beat any physical adapter's, or the tunnel's automatic
    /// multicast and broadcast routes win over the local network's. The one
    /// observed on a Wi-Fi card was 291, and Hyper-V's switch 5256.
    #[test]
    fn the_ipv4_metric_loses_to_every_ordinary_adapter() {
        const { assert!(IPV4_INTERFACE_METRIC > 5_256) };
    }

    /// An IPv4 address is assigned as a `/32`, and an IPv6 one as a `/128`.
    #[test]
    fn addresses_are_assigned_as_single_hosts() {
        let v4 = address_row(Interface::new(7), IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)));
        assert_eq!(v4.OnLinkPrefixLength, 32);
        // SAFETY: built for IPv4 by `address_row`.
        unsafe {
            assert_eq!(v4.Address.si_family, AF_INET);
            assert_eq!(v4.Address.Ipv4.sin_addr.S_un.S_un_b.s_b4, 9);
        }

        let v6 = address_row(Interface::new(7), IpAddr::V6("fd00::1".parse().expect("valid")));
        assert_eq!(v6.OnLinkPrefixLength, 128);
    }

    /// The default route, if it ever appeared in the table, is not something
    /// this crate can produce — and reading one back must not turn into one.
    #[test]
    fn a_default_route_is_never_reconstructed_as_ours() {
        let mut row = row_for(&route());
        row.DestinationPrefix.PrefixLength = 0;
        assert_eq!(route_from(&row), None, "a zero-length prefix is refused, not adopted");
    }
}

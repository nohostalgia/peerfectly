//! What the kernel does with the calls this crate makes.
//!
//! Every test here needs `CAP_NET_ADMIN` and `/dev/net/tun`, so each is
//! `#[ignore]`d and runs in the testbed:
//!
//! ```text
//! cargo test -p linux-daemon -- --ignored
//! ```
//!
//! The kernel's own view is read back with `ip -j`, which is the tool a person
//! would use to check, rather than through the code under test.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    reason = "a test reports failure by panicking, and builds packets by hand"
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::Arc;

use daemon::machine::Machine as _;
use daemon::routes::{Interface, Route};
use linux_daemon::firewall::Nftables;
use linux_daemon::machine::Linux;

/// A machine whose firewall record is in a directory of its own.
fn machine() -> (tempfile::TempDir, Linux) {
    let state = tempfile::tempdir().unwrap();
    let machine = Linux::new(Nftables::under(state.path()));
    (state, machine)
}
use linux_daemon::{ifname, netlink};

/// What `ip -j` says, as JSON.
fn ip(arguments: &[&str]) -> serde_json::Value {
    let output = Command::new("ip").arg("-j").args(arguments).output().unwrap();
    assert!(
        output.status.success(),
        "ip {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Array(Vec::new()))
}

/// The addresses on an interface, with their flags.
fn addresses(name: &str) -> Vec<serde_json::Value> {
    ip(&["addr", "show", "dev", name])
        .as_array()
        .and_then(|links| links.first())
        .and_then(|link| link.get("addr_info"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// The routes through an interface, as `dst` strings.
fn routes(name: &str, family: &str) -> Vec<String> {
    ip(&[family, "route", "show", "dev", name])
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|route| route.get("dst").and_then(serde_json::Value::as_str).map(str::to_owned))
        .collect()
}

fn prefix() -> tunnel::Prefix {
    tunnel::Prefix::from_parameter(&[0xfd, 0x6d, 0x79, 0x6e, 0x65, 0x74, 0x00, 0x01]).unwrap()
}

/// **Exactly the planned state**, in the order the portable lifecycle asks for
/// it, and nothing after the interface goes.
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN and /dev/net/tun: run in the testbed"]
async fn a_network_comes_up_as_planned_and_leaves_nothing() {
    let (_state, machine) = machine();
    let guid = [0x11; 16];
    let name = ifname::from_guid(&guid);
    let own: Ipv6Addr = "fd6d:796e:6574:1::1".parse().unwrap();
    let own_ipv4 = Ipv4Addr::new(100, 64, 0, 2);
    let peer_ipv4 = Ipv4Addr::new(100, 64, 0, 3);

    let (interface, _device) = machine.create_adapter("peerfectly casa", guid).await.unwrap();
    machine.assign_address(interface, IpAddr::V6(own)).await.unwrap();
    machine.assign_address(interface, IpAddr::V4(own_ipv4)).await.unwrap();
    machine.install_route(&Route::new(prefix(), interface)).await.unwrap();
    machine.install_route(&Route::host(peer_ipv4, interface)).await.unwrap();

    let link = ip(&["link", "show", "dev", &name]);
    let link = link.as_array().unwrap().first().unwrap();
    assert_eq!(Some(1280), link.get("mtu").and_then(serde_json::Value::as_u64), "{link}");
    assert!(
        link.get("flags").unwrap().as_array().unwrap().iter().any(|flag| flag == "UP"),
        "{link}"
    );

    let held = addresses(&name);
    let ipv6 = held.iter().find(|address| address["local"] == own.to_string()).expect("the /128");
    assert_eq!(128, ipv6["prefixlen"]);
    assert!(ipv6.get("tentative").is_none(), "never tentative: {ipv6}");
    assert!(
        held.iter()
            .any(|address| address["local"] == own_ipv4.to_string() && address["prefixlen"] == 32)
    );

    assert!(
        routes(&name, "-6").iter().any(|route| route == "fd6d:796e:6574:1::/64"),
        "{:?}",
        routes(&name, "-6")
    );
    assert_eq!(vec![peer_ipv4.to_string()], routes(&name, "-4"));
    assert!(!routes(&name, "-6").iter().any(|route| route == "default"), "never a default route");

    // Reconciliation moves IPv4: the peer's host route and this device's
    // address both come out.
    machine.remove_route(&Route::host(peer_ipv4, interface)).await.unwrap();
    machine.remove_address(interface, IpAddr::V4(own_ipv4)).await.unwrap();
    assert!(routes(&name, "-4").is_empty());

    machine.remove_adapter(interface).await.unwrap();
    drop(_device);
    assert!(
        !std::path::Path::new(&format!("/sys/class/net/{name}")).exists(),
        "the interface is gone"
    );
    let everywhere = ip(&["-6", "route", "show"]);
    assert!(
        !everywhere.to_string().contains("fd6d:796e:6574:1::"),
        "and its routes with it: {everywhere}"
    );
}

/// A refusal names what was being done and the kernel's errno.
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN and /dev/net/tun: run in the testbed"]
async fn a_refused_route_names_the_errno() {
    let refused =
        netlink::add_route(&Route::host(Ipv4Addr::new(100, 64, 9, 9), Interface::new(999_999)));
    let said = refused.unwrap_err().to_string();
    assert!(said.contains("adding the route 100.64.9.9/32"), "{said}");
    assert!(said.contains("os error"), "the errno is kept: {said}");
}

/// A packet the kernel sends into the interface is taken, and one delivered to
/// it arrives: `ping` of an address routed into the interface, then an echo
/// reply written back.
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN and /dev/net/tun: run in the testbed"]
async fn packets_cross_in_both_directions() {
    let (_state, machine) = machine();
    let (interface, device) =
        machine.create_adapter("peerfectly packets", [0x22; 16]).await.unwrap();
    let own = Ipv4Addr::new(100, 64, 1, 2);
    let peer = Ipv4Addr::new(100, 64, 1, 3);
    machine.assign_address(interface, IpAddr::V4(own)).await.unwrap();
    machine.install_route(&Route::host(peer, interface)).await.unwrap();

    let pinging = std::thread::spawn(move || {
        Command::new("ping").args(["-c", "1", "-W", "3", &peer.to_string()]).output().unwrap()
    });

    // The kernel speaks first on a new link — router solicitations, listener
    // reports — so what is taken is read until the echo request arrives.
    let taken = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            let packet = device.take().await.unwrap();
            if packet.first().is_some_and(|first| first >> 4 == 4) {
                return packet;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(Some(&1), taken.get(9), "ICMP");
    assert_eq!(peer.octets().as_slice(), taken.get(16..20).unwrap(), "to the peer");

    let reply = echo_reply(&taken);
    device.deliver(&reply).await.unwrap();
    let pinged = pinging.join().unwrap();
    assert!(
        pinged.status.success(),
        "the reply arrived: {}",
        String::from_utf8_lossy(&pinged.stdout)
    );

    machine.remove_adapter(interface).await.unwrap();
    drop(Arc::clone(&device));
}

/// The echo reply to an ICMP echo request: addresses swapped, type zero, both
/// checksums recomputed.
fn echo_reply(request: &[u8]) -> Vec<u8> {
    let mut reply = request.to_vec();
    let header = usize::from(reply[0] & 0x0f) * 4;
    let (source, destination) = (reply[12..16].to_vec(), reply[16..20].to_vec());
    reply[12..16].copy_from_slice(&destination);
    reply[16..20].copy_from_slice(&source);
    reply[10] = 0;
    reply[11] = 0;
    let sum = checksum(&reply[..header]);
    reply[10..12].copy_from_slice(&sum.to_be_bytes());
    reply[header] = 0;
    reply[header + 2] = 0;
    reply[header + 3] = 0;
    let sum = checksum(&reply[header..]);
    reply[header + 2..header + 4].copy_from_slice(&sum.to_be_bytes());
    reply
}

/// The internet checksum.
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in bytes.chunks(2) {
        let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
        sum += u32::from(word);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

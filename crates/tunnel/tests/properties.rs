//! The rules over generated inputs, and the boundaries only reading the source
//! can hold to.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use roster::id::{DeviceId, NetworkId};
use roster::types::{IPV4_RANGE_BLOCKS, Ipv4Range};
use tunnel::{Inbound, Ipv4Holdings, Outbound, Prefix, Tunnel, address_of, ipv4_candidate};

/// The device the tunnel under test belongs to.
fn me() -> DeviceId {
    DeviceId::from_bytes([0xff; 32])
}

fn tunnel() -> Tunnel {
    Tunnel::new(
        Prefix::from_parameter(&[0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).expect("valid"),
        me(),
    )
}

/// An IPv6 header carrying the given addresses.
fn packet(source: Ipv6Addr, destination: Ipv6Addr) -> Vec<u8> {
    let mut out = vec![0u8; 40];
    if let Some(first) = out.first_mut() {
        *first = 0x60;
    }
    out.splice(8..24, source.octets().iter().copied());
    out.splice(24..40, destination.octets().iter().copied());
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The rule, stated over every pair of devices: a session may present its
    /// own address and no other.
    #[test]
    fn a_session_may_present_only_its_own_address(mine in any::<u8>(), theirs in any::<u8>()) {
        let tunnel = tunnel();
        let session = DeviceId::from_bytes([mine; 32]);
        let other = DeviceId::from_bytes([theirs; 32]);

        let claimed = tunnel.address_of(&other);
        // Addressed here, so the source is the only thing that can be at fault.
        let outcome = tunnel.inbound(session, &packet(claimed, tunnel.own_address()));

        if mine == theirs {
            prop_assert_eq!(outcome, Inbound::Accepted);
        } else {
            prop_assert!(
                !outcome.is_accepted(),
                "a session must never present another device's address"
            );
            prop_assert_eq!(outcome.session(), Some(session), "and the refusal names it");
        }
    }

    /// No source other than the session's own is ever accepted, whatever bytes
    /// it happens to be.
    #[test]
    fn no_foreign_source_is_ever_accepted(
        tag in any::<u8>(),
        source in proptest::array::uniform16(any::<u8>()),
    ) {
        let tunnel = tunnel();
        let session = DeviceId::from_bytes([tag; 32]);
        let claimed = Ipv6Addr::from(source);

        let outcome = tunnel.inbound(session, &packet(claimed, tunnel.own_address()));
        if outcome.is_accepted() {
            prop_assert_eq!(
                claimed,
                tunnel.address_of(&session),
                "only the session's own address may be accepted"
            );
        }
    }

    /// Derivation is deterministic, inside the prefix, and collision-free across
    /// distinct devices.
    #[test]
    fn derivation_is_deterministic_and_collision_free(tags in proptest::collection::hash_set(any::<u8>(), 1..40)) {
        let prefix = Prefix::from_parameter(&[0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).expect("valid");
        let mut seen: Vec<Ipv6Addr> = Vec::new();

        for tag in &tags {
            let device = DeviceId::from_bytes([*tag; 32]);
            let address = address_of(&device, &prefix);

            prop_assert_eq!(address, address_of(&device, &prefix), "deterministic");
            prop_assert!(prefix.contains(address), "inside the prefix");
            prop_assert!(!seen.contains(&address), "two devices must never share an address");
            seen.push(address);
        }
    }

    /// One device under two prefixes lands in two networks, and never strays
    /// into the other's range.
    #[test]
    fn a_device_never_strays_into_another_network(tag in any::<u8>(), a in any::<u8>(), b in any::<u8>()) {
        prop_assume!(a != b);
        let ours = Prefix::from_parameter(&[0xfd, a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).expect("valid");
        let theirs = Prefix::from_parameter(&[0xfd, b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).expect("valid");
        let device = DeviceId::from_bytes([tag; 32]);

        let here = address_of(&device, &ours);
        let there = address_of(&device, &theirs);

        prop_assert_ne!(here, there);
        prop_assert!(!theirs.contains(here));
        prop_assert!(!ours.contains(there));
    }

    /// §2.6's split routing: nothing addressed outside the prefix is ever
    /// carried.
    #[test]
    fn nothing_off_network_is_ever_carried(
        destination in proptest::array::uniform16(any::<u8>()),
    ) {
        let tunnel = tunnel();
        let target = Ipv6Addr::from(destination);
        let outcome = tunnel.outbound(&packet(Ipv6Addr::UNSPECIFIED, target));

        if outcome.is_carried() {
            prop_assert!(
                tunnel.prefix().contains(target),
                "only a destination on this network may be carried"
            );
        } else {
            prop_assert_eq!(
                outcome,
                Outbound::DestinationOffNetwork { destination: IpAddr::V6(target) }
            );
        }
    }

    /// Arbitrary bytes never become an accepted packet.
    #[test]
    fn arbitrary_bytes_are_never_accepted(
        bytes in proptest::collection::vec(any::<u8>(), 0..200),
        tag in any::<u8>(),
    ) {
        let tunnel = tunnel();
        let session = DeviceId::from_bytes([tag; 32]);
        let outcome = tunnel.inbound(session, &bytes);

        if outcome.is_accepted() {
            // Only if it happens to be a well-formed header carrying exactly
            // this session's address, which generated bytes will not be.
            prop_assert!(bytes.len() >= 40);
            let source: [u8; 16] = bytes.get(8..24).expect("checked").try_into().expect("16");
            prop_assert_eq!(Ipv6Addr::from(source), tunnel.address_of(&session));
            let destination: [u8; 16] = bytes.get(24..40).expect("checked").try_into().expect("16");
            prop_assert_eq!(Ipv6Addr::from(destination), tunnel.own_address());
        }
    }

    /// A packet shorter than a complete header is never parsed, whatever it
    /// contains. Reading a field out of an incomplete header is how a truncated
    /// packet becomes a plausible-looking lie.
    #[test]
    fn an_incomplete_header_is_never_parsed(
        bytes in proptest::collection::vec(any::<u8>(), 0..40),
        tag in any::<u8>(),
    ) {
        let tunnel = tunnel();
        let mut bytes = bytes;
        // An IPv4 header is complete at twenty bytes; below that every version
        // is incomplete, and below forty an IPv6 one still is.
        if bytes.len() >= 20
            && let Some(first) = bytes.first_mut()
        {
            *first = 0x60 | (*first & 0x0f);
        }
        let outcome = tunnel.inbound(DeviceId::from_bytes([tag; 32]), &bytes);
        prop_assert!(outcome.is_malformed(), "an incomplete header must be malformed, not judged");
        prop_assert!(!outcome.is_spoofed_source(), "and must not read as a lie");
    }

    /// The IPv4 half of the same property.
    #[test]
    fn an_incomplete_ipv4_header_is_never_parsed(
        bytes in proptest::collection::vec(any::<u8>(), 1..20),
        tag in any::<u8>(),
    ) {
        let session = DeviceId::from_bytes([tag; 32]);
        let tunnel = tunnel().with_holdings(Ipv4Holdings::from(
            &NetworkId::from_bytes([1; 32]),
            Ipv4Range::DEFAULT,
            &[session],
            &[],
        ));
        let mut bytes = bytes;
        if let Some(first) = bytes.first_mut() {
            *first = 0x40 | (*first & 0x0f);
        }
        let outcome = tunnel.inbound(session, &bytes);
        prop_assert!(outcome.is_malformed(), "{:?}", outcome);
    }

    /// A candidate lies inside its range and is never its first or last
    /// address, for every allowed prefix length.
    #[test]
    fn an_ipv4_candidate_is_inside_its_range_for_every_length(
        block in 0..IPV4_RANGE_BLOCKS.len(),
        extra in 0u8..=20,
        bits in any::<u32>(),
        device in any::<[u8; 32]>(),
        network in any::<[u8; 32]>(),
    ) {
        let (base, block_len) = IPV4_RANGE_BLOCKS.get(block).copied().unwrap();
        let prefix_len = block_len.saturating_add(extra).min(Ipv4Range::MAX_PREFIX_LEN);
        let mask_of = |len: u8| u32::MAX.checked_shl(32_u32.saturating_sub(u32::from(len))).unwrap();
        let mask = mask_of(prefix_len);
        let block_mask = mask_of(block_len);
        let address = (u32::from_be_bytes(base) & block_mask) | (bits & mask & !block_mask);
        let range = Ipv4Range::new(address.to_be_bytes(), prefix_len).expect("inside its block");

        let candidate = ipv4_candidate(
            &NetworkId::from_bytes(network),
            &DeviceId::from_bytes(device),
            &range,
        );
        let value = u32::from(candidate);
        let first = u32::from_be_bytes(range.address());
        let last = first | !mask;

        prop_assert!(range.contains(candidate.octets()), "{candidate} outside {range}");
        prop_assert!(value != first && value != last, "{candidate} is an edge of {range}");
        prop_assert_eq!(
            candidate,
            ipv4_candidate(&NetworkId::from_bytes(network), &DeviceId::from_bytes(device), &range)
        );
    }

    /// Nothing IPv4 is carried to an address no device holds.
    #[test]
    fn no_unheld_ipv4_destination_is_ever_carried(destination in any::<u32>(), tag in any::<u8>()) {
        let holder = DeviceId::from_bytes([tag; 32]);
        let holdings = Ipv4Holdings::from(
            &NetworkId::from_bytes([1; 32]),
            Ipv4Range::DEFAULT,
            &[holder],
            &[],
        );
        let tunnel = tunnel().with_holdings(holdings.clone());
        let destination = Ipv4Addr::from(destination);
        let mut packet = vec![0x45, 0, 0, 20];
        packet.resize(16, 0);
        packet.extend_from_slice(&destination.octets());

        if tunnel.outbound(&packet).is_carried() {
            prop_assert_eq!(holdings.holder(destination), Some(holder));
        }
    }

    /// The obligation the spec states last, and the one per-case tests cannot
    /// show: over any source, any destination and any session, **every accepted
    /// packet is addressed to an address this device holds**.
    ///
    /// The source is the session's own, so acceptance is **reachable**: a
    /// generated source never equals a derived address, and a property that
    /// cannot reach the branch it asserts on holds nothing. `honest` decides
    /// whether the destination is this device's or generated, so both sides of
    /// the rule are exercised.
    #[test]
    fn no_accepted_packet_is_addressed_elsewhere(
        tag in any::<u8>(),
        destination in proptest::array::uniform16(any::<u8>()),
        honest in any::<bool>(),
    ) {
        let tunnel = tunnel();
        let session = DeviceId::from_bytes([tag; 32]);
        let target =
            if honest { tunnel.own_address() } else { Ipv6Addr::from(destination) };

        let outcome = tunnel.inbound(session, &packet(tunnel.address_of(&session), target));

        if outcome.is_accepted() {
            prop_assert_eq!(target, tunnel.own_address(), "accepted, addressed elsewhere");
        } else {
            prop_assert!(outcome.is_misdirected(), "the only fault left is the destination");
            prop_assert_ne!(target, tunnel.own_address());
        }
    }

    /// The IPv4 half of the same obligation, over a tunnel that does hold an
    /// IPv4 address — the case where accepting something is possible at all.
    #[test]
    fn no_accepted_ipv4_packet_is_addressed_elsewhere(
        tag in any::<u8>(),
        destination in any::<u32>(),
        honest in any::<bool>(),
    ) {
        let session = DeviceId::from_bytes([tag; 32]);
        let tunnel = tunnel().with_holdings(Ipv4Holdings::from(
            &NetworkId::from_bytes([1; 32]),
            Ipv4Range::DEFAULT,
            &[me(), session],
            &[],
        ));
        let (Some(source), Some(mine)) = (tunnel.ipv4_of(&session), tunnel.own_ipv4()) else {
            // The generated device collides with this one and holds nothing;
            // that case is `a_device_holding_no_ipv4_accepts_no_ipv4_packet`.
            return Ok(());
        };
        let target = if honest { mine } else { Ipv4Addr::from(destination) };

        let mut bytes = vec![0x45, 0, 0, 20];
        bytes.resize(12, 0);
        bytes.extend_from_slice(&source.octets());
        bytes.extend_from_slice(&target.octets());

        let outcome = tunnel.inbound(session, &bytes);

        if outcome.is_accepted() {
            prop_assert_eq!(target, mine, "accepted, addressed elsewhere");
        } else {
            prop_assert!(outcome.is_misdirected(), "{:?}", outcome);
            prop_assert_ne!(target, mine);
        }
    }

    /// And the converse, so the rule is not vacuously satisfied by a tunnel that
    /// accepts nothing: an honest packet addressed here **is** accepted.
    #[test]
    fn an_honest_packet_addressed_here_is_accepted(tag in any::<u8>()) {
        let tunnel = tunnel();
        let session = DeviceId::from_bytes([tag; 32]);

        let outcome = tunnel.inbound(
            session,
            &packet(tunnel.address_of(&session), tunnel.own_address()),
        );

        prop_assert_eq!(outcome, Inbound::Accepted);
    }

    /// A derived prefix is always a usable ULA, whatever network it came from.
    #[test]
    fn a_derived_prefix_is_always_a_valid_ula(seed in any::<u8>()) {
        let derived = Prefix::derive_for(&NetworkId::from_bytes([seed; 32]));
        let parameter = derived.to_parameter();

        prop_assert_eq!(parameter.first().copied(), Some(0xfd), "locally assigned");
        prop_assert_eq!(
            Prefix::from_parameter(&parameter).expect("round trips"),
            derived
        );
    }
}

// ---------------------------------------------------------------------------
// Boundaries
// ---------------------------------------------------------------------------

/// The lines of a source file that are not comments.
fn code_of(source: &str) -> String {
    source
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The lines of a manifest that declare something, rather than explain it.
///
/// A comment naming this crate is not a dependency on it. The check below is a
/// text search, and a binding that explains *why* it keeps the overlay's
/// addresses away from its path selection has every reason to say the word.
fn declarations_of(manifest: &str) -> String {
    manifest.lines().map(str::trim).filter(|line| !line.starts_with('#')).collect::<Vec<_>>().join(
        "
",
    )
}

/// The dependency runs one way.
#[test]
fn the_dependency_direction_holds() {
    for (name, manifest) in [
        ("roster", include_str!("../../roster/Cargo.toml")),
        ("identity", include_str!("../../identity/Cargo.toml")),
        ("transport", include_str!("../../transport/Cargo.toml")),
        ("transport-iroh", include_str!("../../transport-iroh/Cargo.toml")),
        ("rendezvous", include_str!("../../rendezvous/Cargo.toml")),
        ("local-discovery", include_str!("../../local-discovery/Cargo.toml")),
    ] {
        assert!(
            !declarations_of(manifest).contains("tunnel"),
            "`{name}` must not depend on this crate"
        );
    }
}

/// No platform type anywhere, so the device can be replaced without touching
/// the rules.
#[test]
fn no_platform_type_appears() {
    for source in [
        include_str!("../src/device.rs"),
        include_str!("../src/address.rs"),
        include_str!("../src/outcome.rs"),
    ] {
        let code = code_of(source);
        for platform in ["wintun", "tun_tap", "/dev/net/tun", "VpnService", "windows_sys", "libc"] {
            assert!(!code.contains(platform), "`{platform}` ties this to one platform");
        }
    }
}

/// Validation consults nothing beyond the session. Anything more would put a
/// second authority in the path of every packet.
#[test]
fn validation_consults_nothing_beyond_the_session() {
    let code = code_of(include_str!("../src/device.rs"));

    for forbidden in ["RosterState", "is_member", "permitted", "allowed_devices", "cache", "Cache"]
    {
        assert!(
            !code.contains(forbidden),
            "`{forbidden}` would be a second authority in front of every packet"
        );
    }
    assert!(code.contains("session: DeviceId"), "the session's identity is the whole input");
}

/// §2.5's rule decides packets, never membership. The cheapest way to keep that
/// true is to have nothing that could express the other thing.
#[test]
fn nothing_here_can_express_membership() {
    for source in [include_str!("../src/device.rs"), include_str!("../src/outcome.rs")] {
        let code = code_of(source);
        for forbidden in ["Role", "is_admin", "authorize", "authorise", "revoked"] {
            assert!(!code.contains(forbidden), "`{forbidden}` is the roster's to decide");
        }
    }
}

/// The departure from §2.5's literal wording is recorded where a reader meets
/// it, so the VINCOLO reads as a decision rather than a contradiction.
#[test]
fn the_reading_of_section_2_5_is_recorded() {
    let address = include_str!("../src/address.rs");

    assert!(address.contains("§2.5"), "the source must name the constraint it reads");
    assert!(
        address.contains("device id") && address.contains("transport key"),
        "and say which was chosen over which"
    );
    assert!(
        address.contains("stability") || address.contains("stable"),
        "and why: an address that moves under a name is a broken name"
    );
    assert!(
        address.contains("identical"),
        "and that both are equal against the threat the rule exists for"
    );
}

/// What the rule is actually for, recorded where someone will find it. Read as
/// a defence against outsiders it looks redundant, and a redundant-looking rule
/// is one somebody eventually removes.
#[test]
fn what_the_rule_is_for_is_recorded() {
    let lib = include_str!("../src/lib.rs");
    assert!(
        lib.contains("member") && lib.contains("spoof"),
        "the crate must say the rule is aimed at a member spoofing another member"
    );
    assert!(
        lib.contains("already refuses") || lib.contains("already refuse"),
        "and that the transport already handles outsiders"
    );
}

/// The format document covers every requirement the specification adds.
#[test]
fn the_format_covers_every_requirement() {
    let format = include_str!("../FORMAT.md");
    for (requirement, marker) in [
        ("Every device has one derived address", "## 2. Addressing"),
        ("A packet's source must match its session", "## 4. Inbound packets"),
        ("A packet's destination must be this device", "### The destination half"),
        ("Only the network's prefix leaves through the tunnel", "## 6. Claimed prefixes"),
        ("This layer decides nothing the roster decides", "never about the peer"),
        ("The tunnel interface is small and replaceable", "## 8. Deliberately absent"),
    ] {
        assert!(format.contains(marker), "FORMAT.md must cover `{requirement}`");
    }
}

/// The README records why, not only what.
#[test]
fn the_readme_records_the_reasoning() {
    let readme = include_str!("../README.md");
    for topic in [
        "looks redundant",
        "not the transport key",
        "incomplete header",
        "enforced, not configured",
        "still have to prove",
    ] {
        assert!(
            readme.to_lowercase().contains(&topic.to_lowercase()),
            "the README must explain `{topic}`"
        );
    }
}

/// Every deferral names where it went.
#[test]
fn every_deferral_names_its_destination() {
    let readme = include_str!("../README.md");
    for destination in ["windows-daemon", "android-client", "reverse lookup"] {
        assert!(readme.contains(destination), "a deferral must name `{destination}`");
    }
}

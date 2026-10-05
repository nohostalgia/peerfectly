//! The rule, and the interface a real device sits behind.
//!
//! # Validation consults nothing beyond the session
//!
//! The transport resolved a key to a device once, at establishment.
//! [`transport::session::Session::peer`] carries that answer. At packet time the
//! check is `address_of(session.peer()) == source` for IPv6, and
//! `holdings.of(session.peer()) == source` for IPv4: no roster lookup, no cache,
//! no table of members.
//!
//! The destination is judged from the same inputs, against this tunnel's own
//! device rather than the session's: `own_address() == destination`, and
//! `own_ipv4() == Some(destination)`. Two comparisons against values computed
//! when the roster changed, and nothing else.
//!
//! That is deliberate. Consulting anything further would put a second authority
//! in the path of every packet — one that could disagree with the roster under
//! exactly the conditions where it matters. The IPv4 holdings are not a second
//! authority: they are computed from the roster state in the one place roster
//! changes reach this layer, and replaced whole.
//!
//! # A real device is elsewhere
//!
//! Carrying packets sits behind a few operations, so the rules above can be
//! exercised with no device, no privileges and no network. Creating a real TUN
//! device needs administrator rights and a platform driver, and binding an
//! untestable requirement to a testable one leaves the testable part unverified
//! in practice.
//!
//! The same split that worked for `transport-session` and then `transport-iroh`,
//! which inherited its behavioural suite unchanged.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use async_trait::async_trait;
use roster::id::DeviceId;

use crate::address::{self, Prefix};
use crate::holdings::Ipv4Holdings;
use crate::limits;
use crate::outcome::{Inbound, Outbound};

/// The IP version a packet declares, if it declares one.
///
/// The high nibble of the first byte.
fn version_of(packet: &[u8]) -> Option<u8> {
    packet.first().map(|byte| byte >> 4)
}

/// Reads an IPv6 address out of a packet at an offset.
///
/// Refuses anything shorter than a **complete** IPv6 header, not merely
/// anything too short to hold this one field. A 39-byte packet does contain
/// bytes 8 to 24, but the header it claims to be is not all there — and reading
/// a field out of an incomplete header is exactly the optimistic parsing that
/// turns a truncated packet into a plausible-looking lie.
fn address_at(packet: &[u8], offset: usize) -> Option<Ipv6Addr> {
    if packet.len() < limits::MIN_PACKET_LEN {
        return None;
    }
    let end = offset.checked_add(16)?;
    let slice = packet.get(offset..end)?;
    let octets: [u8; 16] = slice.try_into().ok()?;
    Some(Ipv6Addr::from(octets))
}

/// Reads an IPv4 address out of a packet at an offset, refusing anything
/// shorter than a complete minimal IPv4 header, for the reason above.
fn ipv4_at(packet: &[u8], offset: usize) -> Option<Ipv4Addr> {
    if packet.len() < limits::IPV4_MIN_HEADER {
        return None;
    }
    let end = offset.checked_add(4)?;
    let octets: [u8; 4] = packet.get(offset..end)?.try_into().ok()?;
    Some(Ipv4Addr::from(octets))
}

/// The rules a tunnel applies, for one device in one network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tunnel {
    /// The network's range. The only prefix this tunnel will ever claim.
    prefix: Prefix,
    /// The device this tunnel belongs to, which is the only device a packet may
    /// be addressed to.
    ///
    /// Not optional, and not set afterwards. A tunnel that does not know which
    /// device it is has one behaviour available — accept whatever a packet is
    /// addressed to — and that was the defect. A holdings-less tunnel is a
    /// truthful state, because a network can have nobody holding an IPv4
    /// address yet; a tunnel belonging to nobody is not a state this product
    /// ever has, so it is not one that can be built.
    own: DeviceId,
    /// Which device holds which IPv4 address, replaced whole when the roster
    /// changes.
    holdings: Arc<Ipv4Holdings>,
}

impl Tunnel {
    /// A tunnel for one device in a network, in which no device holds an IPv4
    /// address yet.
    #[must_use]
    pub fn new(prefix: Prefix, own: DeviceId) -> Self {
        Self { prefix, own, holdings: Arc::new(Ipv4Holdings::default()) }
    }

    /// The device this tunnel belongs to.
    #[must_use]
    pub const fn own(&self) -> &DeviceId {
        &self.own
    }

    /// This device's own address in the network.
    #[must_use]
    pub fn own_address(&self) -> Ipv6Addr {
        self.address_of(&self.own)
    }

    /// This device's own IPv4 address, if the network gave it one.
    #[must_use]
    pub fn own_ipv4(&self) -> Option<Ipv4Addr> {
        self.ipv4_of(&self.own)
    }

    /// The same tunnel, with these IPv4 holdings.
    #[must_use]
    pub fn with_holdings(mut self, holdings: Ipv4Holdings) -> Self {
        self.set_holdings(holdings);
        self
    }

    /// Replaces the IPv4 holdings, whole.
    pub fn set_holdings(&mut self, holdings: Ipv4Holdings) {
        self.holdings = Arc::new(holdings);
    }

    /// The network's range.
    #[must_use]
    pub const fn prefix(&self) -> &Prefix {
        &self.prefix
    }

    /// Which device holds which IPv4 address.
    #[must_use]
    pub fn holdings(&self) -> &Ipv4Holdings {
        &self.holdings
    }

    /// The address this tunnel expects from a device.
    #[must_use]
    pub fn address_of(&self, device: &DeviceId) -> Ipv6Addr {
        address::address_of(device, &self.prefix)
    }

    /// The IPv4 address a device holds, if it holds one.
    #[must_use]
    pub fn ipv4_of(&self, device: &DeviceId) -> Option<Ipv4Addr> {
        self.holdings.of(device)
    }

    /// Every prefix this tunnel claims.
    ///
    /// Exactly one, and never a default route. §2.6's split routing is a
    /// property of this function rather than a hope about what an installer
    /// wrote into a routing table.
    ///
    /// Nothing widens it short of different signed network parameters, because
    /// there is nowhere for anything else to go. IPv4 is claimed per held
    /// address, never as a range; see [`Self::holdings`].
    #[must_use]
    pub fn claimed_prefixes(&self) -> Vec<Prefix> {
        vec![self.prefix]
    }

    /// Judges a packet that arrived on a session.
    ///
    /// `session` is the device the transport authenticated. That is the whole
    /// input beyond the packet and the holdings the roster implies: no cache
    /// and no membership list.
    #[must_use]
    pub fn inbound(&self, session: DeviceId, packet: &[u8]) -> Inbound {
        if packet.len() > limits::MAX_PACKET_LEN {
            return Inbound::TooLong { len: packet.len(), limit: limits::MAX_PACKET_LEN };
        }

        // Before any field is read. The source lives at an offset that depends
        // on the version; in a packet of another version those bytes are
        // payload, and a sender chooses their payload. Reading them anyway would
        // let anyone satisfy the source check with a crafted packet of the other
        // family — found on a real machine, where Windows' own IPv4 chatter was
        // being reported as nonsense IPv6 addresses.
        let Some(version) = version_of(packet) else {
            return Inbound::TooShort { len: packet.len(), needed: limits::IPV4_MIN_HEADER };
        };
        match version {
            limits::IP_VERSION => self.inbound_v6(session, packet),
            limits::IPV4_VERSION => self.inbound_v4(session, packet),
            version => Inbound::UnknownVersion { version },
        }
    }

    /// Judges an IPv6 packet.
    fn inbound_v6(&self, session: DeviceId, packet: &[u8]) -> Inbound {
        // Dropped rather than parsed optimistically: a parser that guesses at a
        // truncated header reads attacker-chosen memory.
        let Some(claimed) = address_at(packet, limits::SOURCE_OFFSET) else {
            return Inbound::TooShort { len: packet.len(), needed: limits::MIN_PACKET_LEN };
        };

        if !self.prefix.contains(claimed) {
            return Inbound::SourceOffNetwork { session, claimed: claimed.into() };
        }

        let expected = self.address_of(&session);
        if claimed != expected {
            // The case the rule exists for: a member claiming another member's
            // address inside its own legitimate session.
            return Inbound::SourceIsNotTheSession {
                session,
                claimed: claimed.into(),
                expected: expected.into(),
            };
        }

        // The destination, from the same header, against this device rather than
        // the session's. `address_at` refused anything under a whole forty-byte
        // header above, and `DESTINATION_OFFSET + 16 == MIN_PACKET_LEN`, so these
        // bytes are within the packet wherever the source was.
        //
        // Multicast, broadcast and link-local need no case of their own: none of
        // them is this device's address, so they fall out of the one comparison.
        // A rule with no exceptions has no exception to get wrong.
        let Some(destination) = address_at(packet, limits::DESTINATION_OFFSET) else {
            return Inbound::TooShort { len: packet.len(), needed: limits::MIN_PACKET_LEN };
        };
        let mine = self.own_address();
        if destination == mine {
            Inbound::Accepted
        } else {
            Inbound::DestinationIsNotThisDevice {
                session,
                destination: destination.into(),
                held: Some(mine.into()),
            }
        }
    }

    /// Judges an IPv4 packet.
    ///
    /// The header is checked whole before its source is believed: a header
    /// length that runs past the packet, or a total length that is not what
    /// arrived, is a header describing some other packet.
    fn inbound_v4(&self, session: DeviceId, packet: &[u8]) -> Inbound {
        let len = packet.len();
        let (Some(first), Some(claimed)) =
            (packet.first(), ipv4_at(packet, limits::IPV4_SOURCE_OFFSET))
        else {
            return Inbound::TooShort { len, needed: limits::IPV4_MIN_HEADER };
        };

        let declared = usize::from(first & 0x0f).saturating_mul(4);
        if declared < limits::IPV4_MIN_HEADER || declared > len {
            return Inbound::Ipv4HeaderLength { declared, len };
        }
        let total = packet
            .get(
                limits::IPV4_TOTAL_LENGTH_OFFSET
                    ..limits::IPV4_TOTAL_LENGTH_OFFSET.saturating_add(2),
            )
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .map_or(0, |bytes| usize::from(u16::from_be_bytes(bytes)));
        if total != len {
            return Inbound::Ipv4TotalLength { declared: total, len };
        }

        if !self.holdings.range().contains(claimed.octets()) {
            return Inbound::SourceOffNetwork { session, claimed: claimed.into() };
        }
        match self.holdings.of(&session) {
            None => return Inbound::NoIpv4ForSession { session, claimed },
            Some(expected) if expected == claimed => {}
            Some(expected) => {
                return Inbound::SourceIsNotTheSession {
                    session,
                    claimed: claimed.into(),
                    expected: expected.into(),
                };
            }
        }

        // Read only after the header length and the total length were believed:
        // a header describing some other packet is not a header to take a
        // destination out of. `IPV4_DESTINATION_OFFSET + 4 == IPV4_MIN_HEADER`,
        // which `ipv4_at` already required.
        let Some(destination) = ipv4_at(packet, limits::IPV4_DESTINATION_OFFSET) else {
            return Inbound::TooShort { len, needed: limits::IPV4_MIN_HEADER };
        };
        // A device the network gave no IPv4 address has no destination that
        // would have been right, which is a different sentence from "you sent it
        // to the wrong one" and is reported as one.
        match self.own_ipv4() {
            Some(mine) if mine == destination => Inbound::Accepted,
            Some(mine) => Inbound::DestinationIsNotThisDevice {
                session,
                destination: destination.into(),
                held: Some(mine.into()),
            },
            None => Inbound::DestinationIsNotThisDevice {
                session,
                destination: destination.into(),
                held: None,
            },
        }
    }

    /// Judges a packet on its way out.
    #[must_use]
    pub fn outbound(&self, packet: &[u8]) -> Outbound {
        let Some(version) = version_of(packet) else {
            return Outbound::TooShort { len: packet.len(), needed: limits::IPV4_MIN_HEADER };
        };
        match version {
            limits::IP_VERSION => {
                let Some(destination) = address_at(packet, limits::DESTINATION_OFFSET) else {
                    return Outbound::TooShort {
                        len: packet.len(),
                        needed: limits::MIN_PACKET_LEN,
                    };
                };
                if self.prefix.contains(destination) {
                    Outbound::Carried
                } else {
                    Outbound::DestinationOffNetwork { destination: destination.into() }
                }
            }
            limits::IPV4_VERSION => {
                let Some(destination) = ipv4_at(packet, limits::IPV4_DESTINATION_OFFSET) else {
                    return Outbound::TooShort {
                        len: packet.len(),
                        needed: limits::IPV4_MIN_HEADER,
                    };
                };
                if !self.holdings.range().contains(destination.octets()) {
                    Outbound::DestinationOffNetwork { destination: destination.into() }
                } else if self.holdings.holder(destination).is_none() {
                    Outbound::DestinationHeldByNobody { destination }
                } else {
                    Outbound::Carried
                }
            }
            version => Outbound::UnknownVersion { version },
        }
    }
}

/// The destination of a packet, by its version.
///
/// For a packet [`Tunnel::outbound`] has already carried; `None` for anything
/// else.
#[must_use]
pub fn destination_of(packet: &[u8]) -> Option<IpAddr> {
    match version_of(packet)? {
        limits::IP_VERSION => address_at(packet, limits::DESTINATION_OFFSET).map(IpAddr::V6),
        limits::IPV4_VERSION => ipv4_at(packet, limits::IPV4_DESTINATION_OFFSET).map(IpAddr::V4),
        _ => None,
    }
}

/// A device that carries packets.
///
/// Deliberately small, and free of any platform type, so the real device can be
/// replaced without touching the rules above. A `windows-daemon` implementation
/// and an `android-client` one both sit here.
#[async_trait]
pub trait Packets: Send + Sync {
    /// Hands a packet to the host's networking stack.
    async fn deliver(&self, packet: &[u8]) -> std::io::Result<()>;

    /// Takes the next packet the host wants to send.
    async fn take(&self) -> std::io::Result<Vec<u8>>;
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test reports a failed expectation by panicking")]
mod tests {
    use roster::types::Ipv4Range;

    use super::*;
    use crate::address::ipv4_candidate;

    fn device(tag: u8) -> DeviceId {
        DeviceId::from_bytes([tag; 32])
    }

    /// The device the tunnel under test belongs to. Distinct from every `device(n)`
    /// a test uses as a peer, so "addressed to this device" and "addressed to the
    /// session's device" are never the same address by accident.
    fn me() -> DeviceId {
        device(0)
    }

    fn tunnel() -> Tunnel {
        Tunnel::new(
            Prefix::from_parameter(&[0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .expect("valid"),
            me(),
        )
    }

    /// An IPv6 header with the given source and destination, and nothing else
    /// that matters here.
    fn packet(source: Ipv6Addr, destination: Ipv6Addr) -> Vec<u8> {
        let mut out = vec![0u8; limits::MIN_PACKET_LEN];
        // The version nibble. Every builder here omitted it until a real
        // machine sent real packets, and nothing noticed because nothing
        // checked.
        if let Some(first) = out.first_mut() {
            *first = limits::IP_VERSION << 4;
        }
        out.splice(
            limits::SOURCE_OFFSET..limits::SOURCE_OFFSET + 16,
            source.octets().iter().copied(),
        );
        out.splice(
            limits::DESTINATION_OFFSET..limits::DESTINATION_OFFSET + 16,
            destination.octets().iter().copied(),
        );
        out
    }

    #[test]
    fn a_packet_from_the_sessions_own_device_is_accepted() {
        let tunnel = tunnel();
        let peer = device(1);
        let theirs = tunnel.address_of(&peer);

        assert_eq!(tunnel.inbound(peer, &packet(theirs, tunnel.own_address())), Inbound::Accepted);
    }

    /// The case the whole change exists for. A member on a legitimate session
    /// claiming another member's address must be stopped, and the refusal must
    /// say which member did it.
    #[test]
    fn a_member_cannot_claim_another_members_address() {
        let tunnel = tunnel();
        let mine = device(1);
        let yours = device(2);
        let your_address = tunnel.address_of(&yours);

        let outcome = tunnel.inbound(mine, &packet(your_address, tunnel.own_address()));

        match outcome {
            Inbound::SourceIsNotTheSession { session, claimed, expected } => {
                assert_eq!(session, mine, "the refusal names who did it");
                assert_eq!(claimed, IpAddr::V6(your_address));
                assert_eq!(expected, IpAddr::V6(tunnel.address_of(&mine)));
            }
            other => panic!("a member must not claim another's address, got {other:?}"),
        }
        assert!(outcome.is_spoofed_source());
    }

    /// The other half of the rule, IPv6. A member with an honest source, inside
    /// its own session, addressing the packet anywhere it likes.
    #[test]
    fn a_packet_addressed_to_another_member_is_dropped() {
        let tunnel = tunnel();
        let peer = device(1);
        let theirs = tunnel.address_of(&peer);
        let someone_else = tunnel.address_of(&device(2));

        let outcome = tunnel.inbound(peer, &packet(theirs, someone_else));

        match outcome {
            Inbound::DestinationIsNotThisDevice { session, destination, held } => {
                assert_eq!(session, peer, "the refusal names who sent it");
                assert_eq!(destination, IpAddr::V6(someone_else));
                assert_eq!(held, Some(IpAddr::V6(tunnel.own_address())));
            }
            other => panic!("a packet for another member must be dropped, got {other:?}"),
        }
        // Its own kind. The source was honest, so calling this a spoofed source
        // would blunt the predicate an operator uses to find a device
        // impersonating others.
        assert!(outcome.is_misdirected());
        assert!(!outcome.is_spoofed_source());
        assert!(!outcome.is_malformed());
        assert_eq!(outcome.session(), Some(peer));
    }

    /// Multicast and link-local need no case of their own, and this is the test
    /// that says so: they are refused by the same comparison as anything else.
    #[test]
    fn multicast_and_link_local_destinations_are_dropped() {
        let tunnel = tunnel();
        let peer = device(1);
        let theirs = tunnel.address_of(&peer);

        for text in ["ff02::1", "ff02::fb", "ff02::2", "fe80::1"] {
            let destination: Ipv6Addr = text.parse().expect("valid");
            let outcome = tunnel.inbound(peer, &packet(theirs, destination));
            assert!(outcome.is_misdirected(), "{text} must not reach this device: {outcome:?}");
        }
    }

    /// A destination off the network entirely — the overlay is not a way into
    /// the machine's other networks.
    #[test]
    fn a_destination_outside_the_network_is_dropped() {
        let tunnel = tunnel();
        let peer = device(1);
        let theirs = tunnel.address_of(&peer);
        let outside: Ipv6Addr = "2001:db8::1".parse().expect("valid");

        assert!(tunnel.inbound(peer, &packet(theirs, outside)).is_misdirected());
    }

    /// The source is judged first, so a packet wrong in both ways is reported as
    /// the more serious of the two: a member lying about who it is.
    #[test]
    fn a_packet_wrong_in_both_ways_is_reported_as_the_spoofed_source() {
        let tunnel = tunnel();
        let peer = device(1);
        let someone_else = tunnel.address_of(&device(2));

        let outcome = tunnel.inbound(peer, &packet(someone_else, someone_else));

        assert!(outcome.is_spoofed_source(), "{outcome:?}");
        assert!(!outcome.is_misdirected());
    }

    #[test]
    fn a_source_belonging_to_nobody_is_dropped() {
        let tunnel = tunnel();
        let peer = device(1);
        // Inside the prefix, but no device derives it.
        let nobody: Ipv6Addr = "fd00:0:0:0:dead:beef:dead:beef".parse().expect("valid");

        assert!(tunnel.inbound(peer, &packet(nobody, tunnel.own_address())).is_spoofed_source());
    }

    #[test]
    fn a_source_outside_the_network_is_dropped() {
        let tunnel = tunnel();
        let peer = device(1);
        let outside: Ipv6Addr = "2001:db8::1".parse().expect("valid");

        match tunnel.inbound(peer, &packet(outside, tunnel.own_address())) {
            Inbound::SourceOffNetwork { session, claimed } => {
                assert_eq!(session, peer);
                assert_eq!(claimed, IpAddr::V6(outside));
            }
            other => panic!("expected an off-network drop, got {other:?}"),
        }
    }

    /// Dropped rather than parsed: a truncated header is attacker-chosen memory.
    /// The hole this closes, and how it was found.
    ///
    /// An IPv4 packet's bytes 8 to 24 are payload, and a sender chooses their
    /// payload. Without a version check a member could put its own overlay
    /// address there, satisfy the source rule, and have the host accept an IPv4
    /// packet carrying any source it liked — §2.5 enforced for IPv6 and bypassed
    /// for everything else.
    ///
    /// Found by running the daemon on a real machine: Windows' own IPv4 SSDP
    /// chatter was reported as impossible IPv6 addresses, because the payload
    /// bytes `4d2d 5345 4152 4348` spell `M-SEARCH`.
    #[test]
    fn a_crafted_ipv4_packet_cannot_satisfy_the_source_rule() {
        let tunnel = tunnel();
        let peer = device(1);
        let mine = tunnel.address_of(&peer);

        // An IPv4 packet whose bytes 8..24 hold exactly the address the rule
        // wants to see.
        let mut forged = vec![0u8; limits::MIN_PACKET_LEN];
        if let Some(first) = forged.first_mut() {
            *first = 0x45; // IPv4, five words of header
        }
        forged.splice(
            limits::SOURCE_OFFSET..limits::SOURCE_OFFSET + 16,
            mine.octets().iter().copied(),
        );

        let outcome = tunnel.inbound(peer, &forged);
        assert!(!outcome.is_accepted(), "an IPv4 packet must never be judged as IPv6: {outcome:?}");
        assert!(
            !matches!(
                outcome,
                Inbound::SourceIsNotTheSession { claimed: IpAddr::V6(_), .. }
                    | Inbound::SourceOffNetwork { claimed: IpAddr::V6(_), .. }
            ),
            "no IPv6 address was read out of it: {outcome:?}"
        );
    }

    /// The mirror: an IPv6 packet whose bytes 12..16 hold the session's IPv4
    /// address is judged as IPv6, and refused as the lie it is.
    #[test]
    fn a_crafted_ipv6_packet_cannot_satisfy_the_ipv4_source_rule() {
        let peer = device(1);
        let tunnel = held(&[peer]);
        let mine = tunnel.ipv4_of(&peer).expect("held");
        let mut forged = packet("2001:db8::1".parse().expect("valid"), tunnel.address_of(&peer));
        forged.splice(
            limits::IPV4_SOURCE_OFFSET..limits::IPV4_SOURCE_OFFSET + 4,
            mine.octets().iter().copied(),
        );

        match tunnel.inbound(peer, &forged) {
            Inbound::SourceOffNetwork { claimed: IpAddr::V6(_), .. } => {}
            other => panic!("expected an IPv6 judgement, got {other:?}"),
        }
    }

    #[test]
    fn a_version_other_than_four_or_six_is_refused_before_any_field_is_read() {
        let tunnel = tunnel();
        for version in [0u8, 5, 7, 15] {
            let mut odd = vec![0u8; limits::MIN_PACKET_LEN];
            if let Some(first) = odd.first_mut() {
                *first = version << 4;
            }
            let outcome = tunnel.inbound(device(1), &odd);
            assert_eq!(outcome, Inbound::UnknownVersion { version });
            assert!(outcome.is_malformed());
            assert_eq!(tunnel.outbound(&odd), Outbound::UnknownVersion { version });
        }
    }

    /// The machine's own IPv4 chatter to anywhere but a peer leaves by no
    /// path, and reads as what it is rather than as a nonsense address.
    #[test]
    fn outbound_ipv4_off_the_range_is_refused_as_ipv4() {
        let tunnel = held(&[device(1)]);
        let broadcast = ipv4_packet(Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(239, 255, 255, 250));

        match tunnel.outbound(&broadcast) {
            Outbound::DestinationOffNetwork { destination } => {
                assert_eq!(destination, IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)));
            }
            other => panic!("expected an IPv4 refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_packet_is_dropped_rather_than_parsed() {
        let tunnel = tunnel();
        assert!(tunnel.inbound(device(1), &[]).is_malformed(), "nothing at all");
        for len in [1usize, 8, limits::MIN_PACKET_LEN - 1] {
            let mut truncated = vec![0u8; len];
            if let Some(first) = truncated.first_mut() {
                *first = limits::IP_VERSION << 4;
            }
            let outcome = tunnel.inbound(device(1), &truncated);
            match outcome {
                Inbound::TooShort { len: reported, needed } => {
                    assert_eq!(reported, len);
                    assert_eq!(needed, limits::MIN_PACKET_LEN);
                }
                other => panic!("{len} bytes must be too short, got {other:?}"),
            }
            assert!(outcome.is_malformed(), "and must not read as a lie");
        }
    }

    #[test]
    fn an_oversized_packet_is_refused() {
        let tunnel = tunnel();
        let huge = vec![0u8; limits::MAX_PACKET_LEN + 1];
        assert!(matches!(tunnel.inbound(device(1), &huge), Inbound::TooLong { .. }));
    }

    // -----------------------------------------------------------------------
    // Outbound
    // -----------------------------------------------------------------------

    #[test]
    fn a_packet_to_a_peer_is_carried() {
        let tunnel = tunnel();
        let peer = tunnel.address_of(&device(2));
        assert_eq!(tunnel.outbound(&packet(Ipv6Addr::UNSPECIFIED, peer)), Outbound::Carried);
    }

    /// §2.6: a VPN that captures everything gets switched off, and a tunnel a
    /// person switched off protects nothing.
    #[test]
    fn a_packet_to_the_wider_internet_is_refused() {
        let tunnel = tunnel();
        let elsewhere: Ipv6Addr = "2001:db8::1".parse().expect("valid");

        match tunnel.outbound(&packet(Ipv6Addr::UNSPECIFIED, elsewhere)) {
            Outbound::DestinationOffNetwork { destination } => {
                assert_eq!(destination, IpAddr::V6(elsewhere));
            }
            other => panic!("expected an off-network refusal, got {other:?}"),
        }
    }

    /// Split routing as a property of the code. A misconfigured routing table
    /// cannot quietly turn this into a full tunnel, because there is nowhere for
    /// a default route to come from.
    #[test]
    fn no_default_route_is_ever_claimed() {
        let tunnel = tunnel();
        let claimed = tunnel.claimed_prefixes();

        assert_eq!(claimed.len(), 1, "exactly the network's prefix");
        for prefix in claimed {
            assert!(prefix.bits() > 0, "a zero-length prefix would be a default route");
            assert!(!prefix.contains("2001:db8::1".parse().expect("valid")));
        }
    }

    #[test]
    fn the_claimed_prefix_follows_the_parameters() {
        let one = Tunnel::new(
            Prefix::from_parameter(&[0xfd, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .expect("valid"),
            me(),
        );
        let two = Tunnel::new(
            Prefix::from_parameter(&[0xfd, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .expect("valid"),
            me(),
        );
        assert_ne!(one.claimed_prefixes(), two.claimed_prefixes());
    }

    /// An application addressing the wrong place must not read as an attack.
    #[test]
    fn an_outbound_refusal_is_a_different_outcome_from_an_inbound_drop() {
        let tunnel = tunnel();
        let elsewhere: Ipv6Addr = "2001:db8::1".parse().expect("valid");

        let outbound = tunnel.outbound(&packet(Ipv6Addr::UNSPECIFIED, elsewhere));
        let inbound = tunnel.inbound(device(1), &packet(elsewhere, tunnel.own_address()));

        assert!(!outbound.is_carried());
        assert!(inbound.is_spoofed_source());
        // Separate types, so a caller cannot confuse one for the other even by
        // accident.
        assert!(!outbound.to_string().contains("claimed"));
    }

    #[test]
    fn a_truncated_outbound_packet_is_refused() {
        let tunnel = tunnel();
        assert!(matches!(tunnel.outbound(&[0x60u8; 8]), Outbound::TooShort { .. }));
        assert!(matches!(tunnel.outbound(&[0x45u8; 8]), Outbound::TooShort { .. }));
        assert!(matches!(tunnel.outbound(&[]), Outbound::TooShort { .. }));
    }

    // -----------------------------------------------------------------------
    // IPv4
    // -----------------------------------------------------------------------

    fn network() -> roster::id::NetworkId {
        roster::id::NetworkId::from_bytes([7; 32])
    }

    /// A tunnel in which these devices, and this one, hold their IPv4 candidates.
    ///
    /// This device is always among them: a tunnel whose own device holds no IPv4
    /// address refuses every IPv4 packet, and a fixture that did that would make
    /// the source tests below pass for the wrong reason.
    fn held(devices: &[DeviceId]) -> Tunnel {
        let mut all = vec![me()];
        all.extend_from_slice(devices);
        let holdings = Ipv4Holdings::from(&network(), Ipv4Range::DEFAULT, &all, &[]);
        for device in &all {
            assert!(holdings.of(device).is_some(), "the fixture devices do not collide");
        }
        tunnel().with_holdings(holdings)
    }

    /// The IPv4 address this device holds in a fixture that gave it one.
    fn my_ipv4(tunnel: &Tunnel) -> Ipv4Addr {
        tunnel.own_ipv4().expect("this device holds one")
    }

    /// A minimal IPv4 header with the given addresses, lengths filled in.
    fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        let mut out = vec![0u8; 28];
        let len = u16::try_from(out.len()).expect("small");
        out.splice(0..1, [0x45]);
        out.splice(2..4, len.to_be_bytes());
        out.splice(12..16, source.octets());
        out.splice(16..20, destination.octets());
        out
    }

    #[test]
    fn an_ipv4_packet_from_the_sessions_own_device_is_accepted() {
        let peer = device(1);
        let tunnel = held(&[peer, device(2)]);
        let theirs = tunnel.ipv4_of(&peer).expect("held");

        assert_eq!(tunnel.inbound(peer, &ipv4_packet(theirs, my_ipv4(&tunnel))), Inbound::Accepted);
    }

    #[test]
    fn a_member_cannot_claim_another_members_ipv4_address() {
        let (mine, yours) = (device(1), device(2));
        let tunnel = held(&[mine, yours]);
        let your_address = tunnel.ipv4_of(&yours).expect("held");

        match tunnel.inbound(mine, &ipv4_packet(your_address, my_ipv4(&tunnel))) {
            Inbound::SourceIsNotTheSession { session, claimed, expected } => {
                assert_eq!(session, mine);
                assert_eq!(claimed, IpAddr::V4(your_address));
                assert_eq!(expected, IpAddr::V4(tunnel.ipv4_of(&mine).expect("held")));
            }
            other => panic!("a member must not claim another's IPv4 address, got {other:?}"),
        }
    }

    /// The other half of the rule, IPv4 — where the access rules an operator
    /// writes usually live, which is why it is held to the same standard.
    #[test]
    fn an_ipv4_packet_addressed_to_another_member_is_dropped() {
        let peer = device(1);
        let tunnel = held(&[peer, device(2)]);
        let theirs = tunnel.ipv4_of(&peer).expect("held");
        let someone_else = tunnel.ipv4_of(&device(2)).expect("held");

        let outcome = tunnel.inbound(peer, &ipv4_packet(theirs, someone_else));

        match outcome {
            Inbound::DestinationIsNotThisDevice { session, destination, held } => {
                assert_eq!(session, peer);
                assert_eq!(destination, IpAddr::V4(someone_else));
                assert_eq!(held, Some(IpAddr::V4(my_ipv4(&tunnel))));
            }
            other => panic!("an IPv4 packet for another member must be dropped, got {other:?}"),
        }
        assert!(outcome.is_misdirected());
        assert!(!outcome.is_spoofed_source());
    }

    #[test]
    fn ipv4_multicast_broadcast_and_lan_destinations_are_dropped() {
        let peer = device(1);
        let tunnel = held(&[peer]);
        let theirs = tunnel.ipv4_of(&peer).expect("held");

        for destination in [
            Ipv4Addr::new(224, 0, 0, 251),
            Ipv4Addr::new(239, 255, 255, 250),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(192, 168, 1, 10),
        ] {
            let outcome = tunnel.inbound(peer, &ipv4_packet(theirs, destination));
            assert!(outcome.is_misdirected(), "{destination} must not reach here: {outcome:?}");
        }
    }

    /// A device the network gave no IPv4 address has no destination that would
    /// have been right, and the refusal says that rather than naming an address
    /// it does not hold.
    #[test]
    fn a_device_holding_no_ipv4_accepts_no_ipv4_packet() {
        let peer = device(1);
        // The holdings name the peer and not this device.
        let holdings = Ipv4Holdings::from(&network(), Ipv4Range::DEFAULT, &[peer], &[]);
        let tunnel = tunnel().with_holdings(holdings);
        assert_eq!(tunnel.own_ipv4(), None, "the fixture gives this device none");
        let theirs = tunnel.ipv4_of(&peer).expect("held");

        for destination in [theirs, Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::BROADCAST] {
            match tunnel.inbound(peer, &ipv4_packet(theirs, destination)) {
                Inbound::DestinationIsNotThisDevice { held, .. } => {
                    assert_eq!(held, None, "there is no address it should have used");
                }
                other => panic!("expected a destination refusal for {destination}, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_ipv4_source_held_by_nobody_is_dropped() {
        let peer = device(1);
        let tunnel = held(&[peer]);
        let mine = tunnel.ipv4_of(&peer).expect("held");
        let nobody = Ipv4Addr::from(u32::from(mine) ^ 1);
        assert_eq!(tunnel.holdings().holder(nobody), None);

        let outcome = tunnel.inbound(peer, &ipv4_packet(nobody, my_ipv4(&tunnel)));
        assert!(outcome.is_spoofed_source(), "{outcome:?}");
    }

    #[test]
    fn an_ipv4_source_outside_the_range_is_dropped() {
        let peer = device(1);
        let tunnel = held(&[peer]);
        let outside = Ipv4Addr::new(192, 168, 1, 10);

        match tunnel.inbound(peer, &ipv4_packet(outside, my_ipv4(&tunnel))) {
            Inbound::SourceOffNetwork { claimed, .. } => assert_eq!(claimed, IpAddr::V4(outside)),
            other => panic!("expected an off-network drop, got {other:?}"),
        }
    }

    #[test]
    fn ipv4_on_a_session_whose_device_holds_none_is_dropped() {
        let tunnel = held(&[device(1)]);
        let stranger = device(2);
        let claimed = tunnel.ipv4_of(&device(1)).expect("held");

        match tunnel.inbound(stranger, &ipv4_packet(claimed, my_ipv4(&tunnel))) {
            Inbound::NoIpv4ForSession { session, claimed: reported } => {
                assert_eq!(session, stranger);
                assert_eq!(reported, claimed);
            }
            other => panic!("expected a refusal for a session without IPv4, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_ipv4_header_is_dropped_rather_than_parsed() {
        let tunnel = held(&[device(1)]);
        let theirs = tunnel.ipv4_of(&device(1)).expect("held");
        let whole = ipv4_packet(theirs, my_ipv4(&tunnel));
        for len in [1usize, 12, limits::IPV4_MIN_HEADER - 1] {
            let outcome = tunnel.inbound(device(1), whole.get(..len).expect("shorter"));
            assert_eq!(outcome, Inbound::TooShort { len, needed: limits::IPV4_MIN_HEADER });
        }

        let mut short_header = whole.clone();
        short_header.splice(0..1, [0x44]);
        assert_eq!(
            tunnel.inbound(device(1), &short_header),
            Inbound::Ipv4HeaderLength { declared: 16, len: 28 }
        );
        let mut long_header = whole;
        long_header.splice(0..1, [0x4f]);
        assert_eq!(
            tunnel.inbound(device(1), &long_header),
            Inbound::Ipv4HeaderLength { declared: 60, len: 28 }
        );
    }

    #[test]
    fn an_ipv4_packet_lying_about_its_total_length_is_dropped() {
        let tunnel = held(&[device(1)]);
        let theirs = tunnel.ipv4_of(&device(1)).expect("held");
        let mut lying = ipv4_packet(theirs, my_ipv4(&tunnel));
        lying.splice(2..4, 60u16.to_be_bytes());

        let outcome = tunnel.inbound(device(1), &lying);
        assert_eq!(outcome, Inbound::Ipv4TotalLength { declared: 60, len: 28 });
        assert!(outcome.is_malformed());
    }

    #[test]
    fn an_ipv4_packet_to_a_held_address_is_carried() {
        let tunnel = held(&[device(1)]);
        let theirs = tunnel.ipv4_of(&device(1)).expect("held");
        assert_eq!(tunnel.outbound(&ipv4_packet(Ipv4Addr::UNSPECIFIED, theirs)), Outbound::Carried);
        assert_eq!(
            destination_of(&ipv4_packet(Ipv4Addr::UNSPECIFIED, theirs)),
            Some(theirs.into())
        );
    }

    #[test]
    fn an_ipv4_packet_inside_the_range_held_by_nobody_is_refused() {
        let tunnel = held(&[device(1)]);
        let nobody = Ipv4Addr::from(u32::from(tunnel.ipv4_of(&device(1)).expect("held")) ^ 1);

        assert_eq!(
            tunnel.outbound(&ipv4_packet(Ipv4Addr::UNSPECIFIED, nobody)),
            Outbound::DestinationHeldByNobody { destination: nobody }
        );
    }

    /// New holdings replace the old ones whole: a device revoked is refused at
    /// once, and one admitted is accepted at once.
    #[test]
    fn replacing_the_holdings_changes_the_verdicts() {
        let (kept, admitted) = (device(1), device(2));
        let mut tunnel = held(&[kept]);
        let address = ipv4_candidate(&network(), &admitted, &Ipv4Range::DEFAULT);
        let here = my_ipv4(&tunnel);
        assert!(!tunnel.inbound(admitted, &ipv4_packet(address, here)).is_accepted());

        tunnel.set_holdings(Ipv4Holdings::from(
            &network(),
            Ipv4Range::DEFAULT,
            &[me(), kept, admitted],
            &[],
        ));
        assert!(tunnel.inbound(admitted, &ipv4_packet(address, here)).is_accepted());

        tunnel.set_holdings(Ipv4Holdings::from(
            &network(),
            Ipv4Range::DEFAULT,
            &[me(), kept],
            &[admitted],
        ));
        assert!(!tunnel.inbound(admitted, &ipv4_packet(address, here)).is_accepted());
        assert_eq!(
            tunnel.outbound(&ipv4_packet(Ipv4Addr::UNSPECIFIED, address)),
            Outbound::DestinationHeldByNobody { destination: address }
        );
    }
}

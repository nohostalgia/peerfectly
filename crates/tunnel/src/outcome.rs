//! What happened to a packet, and why.
//!
//! The distinction that matters most is between a packet **a peer lied about**
//! and one **a caller addressed wrongly**. Collapsing them would make an
//! ordinary application mistake look like an attack and an attack look like a
//! mistake, and an operator needs to tell those apart at a glance.

use core::fmt;
use std::net::{IpAddr, Ipv4Addr};

use roster::id::DeviceId;

/// The result of an addressing operation.
pub type Result<T> = core::result::Result<T, Error>;

/// Why an address could not be derived.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The network's prefix leaves no room for a device part.
    ///
    /// An error rather than a truncation. Silently overlapping device parts
    /// would put two devices at one address, which is the confusion this crate
    /// exists to prevent.
    PrefixTooLong {
        /// The prefix length offered, in bits.
        bits: usize,
        /// The longest that leaves room for a device.
        limit: usize,
    },

    /// The prefix bytes are not a usable IPv6 prefix.
    PrefixMalformed {
        /// How many bytes were offered.
        len: usize,
    },

    /// The prefix is outside the range a network may claim.
    ///
    /// A prefix in global space would route real hosts into the tunnel, and one
    /// wider than a `/64` would route more of the unique local space than the
    /// network uses. The roster refuses such parameters at decoding; this is the
    /// same rule where the prefix becomes an address, so parameters that reached
    /// here another way cannot be used either.
    PrefixNotPrivate {
        /// The rule it broke, in the roster's own words.
        reason: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrefixTooLong { bits, limit } => write!(
                f,
                "a {bits}-bit prefix leaves no room for a device part; {limit} is the longest"
            ),
            Self::PrefixMalformed { len } => {
                write!(f, "{len} bytes is not a usable IPv6 prefix")
            }
            Self::PrefixNotPrivate { reason } => {
                write!(f, "a network prefix must be a unique local /64: {reason}")
            }
        }
    }
}

impl core::error::Error for Error {}

/// What happened to an inbound packet.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Inbound {
    /// Its source is the address derived for the session's device.
    Accepted,

    /// Its source is some other device's address.
    ///
    /// **The case the rule exists for.** The transport already refuses a peer
    /// the roster does not name, so this is a *member* claiming another
    /// member's address inside its own legitimate session. The session is named
    /// because the interesting fact is which member did it.
    SourceIsNotTheSession {
        /// The device whose session it arrived on.
        session: DeviceId,
        /// The source it claimed.
        claimed: IpAddr,
        /// The address that session may use.
        expected: IpAddr,
    },

    /// Its source lies outside the network's prefix, or its IPv4 range,
    /// entirely.
    SourceOffNetwork {
        /// The device whose session it arrived on.
        session: DeviceId,
        /// The source it claimed.
        claimed: IpAddr,
    },

    /// An IPv4 packet on the session of a device that holds no IPv4 address.
    ///
    /// Whatever source it claims is not one that device may use: its candidate
    /// collides, so the network gave it none.
    NoIpv4ForSession {
        /// The device whose session it arrived on.
        session: DeviceId,
        /// The source it claimed.
        claimed: Ipv4Addr,
    },

    /// Its destination is not an address this device holds in this network.
    ///
    /// **The other half of the rule.** Checking only the source leaves a member
    /// — inside its own session, with its own honest source — able to put a
    /// packet addressed to *anything* onto this device's interface: another
    /// member's address, which the host above then handles as though this device
    /// were that member; a multicast group, reaching every listener on the
    /// machine; a link-local or local address, injected into the host from the
    /// overlay. The way out has always been refused, and this is the way in.
    ///
    /// On a phone, where one interface carries every network that is on, it is
    /// also what stops a packet arriving in one network being written to the
    /// interface addressed into another.
    DestinationIsNotThisDevice {
        /// The device whose session it arrived on.
        session: DeviceId,
        /// The destination it was addressed to.
        destination: IpAddr,
        /// The address this device holds for that version, or `None` where it
        /// holds none — an IPv4 packet on a device the network gave no IPv4
        /// address, for which no destination would have been right.
        held: Option<IpAddr>,
    },

    /// Too short to carry a source address.
    ///
    /// Dropped rather than parsed. A parser that guesses at a truncated header
    /// is a parser reading attacker-chosen memory.
    TooShort {
        /// How many bytes arrived.
        len: usize,
        /// How many are needed to hold a source.
        needed: usize,
    },

    /// Larger than this layer will inspect.
    TooLong {
        /// How many bytes arrived.
        len: usize,
        /// The bound.
        limit: usize,
    },

    /// Neither IPv6 nor IPv4.
    ///
    /// **This must be checked before any field is read.** The source lives at a
    /// fixed offset, and the offset depends on the version; in a packet of any
    /// other version those bytes are something else — payload, most likely —
    /// and a sender who controls the payload controls what the source check
    /// sees. Reading them anyway turns the rule §2.5 exists for into a
    /// formality anyone can satisfy.
    UnknownVersion {
        /// The version it declared.
        version: u8,
    },

    /// An IPv4 header whose declared length is under twenty bytes or over the
    /// packet.
    Ipv4HeaderLength {
        /// The header length it declared, in bytes.
        declared: usize,
        /// How many bytes arrived.
        len: usize,
    },

    /// An IPv4 packet whose total length is not the number of bytes that
    /// arrived.
    Ipv4TotalLength {
        /// The total length it declared.
        declared: usize,
        /// How many bytes arrived.
        len: usize,
    },
}

impl Inbound {
    /// Whether the packet may be delivered.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }

    /// Whether a peer claimed an address that is not its own.
    ///
    /// True only for the deliberate case. A truncated packet is a broken sender
    /// or a broken link; this is a member telling a lie about who it is, and it
    /// is the thing an operator most needs to be able to find.
    #[must_use]
    pub const fn is_spoofed_source(&self) -> bool {
        matches!(
            self,
            Self::SourceIsNotTheSession { .. }
                | Self::SourceOffNetwork { .. }
                | Self::NoIpv4ForSession { .. }
        )
    }

    /// Whether the packet was addressed somewhere other than this device.
    ///
    /// Its own answer, and not part of [`Self::is_spoofed_source`]. That one
    /// means *a member told a lie about who it is*, and a member that sends this
    /// told no such lie — its source is honest, which is what makes the packet
    /// worth looking at. Folding the two together would blunt the predicate an
    /// operator uses to find a device impersonating others, to say nothing of
    /// this one.
    #[must_use]
    pub const fn is_misdirected(&self) -> bool {
        matches!(self, Self::DestinationIsNotThisDevice { .. })
    }

    /// Whether the packet was malformed rather than dishonest.
    #[must_use]
    pub const fn is_malformed(&self) -> bool {
        matches!(
            self,
            Self::TooShort { .. }
                | Self::TooLong { .. }
                | Self::UnknownVersion { .. }
                | Self::Ipv4HeaderLength { .. }
                | Self::Ipv4TotalLength { .. }
        )
    }

    /// The session a refusal concerns, when it concerns one.
    #[must_use]
    pub const fn session(&self) -> Option<DeviceId> {
        match self {
            Self::SourceIsNotTheSession { session, .. }
            | Self::SourceOffNetwork { session, .. }
            | Self::NoIpv4ForSession { session, .. }
            | Self::DestinationIsNotThisDevice { session, .. } => Some(*session),
            _ => None,
        }
    }
}

impl fmt::Display for Inbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted => write!(f, "accepted"),
            Self::SourceIsNotTheSession { session, claimed, expected } => write!(
                f,
                "device {session:?} claimed source {claimed}, but its address is {expected}"
            ),
            Self::SourceOffNetwork { session, claimed } => {
                write!(f, "device {session:?} claimed source {claimed}, which is off this network")
            }
            Self::NoIpv4ForSession { session, claimed } => write!(
                f,
                "device {session:?} claimed IPv4 source {claimed}, and holds no IPv4 address"
            ),
            Self::DestinationIsNotThisDevice { session, destination, held: Some(held) } => write!(
                f,
                "device {session:?} sent a packet to {destination}, and this device is {held}"
            ),
            Self::DestinationIsNotThisDevice { session, destination, held: None } => write!(
                f,
                "device {session:?} sent a packet to {destination}, and this device holds no address of that kind"
            ),
            Self::TooShort { len, needed } => {
                write!(f, "{len} bytes cannot carry a source address; {needed} are needed")
            }
            Self::TooLong { len, limit } => write!(f, "{len} bytes is over the {limit} inspected"),
            Self::UnknownVersion { version } => {
                write!(f, "an IP version {version} packet, and this overlay carries IPv6 and IPv4")
            }
            Self::Ipv4HeaderLength { declared, len } => {
                write!(f, "an IPv4 header of {declared} bytes in a packet of {len}")
            }
            Self::Ipv4TotalLength { declared, len } => {
                write!(f, "an IPv4 packet declaring {declared} bytes arrived as {len}")
            }
        }
    }
}

/// What happened to an outbound packet.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outbound {
    /// Its destination is on this network.
    Carried,

    /// Its destination is not on this network.
    ///
    /// §2.6's split routing, enforced here rather than left to an installer's
    /// routing commands. Deliberately a different outcome from an inbound drop:
    /// this says a caller addressed the wrong place, not that a peer lied.
    DestinationOffNetwork {
        /// Where it was addressed.
        destination: IpAddr,
    },

    /// An IPv4 destination inside the network's range that no device holds.
    ///
    /// Nobody to carry it to: no device derived it, or two did and neither holds
    /// it.
    DestinationHeldByNobody {
        /// Where it was addressed.
        destination: Ipv4Addr,
    },

    /// Too short to carry a destination address.
    TooShort {
        /// How many bytes arrived.
        len: usize,
        /// How many are needed.
        needed: usize,
    },

    /// Neither IPv6 nor IPv4.
    ///
    /// Ordinary rather than alarming on the way out: nothing a host sends here
    /// should be anything else, and nothing else has a destination to read.
    UnknownVersion {
        /// The version it declared.
        version: u8,
    },
}

impl Outbound {
    /// Whether the packet may be sent.
    #[must_use]
    pub const fn is_carried(&self) -> bool {
        matches!(self, Self::Carried)
    }
}

impl fmt::Display for Outbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Carried => write!(f, "carried"),
            Self::DestinationOffNetwork { destination } => {
                write!(f, "{destination} is not on this network")
            }
            Self::DestinationHeldByNobody { destination } => {
                write!(f, "{destination} is on this network, and no device holds it")
            }
            Self::TooShort { len, needed } => {
                write!(f, "{len} bytes cannot carry a destination; {needed} are needed")
            }
            Self::UnknownVersion { version } => {
                write!(f, "an IP version {version} packet, and this overlay carries IPv6 and IPv4")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(tag: u8) -> DeviceId {
        DeviceId::from_bytes([tag; 32])
    }

    fn address(last: u16) -> IpAddr {
        IpAddr::V6(std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, last))
    }

    #[test]
    fn every_inbound_outcome_is_distinct() {
        let all = [
            Inbound::Accepted,
            Inbound::SourceIsNotTheSession {
                session: device(1),
                claimed: address(1),
                expected: address(2),
            },
            Inbound::SourceOffNetwork { session: device(1), claimed: address(3) },
            Inbound::TooShort { len: 4, needed: 40 },
            Inbound::TooLong { len: 99_999, limit: 65_535 },
            Inbound::NoIpv4ForSession { session: device(1), claimed: Ipv4Addr::new(100, 64, 0, 1) },
            Inbound::UnknownVersion { version: 5 },
            Inbound::Ipv4HeaderLength { declared: 16, len: 40 },
            Inbound::Ipv4TotalLength { declared: 60, len: 40 },
            Inbound::DestinationIsNotThisDevice {
                session: device(1),
                destination: address(4),
                held: Some(address(5)),
            },
            Inbound::DestinationIsNotThisDevice {
                session: device(1),
                destination: address(4),
                held: None,
            },
        ];
        for (i, left) in all.iter().enumerate() {
            for (j, right) in all.iter().enumerate() {
                assert_eq!(i == j, left == right, "{left:?} vs {right:?}");
            }
        }
    }

    /// A peer telling a lie about who it is must not read the same as a broken
    /// link, and the reverse.
    #[test]
    fn a_lie_is_distinguishable_from_a_broken_packet() {
        let lie = Inbound::SourceIsNotTheSession {
            session: device(1),
            claimed: address(1),
            expected: address(2),
        };
        assert!(lie.is_spoofed_source());
        assert!(!lie.is_malformed());

        let broken = Inbound::TooShort { len: 4, needed: 40 };
        assert!(broken.is_malformed());
        assert!(!broken.is_spoofed_source());
    }

    /// Three kinds, not two. A member that addressed a packet elsewhere told no
    /// lie about who it is, and a fault an operator reads must not suggest it
    /// did — `is_spoofed_source` is how a device impersonating others is found,
    /// and it stops meaning that if this joins it.
    #[test]
    fn a_misdirected_packet_is_neither_a_lie_nor_a_broken_one() {
        let elsewhere = Inbound::DestinationIsNotThisDevice {
            session: device(3),
            destination: address(4),
            held: Some(address(5)),
        };

        assert!(elsewhere.is_misdirected());
        assert!(!elsewhere.is_spoofed_source());
        assert!(!elsewhere.is_malformed());
        assert_eq!(elsewhere.session(), Some(device(3)), "which member sent it");

        // And the three predicates do not overlap anywhere.
        let lie = Inbound::SourceIsNotTheSession {
            session: device(1),
            claimed: address(1),
            expected: address(2),
        };
        let broken = Inbound::TooShort { len: 4, needed: 40 };
        assert!(!lie.is_misdirected());
        assert!(!broken.is_misdirected());
        assert!(!Inbound::Accepted.is_misdirected());
    }

    /// What a person reads must say the destination was the fault, and must not
    /// read as a source that was.
    #[test]
    fn a_misdirected_packet_names_the_destination_as_the_fault() {
        let known = Inbound::DestinationIsNotThisDevice {
            session: device(3),
            destination: address(4),
            held: Some(address(5)),
        }
        .to_string();
        assert!(known.contains("sent a packet to"), "{known}");
        assert!(known.contains("this device is"), "{known}");
        assert!(!known.contains("source"), "it is not a source refusal: {known}");

        let none = Inbound::DestinationIsNotThisDevice {
            session: device(3),
            destination: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            held: None,
        }
        .to_string();
        assert!(none.contains("holds no address of that kind"), "{none}");
        assert!(!none.contains("source"), "{none}");
    }

    /// The interesting fact about a spoofed packet is which member sent it.
    #[test]
    fn a_spoofed_packet_names_its_session() {
        let refusal = Inbound::SourceIsNotTheSession {
            session: device(7),
            claimed: address(1),
            expected: address(2),
        };
        assert_eq!(refusal.session(), Some(device(7)));
        assert_eq!(Inbound::Accepted.session(), None);
        assert_eq!(Inbound::TooShort { len: 1, needed: 40 }.session(), None);
    }

    /// An application addressing the wrong place must not look like an attack.
    #[test]
    fn an_outbound_refusal_is_not_an_inbound_drop() {
        let wrong_place = Outbound::DestinationOffNetwork { destination: address(9) };
        assert!(!wrong_place.is_carried());

        // The two families are separate types, so a caller cannot confuse one
        // for the other even by accident.
        assert!(wrong_place.to_string().contains("not on this network"), "{wrong_place}");
    }

    #[test]
    fn a_refusal_says_which_addresses_were_involved() {
        let refusal = Inbound::SourceIsNotTheSession {
            session: device(1),
            claimed: address(0xaa),
            expected: address(0xbb),
        };
        let message = refusal.to_string();
        assert!(message.contains("::aa"), "{message}");
        assert!(message.contains("::bb"), "{message}");
    }

    #[test]
    fn a_prefix_error_names_the_bound() {
        let refusal = Error::PrefixTooLong { bits: 120, limit: 64 };
        let message = refusal.to_string();
        assert!(message.contains("120") && message.contains("64"), "{message}");
    }
}

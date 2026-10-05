//! The names and bounds the daemon uses, in one place.
//!
//! Everything here that identifies the product derives from [`PRODUCT`]. It
//! appears in a directory path, an adapter name, a pipe name and a registry tag —
//! four places that must agree and one of which is a machine-wide identifier.
//! One constant means they cannot drift apart.

/// The product's short name.
///
/// Decided before anything was published (DESIGN.md §13.3). It
/// replaced the placeholder `mynet` everywhere, the protocol's own constants
/// included: nothing before the rename speaks to anything after it.
///
/// Note the suffix is *not* here and must never be: §2.5 makes it a signed
/// roster parameter, and `DESIGN.md` §0 forbids it as a compile-time constant.
pub const PRODUCT: &str = "peerfectly";

/// The adapter's name for one network, as it appears in network connections.
///
/// It carries the network because a device may hold several and each gets its
/// own adapter. A person looking at `ipconfig` with three networks up should be
/// able to tell which is which, and the machine needs three distinct names in
/// any case.
#[must_use]
pub fn adapter_name(network: &str) -> String {
    format!("{PRODUCT} {network}")
}

/// The GUID a network's adapter is created with.
///
/// **The same every time that network comes up, and different for every other.**
/// Windows keys a network's profile and any firewall rule bound to an adapter on
/// its GUID; a random one at every raise made both forget the adapter, and pushed
/// a person towards firewall rules that apply on every interface (F-11).
///
/// Derived, not stored: there is nothing to lose or keep in step. One-way and
/// domain-separated, and shaped as an RFC 9562 UUIDv8 — version nibble 8, variant
/// bits `10` — so the platform takes it as the well-formed GUID it is.
#[must_use]
pub fn adapter_guid(network: &roster::id::NetworkId) -> [u8; 16] {
    let derived = blake3::derive_key("peerfectly adapter guid v1", network.as_bytes());
    let mut guid = [0_u8; 16];
    guid.copy_from_slice(&derived[..16]);
    guid[6] = (guid[6] & 0x0f) | 0x80;
    guid[8] = (guid[8] & 0x3f) | 0x80;
    guid
}

/// The tag identifying a name-resolution rule as this daemon's.
///
/// A rule is a registry value and survives a crash, a kill and a power loss, so
/// the daemon must be able to recognise its own leftovers on the next start.
/// Without a tag it could only remove rules by suffix, which would mean deleting
/// a rule somebody else wrote for the same suffix.
pub const RULE_TAG: &str = "peerfectly-daemon-v1";

/// The key one network's resolution rule lives under.
///
/// Built from [`RULE_TAG`] so that a sweep looking for this daemon's leftovers
/// still finds every network's, and carrying the network so that bringing one up
/// does not remove another's while it is carrying traffic. That is not a
/// hypothetical: the rule used to be a single key, and a second network would
/// have written over the first.
#[must_use]
pub fn rule_key(network: &str) -> String {
    format!("{RULE_TAG}-{network}")
}

/// The longest label a person may give one of this device's networks.
///
/// It becomes the name of a folder, so the bound is about what a path and a
/// person can carry rather than about anything the protocol cares for.
pub const MAX_LABEL_LEN: usize = 64;

/// The adapter's MTU.
///
/// Below what the transport can carry, so a large packet is refused here rather
/// than failing somewhere that looks like packet loss. Verified by transferring
/// data, not by a ping — see `VERIFICATION.md`.
pub const MTU: usize = 1_280;

/// The largest packet this daemon will move in either direction.
///
/// Matches [`MTU`]. A packet above it is refused whole; no prefix of it is
/// judged, because judging the first fragment of something as though it were the
/// whole is how a truncated packet becomes a plausible-looking lie.
pub const MAX_PACKET: usize = MTU;

/// The port the resolver listens on.
///
/// The standard port, but bound on the device's own overlay address rather than
/// loopback: port 53 on loopback is contested on a desktop, and binding inside
/// the tunnel keeps the resolver unreachable while the tunnel is down.
pub const RESOLVER_PORT: u16 = 53;

/// The largest DNS message the resolver will parse.
///
/// Plain UDP DNS without EDNS0. A larger message is refused rather than parsed
/// in part.
pub const MAX_DNS_MESSAGE: usize = 512;

/// How often the daemon looks at this device's interfaces for a change that
/// could withhold a peer's IPv4 address, or stop withholding one.
///
/// A person moving a laptop to another Wi-Fi notices within this many seconds;
/// listing interfaces this often costs nothing a person would notice.
pub const INTERFACE_RECHECK: std::time::Duration = std::time::Duration::from_secs(5);

/// The largest request the control protocol carries, in bytes.
///
/// The biggest real one is `Command::Found`, whose relay certificate is DER
/// written out as a JSON array of numbers — a few kilobytes at the outside. This
/// is comfortably above anything the product sends and far below anything worth
/// holding, which is the point: a bound is not a guess at what is needed, it is
/// the line past which nothing is read.
///
/// Portable, because it is a property of the protocol. Every platform that ever
/// carries this protocol over a channel somebody else can open needs the same
/// bound, and a copy per platform is a bound that drifts.
pub const MAX_CONTROL_REQUEST: u64 = 64 * 1_024;

/// How long a connection may say nothing before it is dropped.
///
/// A client that connects and falls silent costs a connection and a task for as
/// long as it likes. This is generous for anything a program does — the request
/// is written immediately after connecting — and short enough that a wedged
/// client is gone before anybody notices.
pub const SAYS_SOMETHING_WITHIN: std::time::Duration = std::time::Duration::from_secs(10);

const _: () = {
    assert!(MAX_PACKET <= MTU, "the daemon must not accept more than the adapter carries");
    assert!(
        MAX_PACKET <= transport::limits::MAX_PACKET,
        "a full-size tunnel packet must fit the transport's packet channel"
    );
    assert!(MTU >= 1_280, "IPv6 requires a link MTU of at least 1280");
    assert!(!PRODUCT.is_empty());
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The bound exists because IPv6 requires it; a smaller one would be a bug
    /// that looks like packet loss.
    #[test]
    fn the_mtu_meets_the_ipv6_minimum() {
        const { assert!(MTU >= 1_280) };
    }

    #[test]
    fn nothing_larger_than_the_adapter_carries_is_accepted() {
        const { assert!(MAX_PACKET <= MTU) };
    }

    /// The suffix is the roster's, not ours. A constant here would violate
    /// `DESIGN.md` §0 directly, so the absence is asserted rather than assumed.
    #[test]
    fn no_suffix_is_hardcoded() {
        let code = crate::code_of(include_str!("limits.rs"));
        assert!(
            !code.contains(".internal"),
            "the network suffix is a signed roster parameter, never a constant"
        );
    }

    /// An adapter keeps one identity per network, and no two networks share one.
    #[test]
    fn a_networks_adapter_has_one_guid_of_its_own() {
        let casa = roster::id::NetworkId::from_bytes([1; 32]);
        let lavoro = roster::id::NetworkId::from_bytes([2; 32]);
        assert_eq!(adapter_guid(&casa), adapter_guid(&casa), "the same at every raise");
        assert_ne!(adapter_guid(&casa), adapter_guid(&lavoro), "and its own");

        let guid = adapter_guid(&casa);
        assert_eq!(0x80, guid[6] & 0xf0, "version 8");
        assert_eq!(0x80, guid[8] & 0xc0, "variant 10");

        // Domain-separated: not the id's plain hash, which anything else could compute
        // for another purpose and collide with.
        let plain = blake3::hash(casa.as_bytes());
        assert_ne!(&plain.as_bytes()[..16], &guid[..], "the domain string is part of it");
    }

    /// Every machine-wide identifier derives from one name, so §13.3 is one edit.
    #[test]
    fn the_identifiers_derive_from_one_name() {
        assert!(adapter_name("casa").contains(PRODUCT));
        assert!(adapter_name("casa").contains("casa"));
        assert_ne!(adapter_name("casa"), adapter_name("lavoro"));
        assert!(rule_key("casa").contains(RULE_TAG), "a sweep finds every network's");
        assert_ne!(rule_key("casa"), rule_key("lavoro"));
        assert!(RULE_TAG.contains(PRODUCT));
    }
}

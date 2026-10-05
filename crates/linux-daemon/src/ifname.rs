//! What a network's interface is called on Linux.
//!
//! `peer` and eleven hex digits of the network's adapter GUID — the same
//! domain-separated hash Windows gives its adapter, so the name is the same every
//! time a network comes up and different for every other network.
//!
//! **Not the label.** A person chooses the label, it can hold spaces and
//! anything else, and the kernel takes fifteen bytes of a restricted alphabet: a
//! label cut to fit could collide with another, and one with a slash could not be
//! an interface at all.
//!
//! Forty-four bits tell apart the networks one machine holds. The name is not a
//! security boundary: what the firewall admits is named by the whole network
//! identifier, in each rule's comment.

use roster::id::NetworkId;

/// What every interface this daemon makes begins with.
///
/// Not the product's whole name: `peerfectly` would leave five hex digits of
/// fifteen bytes, twenty bits to tell networks apart. `peer` leaves eleven.
pub const PREFIX: &str = "peer";

/// The kernel's limit: `IFNAMSIZ` is sixteen, and one of them is the terminator.
pub const MAX_LEN: usize = 15;

/// How many hex digits follow the prefix.
const DIGITS: usize = MAX_LEN - PREFIX.len();

/// The interface for a network, from its adapter GUID.
#[must_use]
pub fn from_guid(guid: &[u8; 16]) -> String {
    let hex: String = guid.iter().map(|byte| format!("{byte:02x}")).collect();
    let digits: String = hex.chars().take(DIGITS).collect();
    format!("{PREFIX}{digits}")
}

/// The interface for a network.
#[must_use]
pub fn for_network(network: &NetworkId) -> String {
    from_guid(&daemon::limits::adapter_guid(network))
}

/// Whether an interface's name is one this daemon makes.
#[must_use]
pub fn is_ours(name: &str) -> bool {
    name.len() == MAX_LEN
        && name.strip_prefix(PREFIX).is_some_and(|digits| {
            digits.chars().all(|digit| digit.is_ascii_digit() || ('a'..='f').contains(&digit))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(tag: u8) -> NetworkId {
        NetworkId::from_bytes([tag; 32])
    }

    #[test]
    fn it_fits_the_kernel_exactly() {
        let name = for_network(&network(1));
        assert_eq!(MAX_LEN, name.len(), "{name}");
        assert!(name.is_ascii(), "{name}");
    }

    #[test]
    fn the_same_network_the_same_name() {
        assert_eq!(for_network(&network(1)), for_network(&network(1)));
    }

    #[test]
    fn two_networks_two_names() {
        assert_ne!(for_network(&network(1)), for_network(&network(2)));
    }

    #[test]
    fn it_is_recognisably_ours() {
        let name = for_network(&network(3));
        assert!(name.starts_with(PREFIX), "{name}");
        assert!(is_ours(&name), "{name}");
        for theirs in ["eth0", "peer", "peer casa", "peerZZZZZZZZZZZ", "wg0", "peer0123456789ab"] {
            assert!(!is_ours(theirs), "{theirs}");
        }
    }

    /// Named from the GUID Windows gives the same network, so the two
    /// platforms agree on which network an interface is without either storing
    /// anything.
    #[test]
    fn it_is_the_windows_guid_in_hex() {
        let guid = daemon::limits::adapter_guid(&network(4));
        let name = for_network(&network(4));
        let digits = name.strip_prefix(PREFIX).unwrap_or_default();
        let first: String = guid
            .iter()
            .flat_map(|byte| format!("{byte:02x}").chars().collect::<Vec<_>>())
            .take(11)
            .collect();
        assert_eq!(first, digits);
    }
}

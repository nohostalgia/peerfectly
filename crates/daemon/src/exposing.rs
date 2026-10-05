//! Opening a service on this machine to one network, and to nothing else (F-11).
//!
//! What a rule says is decided here, where it can be tested without a firewall:
//! the port, the network's adapter, and the network's own addresses. Writing it
//! is the platform's, behind [`Exposing`]. The firewall is the only record: a
//! rule carries its network's id, so every rule of a network can be found by it,
//! whatever the network is called by then.

use std::net::Ipv6Addr;

use roster::id::NetworkId;
use roster::types::NetworkParams;
use serde::{Deserialize, Serialize};

/// The grouping every rule of this daemon carries, so its own are told apart.
pub const GROUP: &str = crate::limits::PRODUCT;

/// What begins a rule's description, before the network's id.
const DESCRIBED: &str = "peerfectly network ";

/// A transport protocol a port is opened for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl Protocol {
    /// Reads `tcp` or `udp`, in any case.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word.to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }

    /// The word, as a person types it.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    /// The IANA number, as the firewall takes it.
    #[must_use]
    pub const fn number(self) -> i32 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}

/// One port open to one network, as the firewall holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exposure {
    /// The network, by the name this machine gives it.
    pub network: String,
    /// The protocol the port is open for.
    pub protocol: Protocol,
    /// The port.
    pub port: u16,
}

/// A rule of this daemon's, as read back from the firewall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// The network the rule was written for.
    pub network: NetworkId,
    /// The protocol the port is open for.
    pub protocol: Protocol,
    /// The port.
    pub port: u16,
}

/// An inbound rule, every field decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// What a person reads in the firewall's own tools.
    pub name: String,
    /// Starts with the network's id, which is how the rule is found again.
    pub description: String,
    /// The network it opens the port to.
    pub network: NetworkId,
    /// The protocol the port is open for.
    pub protocol: Protocol,
    /// The port.
    pub port: u16,
    /// The network's adapter, by the name it is created with.
    pub interface: String,
    /// The network's own addresses, comma-separated as the firewall takes them.
    pub remote_addresses: String,
}

/// The rule opening `port` to the network, through its adapter and from its
/// addresses alone.
///
/// **Two filters, and both are kept.** The interface keeps a host on the LAN
/// that sends from a spoofed `fd..` or `100.64/10` source out; the addresses
/// still hold if the interface binding were ever lost. The network's ranges
/// rather than each member's address: nothing reaches the adapter from outside
/// the network's addresses anyway — sessions are authenticated, and a packet's
/// source must match its session — and a range needs no rewrite as members come
/// and go.
///
/// # Errors
///
/// When the port is 0, or the parameters do not describe a usable prefix.
pub fn rule_for(
    label: &str,
    network: NetworkId,
    protocol: Protocol,
    port: u16,
    params: &NetworkParams,
) -> Result<Rule, String> {
    if port == 0 {
        return Err("port 0 is not a port a service listens on".to_owned());
    }
    roster::params::unique_local_prefix(&params.ula)
        .map_err(|cause| format!("the network's prefix is not usable: {cause}"))?;
    let mut octets = [0_u8; 16];
    let (head, _) = octets.split_at_mut(params.ula.len());
    head.copy_from_slice(&params.ula);
    let prefix = format!("{}/{}", Ipv6Addr::from(octets), params.ula.len().saturating_mul(8));

    Ok(Rule {
        name: format!("{} {label} {} {port}", crate::limits::PRODUCT, protocol.word()),
        description: format!(
            "{DESCRIBED}{}: {label}, {} {port}. Opened with `peerfectly expose`; removed with the network.",
            network.to_hex(),
            protocol.word()
        ),
        network,
        protocol,
        port,
        interface: crate::limits::adapter_name(label),
        remote_addresses: format!("{prefix},{}", params.ipv4_range()),
    })
}

/// The network a rule of this daemon's was written for, read from its description.
#[must_use]
pub fn network_of(description: &str) -> Option<NetworkId> {
    let rest = description.strip_prefix(DESCRIBED)?;
    let hex = rest.split(':').next()?;
    NetworkId::from_hex(hex)
}

/// Writing rules into the machine's firewall.
///
/// Every method is the platform's whole act: a failure is the firewall's words,
/// and nothing is half-written behind it.
#[async_trait::async_trait]
pub trait Exposing: Send + Sync {
    /// Adds the rule, replacing one for the same network, protocol and port.
    async fn expose(&self, rule: &Rule) -> Result<(), String>;

    /// Removes the rule for this network, protocol and port. `false` when there
    /// was none, which is an answer and not a failure.
    async fn unexpose(
        &self,
        network: &NetworkId,
        protocol: Protocol,
        port: u16,
    ) -> Result<bool, String>;

    /// Every rule this daemon holds, whichever network it is for.
    async fn held(&self) -> Result<Vec<Held>, String>;

    /// Removes every rule of this network. How many went.
    async fn forget(&self, network: &NetworkId) -> Result<usize, String>;

    /// Removes every rule whose network is not in `kept`. How many went.
    async fn sweep(&self, kept: &[NetworkId]) -> Result<usize, String>;
}

/// A platform with no firewall rules to write: a phone, a test.
pub struct Nowhere;

/// What [`Nowhere`] answers.
pub const NOT_HERE: &str =
    "exposing a service is a desktop's: this platform has no firewall rules to write";

#[async_trait::async_trait]
impl Exposing for Nowhere {
    async fn expose(&self, _rule: &Rule) -> Result<(), String> {
        Err(NOT_HERE.to_owned())
    }
    async fn unexpose(&self, _: &NetworkId, _: Protocol, _: u16) -> Result<bool, String> {
        Err(NOT_HERE.to_owned())
    }
    async fn held(&self) -> Result<Vec<Held>, String> {
        Ok(Vec::new())
    }
    async fn forget(&self, _network: &NetworkId) -> Result<usize, String> {
        Ok(0)
    }
    async fn sweep(&self, _kept: &[NetworkId]) -> Result<usize, String> {
        Ok(0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    fn params(ipv4: Option<roster::types::Ipv4Range>) -> NetworkParams {
        let mut params =
            NetworkParams::new(vec![0xfd, 1, 2, 3, 4, 5, 6, 7], "casa.internal", 600).unwrap();
        params.ipv4 = ipv4;
        params
    }

    fn casa() -> NetworkId {
        NetworkId::from_bytes([7; 32])
    }

    #[test]
    fn a_rule_admits_the_network_through_its_adapter_and_from_its_addresses() {
        let rule = rule_for("casa", casa(), Protocol::Tcp, 8000, &params(None)).unwrap();
        assert_eq!("peerfectly casa", rule.interface, "the network's adapter, by name");
        assert_eq!(
            "fd01:203:405:607::/64,100.64.0.0/10", rule.remote_addresses,
            "its prefix and its IPv4 range, the default when none was chosen"
        );
        assert_eq!((Protocol::Tcp, 8000), (rule.protocol, rule.port));
        assert_eq!("peerfectly casa tcp 8000", rule.name);
    }

    #[test]
    fn a_chosen_ipv4_range_is_the_one_admitted() {
        let chosen = roster::types::Ipv4Range::new([10, 42, 0, 0], 16).unwrap();
        let rule = rule_for("casa", casa(), Protocol::Udp, 53, &params(Some(chosen))).unwrap();
        assert!(rule.remote_addresses.ends_with(",10.42.0.0/16"), "{}", rule.remote_addresses);
    }

    /// Found by the id, not the label: a label can be renamed, and a rule found
    /// by a name that has moved would be left behind or given to another network.
    #[test]
    fn a_rule_names_its_network_by_id() {
        let rule = rule_for("casa", casa(), Protocol::Tcp, 8000, &params(None)).unwrap();
        assert!(rule.description.contains(&casa().to_hex()));
        assert_eq!(Some(casa()), network_of(&rule.description));
        assert_eq!(None, network_of("a rule somebody else wrote"), "never another's");
    }

    #[test]
    fn port_zero_is_refused() {
        assert!(rule_for("casa", casa(), Protocol::Tcp, 0, &params(None)).is_err());
    }

    #[test]
    fn protocols_are_read_as_typed() {
        assert_eq!(Some(Protocol::Tcp), Protocol::parse("TCP"));
        assert_eq!(Some(Protocol::Udp), Protocol::parse("udp"));
        assert_eq!(None, Protocol::parse("icmp"));
        assert_eq!((6, 17), (Protocol::Tcp.number(), Protocol::Udp.number()));
    }
}

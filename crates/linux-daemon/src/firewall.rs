//! What reaches this machine from its networks: nothing, unless exposed.
//!
//! A Linux machine has no inbound firewall by default. Without this table, a
//! tunnel coming up would make every service listening on `0.0.0.0` reachable by
//! every device in the network — the opposite of what Windows does, where the
//! adapter is filtered until `peerfectly expose` opens a port.
//!
//! # One table, three chains, always written whole
//!
//! The daemon owns `table inet peerfectly` and nothing else:
//!
//! - `input` hooks the input path with policy **accept**, and only sends what
//!   arrived on one of this daemon's interfaces on to `from_networks`. Nothing
//!   else on the machine is judged here, so the table cannot break it.
//! - `from_networks` admits replies, ICMP, and the network's resolver on this
//!   device's own overlay address; then consults `exposed`; then **drops**.
//! - `exposed` holds one rule per port and address family a person opened, each
//!   with a comment naming the network by its whole identifier.
//!
//! Every change writes the whole table in one `nft -f` transaction — at start,
//! at every bring-up, and at every `expose`, `unexpose`, `forget` and sweep —
//! so it never exists half written, and a later version's rules replace an
//! earlier one's.
//!
//! # The exposures are kept in a file, not in the table
//!
//! A table lives in the kernel, and the kernel forgets it at every boot. An
//! exposure must last until it is removed or its network is forgotten, as a
//! Windows Firewall rule does, so the record is `exposed.json` in the state
//! directory — root's, `0600`, written by rename — and the table is drawn from
//! it. The testbed found this: a container restarted, which is a boot as far as
//! its network namespace is concerned, came back with its exposures gone.
//!
//! A record that cannot be read is refused, not treated as empty: an empty
//! record would quietly close every port a person opened, and a network brought
//! up on a table drawn from a guess is a network whose firewall nobody chose.
//!
//! # The tool is found at fixed places
//!
//! `nft`, from `/usr/sbin` or `/sbin`, never through a search path, with the
//! ruleset on its standard input and no shell anywhere.

use daemon::exposing::{Held, Protocol, Rule};
use roster::id::NetworkId;

use crate::ifname;

/// Where `nft` may be, and nowhere else.
pub const NFT: &[&str] = &["/usr/sbin/nft", "/sbin/nft"];

/// The table this daemon owns.
pub const TABLE: &str = "inet peerfectly";

/// The record of what is exposed, in the state directory.
pub const RECORD: &str = "exposed.json";

/// What every exposure's comment begins with, before the network's id: the
/// portable description's own start, so `exposing::network_of` reads it.
const DESCRIBED: &str = "peerfectly network ";

/// One port open to one network, as recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposed {
    /// The network, by identifier.
    pub network: NetworkId,
    /// The protocol.
    pub protocol: Protocol,
    /// The port.
    pub port: u16,
    /// The network's address ranges the port is open to.
    pub ranges: Vec<String>,
}

impl Exposed {
    /// The exposure a portable rule describes.
    ///
    /// # Errors
    ///
    /// When a range is not an address range — the portable half made it, so
    /// this would be a fault there, refused rather than written into a firewall.
    pub fn from_rule(rule: &Rule) -> Result<Self, String> {
        let ranges: Vec<String> = rule
            .remote_addresses
            .split(',')
            .map(str::trim)
            .filter(|range| !range.is_empty())
            .map(str::to_owned)
            .collect();
        if ranges.is_empty() {
            return Err("the rule names no address range".to_owned());
        }
        for range in &ranges {
            judge_range(range)?;
        }
        Ok(Self { network: rule.network, protocol: rule.protocol, port: rule.port, ranges })
    }

    /// Whether it opens the same port to the same network.
    #[must_use]
    pub fn same_port(&self, other: &Self) -> bool {
        self.network == other.network && self.protocol == other.protocol && self.port == other.port
    }

    /// As the portable half asks for it.
    #[must_use]
    pub fn held(&self) -> Held {
        Held { network: self.network, protocol: self.protocol, port: self.port }
    }
}

/// Whether a range is an address and a length, and nothing that could be read
/// as more of a ruleset.
fn judge_range(range: &str) -> Result<(), String> {
    if range.is_empty()
        || !range.chars().all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.' | '/'))
    {
        return Err(format!("`{range}` is not an address range"));
    }
    Ok(())
}

/// The comment every rule of one exposure carries.
#[must_use]
pub fn comment(network: &NetworkId, protocol: Protocol, port: u16) -> String {
    format!("{DESCRIBED}{}: {} {port}", network.to_hex(), protocol.word())
}

/// The whole table, as one transaction: created if it is not there, every
/// chain emptied, and every rule written again.
///
/// **ICMP and ICMPv6 by number** — 1 and 58 — because a name is looked up in
/// `/etc/protocols`, which a minimal system does not have: the testbed's image
/// did not, and the whole table was refused for it.
///
/// **Port 53 is admitted to overlay addresses, on our interfaces.** Nothing
/// finer is needed and nothing finer is portable: the tunnel delivers a packet
/// only when its destination is this device's own overlay address
/// (`tunnel::Tunnel::inbound`), and the resolver binds that address alone,
/// which Linux prefers to any wildcard bind — so a `dnsmasq` on `[::]:53` is
/// not what answers. `fib daddr type local` would say the same again, and is a
/// kernel module some kernels do not carry (Docker Desktop's among them).
///
/// # Errors
///
/// When a recorded range is not an address range.
pub fn table(exposed: &[Exposed]) -> Result<String, String> {
    let prefix = ifname::PREFIX;
    let mut commands = format!(
        "add table {TABLE}\n\
         add chain {TABLE} input {{ type filter hook input priority filter; policy accept; }}\n\
         add chain {TABLE} from_networks\n\
         add chain {TABLE} exposed\n\
         flush chain {TABLE} input\n\
         flush chain {TABLE} from_networks\n\
         flush chain {TABLE} exposed\n\
         add rule {TABLE} input iifname \"{prefix}*\" jump from_networks\n\
         add rule {TABLE} from_networks ct state established,related accept\n\
         add rule {TABLE} from_networks meta l4proto {{ 1, 58 }} accept\n\
         add rule {TABLE} from_networks ip6 daddr fc00::/7 udp dport 53 accept\n\
         add rule {TABLE} from_networks ip6 daddr fc00::/7 tcp dport 53 accept\n\
         add rule {TABLE} from_networks jump exposed\n\
         add rule {TABLE} from_networks drop\n"
    );
    for one in exposed {
        let interface = ifname::for_network(&one.network);
        let comment = comment(&one.network, one.protocol, one.port);
        for range in &one.ranges {
            judge_range(range)?;
            let family = if range.contains(':') { "ip6" } else { "ip" };
            commands.push_str(&format!(
                "add rule {TABLE} exposed iifname \"{interface}\" {family} saddr {range} {} dport {} accept comment \"{comment}\"\n",
                one.protocol.word(),
                one.port
            ));
        }
    }
    Ok(commands)
}

/// The record, as written to `exposed.json`.
#[must_use]
pub fn to_record(exposed: &[Exposed]) -> String {
    let entries: Vec<serde_json::Value> = exposed
        .iter()
        .map(|one| {
            serde_json::json!({
                "network": one.network.to_hex(),
                "protocol": one.protocol.word(),
                "port": one.port,
                "ranges": one.ranges,
            })
        })
        .collect();
    serde_json::Value::Array(entries).to_string()
}

/// The record, read back.
///
/// # Errors
///
/// When it is not a record this build wrote, in words naming what is wrong.
pub fn from_record(text: &str) -> Result<Vec<Exposed>, String> {
    let unreadable = |what: &str| format!("the record of exposed ports is not readable: {what}");
    let parsed: serde_json::Value =
        serde_json::from_str(text).map_err(|cause| unreadable(&cause.to_string()))?;
    let entries = parsed.as_array().ok_or_else(|| unreadable("not a list"))?;
    entries
        .iter()
        .map(|entry| {
            let network = entry
                .get("network")
                .and_then(serde_json::Value::as_str)
                .and_then(NetworkId::from_hex)
                .ok_or_else(|| unreadable("a network that is not an identifier"))?;
            let protocol = entry
                .get("protocol")
                .and_then(serde_json::Value::as_str)
                .and_then(Protocol::parse)
                .ok_or_else(|| unreadable("a protocol that is not tcp or udp"))?;
            let port = entry
                .get("port")
                .and_then(serde_json::Value::as_u64)
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .ok_or_else(|| unreadable("a port that is not a port"))?;
            let ranges: Vec<String> = entry
                .get("ranges")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| unreadable("no ranges"))?
                .iter()
                .map(|range| {
                    range
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| unreadable("a range that is not text"))
                })
                .collect::<Result<_, _>>()?;
            for range in &ranges {
                judge_range(range).map_err(|cause| unreadable(&cause))?;
            }
            Ok(Exposed { network, protocol, port, ranges })
        })
        .collect()
}

/// The record with `new` in it, replacing an exposure of the same port.
#[must_use]
pub fn with(record: &[Exposed], new: Exposed) -> Vec<Exposed> {
    let mut out: Vec<Exposed> = record.iter().filter(|one| !one.same_port(&new)).cloned().collect();
    out.push(new);
    out
}

/// The record without what `gone` picks, and how many went.
#[must_use]
pub fn without(record: &[Exposed], gone: impl Fn(&Exposed) -> bool) -> (Vec<Exposed>, usize) {
    let kept: Vec<Exposed> = record.iter().filter(|one| !gone(one)).cloned().collect();
    let removed = record.len().saturating_sub(kept.len());
    (kept, removed)
}

#[cfg(target_os = "linux")]
pub use self::calls::Nftables;

#[cfg(target_os = "linux")]
mod calls {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use daemon::exposing::{Exposing, Held, Protocol, Rule};
    use roster::id::NetworkId;

    use super::{Exposed, NFT, RECORD, from_record, table, to_record, with, without};

    /// The firewall: the record in the state directory, and the table drawn
    /// from it.
    #[derive(Debug, Clone)]
    pub struct Nftables {
        /// Where the record is.
        record: PathBuf,
    }

    impl Nftables {
        /// The firewall whose record is in `state`.
        #[must_use]
        pub fn under(state: &Path) -> Self {
            Self { record: state.join(RECORD) }
        }

        /// Writes the whole table from the record, in one transaction.
        ///
        /// # Errors
        ///
        /// When the record cannot be read, or `nft` is missing or refuses.
        pub fn ensure(&self) -> Result<(), String> {
            apply(&table(&self.read()?)?)
        }

        /// What is recorded; nothing when there is no record yet.
        fn read(&self) -> Result<Vec<Exposed>, String> {
            match std::fs::read_to_string(&self.record) {
                Ok(text) => from_record(&text),
                Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
                Err(cause) => Err(format!("{}: {cause}", self.record.display())),
            }
        }

        /// Writes the record by rename, `0600`, so it is never half written.
        fn write(&self, record: &[Exposed]) -> Result<(), String> {
            let fresh = self.record.with_extension("json.new");
            let failed = |cause: std::io::Error| format!("{}: {cause}", fresh.display());
            let _ = std::fs::remove_file(&fresh);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&fresh)
                .map_err(failed)?;
            file.write_all(to_record(record).as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(failed)?;
            std::fs::rename(&fresh, &self.record)
                .map_err(|cause| format!("{}: {cause}", self.record.display()))
        }

        /// Changes the record and the table together: the table first, and the
        /// record only once the table took it — and the table put back if the
        /// record cannot be written.
        fn change(&self, next: &[Exposed]) -> Result<(), String> {
            let before = self.read()?;
            apply(&table(next)?)?;
            if let Err(cause) = self.write(next) {
                let _ = apply(&table(&before)?);
                return Err(cause);
            }
            Ok(())
        }
    }

    /// Runs one transaction.
    fn apply(commands: &str) -> Result<(), String> {
        let tool = crate::resolved::first_present(NFT).ok_or_else(|| {
            "nftables is not installed (`nft` is in neither /usr/sbin nor /sbin); without it no \
             network can come up here, because every service on this machine would be \
             reachable from it"
                .to_owned()
        })?;
        let mut child = Command::new(&tool)
            .args(["-f", "-"])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|cause| format!("running {}: {cause}", tool.display()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| "nft took no input".to_owned())?
            .write_all(commands.as_bytes())
            .map_err(|cause| format!("writing to nft: {cause}"))?;
        let output =
            child.wait_with_output().map_err(|cause| format!("waiting for nft: {cause}"))?;
        if output.status.success() {
            return Ok(());
        }
        Err(format!("the firewall refused: {}", String::from_utf8_lossy(&output.stderr).trim()))
    }

    /// Runs a blocking firewall call off the runtime's threads.
    async fn blocking<T: Send + 'static>(
        call: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        tokio::task::spawn_blocking(call).await.map_err(|cause| cause.to_string())?
    }

    #[async_trait::async_trait]
    impl Exposing for Nftables {
        async fn expose(&self, rule: &Rule) -> Result<(), String> {
            let (firewall, new) = (self.clone(), Exposed::from_rule(rule)?);
            blocking(move || {
                let next = with(&firewall.read()?, new);
                firewall.change(&next)
            })
            .await
        }

        async fn unexpose(
            &self,
            network: &NetworkId,
            protocol: Protocol,
            port: u16,
        ) -> Result<bool, String> {
            let (firewall, network) = (self.clone(), *network);
            blocking(move || {
                let (next, removed) = without(&firewall.read()?, |one| {
                    one.network == network && one.protocol == protocol && one.port == port
                });
                if removed > 0 {
                    firewall.change(&next)?;
                }
                Ok(removed > 0)
            })
            .await
        }

        async fn held(&self) -> Result<Vec<Held>, String> {
            let firewall = self.clone();
            blocking(move || Ok(firewall.read()?.iter().map(Exposed::held).collect())).await
        }

        async fn forget(&self, network: &NetworkId) -> Result<usize, String> {
            let (firewall, network) = (self.clone(), *network);
            blocking(move || {
                let (next, removed) = without(&firewall.read()?, |one| one.network == network);
                if removed > 0 {
                    firewall.change(&next)?;
                }
                Ok(removed)
            })
            .await
        }

        async fn sweep(&self, kept: &[NetworkId]) -> Result<usize, String> {
            let (firewall, kept) = (self.clone(), kept.to_vec());
            blocking(move || {
                let (next, removed) =
                    without(&firewall.read()?, |one| !kept.contains(&one.network));
                if removed > 0 {
                    firewall.change(&next)?;
                }
                Ok(removed)
            })
            .await
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    fn network(tag: u8) -> NetworkId {
        NetworkId::from_bytes([tag; 32])
    }

    fn rule(tag: u8, protocol: Protocol, port: u16) -> Rule {
        Rule {
            name: "peerfectly casa tcp 8000".to_owned(),
            description: String::new(),
            network: network(tag),
            protocol,
            port,
            interface: "peerfectly casa".to_owned(),
            remote_addresses: "fd01:203:405:607::/64,100.64.0.0/10".to_owned(),
        }
    }

    fn exposed(tag: u8, protocol: Protocol, port: u16) -> Exposed {
        Exposed::from_rule(&rule(tag, protocol, port)).unwrap()
    }

    /// **The table's last word is `drop`**, for what arrived on our interfaces
    /// and nothing else: the hook's own policy is accept, and only our
    /// interfaces are sent to the chain that drops.
    #[test]
    fn with_nothing_exposed_everything_new_is_dropped() {
        let text = table(&[]).unwrap();
        let judged: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("add rule inet peerfectly from_networks"))
            .collect();
        assert_eq!(Some(&"add rule inet peerfectly from_networks drop"), judged.last(), "{text}");
        assert!(text.contains("policy accept"), "traffic from elsewhere is not judged here");
        assert!(text.contains("iifname \"peer*\" jump from_networks"));
        assert!(text.contains("ct state established,related accept"), "replies arrive");
        assert!(
            text.contains("meta l4proto { 1, 58 } accept"),
            "the network needs ICMP and ICMPv6"
        );
        assert!(!text.contains("icmp"), "by number: a name needs /etc/protocols");
        assert!(
            !text.contains("flush ruleset") && !text.contains("delete table"),
            "nothing else is touched"
        );
        assert!(!text.contains("add rule inet peerfectly exposed"), "nothing exposed");
    }

    /// Port 53 only to overlay addresses — the only ones the tunnel delivers
    /// to — and never IPv4, where the resolver does not listen.
    #[test]
    fn the_resolver_is_admitted_on_overlay_addresses_only() {
        let text = table(&[]).unwrap();
        let dns: Vec<&str> = text.lines().filter(|line| line.contains("dport 53")).collect();
        assert_eq!(2, dns.len(), "udp and tcp");
        for line in dns {
            assert!(line.contains("ip6 daddr fc00::/7 "), "{line}");
            assert!(!line.contains(" ip daddr"), "{line}");
        }
    }

    /// **Written whole**: every chain emptied and refilled, so what is in the
    /// kernel is exactly what is drawn, whatever was there before.
    #[test]
    fn every_chain_is_rewritten() {
        let text = table(&[exposed(1, Protocol::Tcp, 8000)]).unwrap();
        for chain in ["input", "from_networks", "exposed"] {
            let flushed = text.find(&format!("flush chain inet peerfectly {chain}\n")).unwrap();
            let refilled = text.find(&format!("add rule inet peerfectly {chain} ")).unwrap();
            assert!(flushed < refilled, "{chain}");
        }
    }

    #[test]
    fn one_port_is_one_rule_per_address_family_on_its_interface() {
        let text = table(&[exposed(1, Protocol::Tcp, 8000)]).unwrap();
        let lines: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("add rule inet peerfectly exposed"))
            .collect();
        assert_eq!(2, lines.len(), "{text}");
        let interface = ifname::for_network(&network(1));
        assert!(lines.iter().all(|line| line.contains(&format!("iifname \"{interface}\""))));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("ip6 saddr fd01:203:405:607::/64 tcp dport 8000"))
        );
        assert!(lines.iter().any(|line| line.contains("ip saddr 100.64.0.0/10 tcp dport 8000")));
    }

    /// The comment names the network whole, and the portable reader agrees.
    #[test]
    fn the_comment_names_the_network_whole() {
        let written = comment(&network(9), Protocol::Udp, 5353);
        assert!(written.contains(&network(9).to_hex()), "the whole identifier: {written}");
        assert!(written.len() < 128, "nft keeps comments up to 128 bytes: {}", written.len());
        assert_eq!(Some(network(9)), daemon::exposing::network_of(&written));
    }

    #[test]
    fn a_range_that_is_not_one_is_refused() {
        let mut bad = rule(1, Protocol::Tcp, 22);
        bad.remote_addresses = "fd00::/8; flush ruleset".to_owned();
        assert!(Exposed::from_rule(&bad).is_err());
        bad.remote_addresses = String::new();
        assert!(Exposed::from_rule(&bad).is_err());
    }

    /// **The record survives what the kernel forgets**, and reads back as it
    /// was written.
    #[test]
    fn the_record_round_trips() {
        let record = vec![exposed(1, Protocol::Tcp, 8000), exposed(2, Protocol::Udp, 5353)];
        assert_eq!(record, from_record(&to_record(&record)).unwrap());
        assert_eq!(Vec::<Exposed>::new(), from_record("[]").unwrap());
    }

    /// A record that cannot be read is refused, never taken as empty: empty
    /// would close every port a person opened, without a word.
    #[test]
    fn an_unreadable_record_is_refused_and_not_emptied() {
        for bad in [
            "not json",
            "{}",
            r#"[{"network":"zz","protocol":"tcp","port":80,"ranges":["fd00::/8"]}]"#,
            &format!(
                r#"[{{"network":"{}","protocol":"icmp","port":80,"ranges":["fd00::/8"]}}]"#,
                network(1).to_hex()
            ),
            &format!(
                r#"[{{"network":"{}","protocol":"tcp","port":0,"ranges":["fd00::/8"]}}]"#,
                network(1).to_hex()
            ),
            &format!(
                r#"[{{"network":"{}","protocol":"tcp","port":80,"ranges":["fd00::/8 accept"]}}]"#,
                network(1).to_hex()
            ),
        ] {
            assert!(from_record(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn exposing_again_replaces_and_forgetting_removes() {
        let record = with(&[], exposed(1, Protocol::Tcp, 8000));
        let record = with(&record, exposed(1, Protocol::Tcp, 8000));
        assert_eq!(1, record.len(), "the same port, once");
        let record = with(&record, exposed(1, Protocol::Udp, 8000));
        let record = with(&record, exposed(2, Protocol::Tcp, 8000));
        assert_eq!(3, record.len());
        let (kept, removed) = without(&record, |one| one.network == network(1));
        assert_eq!((1, 2), (kept.len(), removed));
    }

    /// The tool is looked for at fixed places, never through `PATH`, and the
    /// ruleset goes on its input rather than through a shell.
    #[test]
    fn the_tool_is_never_found_through_the_path() {
        assert!(NFT.iter().all(|place| place.starts_with('/')));
        let code =
            include_str!("firewall.rs").split("#[cfg(test)]\n#[allow").next().unwrap_or_default();
        assert!(!code.contains("Command::new(\"nft\")"));
        assert!(!code.contains("\"sh\"") && !code.contains("\"bash\""), "no shell");
        assert!(code.contains(".env_clear()"));
    }
}

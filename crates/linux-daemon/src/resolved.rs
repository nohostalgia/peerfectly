//! Names under a network's suffix, through systemd-resolved.
//!
//! Three settings on the network's own interface, with `resolvectl`:
//!
//! 1. the network's resolver as that link's DNS server;
//! 2. `~suffix` as its domain — the `~` makes it a **routing-only** domain: names
//!    under it go to that link, and it is added to no search list;
//! 3. `default-route false`, so no other name is ever sent to the link.
//!
//! They belong to the interface and go when it goes. The interface goes with the
//! daemon (see [`crate::tun`]), so a crash leaves no setting pointing at a
//! resolver that is not running — which is why there is nothing to sweep.
//!
//! # When systemd-resolved is not in use
//!
//! The network comes up without names, and `peerfectly status` says so. Nothing
//! machine-wide is rewritten: `/etc/resolv.conf` belongs to whoever manages it,
//! and a daemon that rewrote it would leave the whole machine without DNS the
//! first time it crashed.
//!
//! # The tools are found at fixed places
//!
//! Never through a search path: this runs as root, and a `PATH` is the caller's
//! choice of what runs.

use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};

/// Where `resolvectl` may be, and nowhere else.
pub const RESOLVECTL: &[&str] = &["/usr/bin/resolvectl", "/bin/resolvectl"];

/// Where systemd-resolved keeps what it serves.
pub const RUNTIME: &str = "/run/systemd/resolve";

/// What glibc reads.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";

/// The stub resolver's address.
const STUB: &str = "127.0.0.53";

/// The three calls that route a suffix to a link, in order.
#[must_use]
pub fn routing(interface: &str, nameserver: Ipv6Addr, suffix: &str) -> [Vec<String>; 3] {
    let suffix = suffix.trim().trim_matches('.');
    [
        vec!["dns".to_owned(), interface.to_owned(), nameserver.to_string()],
        vec!["domain".to_owned(), interface.to_owned(), format!("~{suffix}")],
        vec!["default-route".to_owned(), interface.to_owned(), "false".to_owned()],
    ]
}

/// The call that undoes all three.
#[must_use]
pub fn reverting(interface: &str) -> Vec<String> {
    vec!["revert".to_owned(), interface.to_owned()]
}

/// What `/etc/resolv.conf` turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvConf {
    /// A symbolic link, to here.
    Link(PathBuf),
    /// A file, holding this.
    Text(String),
    /// Nothing there.
    Missing,
}

/// What was found on the machine, for [`in_use`] to judge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// Where `resolvectl` is, if at one of the fixed places.
    pub resolvectl: Option<PathBuf>,
    /// Whether systemd-resolved's runtime directory exists.
    pub running: bool,
    /// What glibc will read.
    pub resolv_conf: ResolvConf,
}

impl Found {
    /// Looks at this machine.
    #[must_use]
    pub fn here() -> Self {
        let resolv_conf = match std::fs::read_link(RESOLV_CONF) {
            Ok(target) => ResolvConf::Link(target),
            Err(_) => {
                std::fs::read_to_string(RESOLV_CONF).map_or(ResolvConf::Missing, ResolvConf::Text)
            }
        };
        Self {
            resolvectl: first_present(RESOLVECTL),
            running: Path::new(RUNTIME).is_dir(),
            resolv_conf,
        }
    }
}

/// The first of these that exists.
#[must_use]
pub fn first_present(candidates: &[&str]) -> Option<PathBuf> {
    candidates.iter().map(PathBuf::from).find(|path| path.is_file())
}

/// Why names will not resolve here, or `None` when systemd-resolved is in use.
///
/// **In use** means all three: the tool is there, the service is running, and
/// glibc asks it. The last is the one that is easy to miss — with resolved
/// running and `/etc/resolv.conf` written by something else, a routing domain is
/// set and nothing ever consults it.
#[must_use]
pub fn not_in_use(found: &Found) -> Option<&'static str> {
    if found.resolvectl.is_none() {
        return Some("`resolvectl` is not installed");
    }
    if !found.running {
        return Some("systemd-resolved is not running");
    }
    let asks_resolved = match &found.resolv_conf {
        ResolvConf::Link(target) => {
            target.starts_with(RUNTIME) || target.starts_with("../run/systemd/resolve")
        }
        ResolvConf::Text(text) => text.lines().any(|line| {
            let mut words = line.split_whitespace();
            words.next() == Some("nameserver") && words.next() == Some(STUB)
        }),
        ResolvConf::Missing => false,
    };
    if !asks_resolved {
        return Some("/etc/resolv.conf does not send names to systemd-resolved");
    }
    None
}

/// The sentence `peerfectly status` prints when names will not resolve here.
///
/// For every network at once: what is missing is the machine's, not any one
/// network's, and the command line prints it after the report without having
/// to name each suffix again.
#[must_use]
pub fn status_line(why: &str) -> String {
    format!(
        "Names under this machine's networks will not resolve here: {why}. The networks \
         carry traffic without them; install and enable systemd-resolved for names."
    )
}

#[cfg(target_os = "linux")]
pub use self::calls::{install, revert};

#[cfg(target_os = "linux")]
mod calls {
    use std::net::Ipv6Addr;
    use std::process::Command;

    use super::{Found, not_in_use, reverting, routing};

    /// Routes the suffix to the link. `Ok(false)` when systemd-resolved is not in
    /// use, which is not a failure: the network comes up without names, and
    /// status says so.
    ///
    /// # Errors
    ///
    /// When systemd-resolved is in use and refuses, with its words.
    pub fn install(interface: &str, nameserver: Ipv6Addr, suffix: &str) -> Result<bool, String> {
        let found = Found::here();
        if let Some(why) = not_in_use(&found) {
            tracing::warn!(why, "names under this network's suffix will not resolve");
            return Ok(false);
        }
        let Some(tool) = found.resolvectl else { return Ok(false) };
        for arguments in routing(interface, nameserver, suffix) {
            run(&tool, &arguments)?;
        }
        Ok(true)
    }

    /// Undoes the routing. An interface that is already gone has nothing to
    /// undo, and that is not an error.
    ///
    /// # Errors
    ///
    /// When systemd-resolved refuses for an interface that exists.
    pub fn revert(interface: &str) -> Result<(), String> {
        let Some(tool) = Found::here().resolvectl else { return Ok(()) };
        if !std::path::Path::new(&format!("/sys/class/net/{interface}")).exists() {
            return Ok(());
        }
        run(&tool, &reverting(interface))
    }

    /// One call, its failure in its own words.
    fn run(tool: &std::path::Path, arguments: &[String]) -> Result<(), String> {
        let output = Command::new(tool)
            .args(arguments)
            .env_clear()
            .output()
            .map_err(|cause| format!("running {}: {cause}", tool.display()))?;
        if output.status.success() {
            return Ok(());
        }
        Err(format!(
            "`resolvectl {}` failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    fn found(resolv_conf: ResolvConf) -> Found {
        Found { resolvectl: Some(PathBuf::from("/usr/bin/resolvectl")), running: true, resolv_conf }
    }

    /// **Only the suffix, and never the default.** The `~` makes the domain a
    /// route and not a search entry; `default-route false` keeps every other
    /// name off the link.
    #[test]
    fn the_suffix_is_routed_and_nothing_else() {
        let [dns, domain, default] =
            routing("peer0123456789a", "fd01::1".parse().unwrap(), ".casa.internal.");
        assert_eq!(["dns", "peer0123456789a", "fd01::1"], dns.as_slice());
        assert_eq!(["domain", "peer0123456789a", "~casa.internal"], domain.as_slice());
        assert_eq!(["default-route", "peer0123456789a", "false"], default.as_slice());
        assert_eq!(["revert", "peer0123456789a"], reverting("peer0123456789a").as_slice());
    }

    #[test]
    fn a_link_into_resolved_is_in_use() {
        for target in [
            "/run/systemd/resolve/stub-resolv.conf",
            "/run/systemd/resolve/resolv.conf",
            "../run/systemd/resolve/stub-resolv.conf",
        ] {
            assert_eq!(
                None,
                not_in_use(&found(ResolvConf::Link(PathBuf::from(target)))),
                "{target}"
            );
        }
    }

    #[test]
    fn a_file_naming_the_stub_is_in_use() {
        let text = "# managed\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n";
        assert_eq!(None, not_in_use(&found(ResolvConf::Text(text.to_owned()))));
    }

    /// Running, and not asked: the routing domain would be set and consulted by
    /// nobody.
    #[test]
    fn another_resolver_is_not_in_use() {
        let text = "nameserver 192.168.1.1\n";
        assert!(not_in_use(&found(ResolvConf::Text(text.to_owned()))).is_some());
        assert!(
            not_in_use(&found(ResolvConf::Link(PathBuf::from("/run/NetworkManager/resolv.conf"))))
                .is_some()
        );
        assert!(not_in_use(&found(ResolvConf::Missing)).is_some());
    }

    #[test]
    fn without_the_tool_or_the_service_it_is_not_in_use() {
        let stub = ResolvConf::Text("nameserver 127.0.0.53\n".to_owned());
        let mut without_tool = found(stub.clone());
        without_tool.resolvectl = None;
        assert_eq!(Some("`resolvectl` is not installed"), not_in_use(&without_tool));
        let mut stopped = found(stub);
        stopped.running = false;
        assert_eq!(Some("systemd-resolved is not running"), not_in_use(&stopped));
    }

    /// The tool is looked for at fixed places, never through `PATH`.
    #[test]
    fn the_tool_is_never_found_through_the_path() {
        assert!(RESOLVECTL.iter().all(|place| place.starts_with('/')));
        let code =
            include_str!("resolved.rs").split("#[cfg(test)]\n#[allow").next().unwrap_or_default();
        assert!(!code.contains("Command::new(\"resolvectl\")"), "a bare name is a PATH lookup");
        assert!(code.contains(".env_clear()"), "and the caller's environment is not handed on");
    }

    #[test]
    fn the_status_line_names_what_is_missing_and_the_remedy() {
        let line = status_line("systemd-resolved is not running");
        assert!(line.contains("systemd-resolved is not running"));
        assert!(line.contains("install and enable systemd-resolved"));
        assert!(line.contains("carry traffic"), "the tunnel works without it");
    }
}

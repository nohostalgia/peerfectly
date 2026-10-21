//! A relay, as a person types it and the roster signs it: `key@host:port`.
//!
//! convesso trusts a relay by its key and nothing else (`PROTOCOL.md §6`), and
//! a key cannot be learned from the relay: with Noise IK the dialler must know
//! it before its first packet, and a relay answers nobody who does not. So the
//! key is written with the address, in one string that the roster signs as it
//! is and a join payload carries as it is. Nothing is fetched, and nothing is
//! accepted on sight.
//!
//! ```text
//! <64 hexadecimal digits>@host:port
//! tls://<64 hexadecimal digits>@host:port     a link wrapped in TLS
//! ```
//!
//! The key is written as the convesso relay prints it when it starts. TLS is
//! camouflage for networks that let only TLS out; it authenticates nothing.

use core::fmt;

use convesso_core::identity::Address;
use convesso_tokio::RelayLocation;

/// The prefix of a relay whose link is wrapped in TLS.
pub const TLS_PREFIX: &str = "tls://";

/// The form a relay is written in, for a person reading a refusal.
pub const FORM: &str = "<key>@host:port, or tls://<key>@host:port, where <key> is the 64 \
                        hexadecimal digits the convesso relay prints when it starts";

/// Why a string is not a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// A scheme other than `tls://`, such as an `https://` URL.
    Scheme,
    /// No key in front of the address.
    NoKey,
    /// The key is not one.
    Key(String),
    /// The address is not `host:port`.
    Address(String),
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scheme => write!(f, "a relay is written {FORM}"),
            Self::NoKey => write!(f, "the relay's key is missing: a relay is written {FORM}"),
            Self::Key(reason) => write!(f, "the relay's key is unusable: {reason}"),
            Self::Address(reason) => write!(f, "the relay's address is unusable: {reason}"),
        }
    }
}

impl std::error::Error for RelayError {}

/// Reads a relay.
///
/// # Errors
///
/// When the string is not of the form [`FORM`], naming the part that is wrong.
pub fn parse(text: &str) -> Result<RelayLocation, RelayError> {
    let (rest, tls) = match text.strip_prefix(TLS_PREFIX) {
        Some(rest) => (rest, true),
        None => (text, false),
    };
    if rest.contains("://") {
        return Err(RelayError::Scheme);
    }
    let (key, host) = rest.split_once('@').ok_or(RelayError::NoKey)?;
    let address = key_of(key)?;
    host_and_port(host)?;
    Ok(RelayLocation { address, host: host.to_owned(), tls })
}

/// The string a relay is written as.
#[must_use]
pub fn written(key: &[u8; 32], host: &str, tls: bool) -> String {
    let prefix = if tls { TLS_PREFIX } else { "" };
    format!("{prefix}{}@{host}", hex::encode(key))
}

/// Whether two strings name the same relay: the same key, the same host
/// compared without regard to case or a trailing dot, the same port, and the
/// same use of TLS. Nothing is resolved, and a string that is not a relay is
/// the same as nothing.
#[must_use]
pub fn same(one: &str, other: &str) -> bool {
    let (Ok(one), Ok(other)) = (parse(one), parse(other)) else { return false };
    let (Ok((one_host, one_port)), Ok((other_host, other_port))) =
        (host_and_port(&one.host), host_and_port(&other.host))
    else {
        return false;
    };
    one.address == other.address
        && folded(one_host) == folded(other_host)
        && one_port == other_port
        && one.tls == other.tls
}

/// A host as compared: lower case, without a trailing dot.
fn folded(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// The key, from its 64 hexadecimal digits.
fn key_of(text: &str) -> Result<Address, RelayError> {
    if text.len() != 64 {
        return Err(RelayError::Key(format!(
            "it is {} characters, and a key is 64 hexadecimal digits",
            text.len()
        )));
    }
    let bytes = hex::decode(text)
        .map_err(|_| RelayError::Key("it is not hexadecimal digits".to_owned()))?;
    let bytes: [u8; 32] =
        bytes.try_into().map_err(|_| RelayError::Key("it is not 32 bytes".to_owned()))?;
    Address::parse(bytes).map_err(|cause| RelayError::Key(cause.to_string()))
}

/// The host and the port of `host:port`, or `[address]:port` for IPv6.
fn host_and_port(text: &str) -> Result<(&str, u16), RelayError> {
    let (host, port) = text
        .rsplit_once(':')
        .ok_or_else(|| RelayError::Address(format!("{text:?} has no port")))?;
    let host = host.strip_prefix('[').and_then(|inner| inner.strip_suffix(']')).unwrap_or(host);
    if host.is_empty() || host.contains(['/', '@', ' ']) {
        return Err(RelayError::Address(format!("{text:?} has no usable host")));
    }
    let port: u16 = port
        .parse()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| RelayError::Address(format!("{port:?} is not a port")))?;
    Ok((host, port))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "a test reports failure by panicking")]
mod tests {
    use convesso_core::identity::Identity;

    use super::*;

    fn key(seed: u8) -> [u8; 32] {
        *Identity::from_ed25519_seed(&[seed; 32]).unwrap().address().as_bytes()
    }

    #[test]
    fn both_forms_read() {
        let plain = parse(&written(&key(1), "relay.example:7400", false)).unwrap();
        assert_eq!((plain.host.as_str(), plain.tls), ("relay.example:7400", false));
        assert_eq!(plain.address.as_bytes(), &key(1));
        let wrapped = parse(&written(&key(1), "relay.example:443", true)).unwrap();
        assert_eq!((wrapped.host.as_str(), wrapped.tls), ("relay.example:443", true));
        let six = parse(&written(&key(1), "[2001:db8::1]:7400", false)).unwrap();
        assert_eq!(six.host, "[2001:db8::1]:7400");
    }

    #[test]
    fn a_key_that_is_not_one_is_refused_naming_the_key() {
        let short = format!("{}@relay.example:7400", &hex::encode(key(1))[..60]);
        assert!(matches!(parse(&short), Err(RelayError::Key(_))));
        let not_hex = format!("{}@relay.example:7400", "z".repeat(64));
        assert!(matches!(parse(&not_hex), Err(RelayError::Key(_))));
        // Not a point of the curve: an address convesso refuses.
        let not_a_point = format!("{}@relay.example:7400", "ff".repeat(32));
        assert!(matches!(parse(&not_a_point), Err(RelayError::Key(_))));
        assert!(parse(&short).unwrap_err().to_string().contains("key"));
    }

    #[test]
    fn an_address_without_a_port_is_refused() {
        let text = format!("{}@relay.example", hex::encode(key(1)));
        assert!(matches!(parse(&text), Err(RelayError::Address(_))));
        let zero = format!("{}@relay.example:0", hex::encode(key(1)));
        assert!(matches!(parse(&zero), Err(RelayError::Address(_))));
    }

    #[test]
    fn a_relay_with_another_scheme_is_refused_saying_how_one_is_written() {
        let refused = parse("https://relay.example:443").unwrap_err();
        assert_eq!(refused, RelayError::Scheme);
        assert!(refused.to_string().contains("tls://<key>@host:port"));
        assert_eq!(parse("relay.example:7400"), Err(RelayError::NoKey));
    }

    #[test]
    fn the_same_relay_is_the_same_in_any_case() {
        let ours = written(&key(1), "Relay.Example.:7400", false);
        assert!(same(&ours, &written(&key(1), "relay.example:7400", false)));
        assert!(!same(&ours, &written(&key(2), "relay.example:7400", false)), "another key");
        assert!(!same(&ours, &written(&key(1), "relay.example:7401", false)), "another port");
        assert!(!same(&ours, &written(&key(1), "relay.example:7400", true)), "TLS");
        assert!(!same(&ours, "relay.example:7400"), "not a relay");
    }
}

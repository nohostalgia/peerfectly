//! Which relays a node uses at a given moment, and how each one is verified.
//!
//! Almost always one: the relay the network's parameters name. During a move
//! there are two — the relay, and the relay being left — because a node that was
//! switched off when the relay moved wakes knowing only the old one, and must
//! find somebody there to learn the change from.
//!
//! # Each relay is verified the way its network said
//!
//! A relay the network pinned is verified against that certificate and nothing
//! else; one it did not is verified the way any unpinned relay is. With one relay
//! that is one trust store. With two it cannot be: pin only one and the other
//! becomes unreachable, add the public authorities to the pin and anyone who can
//! get a certificate for the pinned relay's name can stand in front of it.
//!
//! So during a move the verifier is **chosen by host**. Each relay keeps exactly
//! the rule it had, and a host that is neither is refused — `presets::Minimal`
//! speaks TLS to nothing but relays, so there is nothing else for it to reach.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use iroh::RelayUrl;
use iroh::tls::CaTlsConfig;
use roster::types::NetworkParams;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

use crate::error::{BuildError, Result};

/// One relay, and the certificate the network pinned for it, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Relay {
    /// Where it is.
    pub url: RelayUrl,
    /// What it must present, where the network pinned it.
    pub pinned: Option<Vec<u8>>,
}

/// The relays in use at `now`, milliseconds since the epoch.
///
/// The relay first, then the relay being left while its transition lasts. Past
/// the end the relay being left is not here, whatever the parameters still say:
/// the end is the rule, and nothing has to be signed for a move to finish.
///
/// # Errors
///
/// When an address is not a usable relay URL.
pub(crate) fn relays_at(params: &NetworkParams, now: u64) -> Result<Vec<Relay>> {
    let mut relays = Vec::new();
    if let Some(address) = params.relay.as_deref() {
        relays.push(Relay { url: parsed(address)?, pinned: params.relay_cert.clone() });
    }
    if let Some(leaving) = params.leaving_at(now) {
        relays.push(Relay { url: parsed(&leaving.relay)?, pinned: leaving.relay_cert.clone() });
    }
    Ok(relays)
}

/// The relay a node lives on at `now`: the relay being left while a move
/// lasts, the relay otherwise.
///
/// **Everybody on the old relay until the end, then everybody on the new one.**
/// A node lives on one relay at a time and is reachable there, and elsewhere
/// only while it happens to be using it — `iroh` picks that relay by latency
/// from its map and drops any other after a minute idle. So the map holds this
/// relay alone. With both in it, each node would home on whichever answered
/// faster, and a device waking on the old relay would find whoever happened to
/// be there rather than everybody.
pub(crate) fn home_at(params: &NetworkParams, now: u64) -> Result<Option<Relay>> {
    if let Some(leaving) = params.leaving_at(now) {
        return Ok(Some(Relay {
            url: parsed(&leaving.relay)?,
            pinned: leaving.relay_cert.clone(),
        }));
    }
    match params.relay.as_deref() {
        Some(address) => {
            Ok(Some(Relay { url: parsed(address)?, pinned: params.relay_cert.clone() }))
        }
        None => Ok(None),
    }
}

/// The relay map: the home relay alone, or disabled where there is none.
///
/// The QUIC address-discovery port is the relay's own URL's port rather than
/// the library default — see the note in `node` on why a relay served on 443
/// would otherwise never be asked, and every connection would stay relayed.
pub(crate) fn relay_mode(home: Option<&Relay>) -> iroh::endpoint::RelayMode {
    match home {
        None => iroh::endpoint::RelayMode::Disabled,
        Some(relay) => {
            let port = relay.url.port_or_known_default().unwrap_or(443);
            iroh::endpoint::RelayMode::Custom(iroh::RelayMap::from(iroh::RelayConfig::new(
                relay.url.clone(),
                Some(iroh_relay::RelayQuicConfig::new(port)),
            )))
        }
    }
}

/// How often an endpoint pings its relay while the connection is quiet.
///
/// A minute rather than iroh's fifteen seconds. The ping keeps the relay
/// connection open through NATs, and that connection is how a device nobody has
/// dialled is reached; it also notices one that died without a word. At fifteen
/// seconds it cost every device about 60 MB a month at rest, measured on
/// 2026-10-07; a minute is about 15. The connection is TCP, which carriers keep
/// for minutes at the least, and a minute is what Tailscale's relay keeps its
/// connections alive at. What it costs is a dead relay connection noticed within
/// about a minute rather than fifteen seconds; a change of network is acted on at
/// once, as before.
///
/// The relay pings on its own schedule too, and `deploy/server/relay.toml` sets
/// it to the same minute: at its default, the relay's pings would set the pace.
pub(crate) const RELAY_PING_INTERVAL: Duration = Duration::from_secs(60);

/// What an endpoint spends at rest. Every endpoint this crate builds starts here.
///
/// The net report pauses while no connection is open: it learns this device's
/// public address and keeps its NAT mapping warm for a connection to use, and
/// with none open each run was a round trip to the relay every twenty-odd
/// seconds, about 950 MB a month (2026-10-07). It runs again when a connection is
/// dialled or accepted, and on a change of network.
///
/// It keeps its HTTPS latency probes, although a network has one relay and
/// nothing to choose between. Without them, a network where QUIC to the relay
/// gets no answer (one that blocks UDP) never picks a home relay, and the device
/// is left with no relay at all where it needs one most. `minimal()` did that;
/// the binding tests caught it, their relay answering QUIC on another port.
pub(crate) fn quiet_at_rest(builder: iroh::endpoint::Builder) -> iroh::endpoint::Builder {
    let mut net_report = iroh::endpoint::NetReportConfig::default();
    net_report.pause_when_idle = true;
    builder.net_report_config(net_report).relay_ping_interval(RELAY_PING_INTERVAL)
}

/// Now, in milliseconds since the epoch — the clock a move's end is dated by.
///
/// A clock before the epoch reads as the epoch, which reads every transition
/// as still running: the direction that keeps a node where the network is.
#[must_use]
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
}

fn parsed(address: &str) -> Result<RelayUrl> {
    address.parse().map_err(|_| BuildError::UnusableRelay { address: address.to_owned() })
}

/// How the relays' certificates are verified, or `None` for the default.
///
/// * No relay pinned: `None`, which is what an unpinned network has always had.
/// * One relay, pinned: its certificate alone — exactly what it was before moves
///   existed.
/// * Two relays, either pinned: a verifier chosen by host, so each keeps its own
///   rule.
///
/// # Errors
///
/// When a pinned certificate cannot become a trust anchor.
pub(crate) fn tls_for(relays: &[Relay]) -> Result<Option<CaTlsConfig>> {
    match relays {
        [] => Ok(None),
        [only] => match &only.pinned {
            Some(certificate) => crate::node::pinned_roots(certificate).map(Some),
            None => Ok(None),
        },
        _ if relays.iter().all(|relay| relay.pinned.is_none()) => Ok(None),
        _ => {
            // Checked here, where it can be refused, rather than inside the
            // builder where an unusable pin would surface as a failed dial.
            for relay in relays {
                if let Some(certificate) = &relay.pinned {
                    crate::node::pinned_roots(certificate)?;
                }
            }
            let relays = relays.to_vec();
            Ok(Some(CaTlsConfig::custom_server_cert_verifier(Arc::new(move |provider| {
                let mut hosts = Vec::new();
                for relay in &relays {
                    let config = match &relay.pinned {
                        Some(certificate) => {
                            CaTlsConfig::custom_roots([CertificateDer::from(certificate.clone())])
                        }
                        None => CaTlsConfig::default(),
                    };
                    let verifier = config.server_cert_verifier(Arc::clone(&provider))?;
                    hosts.push((Host::of(&relay.url), verifier));
                }
                Ok(Arc::new(ByHost { hosts }) as Arc<dyn ServerCertVerifier>)
            }))))
        }
    }
}

/// A relay's host, as a server name will be compared against it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Host {
    Name(String),
    Address(IpAddr),
}

impl Host {
    fn of(url: &RelayUrl) -> Self {
        match url.host() {
            Some(url::Host::Ipv4(address)) => Self::Address(IpAddr::V4(address)),
            Some(url::Host::Ipv6(address)) => Self::Address(IpAddr::V6(address)),
            Some(url::Host::Domain(name)) => Self::Name(normal(name)),
            None => Self::Name(String::new()),
        }
    }

    fn matches(&self, name: &ServerName<'_>) -> bool {
        match (self, name) {
            (Self::Name(ours), ServerName::DnsName(theirs)) => *ours == normal(theirs.as_ref()),
            (Self::Address(ours), ServerName::IpAddress(theirs)) => *ours == IpAddr::from(*theirs),
            _ => false,
        }
    }
}

/// A host name as compared: case-folded, a trailing dot dropped.
fn normal(name: &str) -> String {
    let name = name.to_ascii_lowercase();
    name.strip_suffix('.').map_or(name.clone(), str::to_owned)
}

/// Verifies each relay with the verifier its network chose for it.
#[derive(Debug)]
struct ByHost {
    hosts: Vec<(Host, Arc<dyn ServerCertVerifier>)>,
}

impl ByHost {
    /// Any of them, for what does not depend on the host: signature checks are
    /// the provider's, and every verifier here was built on the same one.
    fn any(&self) -> Option<&Arc<dyn ServerCertVerifier>> {
        self.hosts.first().map(|(_, verifier)| verifier)
    }
}

impl ServerCertVerifier for ByHost {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> core::result::Result<ServerCertVerified, rustls::Error> {
        // **Every rule for this host, not the first.** TLS carries no port, so
        // two relays on one machine — 443 and 8443 — share a server name, and
        // the first rule alone refused the second relay's own certificate: the
        // move would have lost everybody at its end. One host is one party, so
        // a certificate either of its relays would accept is accepted.
        let mut refused = None;
        for (_, verifier) in self.hosts.iter().filter(|(host, _)| host.matches(server_name)) {
            match verifier.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ) {
                Ok(verified) => return Ok(verified),
                Err(cause) => {
                    refused.get_or_insert(cause);
                }
            }
        }
        Err(refused
            .unwrap_or_else(|| rustls::Error::General("not a relay this network uses".to_owned())))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        let verifier = self.any().ok_or_else(|| rustls::Error::General("no relay".to_owned()))?;
        verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        let verifier = self.any().ok_or_else(|| rustls::Error::General("no relay".to_owned()))?;
        verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.any().map(|verifier| verifier.supported_verify_schemes()).unwrap_or_default()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// Every endpoint this crate builds goes through `quiet_at_rest`: one that did
    /// not would keep iroh's defaults, about a gigabyte a month at rest.
    #[test]
    fn every_endpoint_is_quiet_at_rest() {
        for (file, source) in
            [("node.rs", include_str!("node.rs")), ("enrolment.rs", include_str!("enrolment.rs"))]
        {
            let built = source.matches("Endpoint::builder(").count();
            let quiet = source.matches("quiet_at_rest(Endpoint::builder(").count();
            assert!(built > 0, "{file} builds an endpoint");
            assert_eq!(built, quiet, "every endpoint {file} builds is quiet at rest");
        }
    }

    /// The relay's own pings follow the devices': at iroh's default they would
    /// set the pace, and a device's minute would save nothing.
    #[test]
    fn the_relay_pings_as_seldom_as_the_devices() {
        let config = include_str!("../../../deploy/server/relay.toml");
        let line = format!("ping_interval_secs = {}", RELAY_PING_INTERVAL.as_secs());
        assert!(config.lines().any(|l| l.trim() == line), "deploy/server/relay.toml says `{line}`");
    }

    const ISSUED: u64 = 1_000;
    const WINDOW_S: u64 = 604_800;
    const END: u64 = ISSUED + WINDOW_S * 1_000;

    fn moving(pin_old: Option<Vec<u8>>, pin_new: Option<Vec<u8>>) -> NetworkParams {
        let before = NetworkParams::with_relay(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            Some("https://old.example:443"),
            "casa.internal",
            WINDOW_S,
        )
        .unwrap();
        let before = match pin_old {
            Some(certificate) => before.pinning(certificate).unwrap(),
            None => before,
        };
        before.moving_to("https://new.example:443", pin_new, ISSUED).unwrap()
    }

    fn host(relay: &Relay) -> String {
        relay.url.host_str().unwrap_or_default().trim_end_matches('.').to_owned()
    }

    /// **Everybody lives on the old relay until the end, then on the new one.**
    #[test]
    fn a_node_lives_on_the_relay_being_left_until_the_end() {
        let params = moving(None, None);

        let during = home_at(&params, END - 1).unwrap().unwrap();
        assert_eq!("old.example", host(&during), "on the old one while the move lasts");

        let after = home_at(&params, END).unwrap().unwrap();
        assert_eq!("new.example", host(&after), "and on the new one at the end");
    }

    /// Both are in use during a move — dialled and trusted — and one after.
    #[test]
    fn both_relays_are_in_use_during_a_move_and_one_after() {
        let params = moving(None, None);
        let during: Vec<String> = relays_at(&params, END - 1).unwrap().iter().map(host).collect();
        assert_eq!(vec!["new.example", "old.example"], during);

        let after: Vec<String> = relays_at(&params, END).unwrap().iter().map(host).collect();
        assert_eq!(vec!["new.example"], after, "the end is the rule");
    }

    /// The map holds the home relay alone: with both, each node would home on
    /// whichever answered faster.
    #[test]
    fn the_map_holds_the_home_relay_alone() {
        let params = moving(None, None);
        let home = home_at(&params, END - 1).unwrap();
        let iroh::endpoint::RelayMode::Custom(map) = relay_mode(home.as_ref()) else {
            panic!("a relay, so a map");
        };
        assert_eq!(1, map.len(), "one relay to live on");
        assert!(matches!(relay_mode(None), iroh::endpoint::RelayMode::Disabled));
    }

    /// Unpinned, one relay pinned, and two relays with a pin between them.
    #[test]
    fn the_trust_store_follows_what_is_pinned() {
        let (pinned, _) = certificate_for("old.example");
        assert!(tls_for(&relays_at(&moving(None, None), END - 1).unwrap()).unwrap().is_none());
        assert!(
            tls_for(&relays_at(&moving(None, None), END).unwrap()).unwrap().is_none(),
            "one unpinned relay is the default it always was"
        );
        assert!(
            tls_for(&relays_at(&moving(Some(pinned), None), END - 1).unwrap()).unwrap().is_some(),
            "a pin among two is verified by host"
        );
    }

    /// **Each relay keeps its own rule, chosen by host.**
    ///
    /// The old relay pinned, the new one not: the old one is accepted only with
    /// its certificate, the new one is verified as any unpinned relay is, and a
    /// host that is neither is refused before any certificate is looked at.
    #[test]
    fn each_relay_is_verified_by_its_own_rule() {
        let (old_pin, old_cert) = certificate_for("old.example");
        let (_, impostor) = certificate_for("old.example");
        let (_, new_self_signed) = certificate_for("new.example");
        let (_, third) = certificate_for("third.example");

        let relays = relays_at(&moving(Some(old_pin), None), END - 1).unwrap();
        let verifier = tls_for(&relays)
            .unwrap()
            .unwrap()
            .server_cert_verifier(iroh::tls::default_provider())
            .unwrap();
        let verify = |certificate: &CertificateDer<'static>, name: &str| {
            verifier.verify_server_cert(
                certificate,
                &[],
                &ServerName::try_from(name.to_owned()).unwrap(),
                &[],
                UnixTime::now(),
            )
        };

        assert!(verify(&old_cert, "old.example").is_ok(), "the pinned relay, with its pin");
        assert!(
            verify(&impostor, "old.example").is_err(),
            "the pinned relay's name, with another certificate"
        );

        let unpinned = verify(&new_self_signed, "new.example").expect_err("self-signed, unpinned");
        assert!(
            !unpinned.to_string().contains("not a relay this network uses"),
            "refused by the ordinary rule, not as a stranger: {unpinned}"
        );

        let stranger = verify(&third, "third.example").expect_err("neither relay");
        assert!(stranger.to_string().contains("not a relay this network uses"), "{stranger}");
    }

    /// Two relays on one host, on two ports, each pinned to its own certificate:
    /// each is accepted with its own, and a third certificate is not.
    #[test]
    fn two_relays_on_one_host_each_keep_their_pin() {
        let (old_pin, old_cert) = certificate_for("one.example");
        let (new_pin, new_cert) = certificate_for("one.example");
        let (_, impostor) = certificate_for("one.example");

        let params = NetworkParams::with_relay(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            Some("https://one.example:443"),
            "casa.internal",
            WINDOW_S,
        )
        .unwrap()
        .pinning(old_pin)
        .unwrap()
        .moving_to("https://one.example:8443", Some(new_pin), ISSUED)
        .unwrap();
        let relays = relays_at(&params, END - 1).unwrap();
        let verifier = tls_for(&relays)
            .unwrap()
            .unwrap()
            .server_cert_verifier(iroh::tls::default_provider())
            .unwrap();
        let verify = |certificate: &CertificateDer<'static>| {
            verifier.verify_server_cert(
                certificate,
                &[],
                &ServerName::try_from("one.example".to_owned()).unwrap(),
                &[],
                UnixTime::now(),
            )
        };

        assert!(verify(&old_cert).is_ok(), "the relay being left, with its pin");
        assert!(verify(&new_cert).is_ok(), "the relay moved to, with its own");
        assert!(verify(&impostor).is_err(), "and neither pin is a licence for a third");
    }

    /// A self-signed certificate for `name`: its DER, and the same as a
    /// certificate to present.
    fn certificate_for(name: &str) -> (Vec<u8>, CertificateDer<'static>) {
        let issued = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
        let der = issued.cert.der().to_vec();
        (der.clone(), CertificateDer::from(der))
    }
}

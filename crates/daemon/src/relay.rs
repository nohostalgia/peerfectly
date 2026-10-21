//! Reading the relay a person gives, and asking a relay's host for its key.
//!
//! A relay is signed into the roster as `key@host:port`: its address names its
//! key, so the roster authenticates it with nothing beside it. Typing 64
//! hexadecimal digits is the least pleasant thing peerfectly asked of a person,
//! so a relay may also be given as the host of a peerfectly relay container,
//! which answers over HTTPS with the key and the port it serves
//! (`relay-server`). The daemon asks, shows the key, and signs nothing until a
//! person confirms it.
//!
//! # Trust on first use, and said so
//!
//! The answer is not authenticated. TLS hides the request from the path and
//! accepts any certificate, because there is no root of trust before the key
//! itself. Whoever answers at that host in that moment is what a person is asked
//! about, and the question names where the same key is printed on the relay
//! host. A wrong key costs availability and metadata, never content: sessions
//! between members are end-to-end under their roster keys.

use std::io::{Read as _, Write as _};
use std::sync::Arc;
use std::time::Duration;

/// Why a relay could not be read or asked.
///
/// A message rather than a variant, deliberately: every one of these ends the
/// command that hit it, so there is nothing for a caller to branch on, and the
/// person standing at the terminal needs the sentence rather than the category.
pub type Refusal = String;

/// The form a relay is written in, for a person reading a refusal.
pub const FORM: &str = transport_convesso::relay::FORM;

/// The forms a relay may be given in, for a person reading a refusal.
pub const FORMS: &str = "a relay is given as the host of its peerfectly relay container \
                         (`relay.example` or `203.0.113.10`), as `https://host:port` when the \
                         container answers on another port, or written out as `<key>@host:port`";

/// The port a relay container answers on unless told otherwise.
pub const KEY_PORT: u16 = 443;

/// How long asking a relay's host may take, from connecting to the last byte.
pub const ASKING_WITHIN: Duration = Duration::from_secs(10);

/// The most an answer may be, headers included. The body is a key and a port.
const ANSWER_LIMIT: usize = 4096;

/// A relay as a person gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Given {
    /// Written out, `key@host:port` or `tls://key@host:port`: used as it is.
    Written(String),
    /// The host of a relay container, to be asked for its key.
    Asked {
        /// The host to connect to: a name, or an address without brackets.
        host: String,
        /// The same host as a relay string writes it: IPv6 in brackets.
        written: String,
        /// The port the container answers on.
        port: u16,
    },
}

impl Given {
    /// Reads a relay as a person typed it.
    ///
    /// # Errors
    ///
    /// When it is none of the forms, naming them. A host and a port with no key
    /// is refused rather than guessed at: it is as likely a relay written without
    /// its key as a container on another port.
    pub fn read(text: &str) -> Result<Self, Refusal> {
        let text = text.trim();
        let refused = || format!("`{}` is not a relay: {FORMS}.", crate::control::shown(text));
        if text.contains('@') {
            return match transport_convesso::relay::parse(text) {
                Ok(_) => Ok(Self::Written(text.to_owned())),
                Err(cause) => Err(format!("{cause}. {FORMS}.")),
            };
        }
        if text.starts_with("https://") {
            let parsed = url::Url::parse(text).map_err(|_| refused())?;
            if !matches!(parsed.path(), "" | "/") || parsed.query().is_some() {
                return Err(refused());
            }
            let port = parsed.port().unwrap_or(KEY_PORT);
            let (host, written) = match parsed.host() {
                Some(url::Host::Domain(name)) => (name.to_owned(), name.to_owned()),
                Some(url::Host::Ipv4(address)) => (address.to_string(), address.to_string()),
                Some(url::Host::Ipv6(address)) => (address.to_string(), format!("[{address}]")),
                None => return Err(refused()),
            };
            return Ok(Self::Asked { host, written, port });
        }
        if text.contains("://") {
            return Err(refused());
        }
        if let Some(inner) = text.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
            let address: std::net::Ipv6Addr = inner.parse().map_err(|_| refused())?;
            return Ok(Self::Asked {
                host: address.to_string(),
                written: format!("[{address}]"),
                port: KEY_PORT,
            });
        }
        let usable = !text.is_empty()
            && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
        if !usable {
            // `host:port` lands here, with every other shape that is not a host.
            return Err(refused());
        }
        Ok(Self::Asked { host: text.to_owned(), written: text.to_owned(), port: KEY_PORT })
    }
}

/// What a relay container answers: the key it serves, and where.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Answer {
    /// The relay's key, 64 hexadecimal digits.
    pub key: String,
    /// The port the relay listens on, for UDP and TCP alike.
    pub port: u16,
    /// Whether its TCP link is wrapped in TLS.
    #[serde(default)]
    pub tls: bool,
}

impl Answer {
    /// The relay string this answer makes with the host it was asked on.
    ///
    /// # Errors
    ///
    /// When the key is not a relay key.
    pub fn relay(&self, written_host: &str) -> Result<String, Refusal> {
        let bytes = hex::decode(&self.key)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| "the host answered with something that is not a relay key".to_owned())?;
        let relay = transport_convesso::relay::written(
            &bytes,
            &format!("{written_host}:{}", self.port),
            self.tls,
        );
        transport_convesso::relay::parse(&relay)
            .map_err(|cause| format!("the host answered with an unusable relay: {cause}"))?;
        Ok(relay)
    }
}

/// Asks the relay container at `host:port` which relay it serves, and makes the
/// relay string with `written` as its host.
///
/// Blocking: run it off the runtime's reactor.
///
/// # Errors
///
/// When the host cannot be reached, does not answer as a relay container, or
/// answers with something that is not a relay.
pub fn ask(host: &str, written: &str, port: u16) -> Result<String, Refusal> {
    let body = fetch(host, port)?;
    let answer: Answer = serde_json::from_slice(&body)
        .map_err(|_| format!("{host}:{port} answered, but not as a peerfectly relay container"))?;
    answer.relay(written)
}

/// `GET /relay` over TLS, accepting any certificate, and the body that came back.
fn fetch(host: &str, port: u16) -> Result<Vec<u8>, Refusal> {
    use std::net::ToSocketAddrs as _;

    let unreachable =
        |cause: &dyn core::fmt::Display| format!("could not reach {host}:{port}: {cause}");
    let addresses = (host, port).to_socket_addrs().map_err(|cause| unreachable(&cause))?;
    let mut socket = None;
    let mut last = None;
    for address in addresses {
        match std::net::TcpStream::connect_timeout(&address, ASKING_WITHIN) {
            Ok(connected) => {
                socket = Some(connected);
                break;
            }
            Err(cause) => last = Some(cause),
        }
    }
    let socket = socket.ok_or_else(|| match last {
        Some(cause) => unreachable(&cause),
        None => unreachable(&"the name has no address"),
    })?;
    socket.set_read_timeout(Some(ASKING_WITHIN)).map_err(|cause| cause.to_string())?;
    socket.set_write_timeout(Some(ASKING_WITHIN)).map_err(|cause| cause.to_string())?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|cause| cause.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnything { provider }))
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|cause| format!("{host}: not a usable server name: {cause}"))?;
    let connection =
        rustls::ClientConnection::new(Arc::new(config), name).map_err(|cause| cause.to_string())?;
    let mut stream = rustls::StreamOwned::new(connection, socket);

    let request = format!(
        "GET /relay HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: \
         close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|cause| format!("the exchange with {host}:{port} failed: {cause}"))?;

    let mut answer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                answer.extend_from_slice(chunk.get(..read).unwrap_or_default());
                if answer.len() > ANSWER_LIMIT {
                    return Err(format!("{host}:{port} answered with more than a relay's key"));
                }
            }
            // A server that closes without TLS's own goodbye has still said
            // everything it was going to.
            Err(cause) if cause.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(cause) => return Err(format!("the exchange with {host}:{port} failed: {cause}")),
        }
    }
    body_of(&answer).map_err(|why| format!("{host}:{port} {why}"))
}

/// The body of an HTTP/1.1 response that said 200, or what it said instead.
fn body_of(response: &[u8]) -> Result<Vec<u8>, String> {
    let end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "did not answer over HTTP".to_owned())?;
    let head = String::from_utf8_lossy(response.get(..end).unwrap_or_default()).to_string();
    let body = response.get(end.saturating_add(4)..).unwrap_or_default();
    let mut lines = head.lines();
    let status = lines.next().unwrap_or_default();
    let code = status.split_whitespace().nth(1).unwrap_or_default();
    match code {
        "200" => {}
        "404" => {
            return Err("answered that it serves no relay key: is it a peerfectly relay \
                        container?"
                .to_owned());
        }
        _ => return Err(format!("answered `{}`", crate::control::shown(status))),
    }
    let chunked = lines.any(|line| {
        let line = line.to_ascii_lowercase();
        line.starts_with("transfer-encoding:") && line.contains("chunked")
    });
    if chunked {
        return Err("answered in a form a relay container does not use".to_owned());
    }
    Ok(body.to_vec())
}

/// A relay's key in groups of four hexadecimal digits, for a person to compare
/// with the line the relay printed on its host.
#[must_use]
pub fn grouped_key(relay: &str) -> String {
    let key = relay
        .strip_prefix(transport_convesso::relay::TLS_PREFIX)
        .unwrap_or(relay)
        .split('@')
        .next()
        .unwrap_or_default();
    key.as_bytes()
        .chunks(4)
        .map(|group| String::from_utf8_lossy(group).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether two relay addresses name the same relay.
///
/// A relay is `key@host:port`, or `tls://key@host:port`: the same relay when the
/// keys, the hosts compared without regard to case or a trailing dot, the ports
/// and the use of TLS all agree. `transport_convesso::relay::same` decides.
///
/// **Nothing is resolved.** An address and a name that resolves to it are two
/// relays here: resolving to compare would be the contact this exists to
/// prevent, and a name's answer can change between the comparison and the dial.
///
/// An address that does not parse is the same as nothing, including itself.
#[must_use]
pub fn same_relay(one: &str, other: &str) -> bool {
    transport_convesso::relay::same(one, other)
}

/// Whether a signed relay is what a person asked for when they gave `given`.
///
/// Written out, it must be the same relay. Given as a host, the key and port
/// came from that host's answer, so the signed relay must be on that host: a
/// daemon that asked one host and signed another's relay is caught here.
#[must_use]
pub fn answers_given(signed: &str, given: &str) -> bool {
    match Given::read(given) {
        Ok(Given::Written(written)) => same_relay(signed, &written),
        Ok(Given::Asked { written, .. }) => transport_convesso::relay::parse(signed)
            .ok()
            .and_then(|location| {
                location.host.rsplit_once(':').map(|(host, _)| host.to_ascii_lowercase())
            })
            .is_some_and(|host| {
                host.trim_end_matches('.') == written.to_ascii_lowercase().trim_end_matches('.')
            }),
        Err(_) => false,
    }
}

/// The SHA-256 of some bytes, in the shape `openssl` prints a fingerprint.
///
/// Colon-separated uppercase hex, so it can be compared character for
/// character. A fingerprint in some other shape is one nobody checks.
#[must_use]
pub fn fingerprint(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};

    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(":")
}

/// A verifier that accepts any certificate, because nothing roots trust here
/// before the key the person confirms.
///
/// It exists only inside [`fetch`], which authenticates nothing and says so. It
/// must not migrate into the node.
#[derive(Debug)]
struct AcceptAnything {
    /// The provider whose algorithms verify the handshake signature.
    ///
    /// The signature is still checked. Only the *identity* is unverified.
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for AcceptAnything {
    fn verify_server_cert(
        &self,
        _presented: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _name: &rustls::pki_types::ServerName<'_>,
        _stapled: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A relay container for tests: a TLS server on the loopback that answers one
/// request with `response`, a whole HTTP/1.1 response.
#[cfg(test)]
pub(crate) fn answering_once(response: String) -> u16 {
    let issued =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).expect("a certificate");
    let presented = issued.cert.der().to_vec();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(issued.signing_key.serialize_der());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocols supported by ring")
    .with_no_client_auth()
    .with_single_cert(vec![rustls::pki_types::CertificateDer::from(presented)], key.into())
    .expect("a usable key pair");
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("binds");
    let port = listener.local_addr().expect("bound").port();
    std::thread::spawn(move || {
        let Ok((socket, _)) = listener.accept() else { return };
        let Ok(server) = rustls::ServerConnection::new(Arc::new(config)) else { return };
        let mut stream = rustls::StreamOwned::new(server, socket);
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request);
        let _ = stream.write_all(response.as_bytes());
        stream.conn.send_close_notify();
        let _ = stream.flush();
    });
    port
}

/// A whole HTTP/1.1 response with `status` and `body`.
#[cfg(test)]
pub(crate) fn http_response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: \
         close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// A relay written as the convesso binding writes it, with the key of `seed`.
    fn relay(seed: u8, host: &str, tls: bool) -> String {
        transport_convesso::relay::written(&key(seed), host, tls)
    }

    fn key(seed: u8) -> [u8; 32] {
        *convesso_core::identity::Identity::from_ed25519_seed(&[seed; 32])
            .expect("a seed is an identity")
            .address()
            .as_bytes()
    }

    /// One relay, however its host is written.
    #[test]
    fn one_relay_written_differently_is_one_relay() {
        let ours = relay(1, "relay.example:7400", false);
        for spelled in ["RELAY.Example:7400", "relay.example.:7400"] {
            assert!(same_relay(&ours, &relay(1, spelled, false)), "`{spelled}` is `{ours}`");
        }
        assert!(same_relay(
            &relay(1, "[2001:db8::1]:7400", false),
            &relay(1, "[2001:DB8::1]:7400", false)
        ));
    }

    /// Different relays, including the ones that look close.
    #[test]
    fn a_different_relay_is_different() {
        let ours = relay(1, "relay.example:7400", false);
        for other in [
            relay(2, "relay.example:7400", false),
            relay(1, "relay.example:7401", false),
            relay(1, "relay.example:7400", true),
            relay(1, "relay.example.net:7400", false),
            "https://relay.example:443".to_owned(),
            "not a relay".to_owned(),
            String::new(),
        ] {
            assert!(!same_relay(&ours, &other), "`{other}` is not `{ours}`");
        }
    }

    /// **An address is not the name that resolves to it.** Resolving to compare
    /// would be contacting the host the comparison exists to keep away from.
    #[test]
    fn an_address_is_not_the_name_that_resolves_to_it() {
        assert!(!same_relay(
            &relay(1, "localhost:7400", false),
            &relay(1, "127.0.0.1:7400", false)
        ));
        // The comparison is the binding's: read where it is written.
        let code = crate::code_of(include_str!("../../transport-convesso/src/relay.rs"));
        let comparing = code
            .split("pub fn same")
            .nth(1)
            .and_then(|rest| rest.split("#[cfg(test)]").next())
            .expect("it is declared");
        for resolving in ["to_socket_addrs", "lookup_host", "resolve", "dns"] {
            assert!(!comparing.contains(resolving), "`{resolving}` would contact what it compares");
        }
    }

    /// Every form a relay may be given in, and the ones refused.
    #[test]
    fn a_relay_is_read_in_each_form_it_may_be_given_in() {
        let written = relay(1, "relay.example:8443", false);
        assert_eq!(Given::read(&written), Ok(Given::Written(written.clone())));
        let tls = relay(1, "relay.example:8443", true);
        assert_eq!(Given::read(&tls), Ok(Given::Written(tls.clone())));

        let asked = |host: &str, written: &str, port| Given::Asked {
            host: host.to_owned(),
            written: written.to_owned(),
            port,
        };
        for (text, expected) in [
            ("relay.example", asked("relay.example", "relay.example", 443)),
            ("204.216.216.139", asked("204.216.216.139", "204.216.216.139", 443)),
            ("[2001:db8::1]", asked("2001:db8::1", "[2001:db8::1]", 443)),
            ("https://relay.example", asked("relay.example", "relay.example", 443)),
            ("https://relay.example:9443", asked("relay.example", "relay.example", 9443)),
            ("https://[2001:db8::1]:9443", asked("2001:db8::1", "[2001:db8::1]", 9443)),
            (" relay.example ", asked("relay.example", "relay.example", 443)),
        ] {
            assert_eq!(Given::read(text), Ok(expected), "`{text}`");
        }

        for refused in [
            "relay.example:8443",
            "204.216.216.139:8443",
            "http://relay.example",
            "https://relay.example/somewhere",
            "",
            "relay example",
            "@relay.example:8443",
        ] {
            let refusal = Given::read(refused).expect_err(refused);
            assert!(
                refusal.contains("host of its peerfectly relay container")
                    || refusal.contains("key"),
                "{refusal}"
            );
        }
    }

    /// The string signed is the key and port answered, on the host the person
    /// gave, written as the binding writes it.
    #[test]
    fn an_answer_makes_the_relay_string() {
        let answer = Answer { key: hex::encode(key(3)), port: 8443, tls: false };
        assert_eq!(answer.relay("relay.example"), Ok(relay(3, "relay.example:8443", false)));
        assert_eq!(answer.relay("[2001:db8::1]"), Ok(relay(3, "[2001:db8::1]:8443", false)));
        let wrapped = Answer { tls: true, ..answer.clone() };
        assert_eq!(wrapped.relay("relay.example"), Ok(relay(3, "relay.example:8443", true)));

        let short = Answer { key: "abcd".to_owned(), ..answer };
        assert!(short.relay("relay.example").is_err());
    }

    /// A signed relay answers what was asked: the same relay when written out,
    /// a relay on that host when the host was asked.
    #[test]
    fn a_signed_relay_answers_what_was_given() {
        let signed = relay(4, "relay.example:8443", false);
        assert!(answers_given(&signed, &signed));
        assert!(answers_given(&signed, "relay.example"));
        assert!(answers_given(&signed, "https://Relay.Example:9443"));
        assert!(!answers_given(&signed, "other.example"));
        assert!(!answers_given(&signed, &relay(5, "relay.example:8443", false)));
        let six = relay(4, "[2001:db8::1]:8443", false);
        assert!(answers_given(&six, "[2001:db8::1]"));
        assert!(!answers_given(&signed, "relay.example:8443"), "not a form at all");
    }

    /// The key is shown in groups a person can compare by eye.
    #[test]
    fn a_key_is_grouped_for_reading() {
        let written = relay(1, "relay.example:8443", true);
        let grouped = grouped_key(&written);
        assert_eq!(grouped.replace(' ', ""), hex::encode(key(1)));
        assert_eq!(grouped.split(' ').count(), 16);
    }

    /// Asked over TLS, against a real server, the answer becomes a relay.
    #[test]
    fn a_relay_container_is_asked_for_its_key() {
        let body = format!(r#"{{"key":"{}","port":8443,"tls":false}}"#, hex::encode(key(5)));
        let port = answering_once(http_response("200 OK", &body));
        assert_eq!(
            ask("127.0.0.1", "relay.example", port),
            Ok(relay(5, "relay.example:8443", false))
        );
    }

    /// What is not a relay container is refused, saying what it did.
    #[test]
    fn a_host_that_is_not_a_relay_container_is_refused() {
        let port = answering_once(http_response("404 Not Found", ""));
        let refusal = ask("127.0.0.1", "relay.example", port).expect_err("no key there");
        assert!(refusal.contains("serves no relay key"), "{refusal}");

        let port = answering_once(http_response("200 OK", "<html>hello</html>"));
        let refusal = ask("127.0.0.1", "relay.example", port).expect_err("not a key");
        assert!(refusal.contains("not as a peerfectly relay container"), "{refusal}");

        let port = answering_once(http_response("500 Internal Server Error", ""));
        let refusal = ask("127.0.0.1", "relay.example", port).expect_err("an error");
        assert!(refusal.contains("500"), "{refusal}");

        let closed = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let nobody = closed.local_addr().unwrap().port();
        drop(closed);
        let refusal = ask("127.0.0.1", "relay.example", nobody).expect_err("nobody there");
        assert!(refusal.contains("could not reach"), "{refusal}");
    }

    /// The shape matters as much as the value: compared by eye.
    #[test]
    fn a_fingerprint_reads_the_way_openssl_prints_one() {
        assert_eq!(
            fingerprint(&[0x30, 0x03, 0x02, 0x01, 0x00]),
            "B5:60:83:3D:6F:78:7A:F4:61:13:B9:6A:AD:4D:D5:B5:\
             D1:AE:00:DC:CC:69:CF:30:CC:92:BE:D6:51:C5:66:17"
        );
    }
}

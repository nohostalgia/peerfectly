//! Getting a relay's certificate, and deciding whether it can be one.
//!
//! Two commands need this and they need it for opposite reasons. **Founding**
//! pins the certificate into the signed parameters, so it had better be a
//! certificate a verifying client will accept — a pin that cannot work produces
//! a network where every device fails to reach the relay and the only sign of it
//! is an alert in the relay's log. **Joining** has to reach a relay before any
//! roster exists to vouch for it, so it verifies the ordinary way and falls back
//! to accepting one on sight, showing the fingerprint.
//!
//! # Why the fingerprint is SHA-256, in that shape
//!
//! Because that is what `openssl x509 -noout -fingerprint -sha256` prints on the
//! relay host. A digest nobody can compare against anything is not a check.

use std::io::Write as _;
use std::sync::Arc;

/// Why a certificate could not be obtained or used.
///
/// A message rather than a variant, deliberately: every one of these ends the
/// command that hit it, so there is nothing for a caller to branch on, and the
/// person standing at the terminal needs the sentence rather than the category.
/// What each says is tested; that they are distinct kinds is not, because
/// nothing acts on the difference.
pub type Refusal = String;

/// Reads a certificate from a file, as PEM or as DER.
///
/// Whoever runs a relay has a PEM file, because that is what the tools that make
/// certificates write. The roster carries DER, so the conversion happens here.
///
/// # Errors
///
/// When the file cannot be read, or is neither PEM nor DER.
pub fn read_certificate(path: &str) -> Result<Vec<u8>, Refusal> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject as _;

    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";

    let bytes = std::fs::read(path).map_err(|cause| format!("{path}: {cause}"))?;

    if bytes.windows(BEGIN.len()).any(|window| window == BEGIN) {
        let certificate = CertificateDer::from_pem_slice(&bytes)
            .map_err(|cause| format!("{path}: not a usable PEM certificate: {cause}"))?;
        return Ok(certificate.to_vec());
    }

    // DER. A certificate is an ASN.1 SEQUENCE, which begins 0x30.
    if bytes.first() != Some(&0x30) {
        return Err(format!("{path}: neither a PEM certificate nor DER"));
    }
    Ok(bytes)
}

/// Asks a relay for the certificate it presents, and pins it once confirmed.
///
/// This is **trust on first use**, and the prompt says so rather than implying a
/// check that did not happen: whoever answers at that address in this moment is
/// what gets signed into the roster. Copying the file off the relay by hand is
/// no better — the same bytes, obtained the same way — unless the fingerprint is
/// compared against the relay host, which is what the prompt puts in front of
/// the person founding the network.
///
/// # Errors
///
/// When the relay cannot be reached, presents a certificate a verifying client
/// could not accept, or the person declines.
pub fn fetch_and_confirm(relay: &str) -> Result<Vec<u8>, Refusal> {
    let (host, port) = host_and_port(relay)?;
    println!("asking {host}:{port} for its certificate...");
    let certificate = presented_certificate(&host, port)?;

    // Refused here, not pinned and discovered later. This certificate is the one
    // the relay presents as its own, so if a verifying client cannot accept it,
    // pinning it produces a network where every device fails to reach the relay
    // and the only sign of it is an alert in the relay's log.
    if let Err(reason) = usable_as_a_server_certificate(&certificate, &host) {
        return Err(format!("{host}:{port} presented a certificate that cannot work:\n{reason}"));
    }

    println!();
    println!("  SHA-256  {}", fingerprint(&certificate));
    println!("  {} bytes of DER", certificate.len());
    println!();
    println!("Nothing has checked that this is your relay. Anyone in the path could");
    println!("have answered. On the relay host, the same certificate prints as:");
    println!();
    println!("  openssl x509 -in <the relay's cert file> -noout -fingerprint -sha256");
    println!();
    print!("Pin this certificate? [yes/no] ");
    std::io::stdout().flush().map_err(|cause| cause.to_string())?;

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer).map_err(|cause| cause.to_string())?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "yes" | "y") {
        return Err("not pinned; nothing was written".to_owned());
    }
    Ok(certificate)
}

/// Splits a relay URL into the host and port to connect to.
///
/// # Errors
///
/// When it is not a URL, or names no host.
pub fn host_and_port(relay: &str) -> Result<(String, u16), Refusal> {
    let parsed = url::Url::parse(relay).map_err(|cause| format!("{relay}: {cause}"))?;
    // Not `host_str`, which returns an IPv6 address inside the brackets the URL
    // syntax requires — `[2001:db8::1]` is neither a name that resolves nor an
    // address that connects. Found by the test below.
    let host = match parsed.host() {
        Some(url::Host::Domain(name)) => name.to_owned(),
        Some(url::Host::Ipv4(address)) => address.to_string(),
        Some(url::Host::Ipv6(address)) => address.to_string(),
        None => return Err(format!("{relay}: no host in the address")),
    };
    // 443 for a relay served on https with no port written down, which is what
    // `transport-iroh` assumes when it dials the same address.
    let port = parsed.port_or_known_default().unwrap_or(443);
    Ok((host, port))
}

/// Whether two relay addresses name the same relay.
///
/// Compared on scheme, host and port: the scheme and a host name case-folded, a
/// trailing dot dropped, an IPv6 address without its brackets, and the port made
/// explicit where the scheme implies one. The path plays no part — a relay is
/// reached by its host.
///
/// **Nothing is resolved.** An address and a name that resolves to it are two
/// relays here: resolving to compare would be the contact this exists to
/// prevent, and a name's answer can change between the comparison and the dial.
///
/// An address that does not parse is the same as nothing, including itself.
#[must_use]
pub fn same_relay(one: &str, other: &str) -> bool {
    match (identity_of(one), identity_of(other)) {
        (Some(one), Some(other)) => one == other,
        _ => false,
    }
}

/// Whether two URLs name the same host, whatever their scheme and port.
///
/// A name case-folded and without a trailing dot; an address as an address,
/// so two spellings of one IPv6 address agree. Compared as written, never by
/// resolving: a name and the address it resolves to are **different** hosts
/// here, as they are to a certificate check.
#[must_use]
pub fn same_host(one: &str, other: &str) -> bool {
    match (host_of(one), host_of(other)) {
        (Some(one), Some(other)) => one == other,
        _ => false,
    }
}

/// The host a URL names, as [`same_host`] compares it.
fn host_of(address: &str) -> Option<url::Host<String>> {
    match url::Url::parse(address).ok()?.host()? {
        url::Host::Domain(name) => {
            let name = name.to_ascii_lowercase();
            Some(url::Host::Domain(name.strip_suffix('.').map_or(name.clone(), str::to_owned)))
        }
        url::Host::Ipv4(address) => Some(url::Host::Ipv4(address)),
        url::Host::Ipv6(address) => Some(url::Host::Ipv6(address)),
    }
}

/// What a relay address names, as [`same_relay`] compares it.
fn identity_of(relay: &str) -> Option<(String, String, u16)> {
    let scheme = url::Url::parse(relay).ok()?.scheme().to_ascii_lowercase();
    let (host, port) = host_and_port(relay).ok()?;
    let host = host.to_ascii_lowercase();
    let host = host.strip_suffix('.').map_or(host.clone(), str::to_owned);
    Some((scheme, host, port))
}

/// The first certificate the server at `host:port` presents.
///
/// # Errors
///
/// When the host cannot be reached or the handshake fails.
pub fn presented_certificate(host: &str, port: u16) -> Result<Vec<u8>, Refusal> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|cause| cause.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnything { provider }))
        .with_no_client_auth();

    let name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|cause| format!("{host}: not a usable server name: {cause}"))?;
    let mut connection =
        rustls::ClientConnection::new(Arc::new(config), name).map_err(|cause| cause.to_string())?;
    let mut socket = std::net::TcpStream::connect((host, port))
        .map_err(|cause| format!("could not reach {host}:{port}: {cause}"))?;

    while connection.is_handshaking() {
        connection
            .complete_io(&mut socket)
            .map_err(|cause| format!("the handshake with {host}:{port} failed: {cause}"))?;
    }

    let presented = connection
        .peer_certificates()
        .and_then(|chain| chain.first().cloned())
        .ok_or_else(|| format!("{host}:{port} presented no certificate"))?;
    Ok(presented.to_vec())
}

/// Whether a verifying client can accept this certificate from `host`.
///
/// The certificate is pinned as the trust anchor *and* presented as the server's
/// own certificate, so both roles have to hold at once. Checked because the
/// failure is otherwise unreadable: the client sends a TLS alert, the relay logs
/// it, and nothing on the machine that refused says a word.
///
/// Written after a real one. A certificate made with `openssl req -x509` carries
/// `basicConstraints: CA:TRUE` by default, rustls refuses a certificate authority
/// as an end entity, and the resulting `certificate_unknown` alert names nothing
/// a person can act on.
///
/// # Errors
///
/// When no verifying client could accept it, with the reason spelled out.
pub fn usable_as_a_server_certificate(certificate: &[u8], host: &str) -> Result<(), Refusal> {
    use rustls::client::danger::ServerCertVerifier as _;

    let der = rustls::pki_types::CertificateDer::from(certificate.to_vec());
    let mut store = rustls::RootCertStore::empty();
    let (accepted, _) = store.add_parsable_certificates([der.clone()]);
    if accepted == 0 {
        return Err("  it cannot be used as a trust anchor at all — the bytes parse as a \
                    certificate but nothing can be verified against them"
            .to_owned());
    }

    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(store),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .map_err(|cause| format!("  it cannot be used as a trust anchor: {cause}"))?;

    let name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|cause| format!("  {host} is not a usable server name: {cause}"))?;

    match verifier.verify_server_cert(&der, &[], &name, &[], rustls::pki_types::UnixTime::now()) {
        Ok(_) => Ok(()),
        Err(refusal) => Err(explain(&refusal, host)),
    }
}

/// Turns a verification failure into something a person can act on.
fn explain(refusal: &rustls::Error, host: &str) -> Refusal {
    use rustls::CertificateError;

    let rustls::Error::InvalidCertificate(reason) = refusal else {
        return format!("  {refusal}");
    };
    match reason {
        CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
            format!(
                "  it does not cover {host}. A certificate for an address needs that\n  address \
                 in its subjectAltName — `IP:{host}` for an address, `DNS:` for a\n  name — and \
                 the relay has to be reached by exactly what is written there."
            )
        }
        CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
            "  it has expired. A pin is signed into the roster, so an expired certificate stops\n  \
             the whole network reaching the relay until a `set_network` operation replaces it.\n  \
             Issue a long-lived one before founding."
                .to_owned()
        }
        CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
            "  it is not valid yet — check the clock on this machine and on the relay.".to_owned()
        }
        other => {
            let described = format!("{other:?}");
            if described.contains("CaUsedAsEndEntity") {
                "  it is a certificate authority's certificate — `basicConstraints: CA:TRUE` —\n  \
                 and a verifying client will not accept one as a server's own certificate.\n  \
                 `openssl req -x509` sets that by default, which is how this usually happens.\n\n  \
                 Either reissue the relay's certificate with \
                 `basicConstraints=critical,CA:FALSE`,\n  or keep this one as an authority, serve \
                 a certificate signed by it, and pin this\n  one with `--relay-cert` rather than \
                 fetching."
                    .to_owned()
            } else {
                format!("  {other:?}")
            }
        }
    }
}

/// A certificate's SHA-256 fingerprint, in the shape `openssl` prints.
///
/// Colon-separated uppercase hex, so it can be compared against
/// `openssl x509 -noout -fingerprint -sha256` character for character. A
/// fingerprint in some other shape is one nobody checks.
#[must_use]
pub fn fingerprint(certificate: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};

    let digest = Sha256::digest(certificate);
    digest.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(":")
}

/// A verifier that accepts any certificate, because the point is to *see* one.
///
/// It exists only inside [`presented_certificate`], which authenticates nothing
/// and says so. It must not migrate into the node: a device that accepted any
/// relay certificate could be steered onto an impostor relay, which learns who
/// talks to whom and when.
#[derive(Debug)]
struct AcceptAnything {
    /// The provider whose algorithms verify the handshake signature.
    ///
    /// The signature is still checked. Only the *identity* is unverified, which
    /// is the question this fetch exists to put to a person.
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

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// One relay, however it is written.
    #[test]
    fn one_relay_written_differently_is_one_relay() {
        let ours = "https://relay.example:443";
        for spelled in [
            "https://relay.example",
            "https://RELAY.Example:443",
            "HTTPS://relay.example:443",
            "https://relay.example.:443",
            "https://relay.example:443/",
            "https://relay.example:443/some/path",
        ] {
            assert!(same_relay(ours, spelled), "`{spelled}` is `{ours}`");
        }
        assert!(same_relay("https://[2001:db8::1]:443", "https://[2001:DB8::1]"));
    }

    /// Different relays, including the ones that look close.
    #[test]
    fn a_different_relay_is_different() {
        let ours = "https://relay.example:443";
        for other in [
            "https://relay.example:8443",
            "http://relay.example:443",
            "https://relay.example.net:443",
            "https://evil.example:443",
            "not a url",
            "",
        ] {
            assert!(!same_relay(ours, other), "`{other}` is not `{ours}`");
        }
    }

    /// **An address is not the name that resolves to it.** Resolving to compare
    /// would be contacting the host the comparison exists to keep away from.
    #[test]
    fn an_address_is_not_the_name_that_resolves_to_it() {
        assert!(!same_relay("https://localhost:443", "https://127.0.0.1:443"));
        let code = crate::code_of(include_str!("relay.rs"));
        let comparing = code
            .split("pub fn same_relay")
            .nth(1)
            .and_then(|rest| rest.split("pub fn presented_certificate").next())
            .expect("it is declared");
        for resolving in ["to_socket_addrs", "lookup_host", "resolve", "dns"] {
            assert!(!comparing.contains(resolving), "`{resolving}` would contact what it compares");
        }
    }

    /// A stand-in for a certificate: these tests are about which file shapes are
    /// read, and the roster does not parse the bytes either.
    const DER: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x00];

    /// A self-signed certificate for `name`, as an authority or as a leaf — the
    /// difference the usability check exists for.
    fn self_signed(name: &str, authority: bool) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).expect("params");
        params.is_ca = if authority {
            rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
        } else {
            rcgen::IsCa::NoCa
        };
        let key = rcgen::KeyPair::generate().expect("a key");
        params.self_signed(&key).expect("signs").der().to_vec()
    }

    /// The relay operator has a PEM file; the roster carries DER. Whichever they
    /// point at, the same bytes end up signed.
    #[test]
    fn a_certificate_is_read_as_pem_or_as_der() {
        let dir = tempfile::tempdir().expect("a scratch directory");

        let pem = dir.path().join("relay.pem");
        std::fs::write(&pem, "-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n")
            .expect("writes");

        let der = dir.path().join("relay.der");
        std::fs::write(&der, DER).expect("writes");

        assert_eq!(read_certificate(&pem.to_string_lossy()).expect("reads"), DER);
        assert_eq!(read_certificate(&der.to_string_lossy()).expect("reads"), DER);
    }

    #[test]
    fn a_file_that_is_not_a_certificate_is_refused() {
        let dir = tempfile::tempdir().expect("a scratch directory");

        let text = dir.path().join("notes.txt");
        std::fs::write(&text, "the relay is at relay.example").expect("writes");
        let refusal = read_certificate(&text.to_string_lossy()).expect_err("not a certificate");
        assert!(refusal.contains("neither a PEM certificate nor DER"), "{refusal}");

        let broken = dir.path().join("broken.pem");
        std::fs::write(&broken, "-----BEGIN CERTIFICATE-----\nnot base64 at all\n")
            .expect("writes");
        let refusal = read_certificate(&broken.to_string_lossy()).expect_err("not a certificate");
        assert!(refusal.contains("PEM"), "{refusal}");
    }

    /// The shape matters as much as the value: this is compared by eye against
    /// what `openssl` prints on the relay host.
    #[test]
    fn a_fingerprint_reads_the_way_openssl_prints_one() {
        assert_eq!(
            fingerprint(DER),
            "B5:60:83:3D:6F:78:7A:F4:61:13:B9:6A:AD:4D:D5:B5:\
             D1:AE:00:DC:CC:69:CF:30:CC:92:BE:D6:51:C5:66:17"
        );
    }

    /// The port is where the relay is, and getting it wrong means fetching a
    /// certificate from somewhere the network will never talk to. IPv6 literals
    /// are here because hand-parsing is what gets them wrong.
    #[test]
    fn a_relay_address_is_split_into_the_host_and_port_it_is_reached_on() {
        for (address, host, port) in [
            ("https://relay.example.com:4433", "relay.example.com", 4433),
            ("https://relay.example.com", "relay.example.com", 443),
            ("https://203.0.113.9:443", "203.0.113.9", 443),
            ("https://[2001:db8::1]:4433", "2001:db8::1", 4433),
        ] {
            assert_eq!(host_and_port(address).expect("parses"), (host.to_owned(), port));
        }

        assert!(host_and_port("not an address").is_err());
    }

    /// A certificate a client cannot accept must be refused where a person can
    /// read it, not pinned and left to become a TLS alert in the relay's log.
    #[test]
    fn a_certificate_the_relay_cannot_present_is_refused_with_the_reason() {
        let authority = self_signed("203.0.113.10", true);
        let refusal = usable_as_a_server_certificate(&authority, "203.0.113.10")
            .expect_err("a certificate authority is not a server certificate");
        assert!(refusal.contains("CA:FALSE"), "{refusal}");
        assert!(refusal.contains("--relay-cert"), "the other way out is named: {refusal}");

        let leaf = self_signed("203.0.113.10", false);
        usable_as_a_server_certificate(&leaf, "203.0.113.10").expect("a leaf is usable");

        let elsewhere = usable_as_a_server_certificate(&leaf, "203.0.113.7")
            .expect_err("a certificate for one address is not one for another");
        assert!(elsewhere.contains("subjectAltName"), "{elsewhere}");
    }

    /// The fetch is exercised against a real TLS server rather than asserted
    /// about. What gets signed into a roster must be exactly the bytes the
    /// server presented — a fetch that returned anything else would pin a
    /// certificate nobody has.
    #[test]
    fn the_certificate_fetched_is_the_one_the_server_presented() {
        let issued = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
            .expect("a certificate");
        let presented = issued.cert.der().to_vec();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(issued.signing_key.serialize_der());

        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocols supported by ring")
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(presented.clone())],
            key.into(),
        )
        .expect("a usable key pair");

        let listener =
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("binds");
        let port = listener.local_addr().expect("bound").port();
        std::thread::spawn(move || {
            let Ok((mut socket, _)) = listener.accept() else {
                return;
            };
            let Ok(mut server) = rustls::ServerConnection::new(Arc::new(config)) else {
                return;
            };
            // The client hangs up as soon as it has the certificate, so a
            // failure here is the expected end of the conversation.
            let _ = server.complete_io(&mut socket);
        });

        let fetched = presented_certificate("127.0.0.1", port).expect("fetches");
        assert_eq!(fetched, presented, "the bytes pinned must be the bytes presented");
        assert_eq!(fingerprint(&fetched), fingerprint(&presented));
    }
}

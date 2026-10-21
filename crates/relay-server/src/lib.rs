//! The relay container's one program: a convesso relay, and the key it serves.
//!
//! A network's relay is signed into its roster as `key@host:port`. Typing 64
//! hexadecimal digits at every founding was the least pleasant thing peerfectly
//! asked of a person, so the relay answers for itself: beside the relay, on a
//! port of its own, it answers over HTTPS which key and port it serves. A
//! founding device asks, shows the key, and signs nothing until a person
//! confirms it against the line this program printed when it started.
//!
//! # It knows its key because it is the relay
//!
//! One process runs both, so the key is the relay's own and nothing reads the
//! relay's identity file from outside: the secret stays with the relay. Nothing
//! is configured by hand for the ordinary case.
//!
//! # TLS here authenticates nothing
//!
//! The certificate is made on first start and kept, so it is the same at every
//! restart, but no client checks it: there is no root of trust before the key
//! itself, which the person confirms. TLS hides the request from the path, as
//! convesso's own TLS link does, and nothing more.
//!
//! # It logs nothing per request
//!
//! A line with the key when it starts, which is what a person compares, and
//! nothing about who asked: an operator who never kept a log has nothing to
//! hand over.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Where the relay listens unless told otherwise, UDP and TCP alike.
pub const RELAY_DEFAULT: &str = "0.0.0.0:8443";

/// Where the key is served unless told otherwise. Not 443 inside the container:
/// it runs as an unprivileged user, and the host publishes 443 to this.
pub const KEY_DEFAULT: &str = "0.0.0.0:8444";

/// Where the identity and the certificate are kept unless told otherwise.
pub const DATA_DEFAULT: &str = "/data";

/// How long a client has to finish its request, from connecting.
pub const ANSWER_WITHIN: Duration = Duration::from_secs(10);

/// The most a request may be, headers included. It asks one path.
const REQUEST_LIMIT: usize = 4096;

/// What the program was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Where the identity and the certificate are kept.
    pub data: PathBuf,
    /// Where the relay listens, UDP and TCP.
    pub relay: SocketAddr,
    /// Where the key is served over HTTPS.
    pub key: SocketAddr,
    /// The port clients reach the relay on, when the host publishes it on
    /// another number than the relay listens on.
    pub public_port: Option<u16>,
    /// More of the relay's configuration, in its own TOML: `[limits]`,
    /// `[allowlist]`. Optional.
    pub extra: Option<String>,
}

impl Settings {
    /// Reads `PEERFECTLY_DATA`, `PEERFECTLY_RELAY_LISTEN`, `PEERFECTLY_KEY_LISTEN`,
    /// `PEERFECTLY_PUBLIC_PORT` and `PEERFECTLY_RELAY_CONFIG`, each defaulted.
    ///
    /// # Errors
    ///
    /// When a value set is not one, naming it.
    pub fn from_env() -> Result<Self, String> {
        let read = |name: &str| std::env::var(name).ok().filter(|value| !value.trim().is_empty());
        let address = |name: &str, default: &str| -> Result<SocketAddr, String> {
            let text = read(name).unwrap_or_else(|| default.to_owned());
            text.trim().parse().map_err(|_| format!("{name}: `{text}` is not an address and port"))
        };
        let public_port = match read("PEERFECTLY_PUBLIC_PORT") {
            Some(text) => Some(
                text.trim()
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or_else(|| format!("PEERFECTLY_PUBLIC_PORT: `{text}` is not a port"))?,
            ),
            None => None,
        };
        let extra = match read("PEERFECTLY_RELAY_CONFIG") {
            Some(path) => Some(
                std::fs::read_to_string(&path)
                    .map_err(|cause| format!("PEERFECTLY_RELAY_CONFIG: {path}: {cause}"))?,
            ),
            None => None,
        };
        Ok(Self {
            data: PathBuf::from(read("PEERFECTLY_DATA").unwrap_or_else(|| DATA_DEFAULT.to_owned())),
            relay: address("PEERFECTLY_RELAY_LISTEN", RELAY_DEFAULT)?,
            key: address("PEERFECTLY_KEY_LISTEN", KEY_DEFAULT)?,
            public_port,
            extra,
        })
    }
}

/// A relay and its key, bound and ready to serve.
pub struct Running {
    /// The relay's key, 64 hexadecimal digits: what a person compares.
    pub key: String,
    /// Whether its identity was made now.
    pub created: bool,
    /// Where the relay listens, UDP.
    pub relay_udp: SocketAddr,
    /// Where the relay listens, TCP.
    pub relay_tcp: SocketAddr,
    /// Where the key is served.
    pub key_at: SocketAddr,
    /// What a request for the relay is answered with.
    pub answer: String,
    relay: convesso_tokio::relay_config::Started,
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

/// Loads or makes the identity and the certificate, binds every socket, and
/// says what it will answer.
///
/// # Errors
///
/// When the data directory cannot be used, a socket cannot be bound, or the
/// extra configuration is not the relay's.
pub async fn start(settings: &Settings) -> Result<Running, String> {
    std::fs::create_dir_all(&settings.data)
        .map_err(|cause| format!("{}: {cause}", settings.data.display()))?;

    // A literal TOML string, single-quoted, so a Windows path's backslashes are
    // not read as escapes.
    let identity = settings.data.join("relay.key");
    let text = format!(
        "udp = \"{relay}\"\ntcp = \"{relay}\"\nidentity = '{identity}'\n{extra}",
        relay = settings.relay,
        identity = identity.display(),
        extra = settings.extra.as_deref().unwrap_or_default(),
    );
    let config = convesso_tokio::relay_config::parse(&text)
        .map_err(|cause| format!("the relay's configuration: {cause}"))?;
    let relay = convesso_tokio::relay_config::start(&config)
        .await
        .map_err(|cause| format!("the relay did not start: {cause}"))?;

    let key = convesso_tokio::relay_config::hex(&relay.address);
    let port = settings.public_port.unwrap_or(relay.udp.port());
    let answer = answer_body(&key, port, relay.tls);

    let (chain, private) = certificate(&settings.data)?;
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|cause| cause.to_string())?
    .with_no_client_auth()
    .with_single_cert(chain, private)
    .map_err(|cause| format!("the HTTPS certificate: {cause}"))?;
    let listener = TcpListener::bind(settings.key)
        .await
        .map_err(|cause| format!("binding {}: {cause}", settings.key))?;
    let key_at = listener.local_addr().map_err(|cause| cause.to_string())?;

    Ok(Running {
        key,
        created: relay.created,
        relay_udp: relay.udp,
        relay_tcp: relay.tcp,
        key_at,
        answer,
        relay,
        listener,
        acceptor: TlsAcceptor::from(Arc::new(tls)),
    })
}

impl Running {
    /// Serves the relay and its key until either fails, which ends both: a
    /// container that restarts is better than one half alive.
    ///
    /// # Errors
    ///
    /// What failed.
    pub async fn serve(self) -> Result<(), String> {
        let Self { relay, listener, acceptor, answer, .. } = self;
        let answer: Arc<str> = Arc::from(answer);
        let keys = async move {
            loop {
                let (stream, _from) = listener.accept().await.map_err(|cause| cause.to_string())?;
                let acceptor = acceptor.clone();
                let answer = Arc::clone(&answer);
                // Each on its own task, with a deadline: a client that connected
                // and sent nothing holds up nobody behind it.
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(ANSWER_WITHIN, async move {
                        let mut stream = acceptor.accept(stream).await.ok()?;
                        let head = read_head(&mut stream).await?;
                        stream.write_all(&respond(&head, &answer)).await.ok()?;
                        stream.shutdown().await.ok()
                    })
                    .await;
                });
            }
        };
        tokio::select! {
            served = relay.serve() => served.map_err(|cause| format!("the relay stopped: {cause}")),
            served = keys => served,
        }
    }
}

/// What the key is served as.
#[must_use]
pub fn answer_body(key: &str, port: u16, tls: bool) -> String {
    serde_json::json!({ "key": key, "port": port, "tls": tls }).to_string()
}

/// The response to a request whose head is `head`: the relay for `GET /relay`,
/// nothing for anything else.
#[must_use]
pub fn respond(head: &[u8], answer: &str) -> Vec<u8> {
    let line = head.split(|byte| *byte == b'\n').next().unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let mut words = line.split_whitespace();
    let (status, body) = match (words.next(), words.next()) {
        (Some("GET"), Some("/relay")) => ("200 OK", answer),
        (Some("GET"), Some(_)) => ("404 Not Found", ""),
        _ => ("405 Method Not Allowed", ""),
    };
    format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: \
         close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A request's head, up to its blank line, or `None` past the limit.
async fn read_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Option<Vec<u8>> {
    let mut head = Vec::new();
    let mut chunk = [0_u8; 512];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        head.extend_from_slice(chunk.get(..read)?);
        if head.len() > REQUEST_LIMIT {
            return None;
        }
    }
    Some(head)
}

/// The certificate the key is served with: the one kept in `data`, or one made
/// now and kept there, so a restart presents the same.
fn certificate(
    data: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let cert_path = data.join("https.crt");
    let key_path = data.join("https.key");
    if !cert_path.exists() || !key_path.exists() {
        let issued = rcgen::generate_simple_self_signed(vec!["peerfectly-relay".to_owned()])
            .map_err(|cause| format!("making the HTTPS certificate: {cause}"))?;
        write_private(&key_path, issued.signing_key.serialize_pem().as_bytes())?;
        std::fs::write(&cert_path, issued.cert.pem())
            .map_err(|cause| format!("{}: {cause}", cert_path.display()))?;
    }
    let chain = CertificateDer::pem_file_iter(&cert_path)
        .map_err(|cause| format!("{}: {cause}", cert_path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|cause| format!("{}: {cause}", cert_path.display()))?;
    let private = PrivateKeyDer::from_pem_file(&key_path)
        .map_err(|cause| format!("{}: {cause}", key_path.display()))?;
    Ok((chain, private))
}

/// Writes a private key readable by its owner alone, where the platform has
/// such a thing.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|cause| format!("{}: {cause}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|cause| format!("{}: {cause}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "a test reports failure by panicking"
)]
mod tests {
    use super::*;

    #[test]
    fn the_relay_is_answered_and_nothing_else() {
        let answer = answer_body("ab", 8443, false);
        let ok =
            String::from_utf8(respond(b"GET /relay HTTP/1.1\r\nHost: x\r\n\r\n", &answer)).unwrap();
        assert!(ok.starts_with("HTTP/1.1 200 OK"), "{ok}");
        assert!(ok.ends_with(&answer), "{ok}");

        let missing =
            String::from_utf8(respond(b"GET /elsewhere HTTP/1.1\r\n\r\n", &answer)).unwrap();
        assert!(missing.starts_with("HTTP/1.1 404"), "{missing}");
        assert!(!missing.contains(&answer), "nothing about the relay: {missing}");

        let posted = String::from_utf8(respond(b"POST /relay HTTP/1.1\r\n\r\n", &answer)).unwrap();
        assert!(posted.starts_with("HTTP/1.1 405"), "{posted}");
    }

    #[test]
    fn the_answer_is_the_key_the_port_and_whether_tls() {
        let answer: serde_json::Value =
            serde_json::from_str(&answer_body("00ff", 8443, true)).unwrap();
        assert_eq!(answer["key"], "00ff");
        assert_eq!(answer["port"], 8443);
        assert_eq!(answer["tls"], true);
    }
}

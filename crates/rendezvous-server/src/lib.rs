//! The rendezvous, served.
//!
//! The service is the library's (`rendezvous::service`): two routes, no
//! authentication, per-source limits keyed on the client's address. This puts
//! it on a socket, over TLS, and does nothing else.
//!
//! # TLS only
//!
//! Records are sealed and signed, so TLS protects no record. It protects
//! **which pseudonyms are asked for, and when**, from anybody on the path, and
//! keeps an on-path party from withholding them. A connection that does not
//! complete a TLS handshake is closed and never reaches the service.
//!
//! # A slow handshake holds up nobody
//!
//! Each handshake runs on its own task, with a deadline. Done in the accept
//! loop, a client that connected and sent nothing would stop everybody behind
//! it, and all it takes to do that is to open a socket and wait.
//!
//! # It remembers nothing
//!
//! The store is in memory. A restart empties it, and each device publishes
//! again on its next interval, which the protocol already assumes: the network
//! works with no rendezvous at all.
//!
//! # It logs nothing per request
//!
//! A line when it starts. Nothing about who published or fetched what: the
//! operator of a rendezvous sees pseudonyms and addresses, and a log is where
//! that would outlive the moment.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

/// Where both services find the certificate unless told otherwise.
pub const CERT_DEFAULT: &str = "/etc/peerfectly/certs/relay.crt";

/// Where both services find the key unless told otherwise.
pub const KEY_DEFAULT: &str = "/etc/peerfectly/certs/relay.key";

/// The variable naming the certificate, for this program and the relay alike.
pub const CERT_VARIABLE: &str = "PEERFECTLY_CERT";

/// The variable naming the key, for this program and the relay alike.
pub const KEY_VARIABLE: &str = "PEERFECTLY_KEY";

/// Where it listens unless told otherwise.
pub const LISTEN_DEFAULT: &str = "[::]:8444";

/// How long a client has to finish its handshake.
pub const HANDSHAKE_WITHIN: Duration = Duration::from_secs(10);

/// How many handshaken connections may wait to be served.
const WAITING: usize = 64;

/// What went wrong, in words.
pub type Refusal = String;

/// What the program was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    /// Where to listen.
    pub listen: SocketAddr,
    /// The certificate, as PEM.
    pub cert: PathBuf,
    /// The key, as PEM.
    pub key: PathBuf,
}

impl Asked {
    /// Reads `--listen`, `--cert` and `--key`. The last two default to the
    /// variables, then to the defaults, so the relay and this read one setting.
    ///
    /// # Errors
    ///
    /// On a word it does not know, a flag with no value, or an address that
    /// will not parse.
    pub fn from_words(
        words: impl IntoIterator<Item = String>,
        variable: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, Refusal> {
        let mut listen = LISTEN_DEFAULT.to_owned();
        let mut cert = variable(CERT_VARIABLE).unwrap_or_else(|| CERT_DEFAULT.to_owned());
        let mut key = variable(KEY_VARIABLE).unwrap_or_else(|| KEY_DEFAULT.to_owned());

        let mut words = words.into_iter();
        while let Some(word) = words.next() {
            let slot = match word.as_str() {
                "--listen" => &mut listen,
                "--cert" => &mut cert,
                "--key" => &mut key,
                other => return Err(format!("unknown argument `{other}`\n{}", usage())),
            };
            *slot = words.next().ok_or_else(|| format!("`{word}` needs a value\n{}", usage()))?;
        }

        let listen =
            listen.parse().map_err(|cause| format!("`{listen}` is not an address: {cause}"))?;
        Ok(Self { listen, cert: cert.into(), key: key.into() })
    }
}

/// How the program is spelled.
#[must_use]
pub fn usage() -> String {
    format!(
        "usage: peerfectly-rendezvous [--listen ADDRESS] [--cert PEM] [--key PEM]\n\
         defaults: --listen {LISTEN_DEFAULT}, --cert ${CERT_VARIABLE} or {CERT_DEFAULT}, \
         --key ${KEY_VARIABLE} or {KEY_DEFAULT}"
    )
}

/// The TLS configuration for a certificate and key read from PEM files.
///
/// # Errors
///
/// When either file cannot be read or holds nothing usable.
pub fn tls(cert: &Path, key: &Path) -> Result<Arc<rustls::ServerConfig>, Refusal> {
    let read = |path: &Path| {
        std::fs::read(path)
            .map_err(|cause| format!("{} could not be read: {cause}", path.display()))
    };
    let chain = CertificateDer::pem_slice_iter(&read(cert)?)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|cause| format!("{} is not a PEM certificate: {cause}", cert.display()))?;
    if chain.is_empty() {
        return Err(format!("{} holds no certificate", cert.display()));
    }
    let private = PrivateKeyDer::from_pem_slice(&read(key)?)
        .map_err(|cause| format!("{} is not a PEM private key: {cause}", key.display()))?;

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|cause| cause.to_string())?
    .with_no_client_auth()
    .with_single_cert(chain, private)
    .map_err(|cause| format!("the certificate and key do not make a TLS server: {cause}"))?;
    Ok(Arc::new(config))
}

/// Connections that completed a TLS handshake, with who made them.
pub struct Handshaken {
    /// Where they arrive.
    arriving: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    /// Where the socket is.
    local: SocketAddr,
}

impl Handshaken {
    /// Accepts on `listener`, handshaking each connection on its own task.
    ///
    /// # Errors
    ///
    /// When the listener cannot say where it is.
    pub fn over(listener: TcpListener, tls: Arc<rustls::ServerConfig>) -> std::io::Result<Self> {
        let local = listener.local_addr()?;
        let acceptor = TlsAcceptor::from(tls);
        let (sending, arriving) = mpsc::channel(WAITING);
        tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    // One failed accept — a descriptor limit, a reset — is not
                    // a reason to stop accepting the next.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let acceptor = acceptor.clone();
                let sending = sending.clone();
                tokio::spawn(async move {
                    // Not TLS, too slow, or refused: closed, and never served.
                    if let Ok(Ok(secured)) =
                        tokio::time::timeout(HANDSHAKE_WITHIN, acceptor.accept(stream)).await
                    {
                        let _ = sending.send((secured, peer)).await;
                    }
                });
            }
        });
        Ok(Self { arriving, local })
    }
}

impl axum::serve::Listener for Handshaken {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.arriving.recv().await {
            Some(arrived) => arrived,
            // The accept loop never ends while this lives; waiting for ever is
            // what an accept with nothing left to accept does.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

/// Serves the rendezvous on `listener` until the process ends.
///
/// The client's address reaches the service as connect info, which is what its
/// per-source limit keys on.
///
/// # Errors
///
/// When serving stops with an error.
pub async fn serve(listener: TcpListener, tls: Arc<rustls::ServerConfig>) -> std::io::Result<()> {
    use axum::serve::ListenerExt as _;

    let app = rendezvous::service::router(rendezvous::service::shared_store());
    // `tap_io` for the connect info: axum gives a listener's own address type
    // connect info through it, and the service reads a `SocketAddr`.
    let listening = Handshaken::over(listener, tls)?.tap_io(|_| {});
    axum::serve(listening, app.into_make_service_with_connect_info::<SocketAddr>()).await
}

//! The endpoint two devices use to enrol, and nothing else.
//!
//! # Why this is not the ordinary endpoint
//!
//! A device with no roster cannot decide membership, having nothing to decide it
//! from. So the side that is *waiting* to join accepts a peer no roster names —
//! the one exception in this crate, and it is an exception to the check rather
//! than to the rule behind it. It grants that peer nothing: this endpoint speaks
//! its own protocol, carries no application payload, and exists only while a
//! person is enrolling.
//!
//! # Waiting and admitting are different types
//!
//! [`Waiting`] accepts and cannot dial. [`Admitting`] dials and **has no
//! listener at all**.
//!
//! That split is the point. Admitting somebody needs an enrolment endpoint on
//! the machine that already holds a roster, routes and data — and an endpoint
//! that could also accept would put a door into exactly the machine the ordinary
//! rule protects. There is no flag here to set wrongly: an [`Admitting`] has no
//! method that listens.
//!
//! # The channel is what the confirmation code is bound to
//!
//! [`Channel::material`] exports keying material from the established QUIC
//! connection. Both ends of one channel export the same value, two channels
//! never export the same value, and neither side can choose it. That is what
//! makes a six-digit code safe: every key involved is public, so a code derived
//! from keys alone could be computed in advance and then matched by grinding key
//! pairs against a space of one million.

use std::sync::{Arc, Mutex};

use identity::NodeIdentity;
use iroh::endpoint::{Connection, RecvStream, RelayMode, SendStream, presets};
use iroh::{
    Endpoint, EndpointAddr, PublicKey as EndpointKey, RelayConfig, RelayMap, RelayUrl, SecretKey,
};
use iroh_relay::RelayQuicConfig;
use roster::sign::PublicKey;
use roster::types::Algorithm;

use crate::error::{BuildError, Result};

/// The protocol name an enrolment speaks.
///
/// Different from the one ordinary sessions use, so the two cannot be confused
/// by anything — an ordinary peer and an enrolment endpoint fail to agree on a
/// protocol and never establish at all. Structural, rather than a check
/// somebody could omit.
pub const ENROLMENT_ALPN: &[u8] = b"peerfectly/enrolment/1";

/// The label the channel material is exported under.
const EXPORT_LABEL: &[u8] = b"peerfectly enrolment channel v1";

/// How many bytes of channel material are exported.
const MATERIAL_LEN: usize = 32;

/// Written by the dialling side the moment the stream is opened.
///
/// QUIC does not surface a stream to the far end until something is written on
/// it, so an exchange whose stream carried nothing until the first message would
/// leave the waiting side blocked — and since the waiting side is the one that
/// speaks first here, neither side would ever move. Four bytes cost nothing and
/// make "the exchange is open" mean the same thing at both ends.
///
/// The same trap the ordinary session protocol hit, and the same answer.
const OPENER: &[u8] = b"enrl";

/// The largest enrolment message this will read, in bytes.
///
/// The roster travels through here, so this admits a log rather than one
/// operation. Bounded because it arrives from a peer nothing has authenticated,
/// and the length is checked before anything is reserved for it.
const MAX_MESSAGE: usize = 1024 * 1024;

/// A device with no roster, waiting to be admitted.
///
/// Accepts, and cannot dial: there is no method here that opens a connection.
#[derive(Debug)]
pub struct Waiting {
    /// The bound endpoint.
    endpoint: Endpoint,
    /// The relay it registered at, as the person supplied it.
    relay: String,
    /// The relay certificate accepted without anything vouching for it.
    ///
    /// `None` when ordinary verification was enough. Readable once the endpoint
    /// is online, and carried forward so that adopting a network can insist the
    /// network pins this same certificate.
    accepted_on_sight: Arc<Mutex<Option<Vec<u8>>>>,
}

impl Waiting {
    /// Binds an endpoint at a relay a person named, with no roster at all.
    ///
    /// The relay's certificate is verified the ordinary way first. Only when
    /// that fails is one accepted on sight, and then it is recorded rather than
    /// waved through — [`Waiting::accepted_on_sight`] returns it so a person can
    /// be shown the fingerprint and a later adoption can insist the network pins
    /// the same certificate.
    ///
    /// # Errors
    ///
    /// When the transport key is not ed25519, the relay address is not one, or
    /// the endpoint cannot be bound.
    pub async fn listen(identity: &NodeIdentity, relay: &str) -> Result<Self> {
        let secret = secret_of(identity)?;
        let url: RelayUrl =
            relay.parse().map_err(|_| BuildError::UnusableRelay { address: relay.to_owned() })?;

        let seen = Arc::new(Mutex::new(None));
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .alpns(vec![ENROLMENT_ALPN.to_vec()])
            .relay_mode(relay_mode(Some(url)))
            .ca_tls_config(trust_on_sight(Arc::clone(&seen)))
            .bind()
            .await
            .map_err(|reason| BuildError::Bind(reason.to_string()))?;

        Ok(Self { endpoint, relay: relay.to_owned(), accepted_on_sight: seen })
    }

    /// Waits until the relay has this endpoint, so a peer can reach it.
    pub async fn online(&self) {
        self.endpoint.online().await;
    }

    /// The relay this endpoint registered at, for the payload to carry.
    #[must_use]
    pub fn relay(&self) -> &str {
        &self.relay
    }

    /// This device's transport key, which is also its endpoint identity.
    #[must_use]
    pub fn transport_key(&self) -> PublicKey {
        transport_key_of(&self.endpoint)
    }

    /// The relay certificate accepted with nothing vouching for it, if any.
    #[must_use]
    pub fn accepted_on_sight(&self) -> Option<Vec<u8>> {
        self.accepted_on_sight.lock().ok().and_then(|held| held.clone())
    }

    /// Waits for somebody to open an enrolment exchange.
    ///
    /// # Errors
    ///
    /// When the endpoint stops accepting, or the connection fails before it is
    /// usable.
    pub async fn accept(&self) -> Result<Channel> {
        let incoming =
            self.endpoint.accept().await.ok_or(BuildError::Bind("stopped accepting".to_owned()))?;
        let connection = incoming.await.map_err(|cause| BuildError::Bind(cause.to_string()))?;
        let (send, mut recv) =
            connection.accept_bi().await.map_err(|cause| BuildError::Bind(cause.to_string()))?;

        let mut opener = [0u8; 4];
        recv.read_exact(&mut opener).await.map_err(|cause| BuildError::Bind(cause.to_string()))?;
        if opener != OPENER {
            return Err(BuildError::Bind("the peer does not speak this exchange".to_owned()));
        }
        Ok(Channel { connection, send, recv })
    }

    /// Stops waiting, and stops being reachable.
    pub async fn close(self) {
        self.endpoint.close().await;
    }
}

/// A device that holds a roster, admitting one that does not.
///
/// Dials, and has no listener: nothing can open an enrolment exchange against a
/// machine that already has a network.
#[derive(Debug)]
pub struct Admitting {
    /// The bound endpoint. No ALPN is offered, so nothing can be accepted.
    endpoint: Endpoint,
}

impl Admitting {
    /// Binds an endpoint that will only ever dial.
    ///
    /// No protocol is offered, so there is nothing for an incoming connection to
    /// agree with. The relay is the one the network names, because this side has
    /// a roster to read it from.
    ///
    /// # Errors
    ///
    /// When the transport key is not ed25519, the network's relay address is not
    /// usable, or the endpoint cannot be bound.
    pub async fn dialling(
        identity: &NodeIdentity,
        state: &roster::state::RosterState,
    ) -> Result<Self> {
        let secret = secret_of(identity)?;
        // As the node's: it lives on the relay being left during a move, and
        // verifies each relay by its own rule. The device it dials may be waiting
        // at either, and `iroh` opens a connection to whichever relay a peer's
        // address names — which is why the payload's relay is checked before this
        // is ever built.
        let now = crate::relays::now_ms();
        let relays = crate::relays::relays_at(&state.params, now)?;
        let home = crate::relays::home_at(&state.params, now)?;

        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            // Deliberately no `alpns`: an endpoint that offers no protocol
            // accepts nothing, whatever anybody sends it.
            .relay_mode(crate::relays::relay_mode(home.as_ref()));

        if let Some(tls) = crate::relays::tls_for(&relays)? {
            builder = builder.ca_tls_config(tls);
        }

        let endpoint =
            builder.bind().await.map_err(|reason| BuildError::Bind(reason.to_string()))?;
        Ok(Self { endpoint })
    }

    /// Opens an exchange with a device waiting at a relay.
    ///
    /// # Errors
    ///
    /// When the key is not an endpoint identity, the relay address is not one,
    /// or the device cannot be reached.
    pub async fn reach(&self, peer: &PublicKey, relay: &str) -> Result<Channel> {
        let bytes: [u8; 32] = peer
            .as_bytes()
            .try_into()
            .map_err(|_| BuildError::Bind("the key is not 32 bytes".to_owned()))?;
        let id =
            EndpointKey::from_bytes(&bytes).map_err(|cause| BuildError::Bind(cause.to_string()))?;
        let url: RelayUrl =
            relay.parse().map_err(|_| BuildError::UnusableRelay { address: relay.to_owned() })?;

        let connection = self
            .endpoint
            .connect(EndpointAddr::new(id).with_relay_url(url), ENROLMENT_ALPN)
            .await
            .map_err(|cause| BuildError::Bind(cause.to_string()))?;
        let (mut send, recv) =
            connection.open_bi().await.map_err(|cause| BuildError::Bind(cause.to_string()))?;
        send.write_all(OPENER).await.map_err(|cause| BuildError::Bind(cause.to_string()))?;
        Ok(Channel { connection, send, recv })
    }

    /// Stops dialling and drops the endpoint.
    pub async fn close(self) {
        self.endpoint.close().await;
    }
}

/// One enrolment exchange.
///
/// Carries enrolment messages and offers no way to send anything else. It is not
/// a [`crate::Session`] and cannot be used where one is expected.
#[derive(Debug)]
pub struct Channel {
    /// The QUIC connection, kept for its keying material.
    connection: Connection,
    /// The half this side writes to.
    send: SendStream,
    /// The half this side reads from.
    recv: RecvStream,
}

impl Channel {
    /// Material that identifies this channel and no other.
    ///
    /// Exported from the connection's own secrets: both ends of one exchange get
    /// the same value, two exchanges never get the same value, and neither side
    /// can choose it. A confirmation code derived over this cannot be computed
    /// before the channel exists, which is what a six-digit code needs to be
    /// worth anything.
    ///
    /// # Errors
    ///
    /// When the connection cannot export, which means it is not established.
    pub fn material(&self) -> Result<Vec<u8>> {
        let mut out = vec![0u8; MATERIAL_LEN];
        self.connection
            .export_keying_material(&mut out, EXPORT_LABEL, &[])
            .map_err(|_| BuildError::Bind("the channel is not established".to_owned()))?;
        Ok(out)
    }

    /// The peer's transport key, as the handshake authenticated it.
    ///
    /// This is the one thing the channel itself proves. The signing key a
    /// payload names is proved separately, by a signature over
    /// [`Channel::material`].
    ///
    /// # Errors
    ///
    /// When the peer's identity cannot be read from the connection.
    pub fn peer(&self) -> Result<PublicKey> {
        let id = self.connection.remote_id();
        PublicKey::new(Algorithm::Ed25519, id.as_bytes().to_vec())
            .map_err(|cause| BuildError::Bind(cause.to_string()))
    }

    /// Sends one message, whole.
    ///
    /// # Errors
    ///
    /// When the message is larger than the bound, or the channel fails.
    pub async fn send(&mut self, message: &[u8]) -> Result<()> {
        let len = u32::try_from(message.len())
            .map_err(|_| BuildError::Bind("the message is too large".to_owned()))?;
        if message.len() > MAX_MESSAGE {
            return Err(BuildError::Bind("the message is too large".to_owned()));
        }
        self.send
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|cause| BuildError::Bind(cause.to_string()))?;
        self.send.write_all(message).await.map_err(|cause| BuildError::Bind(cause.to_string()))?;
        Ok(())
    }

    /// Reads one message, whole.
    ///
    /// # Errors
    ///
    /// When the declared length exceeds the bound — checked before anything is
    /// reserved — or the channel fails before a whole message arrives.
    pub async fn receive(&mut self) -> Result<Vec<u8>> {
        let mut header = [0u8; 4];
        self.recv
            .read_exact(&mut header)
            .await
            .map_err(|cause| BuildError::Bind(cause.to_string()))?;
        let len = u32::from_be_bytes(header) as usize;
        if len > MAX_MESSAGE {
            return Err(BuildError::Bind("the peer declared an oversized message".to_owned()));
        }
        let mut body = vec![0u8; len];
        self.recv
            .read_exact(&mut body)
            .await
            .map_err(|cause| BuildError::Bind(cause.to_string()))?;
        Ok(body)
    }
}

/// The relay mode for an address, or none.
fn relay_mode(relay: Option<RelayUrl>) -> RelayMode {
    match relay {
        Some(url) => {
            let port = url.port_or_known_default().unwrap_or(443);
            RelayMode::Custom(RelayMap::from(RelayConfig::new(
                url,
                Some(RelayQuicConfig::new(port)),
            )))
        }
        None => RelayMode::Disabled,
    }
}

/// This device's transport secret, checked for an algorithm this layer can use.
fn secret_of(identity: &NodeIdentity) -> Result<SecretKey> {
    let key = identity.transport_key();
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(BuildError::NotEd25519 { algorithm: key.algorithm() });
    }
    Ok(SecretKey::from_bytes(key.material().expose()))
}

/// This endpoint's own transport key.
fn transport_key_of(endpoint: &Endpoint) -> PublicKey {
    PublicKey::new(Algorithm::Ed25519, endpoint.id().as_bytes().to_vec())
        .unwrap_or_else(|_| unreachable!("an endpoint identity is always a valid ed25519 key"))
}

/// A TLS configuration that verifies first and accepts on sight second.
///
/// A device with no roster has nothing to check a relay's certificate against,
/// but that is no reason to skip a check that can succeed: a relay with a
/// publicly signed certificate is verified the ordinary way and no person is
/// bothered. Only when that fails is the presented certificate recorded and
/// accepted, so a person can be shown the fingerprint and the network can settle
/// it later.
fn trust_on_sight(seen: Arc<Mutex<Option<Vec<u8>>>>) -> iroh::tls::CaTlsConfig {
    iroh::tls::CaTlsConfig::custom_server_cert_verifier(Arc::new(move |provider| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let ordinary = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&provider),
        )
        .build()
        .map_err(std::io::Error::other)?;

        Ok(Arc::new(OnSight { ordinary, provider, seen: Arc::clone(&seen) }))
    }))
}

/// Verifies the ordinary way, and records what it accepted when it cannot.
#[derive(Debug)]
struct OnSight {
    /// The ordinary verifier, tried first.
    ordinary: Arc<rustls::client::WebPkiServerVerifier>,
    /// The provider whose algorithms check the handshake signature.
    provider: Arc<rustls::crypto::CryptoProvider>,
    /// Where an accepted-on-sight certificate is recorded.
    seen: Arc<Mutex<Option<Vec<u8>>>>,
}

impl rustls::client::danger::ServerCertVerifier for OnSight {
    fn verify_server_cert(
        &self,
        presented: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        name: &rustls::pki_types::ServerName<'_>,
        stapled: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> core::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match self.ordinary.verify_server_cert(presented, intermediates, name, stapled, now) {
            Ok(verified) => Ok(verified),
            Err(_) => {
                // Recorded, not waved through. What makes this safe is not this
                // moment but the one after it: the network this device adopts
                // must pin this same certificate, or the roster is refused.
                if let Ok(mut held) = self.seen.lock() {
                    *held = Some(presented.to_vec());
                }
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> core::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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
    ) -> core::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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

//! Building an endpoint, and dialling and accepting over it.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use identity::NodeIdentity;
use iroh::endpoint::{Connection, presets};
use iroh::{Endpoint, EndpointAddr, PublicKey as EndpointKey, RelayUrl, SecretKey, TransportAddr};
use roster::sign::PublicKey;
use roster::state::RosterState;
use roster::types::Algorithm;
use rustls_pki_types::CertificateDer;
use tokio::sync::Mutex;
use transport::error::{Error, Result as SessionResult};
use transport::session::{Session, Transport};

use crate::error::{BuildError, Result};
use crate::session::{IrohSession, SessionHandle};

/// Written by the dialler the moment the session stream is opened.
///
/// QUIC does not surface a stream to the far end until something is written on
/// it, so a session whose stream carried nothing until the first payload would
/// leave the accepting side waiting — possibly forever, if the dialler had
/// nothing to say yet. Four bytes cost nothing and make establishment mean the
/// same thing on both sides.
///
/// It doubles as a check that both ends speak this framing: a peer that opened a
/// stream and wrote something else is refused here rather than at the first
/// payload, where it would look like corruption.
const STREAM_OPENER: [u8; 4] = *b"MNT1";

/// The protocol this binding speaks.
///
/// A dedicated identifier, so an unrelated application on the same connectivity
/// layer cannot open a session here by accident, and so a future version of this
/// protocol can be told apart from this one rather than being guessed at.
///
/// `2` since sessions are opened on demand and reconciliation leads with a
/// digest: a node of the first version cannot read the second's messages, so
/// the two must not open a session at all. They fail at the handshake instead,
/// which [`Error::IncompatibleVersion`] names.
pub const ALPN: &[u8] = b"peerfectly/transport/2";

/// How many peers direct addresses are remembered for.
///
/// A roster is bounded, and this only ever holds hints for devices in one. The
/// bound is here so that a caller which offered addresses for keys that are not
/// members could not make this grow without end.
const MAX_LEARNED_PEERS: usize = 64;

/// How long a path may deliver nothing before it is abandoned.
///
/// The connectivity layer's own default is fifteen seconds, and a path that has
/// gone silent holds the session for every one of them: fifteen seconds of a
/// frozen tunnel, which is what this was first measured at. Nine seconds is three
/// keep-alives below, the same ratio `iroh` chose for its defaults, and is
/// clamped by it to at most its own fifteen.
///
/// It was three, from a keep-alive every second. Measured on 2026-10-07, that
/// keep-alive was the larger part of what an idle device spent — a packet a
/// second each way on every session, about 0.9 GB a month for one peer — and a
/// session now exists only while something uses it, so the rate it pays is the
/// rate of a session in use. Three seconds is what Tailscale keeps its active
/// paths alive at. What it costs is a tunnel that can stall for up to about nine
/// seconds instead of three when a path dies **silently**; a change of network
/// the machine reports is acted on at once.
///
/// This bounds what the path rule in `paths` cannot foresee — a carrier that
/// stops forwarding, a network that changes under a session. Abandoning the dead
/// path is also the event that asks the rule to choose again, so this is how
/// long every wrong choice can last.
const PATH_IDLE: core::time::Duration = core::time::Duration::from_secs(9);

/// How often a path with nothing to carry says something.
///
/// Three seconds, so [`PATH_IDLE`] is three missed beats rather than one. Clamped
/// by `iroh` to at most its own five. See [`PATH_IDLE`] for why it is no longer
/// one.
const PATH_KEEP_ALIVE: core::time::Duration = core::time::Duration::from_secs(3);

/// How many addresses are remembered per peer.
///
/// A device has a handful: one per interface it is on. Enough for that, and few
/// enough that a dial does not turn into a long list of attempts.
const MAX_LEARNED_ADDRESSES: usize = 8;

/// A node reachable over a real network.
pub struct IrohTransport {
    /// The bound endpoint. Its identity is this device's transport key.
    endpoint: Endpoint,
    /// The roster state membership decisions are taken from.
    ///
    /// **This is the only membership state this transport holds, and no decision
    /// taken from it is cached.** A transport that remembered "this peer is
    /// allowed" would be a second, quieter roster, consulted far more often than
    /// the signed one — and when the two disagreed, the cache would be the thing
    /// actually deciding who is in the network.
    state: Arc<Mutex<RosterState>>,
    /// Sessions opened so far, so a membership change can reach them.
    open: Arc<Mutex<Vec<Arc<IrohSession>>>>,
    /// The network's relay, parsed once.
    ///
    /// Every device in a network shares one relay, because the address is a
    /// signed network parameter. That is what lets a peer be dialled by key
    /// alone: its home relay is already known, so no directory has to be asked
    /// where it is. Discovery is only needed for *direct* addresses, and the
    /// connectivity layer learns those through the relay itself.
    ///
    /// During a move there are two, and a peer is dialled at both: the network
    /// lives on the relay being left until the end, and clocks that disagree near
    /// it can put a peer on the new one a little early.
    relays: Vec<RelayUrl>,
    /// Direct addresses somebody said a peer was at.
    ///
    /// Hints and nothing more. They shorten the path to a peer on the same
    /// network — §2.9's first case, which needs no relay and no internet — and
    /// they decide nothing: a session established over one is authorised from
    /// the roster exactly like any other, so an address from a liar reaches a
    /// peer that refuses it or reaches nobody at all.
    ///
    /// A `std` mutex rather than the async one beside it, because `learned` is
    /// synchronous — the trait cannot make it otherwise without an async
    /// method on every implementation that has no addresses to learn — and the
    /// critical section is an insert.
    learned: std::sync::Mutex<BTreeMap<EndpointKey, BTreeSet<SocketAddr>>>,
    /// The ranges tunnels of ours serve, which no path may run through.
    ///
    /// Shared with the path selector the endpoint was built with: the endpoint
    /// exists before the caller can say what its tunnels are, so what they hold
    /// between them is this rather than a list.
    avoided: crate::paths::Avoided,
}

/// A trust store holding one pinned relay certificate and nothing else.
///
/// `custom_roots` and not `default().with_extra_roots(..)`: the second would keep
/// every public certificate authority trusted alongside the pin, so anyone who
/// could have a certificate issued for the relay's name — or who runs a
/// certificate authority — could still stand in front of it. That is the
/// arrangement §2.8 exists to avoid.
///
/// The verifier is built here and thrown away, because building it is the only
/// way to find out whether the pin is a certificate at all: the trust store
/// ignores what it cannot parse, so an unusable pin would otherwise become an
/// empty store and read, at every dial, as the relay being wrong.
///
/// # Errors
///
/// When the pinned bytes cannot become a trust anchor.
pub(crate) fn pinned_roots(certificate: &[u8]) -> Result<iroh::tls::CaTlsConfig> {
    let roots = iroh::tls::CaTlsConfig::custom_roots([CertificateDer::from(certificate.to_vec())]);
    roots
        .server_cert_verifier(iroh::tls::default_provider())
        .map_err(|reason| BuildError::UnusableRelayCertificate { reason: reason.to_string() })?;
    Ok(roots)
}

impl IrohTransport {
    /// Binds an endpoint whose identity is this device's transport key.
    ///
    /// The relay comes from the network parameters in `state`. Nothing is
    /// compiled in and no local configuration is consulted: whoever supplies a
    /// relay learns who talks to whom and when, so the answer is the signed one
    /// or there is none.
    pub async fn bind(identity: &NodeIdentity, state: RosterState) -> Result<Self> {
        Self::build(identity, state, false).await
    }

    /// Binds an endpoint that will accept a relay's self-signed certificate.
    ///
    /// For tests that run a relay in this process, which necessarily presents a
    /// certificate no authority signed. It exists behind a feature so that an
    /// ordinary build cannot reach it: a node that accepted any relay
    /// certificate could be steered onto an impostor relay, which learns who
    /// talks to whom and when.
    #[cfg(feature = "insecure-test-relay")]
    pub async fn bind_trusting_any_relay_certificate(
        identity: &NodeIdentity,
        state: RosterState,
    ) -> Result<Self> {
        Self::build(identity, state, true).await
    }

    /// The shared construction path.
    async fn build(
        identity: &NodeIdentity,
        state: RosterState,
        trust_any_relay_certificate: bool,
    ) -> Result<Self> {
        let transport_key = identity.transport_key();
        // Checked here rather than at connect time. A key this layer cannot
        // represent is a misconfiguration, and a misconfiguration that waits
        // until the first connection to appear is one diagnosed on a bad day.
        if transport_key.algorithm() != Algorithm::Ed25519 {
            return Err(BuildError::NotEd25519 { algorithm: transport_key.algorithm() });
        }
        let secret = SecretKey::from_bytes(transport_key.material().expose());

        // Which relays are in use now, and which one this node lives on. Almost
        // always one and the same; during a move, the node lives on the relay
        // being left and can reach the new one too. See `relays`.
        //
        // The QUIC address-discovery port is set from each relay's own URL
        // rather than left at the library default. Two reasons. The default is a
        // port of its own (7842), and a relay configured to serve everything on
        // 443 would never be asked on it — address discovery then silently never
        // happens, no peer learns its observed address, and *every* connection
        // stays relayed. That failure is invisible: the relay works, sessions
        // establish and carry bytes, and only the direct-path count is wrong. And
        // keeping everything on one port is what survives the networks §2.9
        // describes: a corporate firewall that permits 443 outbound will not
        // usually permit 7842.
        //
        // A network confined to a LAN has no relay, and must not be made to
        // invent one. Reaching a peer that needs one is then plainly
        // unreachability, not an internal error.
        let now = crate::relays::now_ms();
        let relays = crate::relays::relays_at(&state.params, now)?;
        let home = crate::relays::home_at(&state.params, now)?;
        let relay_mode = crate::relays::relay_mode(home.as_ref());

        // `Minimal` rather than the connectivity layer's own defaults: those
        // bring third-party relay servers and a third-party address lookup.
        // §2.8 requires a self-hosted relay, and §2.6c requires that a node
        // speak to no infrastructure the user did not choose.
        // What a path may not run through, and the selector that reads it. The
        // endpoint is bound before anything can say what this device's tunnels
        // are, so both hold the same handle and an empty one refuses nothing.
        let avoided = crate::paths::Avoided::new();

        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .alpns(vec![ALPN.to_vec()])
            .relay_mode(relay_mode)
            // Which of a connection's paths carries the session is ours to
            // decide: the default policy takes any direct path the moment it
            // validates, and a path through our own tunnel validates.
            .path_selector(std::sync::Arc::new(crate::paths::Selector::new(avoided.clone())))
            // The net report keeps its HTTPS latency probes, although a network
            // has one relay and nothing to choose between. Without them, a
            // network where QUIC to the relay gets no answer (one that blocks
            // UDP) never picks a home relay, and the device is left with no
            // relay at all where it needs one most. `NetReportConfig::minimal()`
            // did that; the binding tests caught it, their relay answering QUIC
            // on another port.
            .net_report_config(iroh::endpoint::NetReportConfig::default())
            // And under that, a bound on every other way a path can fall
            // silent — a carrier that stops forwarding, a network that changes
            // under a session. The defaults are fifteen seconds of nothing
            // before a dead path is abandoned, which is fifteen seconds of a
            // frozen tunnel; nine keeps the ratio to the keep-alive that
            // `iroh` chose for its own defaults. Both are clamped by `iroh` to
            // at most its 15s and 5s, so neither can be set past what it
            // allows.
            .transport_config(
                iroh::endpoint::QuicTransportConfig::builder()
                    .default_path_max_idle_timeout(PATH_IDLE)
                    .default_path_keep_alive_interval(PATH_KEEP_ALIVE)
                    .build(),
            );

        // A pinned certificate makes the roster the authority on which relay is
        // the network's relay.
        //
        // `custom_roots` and not `default().with_extra_roots(..)`: the second
        // would keep every public certificate authority trusted alongside the
        // pin, so anyone who could get a certificate issued for the relay's name
        // — or who runs a certificate authority — could still stand in front of
        // it. That is the arrangement §2.8 exists to avoid, and the one the
        // product exists to avoid: the trust root belongs to the network.
        //
        // Only the relay is affected. `presets::Minimal` speaks to no other
        // service over TLS, so narrowing this trust store narrows nothing else.
        //
        // During a move, each relay keeps the rule its network gave it, chosen by
        // host — see `relays::tls_for`.
        if let Some(tls) = crate::relays::tls_for(&relays)? {
            builder = builder.ca_tls_config(tls);
        }

        if trust_any_relay_certificate {
            #[cfg(feature = "insecure-test-relay")]
            {
                builder = builder.ca_tls_config(iroh::tls::CaTlsConfig::insecure_skip_verify());
            }
        }

        let endpoint =
            builder.bind().await.map_err(|reason| BuildError::Bind(reason.to_string()))?;

        Ok(Self {
            endpoint,
            state: Arc::new(Mutex::new(state)),
            open: Arc::new(Mutex::new(Vec::new())),
            relays: relays.into_iter().map(|relay| relay.url).collect(),
            learned: std::sync::Mutex::new(BTreeMap::new()),
            avoided,
        })
    }

    /// This node's transport public key, which is also its endpoint identity.
    #[must_use]
    pub fn transport_key(&self) -> PublicKey {
        // Round-tripped through the endpoint rather than the identity, so this
        // reports what the endpoint will actually present.
        PublicKey::new(Algorithm::Ed25519, self.endpoint.id().as_bytes().to_vec())
            .expect("an endpoint identity is a valid ed25519 key")
    }

    /// The roster state decisions are currently taken from.
    pub async fn state(&self) -> RosterState {
        self.state.lock().await.clone()
    }

    /// What this endpoint believes its own addresses are.
    ///
    /// The single most useful thing to look at when no connection ever goes
    /// direct. If this shows only private addresses, the endpoint never learned
    /// its observed public address — which means address discovery is not
    /// reaching the relay over UDP, and no amount of NAT behaviour is to blame.
    /// A genuine traversal failure looks different: a public address is known,
    /// and the direct path still does not form.
    #[must_use]
    pub fn observed_addresses(&self) -> Vec<String> {
        self.endpoint
            .addr()
            .addrs
            .iter()
            .map(|addr| match addr {
                iroh::TransportAddr::Ip(socket) => format!("ip:{socket}"),
                iroh::TransportAddr::Relay(url) => format!("relay:{url}"),
                other => format!("other:{other:?}"),
            })
            .collect()
    }

    /// Whether discovery returned an address this host does not hold locally.
    ///
    /// Distinct from [`Self::knows_a_public_address`], and the distinction
    /// matters: discovery can be working perfectly and still return only private
    /// addresses — behind carrier-grade NAT, or inside a lab topology. Reading
    /// "no routable address" as "discovery is broken" is a mistake that costs a
    /// measurement.
    #[must_use]
    pub fn learned_an_address_beyond(&self, own: Option<std::net::IpAddr>) -> bool {
        self.endpoint.addr().addrs.iter().any(|addr| match addr {
            iroh::TransportAddr::Ip(socket) => {
                Some(socket.ip()) != own && !socket.ip().is_loopback()
            }
            _ => false,
        })
    }

    /// Whether any address this endpoint knows for itself is routable.
    ///
    /// False means discovery has not worked, whatever the peer does.
    #[must_use]
    pub fn knows_a_public_address(&self) -> bool {
        self.endpoint.addr().addrs.iter().any(|addr| match addr {
            iroh::TransportAddr::Ip(socket) => {
                let ip = socket.ip();
                !ip.is_loopback() && !is_private(&ip)
            }
            _ => false,
        })
    }

    /// The endpoint, for tests and for a caller that needs its address.
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Turns an established connection into a session, once the roster agrees.
    async fn admit(&self, connection: Connection) -> SessionResult<Box<dyn Session>> {
        // Possession is already proven: the handshake established that the peer
        // holds the private half of the identity it presented, and proved it
        // bound to this channel. What remains is whether the roster names it.
        let remote = connection.remote_id();
        let presented = PublicKey::new(Algorithm::Ed25519, remote.as_bytes().to_vec())
            .map_err(|_| Error::PossessionNotProven)?;

        let state = self.state.lock().await.clone();
        let device = transport::auth::authorize(&state, &presented.key_id())?;

        let (mut outbound, mut inbound) = if connection.side().is_client() {
            let (mut send, recv) = connection.open_bi().await.map_err(|_| Error::ClosedByPeer)?;
            send.write_all(&STREAM_OPENER).await.map_err(|_| Error::ClosedByPeer)?;
            (send, recv)
        } else {
            let (send, mut recv) = connection.accept_bi().await.map_err(|_| Error::ClosedByPeer)?;
            let mut opener = [0u8; STREAM_OPENER.len()];
            recv.read_exact(&mut opener).await.map_err(|_| Error::ClosedByPeer)?;
            if opener != STREAM_OPENER {
                return Err(Error::ClosedByPeer);
            }
            (send, recv)
        };
        // Both halves are handed to the session already past the opener, so no
        // reader can mistake it for a payload.
        let _ = &mut outbound;
        let _ = &mut inbound;

        let session = IrohSession::new(device, connection, outbound, inbound);
        self.open.lock().await.push(Arc::clone(&session));
        Ok(Box::new(SessionHandle(session)))
    }
}

#[async_trait]
impl Transport for IrohTransport {
    /// Hands the transport newer roster state.
    ///
    /// Every session whose peer has stopped being a member is closed. A
    /// revocation that applied only to new connections would leave an
    /// established session alive indefinitely — a window we opened ourselves, on
    /// a channel already carrying traffic.
    ///
    /// Declared only here and not as an inherent method too. Two ways to reach
    /// one operation is how this came to be called by tests and by nothing else,
    /// while the daemon holding a `dyn Transport` had no way to call it at all.
    ///
    /// Sessions that survive are **kept**, not forgotten. An earlier version
    /// cleared the whole list once it had closed what it had to, which left every
    /// still-valid session untracked — so the next membership change closed
    /// nothing, having nothing left to look at. That is only reachable when the
    /// state is replaced more than once, which nothing did until now.
    async fn update_state(&self, state: RosterState) {
        let mut sessions = self.open.lock().await;
        let held = core::mem::take(&mut *sessions);
        let mut kept = Vec::with_capacity(held.len());
        for session in held {
            if !transport::auth::is_member(&state, &session.device()) {
                session.shut(Error::ClosedOnMembershipLoss).await;
                continue;
            }
            // A session the peer already ended is not worth carrying forward.
            if session.closure().await.is_none() {
                kept.push(session);
            }
        }
        *sessions = kept;
        *self.state.lock().await = state;
    }

    /// The path the open session with `peer` is on now, from the connection's own
    /// paths. `None` when no session with that device is open.
    async fn path_to(&self, peer: &roster::id::DeviceId) -> Option<transport::session::Path> {
        let sessions = self.open.lock().await;
        for session in sessions.iter().filter(|session| session.device() == *peer) {
            if session.closure().await.is_none() {
                return Some(session.path());
            }
        }
        None
    }

    async fn connect(&self, peer: &PublicKey) -> SessionResult<Box<dyn Session>> {
        // The bytes being dialled are the bytes the roster authorises. No
        // lookup table stands between them, so there is no second answer to
        // "who is this peer" to disagree with the signed log.
        let bytes: [u8; 32] = peer.as_bytes().try_into().map_err(|_| Error::PeerUnreachable {
            cause: Some("the key is not 32 bytes".to_owned()),
        })?;
        let id = EndpointKey::from_bytes(&bytes)
            .map_err(|cause| Error::PeerUnreachable { cause: Some(cause.to_string()) })?;

        // The network's relay is the peer's home relay too, so the address is
        // known without asking anyone. A network with no relay can only reach
        // peers whose direct addresses are already known, and failing to is
        // unreachability rather than an error.
        let address =
            self.relays.iter().cloned().fold(EndpointAddr::new(id), EndpointAddr::with_relay_url);
        // Direct addresses somebody heard, offered alongside the relay rather
        // than instead of it. The connectivity layer races them: on one network
        // a direct address wins immediately, and off it the relay still works.
        let address = address.with_addrs(
            self.learned
                .lock()
                .map(|held| held.get(&id).cloned().unwrap_or_default())
                .unwrap_or_default()
                .into_iter()
                .map(TransportAddr::Ip),
        );

        // The connectivity layer's own words, kept. Without them a failed dial
        // says only that it failed, and the difference between a relay that is
        // down, a peer that is not there, and a protocol mismatch is exactly what
        // somebody needs at that moment.
        let connection = self.endpoint.connect(address, ALPN).await.map_err(|cause| {
            if offers_another_protocol(&cause) {
                Error::IncompatibleVersion
            } else {
                Error::PeerUnreachable { cause: Some(cause.to_string()) }
            }
        })?;
        self.admit(connection).await
    }

    fn addresses(&self) -> Vec<String> {
        // Only the IP addresses. The relay is a signed network parameter, so
        // every device already knows it and announcing it would be telling
        // peers what they read from the roster.
        self.endpoint
            .addr()
            .addrs
            .into_iter()
            .filter_map(|address| match address {
                TransportAddr::Ip(socket) => Some(socket.to_string()),
                _ => None,
            })
            .collect()
    }

    /// Takes the ranges this device's tunnels serve.
    ///
    /// Held for the path selector to read at its next decision rather than acted
    /// on here: a path already carrying a session is not torn down because a
    /// tunnel came up, it stops being chosen the next time there is a choice —
    /// and the short path idle timeout means that is soon.
    fn avoid(&self, ranges: &[transport::Range]) {
        self.avoided.set(ranges);
    }

    fn own_ports(&self) -> Vec<u16> {
        self.endpoint.bound_sockets().iter().map(std::net::SocketAddr::port).collect()
    }

    fn learned(&self, peer: &PublicKey, addresses: &[String]) {
        let Ok(bytes) = <[u8; 32]>::try_from(peer.as_bytes()) else { return };
        let Ok(id) = EndpointKey::from_bytes(&bytes) else { return };

        // Unparseable addresses are dropped rather than reported. They are
        // hints from the network, and what an address looks like is this
        // crate's business — a caller that passed on what it heard has done
        // nothing wrong.
        let offered: BTreeSet<SocketAddr> =
            addresses.iter().filter_map(|address| address.parse().ok()).collect();
        if offered.is_empty() {
            return;
        }

        let Ok(mut held) = self.learned.lock() else { return };
        if !held.contains_key(&id) && held.len() >= MAX_LEARNED_PEERS {
            return;
        }
        let entry = held.entry(id).or_default();
        // Replaced, not merged: what a peer says now is where it is now, and
        // merging would keep an address it has moved away from.
        *entry = offered.into_iter().take(MAX_LEARNED_ADDRESSES).collect();
    }

    async fn accept(&self) -> SessionResult<Box<dyn Session>> {
        let incoming = self.endpoint.accept().await.ok_or(Error::PeerUnreachable {
            cause: Some("the endpoint stopped accepting".to_owned()),
        })?;
        let connection = incoming
            .await
            .map_err(|cause| Error::PeerUnreachable { cause: Some(cause.to_string()) })?;
        self.admit(connection).await
    }
}

/// Whether an address is one of the ranges that never appears on the internet.
///
/// Includes the carrier-grade NAT range: an endpoint whose only "public" address
/// is in `100.64.0.0/10` has learned a carrier's inside address, not a reachable
/// one, and a peer cannot send to it.
fn is_private(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || (a == 100 && (64..=127).contains(&b))
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments().first().unwrap_or(&0) & 0xfe00) == 0xfc00
        }
    }
}

/// Whether a dial failed because the peer offered no protocol name in common.
///
/// TLS says so with alert 120, `no_application_protocol`, which QUIC carries
/// as the crypto error of that number in the close it receives. Between two
/// devices of one network that means one of them runs another version.
fn offers_another_protocol(cause: &iroh::endpoint::ConnectError) -> bool {
    use iroh::endpoint::{ConnectError, ConnectingError, ConnectionError, TransportErrorCode};
    let no_application_protocol = TransportErrorCode::crypto(120);
    let closed = match cause {
        ConnectError::Connecting {
            source: ConnectingError::ConnectionError { source, .. },
            ..
        }
        | ConnectError::Connection { source, .. } => source,
        _ => return false,
    };
    match closed {
        ConnectionError::ConnectionClosed(close) => close.error_code == no_application_protocol,
        ConnectionError::TransportError(error) => error.code == no_application_protocol,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{PATH_IDLE, PATH_KEEP_ALIVE};

    /// The two numbers the `transport-iroh` capability states: a keep-alive
    /// every three seconds while a session is open, and a silent path left in
    /// under ten. Pinned because either drifting changes what an idle device
    /// spends or how long a tunnel can stall, and neither shows in a test that
    /// only checks a session works.
    #[test]
    fn a_path_is_kept_alive_every_three_seconds_and_left_within_ten() {
        assert_eq!(PATH_KEEP_ALIVE.as_secs(), 3);
        assert!(PATH_IDLE.as_secs() < 10, "a silent path is left in under ten seconds");
        assert_eq!(
            PATH_IDLE.as_secs(),
            PATH_KEEP_ALIVE.as_secs().saturating_mul(3),
            "three missed keep-alives, the ratio iroh uses for its own defaults"
        );
    }
}

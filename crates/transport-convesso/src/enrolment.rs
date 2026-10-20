//! The endpoints two devices use to enrol, and nothing else.
//!
//! The same shape as the iroh binding's, so the daemon calls them alike:
//! [`Waiting`] accepts and cannot dial; [`Admitting`] dials and serves nothing
//! anyone can open; a [`Channel`] carries whole messages and the material a
//! confirmation code is bound to.
//!
//! # A node of their own
//!
//! Each endpoint is a convesso node of its own, in the context
//! [`ENROLMENT_CONTEXT`], with a stream configuration whose largest message is
//! enrolment's bound for a roster ([`MAX_MESSAGE`]).
//!
//! The admitting side runs under a key made for that admission alone. The
//! relay keeps one client per key, so a second node under the admitting
//! machine's own key would take the relay's place from the machine's running
//! transport node. Nothing relied on that key: the joining device verifies what
//! it adopts by the roster's signatures, and the confirmation code binds the
//! two keys the channel authenticated, whatever they are.
//!
//! # The opening message carries the dialler's key
//!
//! convesso tells the accepting side the dialler's X25519 peer id, which the
//! handshake authenticated, and not the ed25519 key a code is derived from. So
//! the dialler's first message is [`OPENER`] followed by its ed25519 key, and
//! the waiting side accepts the key only when it converts to the authenticated
//! peer id. A key that does not is refused, and the exchange with it.
//!
//! # The material
//!
//! [`Channel::material`] is the session's channel binding: the Noise handshake
//! hash, equal at both ends of one channel and different for every handshake,
//! chosen by neither side alone.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use convesso_core::identity::{Address, Identity, PeerId};
use convesso_stream::config::StreamConfig;
use convesso_tokio::entropy::OsEntropy;
use convesso_tokio::{
    Access, Config, Context, ContextEvent, ContextEvents, ContextOptions, Events, Node, NodeEvent,
};
use identity::NodeIdentity;
use roster::sign::PublicKey;
use roster::types::Algorithm;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::error::{BuildError, Result};

/// The context enrolment runs in, apart from the sessions' own.
pub const ENROLMENT_CONTEXT: &[u8] = b"peerfectly/enrolment";

/// The first bytes the dialler sends, before its ed25519 key.
pub const OPENER: &[u8] = b"enrl";

/// The largest enrolment message: the roster travels through here.
pub const MAX_MESSAGE: usize = 1024 * 1024;

convesso_stream::config! {
    /// The stream configuration of an enrolment node: the server's, with room
    /// for enrolment's largest message.
    pub EnrolmentStream: Server {
        max_message: MAX_MESSAGE,
        send_bytes: 2 * MAX_MESSAGE,
        receive_bytes: 2 * MAX_MESSAGE,
    }
}

const _: () = assert!(<EnrolmentStream as StreamConfig>::MAX_MESSAGE >= MAX_MESSAGE);

/// Messages for each peer an exchange is open with, and the openings waiting
/// for `accept`.
#[derive(Default)]
struct Routes {
    open: HashMap<PeerId, mpsc::UnboundedSender<Vec<u8>>>,
}

/// What both endpoints hold: a node, its one context, and the task reading it.
struct Endpoint {
    node: Node,
    context: Context,
    routes: Arc<Mutex<Routes>>,
    /// Messages from peers with no exchange open: openings, for `accept`.
    unrouted: tokio::sync::Mutex<mpsc::UnboundedReceiver<(PeerId, Vec<u8>)>>,
    /// Peers whose session came up, or whose dial failed, for `reach`.
    dials: tokio::sync::Mutex<mpsc::UnboundedReceiver<(PeerId, Option<String>)>>,
    online: watch::Receiver<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Endpoint {
    async fn start(
        own: Identity,
        relay: Option<&str>,
        access: Access,
        reachable: bool,
    ) -> Result<Self> {
        let relay = relay
            .map(crate::relay::parse)
            .transpose()
            .map_err(|cause| BuildError::UnusableRelay { reason: cause.to_string() })?;
        let has_relay = relay.is_some();
        let config = Config { relay, ..Config::default() };
        let (node, node_events) =
            convesso_tokio::start_with_stream::<EnrolmentStream, _>(own, config, OsEntropy)
                .await
                .map_err(|cause| BuildError::Start(cause.to_string()))?;
        let options = ContextOptions { access, ..ContextOptions::default() };
        let (context, context_events) = node
            .context(ENROLMENT_CONTEXT, options)
            .await
            .map_err(|cause| BuildError::Start(cause.to_string()))?;
        if has_relay && reachable {
            node.set_reachable(true).await.map_err(|cause| BuildError::Start(cause.to_string()))?;
        }

        let routes = Arc::new(Mutex::new(Routes::default()));
        let (unrouted_in, unrouted) = mpsc::unbounded_channel();
        let (dials_in, dials) = mpsc::unbounded_channel();
        let (online_in, online) = watch::channel(!has_relay);
        let tasks = vec![
            tokio::spawn(read_node(node_events, online_in, dials_in.clone())),
            tokio::spawn(read_context(context_events, Arc::clone(&routes), unrouted_in, dials_in)),
        ];
        Ok(Self {
            node,
            context,
            routes,
            unrouted: tokio::sync::Mutex::new(unrouted),
            dials: tokio::sync::Mutex::new(dials),
            online,
            tasks,
        })
    }

    /// Routes `peer`'s messages to a channel from now on.
    fn route(&self, peer: PeerId) -> mpsc::UnboundedReceiver<Vec<u8>> {
        let (sender, receiver) = mpsc::unbounded_channel();
        if let Ok(mut routes) = self.routes.lock() {
            routes.open.insert(peer, sender);
        }
        receiver
    }

    /// This node's own key.
    fn own(&self) -> PublicKey {
        key_of(&self.node.address())
    }
}

/// The node's own events: whether the relay has it, and peers it cannot reach.
async fn read_node(
    mut events: Events,
    online: watch::Sender<bool>,
    dials: mpsc::UnboundedSender<(PeerId, Option<String>)>,
) {
    while let Some(event) = events.next().await {
        match event {
            NodeEvent::RelayAvailable => {
                online.send_replace(true);
            }
            NodeEvent::RelayUnavailable { .. } => {
                online.send_replace(false);
            }
            NodeEvent::PeerNotAtRelay { peer } => {
                let _ = dials.send((peer, Some("the relay cannot reach that device".to_owned())));
            }
            NodeEvent::ObservedAddress { .. } => {}
        }
    }
}

/// The context's events: messages to their exchange or to `accept`, and how
/// sessions come up, fail and end.
async fn read_context(
    mut events: ContextEvents,
    routes: Arc<Mutex<Routes>>,
    unrouted: mpsc::UnboundedSender<(PeerId, Vec<u8>)>,
    dials: mpsc::UnboundedSender<(PeerId, Option<String>)>,
) {
    while let Some(event) = events.next().await {
        match event {
            ContextEvent::Message { peer, data } => {
                let routed = routes.lock().ok().and_then(|routes| routes.open.get(&peer).cloned());
                match routed {
                    Some(channel) => {
                        let _ = channel.send(data);
                    }
                    None => {
                        let _ = unrouted.send((peer, data));
                    }
                }
            }
            ContextEvent::Connected { peer } => {
                let _ = dials.send((peer, None));
            }
            ContextEvent::ReopenFailed { peer, error } => {
                let _ = dials.send((peer, Some(error.to_string())));
                end(&routes, &peer);
            }
            ContextEvent::Closed { peer, .. } | ContextEvent::ChannelReset { peer, .. } => {
                end(&routes, &peer);
            }
            ContextEvent::Datagram { .. } | ContextEvent::PathChanged { .. } => {}
        }
    }
}

/// Ends the exchange with `peer`: its channel reads the end.
fn end(routes: &Mutex<Routes>, peer: &PeerId) {
    if let Ok(mut routes) = routes.lock() {
        routes.open.remove(peer);
    }
}

/// An ed25519 key, as the roster writes it.
fn key_of(address: &Address) -> PublicKey {
    PublicKey::new(Algorithm::Ed25519, address.as_bytes().to_vec())
        .expect("a convesso address is a valid ed25519 key")
}

/// A key as convesso dials it.
fn address_of(key: &PublicKey) -> Result<Address> {
    let bytes: [u8; 32] = key
        .as_bytes()
        .try_into()
        .map_err(|_| BuildError::Exchange("the key is not 32 bytes".to_owned()))?;
    Address::parse(bytes).map_err(|cause| BuildError::Exchange(cause.to_string()))
}

/// A device with no roster, waiting to be admitted.
///
/// Accepts, and cannot dial: there is no method here that opens a session.
pub struct Waiting {
    endpoint: Endpoint,
    relay: String,
}

impl Waiting {
    /// Starts a node at the relay a person named, under this device's transport
    /// key, open to anyone in the enrolment context.
    ///
    /// # Errors
    ///
    /// When the transport key is not ed25519, the relay is not `key@host:port`,
    /// or the node cannot start.
    pub async fn listen(identity: &NodeIdentity, relay: &str) -> Result<Self> {
        let key = identity.transport_key();
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(BuildError::NotEd25519 { algorithm: key.algorithm() });
        }
        let own = Identity::from_ed25519_seed(key.material().expose())
            .map_err(|cause| BuildError::Start(cause.to_string()))?;
        let endpoint = Endpoint::start(own, Some(relay), Access::Everyone, true).await?;
        Ok(Self { endpoint, relay: relay.to_owned() })
    }

    /// Waits until the relay has this node, so a peer can reach it.
    pub async fn online(&self) {
        let mut online = self.endpoint.online.clone();
        let _ = online.wait_for(|online| *online).await;
    }

    /// The relay this node registered at, for the payload to carry.
    #[must_use]
    pub fn relay(&self) -> &str {
        &self.relay
    }

    /// This device's transport key.
    #[must_use]
    pub fn transport_key(&self) -> PublicKey {
        self.endpoint.own()
    }

    /// Always `None`: a convesso relay is trusted by the key written with its
    /// address, never on sight.
    #[must_use]
    pub const fn accepted_on_sight(&self) -> Option<Vec<u8>> {
        None
    }

    /// Waits for somebody to open an enrolment exchange.
    ///
    /// # Errors
    ///
    /// When the node stops, or the session's binding cannot be read.
    pub async fn accept(&self) -> Result<Channel> {
        let mut unrouted = self.endpoint.unrouted.lock().await;
        loop {
            let (peer, data) = unrouted
                .recv()
                .await
                .ok_or_else(|| BuildError::Exchange("the node stopped".to_owned()))?;
            // An opening, and a key the handshake authenticated: anything else
            // from a peer with no exchange open is not an exchange.
            let Some(claimed) = data.strip_prefix(OPENER) else { continue };
            let Ok(bytes) = <[u8; 32]>::try_from(claimed) else { continue };
            let Ok(address) = Address::parse(bytes) else { continue };
            if address.peer_id() != peer {
                continue;
            }
            let inbox = self.endpoint.route(peer);
            let material = binding(&self.endpoint.context, peer).await?;
            return Ok(Channel {
                context: self.endpoint.context.clone(),
                peer: address,
                own: self.endpoint.own(),
                material,
                inbox,
            });
        }
    }

    /// Stops waiting, and stops being reachable.
    pub async fn close(self) {
        drop(self);
    }
}

/// A device that holds a roster, admitting one that does not.
///
/// Dials, and serves nothing: its context is dial-only, and its key is made for
/// this admission alone.
pub struct Admitting {
    endpoint: Endpoint,
}

impl Admitting {
    /// Starts a node that will only ever dial.
    ///
    /// `identity` and `state` are taken for the shape the daemon calls: the
    /// admitting node runs under a key of its own (see the module), and its
    /// relay is the one [`Admitting::reach`] is given, which the daemon has
    /// already checked is one this network uses.
    ///
    /// # Errors
    ///
    /// When the generator fails, or the node cannot start.
    pub async fn dialling(
        _identity: &NodeIdentity,
        _state: &roster::state::RosterState,
    ) -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|cause| BuildError::Start(cause.to_string()))?;
        let own = Identity::from_ed25519_seed(&seed)
            .map_err(|cause| BuildError::Start(cause.to_string()))?;
        let endpoint = Endpoint::start(own, None, Access::DialOnly, false).await?;
        Ok(Self { endpoint })
    }

    /// Opens an exchange with a device waiting at `relay`.
    ///
    /// # Errors
    ///
    /// When the key or the relay is not one, or the device cannot be reached.
    pub async fn reach(&self, peer: &PublicKey, relay: &str) -> Result<Channel> {
        let address = address_of(peer)?;
        let location = crate::relay::parse(relay)
            .map_err(|cause| BuildError::UnusableRelay { reason: cause.to_string() })?;
        self.endpoint
            .node
            .set_relay(Some(location))
            .await
            .map_err(|cause| BuildError::Exchange(cause.to_string()))?;

        let inbox = self.endpoint.route(address.peer_id());
        let mut opener = OPENER.to_vec();
        opener.extend_from_slice(self.endpoint.node.address().as_bytes());
        self.endpoint
            .context
            .send_message(address, opener)
            .await
            .map_err(|cause| BuildError::Exchange(cause.to_string()))?;

        let mut dials = self.endpoint.dials.lock().await;
        loop {
            let (dialled, failure) = dials
                .recv()
                .await
                .ok_or_else(|| BuildError::Exchange("the node stopped".to_owned()))?;
            if dialled != address.peer_id() {
                continue;
            }
            if let Some(failure) = failure {
                return Err(BuildError::Exchange(failure));
            }
            break;
        }
        let material = binding(&self.endpoint.context, address.peer_id()).await?;
        Ok(Channel {
            context: self.endpoint.context.clone(),
            peer: address,
            own: self.endpoint.own(),
            material,
            inbox,
        })
    }

    /// Stops dialling, and drops the node.
    pub async fn close(self) {
        drop(self);
    }
}

/// The session's channel binding with `peer`.
async fn binding(context: &Context, peer: PeerId) -> Result<Vec<u8>> {
    context
        .channel_binding(peer)
        .await
        .map_err(|cause| BuildError::Exchange(cause.to_string()))?
        .map(|binding| binding.to_vec())
        .ok_or_else(|| BuildError::Exchange("the session has no keys".to_owned()))
}

/// One enrolment exchange.
///
/// Carries enrolment messages and offers no way to send anything else. It is
/// not a session of the transport interface and cannot be used as one.
pub struct Channel {
    context: Context,
    peer: Address,
    own: PublicKey,
    material: Vec<u8>,
    inbox: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl Channel {
    /// Material that identifies this channel and no other: the session's
    /// channel binding, equal at both ends and different for every handshake.
    ///
    /// # Errors
    ///
    /// Never: read when the channel was opened. A `Result` for the shape the
    /// daemon calls.
    pub fn material(&self) -> Result<Vec<u8>> {
        Ok(self.material.clone())
    }

    /// The peer's transport key, as the handshake authenticated it.
    ///
    /// # Errors
    ///
    /// Never; a `Result` for the shape the daemon calls.
    pub fn peer(&self) -> Result<PublicKey> {
        Ok(key_of(&self.peer))
    }

    /// The key this side presented, which the peer's code is derived over.
    #[must_use]
    pub fn own(&self) -> PublicKey {
        self.own.clone()
    }

    /// Sends one message, whole.
    ///
    /// # Errors
    ///
    /// When the message is larger than the bound, or the session fails.
    pub async fn send(&mut self, message: &[u8]) -> Result<()> {
        if message.len() > MAX_MESSAGE {
            return Err(BuildError::Exchange("the message is too large".to_owned()));
        }
        self.context
            .send_message(self.peer, message.to_vec())
            .await
            .map_err(|cause| BuildError::Exchange(cause.to_string()))
    }

    /// Reads one message, whole.
    ///
    /// # Errors
    ///
    /// When the exchange ended before a message came.
    pub async fn receive(&mut self) -> Result<Vec<u8>> {
        self.inbox.recv().await.ok_or_else(|| BuildError::Exchange("the exchange ended".to_owned()))
    }
}

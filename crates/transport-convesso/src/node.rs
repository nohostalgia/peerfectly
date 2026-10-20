//! A convesso node, and the sessions of the interface carried over it.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use convesso_core::handshake::DialError;
use convesso_core::identity::{Address, Identity, PeerId};
use convesso_core::paths::PathKind;
use convesso_tokio::entropy::OsEntropy;
use convesso_tokio::{
    Access, Config, Context, ContextEvent, ContextEvents, ContextOptions, Delivery, ELEMENT_COST,
    Events, Node, NodeError, NodeEvent, Received, RelayLocation,
};
use identity::NodeIdentity;
use roster::id::DeviceId;
use roster::sign::PublicKey;
use roster::state::RosterState;
use roster::types::{Algorithm, NetworkParams};
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use transport::error::{Error, Result as SessionResult};
use transport::limits;
use transport::session::{Path, Session, Transport};

use crate::error::{BuildError, Result};
use crate::frame::{Frame, MAX_MESSAGE, Reason, SessionId, Stream, VERSION};
use crate::members::{Gate, Members};
use crate::session::{DATAGRAM_ROOM, Live, SessionHandle};

/// The convesso context every session of this binding runs in.
///
/// The protocol's version travels in `OPEN` rather than in the name: a context
/// two ends do not share is silence, which a dialler would read as
/// unreachability, while a version in `OPEN` can be refused as such.
pub const CONTEXT: &[u8] = b"peerfectly/transport";

/// The close code sent to convesso when a peer stops being a member.
const CLOSE_MEMBERSHIP: u16 = 0x0101;

/// How long after a change of network convesso is told: long enough for
/// several changes the system reports together (Wi-Fi gone, then mobile data
/// there 150 ms later) to be one, short enough not to be felt. The relay took
/// a phone back 50 ms after being told; a phone leaving Wi-Fi was unreachable
/// for 1.8 s with a second here, and 0.8 s with this (Android
/// `VERIFICATION.md`, C3).
const SETTLE: Duration = Duration::from_millis(250);

/// How long to wait for the relay to take the node back after each word, before
/// saying it again: 2, 4 and 8 seconds, then nothing more, as convesso's own
/// backoff takes over.
const AGAIN: [Duration; 3] =
    [Duration::from_secs(2), Duration::from_secs(4), Duration::from_secs(8)];

/// How long a dial waits for the far end to take or refuse the session.
///
/// convesso gives up on a handshake at 15 seconds; this leaves room beyond it
/// for the session protocol's own answer.
const DIAL_PATIENCE: Duration = Duration::from_secs(20);

/// What one peer's messages may hold before its sender waits: two of the
/// largest, each at its cost.
const MESSAGE_BUDGET: usize = 2 * (MAX_MESSAGE + ELEMENT_COST);

/// What one peer's datagrams may hold before they are dropped: a session's
/// packet queue, in datagrams of the largest size.
const DATAGRAM_BUDGET: usize = limits::PACKET_QUEUE * (DATAGRAM_ROOM + ELEMENT_COST);

/// What a dial is told.
enum Answer {
    /// The far end took the session.
    Accepted,
    /// It was refused, or could not be made.
    Refused(Error),
}

/// A dial waiting for its answer.
struct Dial {
    /// Whom it dialled.
    peer: PeerId,
    /// Where the answer goes.
    answer: oneshot::Sender<Answer>,
}

/// Something to send, in order, from a task that may wait.
///
/// The readers never wait on the node to send: the node may be waiting on them
/// to read, and the two would wait on each other.
enum Out {
    /// A frame, as a reliable message.
    Message(Address, Vec<u8>),
    /// A frame back to a peer the node holds keys for.
    Reply(PeerId, Vec<u8>),
    /// The session with a peer, closed.
    Close(PeerId, u16),
}

/// What the transport and its tasks share.
struct Shared {
    node: Node,
    context: Context,
    members: Arc<RwLock<Members>>,
    state: Mutex<RosterState>,
    sessions: std::sync::Mutex<HashMap<SessionId, Arc<Live>>>,
    accepted_from: std::sync::Mutex<HashMap<PeerId, SessionId>>,
    dials: std::sync::Mutex<HashMap<SessionId, Dial>>,
    incoming: mpsc::Sender<Arc<Live>>,
    outbound: mpsc::UnboundedSender<Out>,
    addresses: std::sync::Mutex<Vec<String>>,
    /// The relay the node is on now, if any.
    relay: std::sync::Mutex<Option<RelayLocation>>,
    /// Whether the relay has the node registered, so peers reach it there.
    online: watch::Sender<bool>,
    /// One reader per peer, reading what convesso delivers for it.
    readers: std::sync::Mutex<HashMap<PeerId, JoinHandle<()>>>,
    /// The wake-up at the end of a relay move, if one is under way.
    move_ends: std::sync::Mutex<Option<JoinHandle<()>>>,
    /// Following a change of network, if one is being followed.
    following: std::sync::Mutex<Option<JoinHandle<()>>>,
}

/// A node reachable over convesso.
pub struct ConvessoTransport {
    shared: Arc<Shared>,
    accepted: Mutex<mpsc::Receiver<Arc<Live>>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for ConvessoTransport {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        if let Ok(mut readers) = self.shared.readers.lock() {
            for (_, reader) in readers.drain() {
                reader.abort();
            }
        }
        if let Ok(mut move_ends) = self.shared.move_ends.lock()
            && let Some(wake) = move_ends.take()
        {
            wake.abort();
        }
        if let Ok(mut following) = self.shared.following.lock()
            && let Some(follow) = following.take()
        {
            follow.abort();
        }
    }
}

/// A random session id.
fn session_id() -> SessionId {
    let mut bytes = [0u8; 8];
    // A failed generator leaves zeros, and the next dial a duplicate the far end
    // ignores: the dial then fails as unanswered rather than crossing sessions.
    let _ = getrandom::fill(&mut bytes);
    SessionId::from_be_bytes(bytes)
}

/// Milliseconds since the epoch, the clock a relay move is dated by.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
}

/// A relay, from the roster: its string, and the pinned value beside it.
///
/// The string is `key@host:port` (`crate::relay`). A pinned value is what the
/// iroh binding writes, a certificate, and a network written for it cannot be
/// read here: refused, saying so, rather than read as a relay never reached.
///
/// # Errors
///
/// When the string is not a relay, or a value is pinned beside it.
pub fn relay_location(address: &str, pin: Option<&[u8]>) -> Result<RelayLocation> {
    if pin.is_some() {
        return Err(BuildError::UnusableRelay {
            reason: "the network pins a certificate for its relay, as the iroh binding writes \
                     it; this build speaks convesso, whose relays carry their key in their \
                     address"
                .to_owned(),
        });
    }
    crate::relay::parse(address)
        .map_err(|cause| BuildError::UnusableRelay { reason: cause.to_string() })
}

/// The relay a node lives on at `now`: the relay being left while a move
/// lasts, the relay otherwise.
///
/// **Everybody on the old relay until the end, then everybody on the new one**,
/// as in the iroh binding. convesso keeps one relay at a time
/// (`DESIGN.md §6`): peers on different relays reach each other only directly,
/// so the moment everybody switches is the end of the move, which every device
/// reads from the same signed parameters.
///
/// # Errors
///
/// When the relay is not one this build can use.
pub fn home_at(params: &NetworkParams, now: u64) -> Result<Option<RelayLocation>> {
    if let Some(leaving) = params.leaving_at(now) {
        return relay_location(&leaving.relay, leaving.relay_cert.as_deref()).map(Some);
    }
    match params.relay.as_deref() {
        Some(address) => relay_location(address, params.relay_cert.as_deref()).map(Some),
        None => Ok(None),
    }
}

impl ConvessoTransport {
    /// Starts a node whose identity is this device's transport key, on the
    /// relay the network's parameters name.
    ///
    /// # Errors
    ///
    /// When the transport key is not ed25519, the relay's pinned key is not
    /// one, or the node cannot start.
    pub async fn bind(identity: &NodeIdentity, state: RosterState) -> Result<Self> {
        let key = identity.transport_key();
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(BuildError::NotEd25519 { algorithm: key.algorithm() });
        }
        let own = Identity::from_ed25519_seed(key.material().expose())
            .map_err(|cause| BuildError::Start(cause.to_string()))?;
        let home = home_at(&state.params, now_ms())?;

        let config = Config { relay: home.clone(), ..Config::default() };
        let (node, node_events) =
            convesso_tokio::start_with_stream::<Stream, _>(own, config, OsEntropy)
                .await
                .map_err(|cause| BuildError::Start(cause.to_string()))?;

        let members = Arc::new(RwLock::new(Members::from_state(&state)));
        let options = ContextOptions {
            access: Access::Admit(Box::new(Gate(Arc::clone(&members)))),
            delivery: Delivery::PerPeer { messages: MESSAGE_BUDGET, datagrams: DATAGRAM_BUDGET },
            ..ContextOptions::default()
        };
        let (context, context_events) = node
            .context(CONTEXT, options)
            .await
            .map_err(|cause| BuildError::Start(cause.to_string()))?;
        if home.is_some() {
            // So peers can open sessions to this node through the relay.
            node.set_reachable(true).await.map_err(|cause| BuildError::Start(cause.to_string()))?;
        }

        let (incoming, accepted) = mpsc::channel(limits::MAX_PENDING_DIALS);
        let (outbound, queued) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            node,
            context,
            members,
            state: Mutex::new(state.clone()),
            sessions: std::sync::Mutex::new(HashMap::new()),
            accepted_from: std::sync::Mutex::new(HashMap::new()),
            dials: std::sync::Mutex::new(HashMap::new()),
            incoming,
            outbound,
            addresses: std::sync::Mutex::new(Vec::new()),
            relay: std::sync::Mutex::new(home),
            online: watch::Sender::new(false),
            readers: std::sync::Mutex::new(HashMap::new()),
            move_ends: std::sync::Mutex::new(None),
            following: std::sync::Mutex::new(None),
        });
        refresh_addresses(&shared);
        ensure_readers(&shared);
        schedule_move_end(&shared, &state.params);
        let tasks = vec![
            tokio::spawn(read_node_events(Arc::clone(&shared), node_events)),
            tokio::spawn(read_context_events(Arc::clone(&shared), context_events)),
            tokio::spawn(send_queued(shared.context.clone(), queued)),
        ];
        Ok(Self { shared, accepted: Mutex::new(accepted), tasks })
    }

    /// This node's transport public key.
    #[must_use]
    pub fn transport_key(&self) -> PublicKey {
        PublicKey::new(Algorithm::Ed25519, self.shared.node.address().as_bytes().to_vec())
            .expect("a convesso address is a valid ed25519 key")
    }

    /// Waits until the relay has this node registered, so peers reach it there.
    ///
    /// For a caller that must not dial into a race with a peer still coming up,
    /// as `iroh`'s `Endpoint::online` is for the iroh binding. Returns at once
    /// for a node with no relay.
    pub async fn online(&self) {
        let has_relay = self.shared.relay.lock().is_ok_and(|relay| relay.is_some());
        if has_relay {
            let mut watching = self.shared.online.subscribe();
            let _ = watching.wait_for(|online| *online).await;
        }
    }

    /// The relay the node is on now, if any.
    #[must_use]
    pub fn relay(&self) -> Option<RelayLocation> {
        self.shared.relay.lock().ok().and_then(|relay| relay.clone())
    }

    /// The roster state decisions are currently taken from.
    pub async fn state(&self) -> RosterState {
        self.shared.state.lock().await.clone()
    }

    /// The live sessions with `device`.
    fn live_with(&self, device: &DeviceId) -> Vec<Arc<Live>> {
        self.shared.sessions.lock().map_or_else(
            |_| Vec::new(),
            |sessions| {
                sessions
                    .values()
                    .filter(|live| live.device == *device && live.closure().is_none())
                    .cloned()
                    .collect()
            },
        )
    }
}

#[async_trait]
impl Transport for ConvessoTransport {
    async fn connect(&self, peer: &PublicKey) -> SessionResult<Box<dyn Session>> {
        let bytes: [u8; 32] = peer.as_bytes().try_into().map_err(|_| Error::PeerUnreachable {
            cause: Some("the key is not 32 bytes".to_owned()),
        })?;
        let address = Address::parse(bytes)
            .map_err(|cause| Error::PeerUnreachable { cause: Some(cause.to_string()) })?;
        let shared = &self.shared;

        // Decided now, acted on once the far end has answered. A dialler that
        // refused before sending anything would leave the far end's `accept`
        // waiting for ever; this one dials, as the iroh binding does, and closes
        // what it opened (design D3).
        let verdict = {
            let state = shared.state.lock().await;
            transport::auth::authorize(&state, &peer.key_id())
        };
        // The answer comes through this peer's reader, which a peer the roster
        // does not name has none of yet.
        ensure_reader(shared, address);

        let id = session_id();
        let (answer, answered) = oneshot::channel();
        if let Ok(mut dials) = shared.dials.lock() {
            dials.insert(id, Dial { peer: address.peer_id(), answer });
        }
        // Registered before the far end can answer, so nothing it sends right
        // after taking the session is dropped for want of somewhere to go.
        let live = verdict.as_ref().ok().map(|device| {
            let live = Live::new(id, *device, address, shared.context.clone());
            if let Ok(mut sessions) = shared.sessions.lock() {
                sessions.insert(id, Arc::clone(&live));
            }
            live
        });
        let forget = || {
            if let Ok(mut sessions) = shared.sessions.lock() {
                sessions.remove(&id);
            }
            if let Ok(mut dials) = shared.dials.lock() {
                dials.remove(&id);
            }
        };

        let open = Frame::Open { version: VERSION, id }.encode();
        if let Err(cause) = shared.context.send_message(address, open).await {
            forget();
            return Err(Error::PeerUnreachable { cause: Some(cause.to_string()) });
        }

        let outcome = match tokio::time::timeout(DIAL_PATIENCE, answered).await {
            Ok(Ok(Answer::Accepted)) => Ok(()),
            Ok(Ok(Answer::Refused(error))) => Err(error),
            Ok(Err(_)) => Err(Error::PeerUnreachable {
                cause: Some("the node stopped while dialling".to_owned()),
            }),
            Err(_) => Err(Error::PeerUnreachable {
                cause: Some(format!("no answer within {}s", DIAL_PATIENCE.as_secs())),
            }),
        };
        if let Err(error) = outcome {
            forget();
            return Err(error);
        }
        match (verdict, live) {
            (Ok(_), Some(live)) => Ok(Box::new(SessionHandle(live))),
            (verdict, _) => {
                forget();
                let refusal =
                    verdict.err().as_ref().and_then(error_or).unwrap_or(Error::NotAMember);
                let close = Frame::Close { id, reason: reason_of(&refusal) }.encode();
                let _ = shared.outbound.send(Out::Message(address, close));
                Err(refusal)
            }
        }
    }

    async fn accept(&self) -> SessionResult<Box<dyn Session>> {
        let mut accepted = self.accepted.lock().await;
        accepted
            .recv()
            .await
            .map(|live| Box::new(SessionHandle(live)) as Box<dyn Session>)
            .ok_or(Error::PeerUnreachable { cause: Some("the node stopped accepting".to_owned()) })
    }

    fn addresses(&self) -> Vec<String> {
        self.shared.addresses.lock().map(|held| held.clone()).unwrap_or_default()
    }

    fn learned(&self, peer: &PublicKey, addresses: &[String]) {
        let Ok(bytes) = <[u8; 32]>::try_from(peer.as_bytes()) else { return };
        let Ok(address) = Address::parse(bytes) else { return };
        // Every address that reads as one, up to the eight convesso takes; a
        // dial tries them all at once, then the relay.
        let hints: Vec<SocketAddr> =
            addresses.iter().filter_map(|text| text.parse().ok()).take(8).collect();
        if hints.is_empty() {
            return;
        }
        let node = self.shared.node.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = node.set_hints(address.peer_id(), hints).await;
            });
        }
    }

    async fn update_state(&self, state: RosterState) {
        let shared = &self.shared;
        if let Ok(mut members) = shared.members.write() {
            *members = Members::from_state(&state);
        }
        let mut leaving = HashSet::new();
        if let Ok(mut sessions) = shared.sessions.lock() {
            for live in sessions.values() {
                if live.closure().is_none() && !transport::auth::is_member(&state, &live.device) {
                    live.shut(Error::ClosedOnMembershipLoss);
                    let close = Frame::Close { id: live.id, reason: Reason::MembershipLost };
                    let _ = shared.outbound.send(Out::Message(live.address, close.encode()));
                    leaving.insert(live.peer);
                }
            }
            sessions.retain(|_, live| live.closure().is_none());
        }
        for peer in leaving {
            let _ = shared.outbound.send(Out::Close(peer, CLOSE_MEMBERSHIP));
        }
        ensure_readers(shared);
        follow_relay(shared, &state.params).await;
        schedule_move_end(shared, &state.params);
        *shared.state.lock().await = state;
    }

    /// Tells convesso, which re-reads the interfaces and replaces its relay link
    /// (`Node::network_changed`). Without it the link stays bound to a network
    /// that is gone until the keep-alive gives up on it: a minute of silence and
    /// twenty seconds more.
    ///
    /// **Not at once, and more than once.** A phone leaving Wi-Fi lists its
    /// mobile network about 150 ms later, and a link made before the system
    /// routes through it can fail. So convesso is told [`SETTLE`] after the last
    /// change, and told again while the relay has not taken the node back, at
    /// [`AGAIN`] after it. A newer change starts this over. On the runs of
    /// Android `VERIFICATION.md`, C3, the first word was always enough.
    async fn network_changed(&self) {
        let shared = Arc::clone(&self.shared);
        let follow = tokio::spawn(async move {
            tokio::time::sleep(SETTLE).await;
            shared.online.send_replace(false);
            for (attempt, wait) in AGAIN.into_iter().enumerate() {
                tracing::info!(attempt, "telling convesso the network changed");
                let _ = shared.node.network_changed().await;
                refresh_addresses(&shared);
                let mut watching = shared.online.subscribe();
                // Only whether: the borrow it returns is not held across an
                // await.
                let back =
                    tokio::time::timeout(wait, watching.wait_for(|online| *online)).await.is_ok();
                if back {
                    tracing::info!(attempt, "the relay took the node back");
                    return;
                }
            }
            tracing::info!("the relay has not taken the node back; convesso's own backoff goes on");
        });
        if let Ok(mut following) = self.shared.following.lock() {
            if let Some(earlier) = following.take() {
                earlier.abort();
            }
            *following = Some(follow);
        }
    }

    fn avoid(&self, ranges: &[transport::Range]) {
        let prefixes = ranges.iter().map(|range| (range.address(), range.prefix_len())).collect();
        let node = self.shared.node.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = node.set_excluded(prefixes).await;
            });
        }
    }

    fn own_ports(&self) -> Vec<u16> {
        vec![self.shared.node.local_addr().port()]
    }

    async fn path_to(&self, peer: &DeviceId) -> Option<Path> {
        let live = self.live_with(peer).into_iter().next()?;
        match self.shared.context.path(live.peer).await {
            Ok(Some(info)) => Some(match info.path {
                PathKind::Relayed => Path::Relay,
                PathKind::Direct(_) => Path::Direct,
            }),
            _ => None,
        }
    }
}

/// Moves the node to the relay the parameters name at this moment, if that is
/// not the one it is on. Sessions with peers are untouched (`PROTOCOL.md §6`).
async fn follow_relay(shared: &Arc<Shared>, params: &NetworkParams) {
    // A relay the new parameters cannot describe is not followed: the node
    // stays where it can still be reached.
    let Ok(home) = home_at(params, now_ms()) else { return };
    let current = shared.relay.lock().ok().and_then(|relay| relay.clone());
    if current == home {
        return;
    }
    if shared.node.set_relay(home.clone()).await.is_err() {
        return;
    }
    shared.online.send_replace(false);
    if home.is_some() {
        let _ = shared.node.set_reachable(true).await;
    }
    if let Ok(mut relay) = shared.relay.lock() {
        *relay = home;
    }
}

/// Wakes the node at the end of a relay move under way, to move it to the new
/// relay then. Replaces any wake-up set before.
fn schedule_move_end(shared: &Arc<Shared>, params: &NetworkParams) {
    let now = now_ms();
    let wake = params.leaving_at(now).map(|leaving| {
        let after = Duration::from_millis(leaving.until.saturating_sub(now).saturating_add(1));
        let shared = Arc::clone(shared);
        let params = params.clone();
        tokio::spawn(async move {
            tokio::time::sleep(after).await;
            follow_relay(&shared, &params).await;
        })
    });
    if let Ok(mut move_ends) = shared.move_ends.lock() {
        if let Some(earlier) = move_ends.take() {
            earlier.abort();
        }
        *move_ends = wake;
    }
}

/// Starts a reader for every member that has none, and stops those of
/// devices that are no longer members.
fn ensure_readers(shared: &Arc<Shared>) {
    let own = shared.node.address().peer_id();
    let members: Vec<Address> =
        shared.members.read().map(|members| members.others(&own)).unwrap_or_default();
    let keep: HashSet<PeerId> = members.iter().map(Address::peer_id).collect();
    if let Ok(mut readers) = shared.readers.lock() {
        readers.retain(|peer, reader| {
            let kept = keep.contains(peer) && !reader.is_finished();
            if !kept {
                reader.abort();
            }
            kept
        });
    }
    for address in members {
        ensure_reader(shared, address);
    }
}

/// Starts a reader for `address` if it has none running.
fn ensure_reader(shared: &Arc<Shared>, address: Address) {
    let Ok(mut readers) = shared.readers.lock() else { return };
    let peer = address.peer_id();
    if readers.get(&peer).is_some_and(|reader| !reader.is_finished()) {
        return;
    }
    readers.insert(peer, tokio::spawn(read_peer(Arc::clone(shared), peer)));
}

/// Reads what convesso delivers for one peer, for as long as the context is
/// open: one receiver per convesso session, opened again after each ends.
async fn read_peer(shared: Arc<Shared>, peer: PeerId) {
    loop {
        let receiver = match shared.context.receiver(peer).await {
            Ok(receiver) => receiver,
            // The receiver of a session that just ended is still being let go.
            Err(NodeError::ReceiverOpen) => {
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
            Err(_) => return,
        };
        loop {
            tokio::select! {
                received = receiver.recv() => match received {
                    Received::Message(data) => on_message(&shared, peer, &data).await,
                    Received::Reset(reason) => lose_peer(&shared, &peer, &reset(&reason)),
                    Received::Closed(_) => break,
                },
                datagram = receiver.recv_datagram() => match datagram {
                    Ok((data, _)) => on_datagram(&shared, peer, &data),
                    Err(_) => break,
                },
            }
        }
        lose_peer(
            &shared,
            &peer,
            &Error::PeerUnreachable { cause: Some("the session ended".to_owned()) },
        );
    }
}

/// `error` when it is a refusal worth passing on as itself.
fn error_or(error: &Error) -> Option<Error> {
    match error {
        Error::NotAMember | Error::Revoked => Some(error.clone()),
        _ => None,
    }
}

/// The reason a refusal or close is sent with.
const fn reason_of(error: &Error) -> Reason {
    match error {
        Error::NotAMember => Reason::NotAMember,
        Error::Revoked => Reason::Revoked,
        Error::IncompatibleVersion => Reason::Version,
        Error::ClosedOnMembershipLoss => Reason::MembershipLost,
        _ => Reason::Ordinary,
    }
}

/// The refusal a reason received stands for.
const fn refusal_of(reason: Reason) -> Error {
    match reason {
        Reason::NotAMember => Error::NotAMember,
        Reason::Revoked => Error::Revoked,
        Reason::Version => Error::IncompatibleVersion,
        Reason::Ordinary | Reason::MembershipLost | Reason::Unknown(_) => Error::ClosedByPeer,
    }
}

/// A failed dial, as the interface says it.
fn dial_failed(error: &DialError) -> Error {
    match error {
        DialError::Refused(code) => crate::members::refusal(code.get())
            .unwrap_or_else(|| Error::PeerUnreachable { cause: Some(error.to_string()) }),
        DialError::UnsupportedVersion(_) => Error::IncompatibleVersion,
        other => Error::PeerUnreachable { cause: Some(other.to_string()) },
    }
}

/// A reset message channel, as the interface says it.
///
/// A reopen that failed is a failed dial, said the way a dial's failure is:
/// the reset can reach a reader before the context reports the dial itself,
/// and a refusal must not become "unreachable" by arriving first.
fn reset(reason: &convesso_stream::Reason) -> Error {
    match reason {
        convesso_stream::Reason::ReopenFailed(error) => dial_failed(error),
        other => {
            Error::PeerUnreachable { cause: Some(format!("the channel was reset: {other:?}")) }
        }
    }
}

/// Asks the node for its candidates, and keeps them for `addresses`.
fn refresh_addresses(shared: &Arc<Shared>) {
    let shared = Arc::clone(shared);
    tokio::spawn(async move {
        if let Ok(candidates) = shared.node.candidates().await
            && let Ok(mut held) = shared.addresses.lock()
        {
            *held = candidates.iter().map(|candidate| candidate.address.to_string()).collect();
        }
    });
}

/// Sends what the readers and the transport queued, in order.
async fn send_queued(context: Context, mut queued: mpsc::UnboundedReceiver<Out>) {
    while let Some(out) = queued.recv().await {
        let _ = match out {
            Out::Message(address, bytes) => context.send_message(address, bytes).await,
            Out::Reply(peer, bytes) => context.send_message_to_peer(peer, bytes).await,
            Out::Close(peer, code) => context.close(peer, code).await,
        };
    }
}

/// Reads the node's own events: the relay's availability, the addresses it
/// sees, and peers it cannot reach.
async fn read_node_events(shared: Arc<Shared>, mut events: Events) {
    while let Some(event) = events.next().await {
        match event {
            NodeEvent::RelayAvailable => {
                tracing::info!("the relay has this node registered");
                shared.online.send_replace(true);
            }
            NodeEvent::RelayUnavailable { error } => {
                tracing::info!(?error, "the relay is unavailable");
                shared.online.send_replace(false);
            }
            NodeEvent::ObservedAddress { link, address } => {
                tracing::info!(?link, %address, "the relay sees this node at");
                refresh_addresses(&shared);
            }
            NodeEvent::PeerNotAtRelay { peer } => fail_dials(
                &shared,
                &peer,
                &Error::PeerUnreachable {
                    cause: Some("the relay cannot reach that device".to_owned()),
                },
            ),
        }
    }
    // The node stopped: nothing open can carry anything any more.
    let ended: Vec<Arc<Live>> = shared
        .sessions
        .lock()
        .map(|sessions| sessions.values().cloned().collect())
        .unwrap_or_default();
    for live in ended {
        live.shut(Error::ClosedByPeer);
    }
}

/// Reads the context's events. Messages and datagrams go to the peers'
/// readers; what remains is how sessions open, fail and end.
async fn read_context_events(shared: Arc<Shared>, mut events: ContextEvents) {
    while let Some(event) = events.next().await {
        match event {
            ContextEvent::ReopenFailed { peer, error } => {
                // What was queued for the peer is gone, so the sessions with it
                // cannot keep their promises.
                lose_peer(&shared, &peer, &dial_failed(&error));
            }
            ContextEvent::Closed { peer, .. } => lose_peer(
                &shared,
                &peer,
                &Error::PeerUnreachable { cause: Some("the session ended".to_owned()) },
            ),
            ContextEvent::Message { peer, data } => on_message(&shared, peer, &data).await,
            ContextEvent::Datagram { peer, data, .. } => on_datagram(&shared, peer, &data),
            ContextEvent::ChannelReset { peer, reason } => {
                lose_peer(&shared, &peer, &reset(&reason));
            }
            ContextEvent::Connected { .. } | ContextEvent::PathChanged { .. } => {}
        }
    }
}

/// The live session `id`, when it belongs to `peer`.
fn session_of(shared: &Shared, id: SessionId, peer: &PeerId) -> Option<Arc<Live>> {
    let sessions = shared.sessions.lock().ok()?;
    sessions.get(&id).filter(|live| live.peer == *peer).cloned()
}

/// Ends every session with `peer`, and every dial to it.
fn lose_peer(shared: &Shared, peer: &PeerId, dial_error: &Error) {
    if let Ok(sessions) = shared.sessions.lock() {
        for live in sessions.values().filter(|live| live.peer == *peer) {
            live.shut(Error::ClosedByPeer);
        }
    }
    fail_dials(shared, peer, dial_error);
}

/// Fails every dial waiting on `peer`.
fn fail_dials(shared: &Shared, peer: &PeerId, error: &Error) {
    let failed: Vec<Dial> = shared.dials.lock().map_or_else(
        |_| Vec::new(),
        |mut dials| {
            let ids: Vec<SessionId> =
                dials.iter().filter(|(_, dial)| dial.peer == *peer).map(|(id, _)| *id).collect();
            ids.into_iter().filter_map(|id| dials.remove(&id)).collect()
        },
    );
    for dial in failed {
        let _ = dial.answer.send(Answer::Refused(error.clone()));
    }
}

/// Answers a dial `id` from `peer`.
fn answer_dial(shared: &Shared, id: SessionId, peer: &PeerId, answer: Answer) {
    let dial = shared.dials.lock().ok().and_then(|mut dials| {
        if dials.get(&id).is_some_and(|dial| dial.peer == *peer) { dials.remove(&id) } else { None }
    });
    if let Some(dial) = dial {
        let _ = dial.answer.send(answer);
    }
}

/// A peer opens a session with this node.
fn opened(shared: &Shared, peer: PeerId, version: u8, id: SessionId) {
    let refuse = |reason: Reason| {
        let _ = shared.outbound.send(Out::Reply(peer, Frame::Refuse { id, reason }.encode()));
    };
    if version != VERSION {
        refuse(Reason::Version);
        return;
    }
    let entry =
        shared.members.read().ok().map(|members| (members.verdict(&peer), members.address(&peer)));
    let (device, address) = match entry {
        Some((Ok(device), Some(address))) => (device, address),
        Some((Err(error), _)) => {
            refuse(reason_of(&error));
            return;
        }
        _ => {
            refuse(Reason::NotAMember);
            return;
        }
    };
    let Ok(mut sessions) = shared.sessions.lock() else { return };
    if sessions.contains_key(&id) {
        // A repeated `OPEN`: the first one is the session.
        return;
    }
    let live = Live::new(id, device, address, shared.context.clone());
    sessions.insert(id, Arc::clone(&live));
    let replaced = shared.accepted_from.lock().ok().and_then(|mut from| from.insert(peer, id));
    if let Some(older) = replaced.and_then(|older| sessions.get(&older).cloned()) {
        older.shut(Error::ClosedByPeer);
    }
    drop(sessions);

    if shared.incoming.try_send(Arc::clone(&live)).is_err() {
        // Nobody is accepting fast enough: refused rather than queued without
        // end.
        live.shut(Error::SessionClosed);
        refuse(Reason::Ordinary);
        return;
    }
    let _ = shared.outbound.send(Out::Reply(peer, Frame::Accept { id }.encode()));
}

/// A reliable message from `peer`.
async fn on_message(shared: &Shared, peer: PeerId, data: &[u8]) {
    match Frame::decode(data) {
        Some(Frame::Open { version, id }) => opened(shared, peer, version, id),
        Some(Frame::Accept { id }) => answer_dial(shared, id, &peer, Answer::Accepted),
        Some(Frame::Refuse { id, reason }) => {
            answer_dial(shared, id, &peer, Answer::Refused(refusal_of(reason)));
        }
        Some(Frame::Close { id, .. }) => {
            if let Some(live) = session_of(shared, id, &peer) {
                live.shut(Error::ClosedByPeer);
            }
        }
        Some(Frame::Payload { id, bytes }) => {
            if let Some(live) = session_of(shared, id, &peer) {
                live.deliver_payload(bytes).await;
            }
        }
        // A packet sent as a message is not one: ignored.
        Some(Frame::Packet { .. }) | None => {}
    }
}

/// A datagram from `peer`.
fn on_datagram(shared: &Shared, peer: PeerId, data: &[u8]) {
    if let Some(Frame::Packet { id, fragment }) = Frame::decode(data)
        && let Some(live) = session_of(shared, id, &peer)
    {
        live.deliver_fragment(&fragment);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "a test reports failure by panicking")]
mod tests {
    use convesso_core::handshake::{DialError, RefusalCode};
    use transport::error::Error;

    use super::{dial_failed, reason_of, refusal_of, relay_location, reset};
    use crate::error::BuildError;
    use crate::frame::Reason;
    use crate::members::{NOT_A_MEMBER, REVOKED};

    /// What a dialler is told, for every way the far end can say no.
    #[test]
    fn every_refusal_reaches_the_dialler_as_itself() {
        assert_eq!(refusal_of(Reason::Version), Error::IncompatibleVersion);
        assert_eq!(refusal_of(Reason::NotAMember), Error::NotAMember);
        assert_eq!(refusal_of(Reason::Revoked), Error::Revoked);
        assert_eq!(refusal_of(Reason::Unknown(9)), Error::ClosedByPeer);

        let refused = |code| DialError::Refused(RefusalCode::application(code).unwrap());
        assert_eq!(dial_failed(&refused(NOT_A_MEMBER)), Error::NotAMember);
        assert_eq!(dial_failed(&refused(REVOKED)), Error::Revoked);
        assert!(matches!(dial_failed(&refused(0x0200)), Error::PeerUnreachable { .. }));
        assert!(matches!(dial_failed(&DialError::NoResponse), Error::PeerUnreachable { .. }));

        // The same refusal, reaching a reader as a reset before the dial's own
        // event, is still the refusal.
        let reopen = convesso_stream::Reason::ReopenFailed(refused(NOT_A_MEMBER));
        assert_eq!(reset(&reopen), Error::NotAMember);
    }

    /// And what is sent, the other way round.
    #[test]
    fn every_refusal_is_sent_with_its_reason() {
        for (error, reason) in [
            (Error::NotAMember, Reason::NotAMember),
            (Error::Revoked, Reason::Revoked),
            (Error::IncompatibleVersion, Reason::Version),
            (Error::ClosedOnMembershipLoss, Reason::MembershipLost),
        ] {
            assert_eq!(reason_of(&error), reason);
        }
    }

    /// The roster's relay is read through `crate::relay`, and a pinned value,
    /// which only the iroh binding writes, is refused.
    #[test]
    fn a_relay_is_its_string_and_a_pin_is_refused() {
        let key = convesso_core::identity::Identity::from_ed25519_seed(&[3; 32]).unwrap();
        let written = crate::relay::written(key.address().as_bytes(), "relay.example:7400", true);
        let read = relay_location(&written, None).unwrap();
        assert_eq!((read.host.as_str(), read.tls), ("relay.example:7400", true));
        assert!(matches!(
            relay_location(&written, Some(&[0x30; 400])),
            Err(BuildError::UnusableRelay { .. })
        ));
        assert!(matches!(
            relay_location("https://relay.example:443", None),
            Err(BuildError::UnusableRelay { .. })
        ));
    }
}

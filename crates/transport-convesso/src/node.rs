//! A convesso node, and the sessions of the interface carried over it.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use convesso_core::handshake::{DialError, RefusalCode};
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
use transport::session::{CatchingUp, Path, RootsAfter, Session, Transport};

use crate::error::{BuildError, Result};
use crate::frame::{Frame, MAX_MESSAGE, OWN, Reason, SessionId, Stream, VERSION};
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
/// How long before the sender of a session this node does not hold is told so
/// again, while it goes on sending.
const TELL_AGAIN: Duration = Duration::from_secs(2);
/// convesso's close code for a peer whose open was refused, and which holds no
/// other session here.
const CLOSE_REFUSED: u16 = 0x0102;
/// How long a refused peer's session is kept for the refusal to reach it:
/// less than any dialler rests before it tries again.
const REFUSED_GRACE: Duration = Duration::from_secs(5);

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

/// How long a node holding no roster waits for the roots it asked for while a
/// session opens, within the dialler's own patience.
const CATCH_UP_PATIENCE: Duration = Duration::from_secs(10);

/// The most opens held while their roots are asked for. Beyond it an open
/// that would be held is refused, as it was before anything was held.
const MAX_HELD_OPENS: usize = 64;

/// The most sessions remembered as answered with roots, before the record
/// starts again.
const MAX_ANSWERED: usize = 4096;

/// What one peer's messages may hold before its sender waits: two of the
/// largest, each at its cost.
const MESSAGE_BUDGET: usize = 2 * (MAX_MESSAGE + ELEMENT_COST);

/// What one peer's datagrams may hold before they are dropped: a session's
/// packet queue, in datagrams of the largest size.
const DATAGRAM_BUDGET: usize = limits::PACKET_QUEUE * (DATAGRAM_ROOM + ELEMENT_COST);

/// Whether a light node believes a peer's compact evidence: its proof holds
/// against a root the node remembers, and the leaf is still the device's word
/// as far as the node knows.
pub type Judge = Arc<dyn Fn(&roster::membership::Shown) -> bool + Send + Sync>;

/// What a dial is told.
enum Answer {
    /// The far end took the session, showing this evidence.
    Accepted(Vec<u8>),
    /// It was refused, or could not be made.
    Refused(Error),
}

/// An open from a peer, held while the roots its evidence rests on are asked
/// for.
struct HeldOpen {
    peer: PeerId,
    version: u8,
    evidence: Vec<u8>,
    since: tokio::time::Instant,
}

/// A dial of this node waiting for its roots: whom it asked, and where they go.
type CatchUp = (PeerId, oneshot::Sender<Vec<u8>>);

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

/// What the access policy is decided from, kept beside the sessions so the
/// handshake, which cannot wait, reads it at once.
#[derive(Default)]
struct Policy {
    /// The network's rules; none lets everyone reach everyone.
    rules: Vec<roster::parameters::Rule>,
    /// This device's own groups.
    own: Vec<roster::leaf::Group>,
    /// Every member's groups, for a node holding a roster.
    groups: HashMap<DeviceId, Vec<roster::leaf::Group>>,
}

impl Policy {
    /// What a roster state says.
    fn of_state(state: &RosterState, own: &DeviceId) -> Self {
        Self {
            rules: state.params.policy.clone(),
            own: state.settings_of(own).groups,
            groups: state
                .devices
                .iter()
                .map(|(device, leaf)| (device, leaf.settings.groups.clone()))
                .collect(),
        }
    }

    /// Whether `initiator`, with `shown` as its leaf where this node holds no
    /// roster, may open a session to this device.
    fn allows(&self, initiator: &DeviceId, shown: &[u8]) -> bool {
        if self.rules.is_empty() {
            return true;
        }
        let groups = match self.groups.get(initiator) {
            Some(groups) => groups.clone(),
            None => roster::membership::Shown::from_bytes(shown)
                .map(|shown| shown.leaf.settings.groups)
                .unwrap_or_default(),
        };
        roster::parameters::allows(&self.rules, &groups, &self.own)
    }
}

/// What the transport and its tasks share.
struct Shared {
    node: Node,
    context: Context,
    /// What each peer takes, and what it is sending in parts.
    wire: Arc<crate::wire::Wire>,
    members: Arc<RwLock<Members>>,
    state: Mutex<RosterState>,
    /// What this node shows a peer as a session opens; empty for nothing.
    evidence: std::sync::Mutex<Vec<u8>>,
    /// For a node holding no roster: how it judges the root a peer's evidence
    /// rests on. `None` for a node that judges peers by its state.
    judge: Option<Judge>,
    /// For a node holding no roster: how it catches up on a root it cannot
    /// place, while a session opens.
    catching: std::sync::RwLock<Option<CatchingUp>>,
    /// For a node holding a roster: the roots it answers that with.
    roots: std::sync::RwLock<Option<RootsAfter>>,
    /// Dials of this node waiting for the roots they asked for, by session.
    catch_ups: std::sync::Mutex<HashMap<SessionId, CatchUp>>,
    /// Opens held while their roots are asked for, by session.
    held_opens: std::sync::Mutex<HashMap<SessionId, HeldOpen>>,
    /// When each peer was last refused, until its session is closed.
    refusals: std::sync::Mutex<HashMap<PeerId, tokio::time::Instant>>,
    /// Sessions already answered with roots: once each.
    answered: std::sync::Mutex<HashSet<SessionId>>,
    /// Sessions this node does not hold whose sender was told so, and when.
    unknown: std::sync::Mutex<HashMap<SessionId, tokio::time::Instant>>,
    /// The access policy, and the groups it is decided over.
    policy: std::sync::RwLock<Policy>,
    /// This device.
    own: DeviceId,
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

/// A relay, from the roster: its string, `key@host:port` (`crate::relay`).
///
/// # Errors
///
/// When the string is not a relay.
pub fn relay_location(address: &str) -> Result<RelayLocation> {
    crate::relay::parse(address)
        .map_err(|cause| BuildError::UnusableRelay { reason: cause.to_string() })
}

/// The relay a node lives on at `now`: the relay being left while a move
/// lasts, the relay otherwise.
///
/// **Everybody on the old relay until the end, then everybody on the new one.**
/// convesso keeps one relay at a time
/// (`DESIGN.md §6`): peers on different relays reach each other only directly,
/// so the moment everybody switches is the end of the move, which every device
/// reads from the same signed parameters.
///
/// # Errors
///
/// When the relay is not one this build can use.
pub fn home_at(params: &NetworkParams, now: u64) -> Result<Option<RelayLocation>> {
    if let Some(leaving) = params.leaving_at(now) {
        return relay_location(&leaving.relay).map(Some);
    }
    match params.relay.as_deref() {
        Some(address) => relay_location(address).map(Some),
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
        Self::bind_with(identity, state, None, None).await
    }

    /// Starts a node for a device holding no roster: a light member.
    ///
    /// It knows its network and the parameters it uses, shows `evidence` — its
    /// compact evidence — and judges every peer by what that peer shows: its
    /// leaf must name the key the handshake authenticated, and `judge` must
    /// believe its proof against a root the node remembers.
    ///
    /// # Errors
    ///
    /// As [`Self::bind`].
    pub async fn bind_light(
        identity: &NodeIdentity,
        network: roster::id::NetworkId,
        params: roster::types::NetworkParams,
        evidence: Vec<u8>,
        judge: Judge,
    ) -> Result<Self> {
        let state = RosterState::from_parts(
            network,
            params,
            std::collections::BTreeMap::new(),
            std::collections::BTreeSet::new(),
            std::collections::BTreeMap::new(),
        );
        let transport = Self::bind_with(identity, state, None, Some(judge)).await?;
        transport.update_evidence(evidence);
        Ok(transport)
    }

    /// [`Self::bind`], with convesso resolving the relay's host through
    /// `resolver` rather than the system: for tests of a name that resolves
    /// late, which the system's resolver cannot be made to do.
    ///
    /// # Errors
    ///
    /// As [`Self::bind`].
    #[cfg(feature = "fixture")]
    pub async fn bind_resolving(
        identity: &NodeIdentity,
        state: RosterState,
        resolver: convesso_tokio::Resolver,
    ) -> Result<Self> {
        Self::bind_with(identity, state, Some(resolver), None).await
    }

    async fn bind_with(
        identity: &NodeIdentity,
        state: RosterState,
        resolver: Option<convesso_tokio::Resolver>,
        judge: Option<Judge>,
    ) -> Result<Self> {
        let key = identity.transport_key();
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(BuildError::NotEd25519 { algorithm: key.algorithm() });
        }
        let own = Identity::from_ed25519_seed(key.material().expose())
            .map_err(|cause| BuildError::Start(cause.to_string()))?;
        let home = home_at(&state.params, now_ms())?;

        // The host is resolved by convesso when it needs the relay, so a name
        // that does not resolve yet stops nothing: the node starts, reaches its
        // LAN, and takes the relay once the name answers.
        let config = Config { relay: home.clone(), resolver, ..Config::default() };
        let (node, node_events) =
            convesso_tokio::start_with_stream::<Stream, _>(own, config, OsEntropy)
                .await
                .map_err(|cause| BuildError::Start(cause.to_string()))?;

        let members = Arc::new(RwLock::new(Members::from_state(&state)));
        let options = ContextOptions {
            access: Access::Admit(Box::new(Gate(Arc::clone(&members), judge.is_some()))),
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

        // Known before the node is handed over, so the first announcement on
        // the LAN carries them. Asked for in the background, they were not
        // there yet, and the next announcement was five seconds away
        // (`convesso-reach` 5.4).
        let addresses = node.candidates().await.map_or_else(
            |_| Vec::new(),
            |candidates| candidates.iter().map(|candidate| candidate.address.to_string()).collect(),
        );

        let (incoming, accepted) = mpsc::channel(limits::MAX_PENDING_DIALS);
        let (outbound, queued) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            node,
            context,
            wire: Arc::default(),
            members,
            state: Mutex::new(state.clone()),
            evidence: std::sync::Mutex::new(Vec::new()),
            policy: std::sync::RwLock::new(Policy::of_state(&state, &identity.device_id())),
            own: identity.device_id(),
            judge,
            catching: std::sync::RwLock::new(None),
            roots: std::sync::RwLock::new(None),
            catch_ups: std::sync::Mutex::new(HashMap::new()),
            held_opens: std::sync::Mutex::new(HashMap::new()),
            refusals: std::sync::Mutex::new(HashMap::new()),
            answered: std::sync::Mutex::new(HashSet::new()),
            unknown: std::sync::Mutex::new(HashMap::new()),
            sessions: std::sync::Mutex::new(HashMap::new()),
            accepted_from: std::sync::Mutex::new(HashMap::new()),
            dials: std::sync::Mutex::new(HashMap::new()),
            incoming,
            outbound,
            addresses: std::sync::Mutex::new(addresses),
            relay: std::sync::Mutex::new(home),
            online: watch::Sender::new(false),
            readers: std::sync::Mutex::new(HashMap::new()),
            move_ends: std::sync::Mutex::new(None),
            following: std::sync::Mutex::new(None),
        });
        ensure_readers(&shared);
        schedule_move_end(&shared, &state.params);
        let tasks = vec![
            tokio::spawn(read_node_events(Arc::clone(&shared), node_events)),
            tokio::spawn(read_context_events(Arc::clone(&shared), context_events)),
            tokio::spawn(send_queued(shared.context.clone(), Arc::clone(&shared.wire), queued)),
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
    /// For a caller that must not dial into a race with a peer still coming up.
    /// Returns at once for a node with no relay.
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
                    .filter(|live| live.device() == *device && live.closure().is_none())
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
        // waiting for ever; this one dials, and closes what it opened (design D3).
        let verdict = if shared.judge.is_some() {
            // Nothing to decide by yet: the far end's evidence comes back with
            // its answer. Provisionally the device its key is; confirmed below.
            Ok(DeviceId::from_bytes(*peer.key_id().as_bytes()))
        } else {
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
            let live =
                Live::new(id, *device, address, shared.context.clone(), Arc::clone(&shared.wire));
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

        let open =
            Frame::Open { version: VERSION, id, limits: OWN, evidence: own_evidence(shared) }
                .encode();
        if let Err(cause) = send_framed(shared, address, open).await {
            forget();
            return Err(Error::PeerUnreachable { cause: Some(cause.to_string()) });
        }

        let outcome = match tokio::time::timeout(DIAL_PATIENCE, answered).await {
            Ok(Ok(Answer::Accepted(evidence))) => {
                match judged_catching_up(shared, peer, address, id, &evidence).await {
                    // A light node learns here who it reached.
                    Some(Ok(device)) => {
                        if let Some(live) = &live {
                            live.set_device(device);
                            live.set_evidence(evidence);
                        }
                        Ok(())
                    }
                    Some(Err(error)) => Err(error),
                    None => Ok(()),
                }
            }
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
            if error.is_membership_refusal() {
                let close = Frame::Close { id, reason: reason_of(&error) }.encode();
                let _ = shared.outbound.send(Out::Message(address, close));
            }
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

    fn serve_roots(&self, roots: RootsAfter) {
        if let Ok(mut held) = self.shared.roots.write() {
            *held = Some(roots);
        }
    }

    fn catch_up_by(&self, catching: CatchingUp) {
        if let Ok(mut held) = self.shared.catching.write() {
            *held = Some(catching);
        }
    }

    fn update_evidence(&self, evidence: Vec<u8>) {
        // A node holding no roster knows its own groups from its own leaf.
        if self.shared.judge.is_some()
            && let Ok(shown) = roster::membership::Shown::from_bytes(&evidence)
            && let Ok(mut policy) = self.shared.policy.write()
        {
            policy.own = shown.leaf.settings.groups;
        }
        if let Ok(mut held) = self.shared.evidence.lock() {
            *held = evidence;
        }
    }

    fn reconsider(&self) {
        let shared = &self.shared;
        let Some(judge) = shared.judge.as_ref() else { return };
        let Ok(sessions) = shared.sessions.lock() else { return };
        for live in sessions.values().filter(|live| live.closure().is_none()) {
            let Ok(key) = PublicKey::new(Algorithm::Ed25519, live.address.as_bytes().to_vec())
            else {
                continue;
            };
            let shown = live.evidence();
            let holds = transport::auth::authenticate_by_shown(&shown, &key.key_id(), &|shown| {
                judge(shown)
            });
            if holds.ok() != Some(live.device()) {
                live.shut(Error::ClosedOnMembershipLoss);
                let close = Frame::Close { id: live.id, reason: Reason::MembershipLost };
                let _ = shared.outbound.send(Out::Message(live.address, close.encode()));
            } else if live.inbound() && !allowed(shared, &live.device(), &shown) {
                live.shut(Error::NotAllowed);
                let close = Frame::Close { id: live.id, reason: Reason::NotAllowed };
                let _ = shared.outbound.send(Out::Message(live.address, close.encode()));
            }
        }
    }

    async fn update_state(&self, state: RosterState) {
        let shared = &self.shared;
        if shared.judge.is_some() {
            // A node holding no roster is handed the parameters it uses: the
            // policy among them. Its peers are judged by their evidence.
            if let Ok(mut policy) = shared.policy.write() {
                policy.rules = state.params.policy.clone();
            }
            *shared.state.lock().await = state;
            self.reconsider();
            return;
        }
        if let Ok(mut policy) = shared.policy.write() {
            *policy = Policy::of_state(&state, &shared.own);
        }
        if let Ok(mut members) = shared.members.write() {
            *members = Members::from_state(&state);
        }
        let mut leaving = HashSet::new();
        if let Ok(mut sessions) = shared.sessions.lock() {
            for live in sessions.values() {
                // Still a member is not enough: a device whose transport key
                // changed is not the key this session authenticated.
                let still = shared
                    .members
                    .read()
                    .is_ok_and(|members| members.member(&live.peer) == Some(live.device()));
                if live.closure().is_none()
                    && live.inbound()
                    && transport::auth::is_member(&state, &live.device())
                    && still
                    && !allowed(shared, &live.device(), &live.evidence())
                {
                    // A changed policy closes what it no longer allows.
                    live.shut(Error::NotAllowed);
                    let close = Frame::Close { id: live.id, reason: Reason::NotAllowed };
                    let _ = shared.outbound.send(Out::Message(live.address, close.encode()));
                    leaving.insert(live.peer);
                    continue;
                }
                if live.closure().is_none()
                    && (!transport::auth::is_member(&state, &live.device()) || !still)
                {
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

/// Stops the readers of devices that are no longer members, and of those
/// that ended.
///
/// A reader is started when a session with a peer has keys
/// ([`ContextEvent::Connected`]) or this node dials it, and ended when the
/// session has none left ([`ContextEvent::Idle`]): not one for every member.
/// An open reader keeps convesso from forgetting its peer's channel, and one
/// for every member was a task and a channel per member, for good, on every
/// full member of a network of a hundred thousand.
fn ensure_readers(shared: &Arc<Shared>) {
    // A node holding no roster judges by evidence, and knows no members to
    // keep readers to: it keeps those its sessions started.
    if shared.judge.is_some() {
        return;
    }
    // Asked of each reader's peer, not of every member: a reader is kept for
    // a peer the roster still names.
    let Ok(members) = shared.members.read() else { return };
    if let Ok(mut readers) = shared.readers.lock() {
        readers.retain(|peer, reader| {
            let kept = members.member(peer).is_some() && !reader.is_finished();
            if !kept {
                reader.abort();
            }
            kept
        });
    }
}

/// Ends `peer`'s reader once its session has no keys, so that convesso may
/// forget its channel: a message either side sends next opens a new session,
/// and its [`ContextEvent::Connected`] a new reader.
///
/// Asked first whether the session is still without keys: a reader dropped
/// while the peer has opened a new one would reset the channel that new
/// session carries. Dropped while there is none, it tells the peer nothing.
async fn end_reader_if_idle(shared: Arc<Shared>, peer: PeerId) {
    if !matches!(shared.context.is_live(peer).await, Ok(false)) {
        return;
    }
    if let Ok(mut readers) = shared.readers.lock()
        && let Some(reader) = readers.remove(&peer)
    {
        reader.abort();
    }
}

/// Starts a reader for `address` if it has none running.
fn ensure_reader(shared: &Arc<Shared>, address: Address) {
    ensure_reader_of(shared, address.peer_id());
}

/// Starts a reader for `peer` if it has none running.
fn ensure_reader_of(shared: &Arc<Shared>, peer: PeerId) {
    let Ok(mut readers) = shared.readers.lock() else { return };
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
        Error::NotAllowed => Reason::NotAllowed,
        _ => Reason::Ordinary,
    }
}

/// The refusal a reason received stands for.
const fn refusal_of(reason: Reason) -> Error {
    match reason {
        Reason::NotAMember => Error::NotAMember,
        Reason::Revoked => Error::Revoked,
        Reason::Version => Error::IncompatibleVersion,
        Reason::NotAllowed => Error::NotAllowed,
        Reason::Ordinary | Reason::MembershipLost | Reason::Unknown(_) => Error::ClosedByPeer,
    }
}

/// A failed dial, as the interface says it.
fn dial_failed(error: &DialError) -> Error {
    match error {
        // convesso's own codes for a peer with no room now: its handshakes or
        // its sessions are all taken, or it sheds load.
        DialError::Refused(code)
            if *code == RefusalCode::CAPACITY_EXHAUSTED || *code == RefusalCode::BUSY =>
        {
            Error::PeerBusy
        }
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

/// Sends what the readers and the transport queued, in order: each frame cut
/// to what its peer takes.
async fn send_queued(
    context: Context,
    wire: Arc<crate::wire::Wire>,
    mut queued: mpsc::UnboundedReceiver<Out>,
) {
    while let Some(out) = queued.recv().await {
        match out {
            Out::Message(address, bytes) => {
                let _sending = wire.sending(&address.peer_id()).await;
                for piece in wire.messages(&address.peer_id(), bytes) {
                    if context.send_message(address, piece).await.is_err() {
                        break;
                    }
                }
            }
            Out::Reply(peer, bytes) => {
                let _sending = wire.sending(&peer).await;
                for piece in wire.messages(&peer, bytes) {
                    if context.send_message_to_peer(peer, piece).await.is_err() {
                        break;
                    }
                }
            }
            Out::Close(peer, code) => {
                let _ = context.close(peer, code).await;
            }
        }
    }
}

/// Sends one frame to `address` now, cut to what its peer takes.
async fn send_framed(
    shared: &Shared,
    address: Address,
    frame: Vec<u8>,
) -> core::result::Result<(), convesso_tokio::NodeError> {
    let _sending = shared.wire.sending(&address.peer_id()).await;
    for piece in shared.wire.messages(&address.peer_id(), frame) {
        shared.context.send_message(address, piece).await?;
    }
    Ok(())
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
            // Whoever connects is read: convesso grants a peer's channel only
            // the room of its receiver, so a peer with none would have its open
            // held back unread and its dial time out. Whether it is let into a
            // session is decided by what it opens with.
            ContextEvent::Connected { peer } => ensure_reader_of(&shared, peer),
            // A convesso session with no keys left ends no session of this
            // binding: the next frame either side sends opens a new convesso
            // session, and the session carries on (`Live` outlives it). Its
            // reader ends, asked aside: the question goes to the node that
            // sends these events.
            ContextEvent::Idle { peer } => {
                tokio::spawn(end_reader_if_idle(Arc::clone(&shared), peer));
            }
            // No context of this binding takes data in a first contact: it
            // would be unconfirmed, and could be replayed.
            ContextEvent::PathChanged { .. } | ContextEvent::EarlyDatagram { .. } => {}
        }
    }
}

/// The live session `id`, when it belongs to `peer`.
fn session_of(shared: &Shared, id: SessionId, peer: &PeerId) -> Option<Arc<Live>> {
    let sessions = shared.sessions.lock().ok()?;
    sessions.get(&id).filter(|live| live.peer == *peer).cloned()
}

/// Session `id` with `peer`, where it is still open: one closed here is one
/// this node does not hold.
fn open_session(shared: &Shared, id: SessionId, peer: &PeerId) -> Option<Arc<Live>> {
    session_of(shared, id, peer).filter(|live| live.closure().is_none())
}

/// Ends every session with `peer`, and every dial to it.
fn lose_peer(shared: &Shared, peer: &PeerId, dial_error: &Error) {
    shared.wire.forget(peer);
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
///
/// **A session accepted for a dial this side gave up on is closed.** The far
/// end holds it as open, and a peer that holds a session nobody here reads
/// keeps choosing it over every new one (`convesso-reach` 5.4).
fn answer_dial(shared: &Shared, id: SessionId, peer: &PeerId, answer: Answer) {
    let dial = shared.dials.lock().ok().and_then(|mut dials| {
        if dials.get(&id).is_some_and(|dial| dial.peer == *peer) { dials.remove(&id) } else { None }
    });
    let unwanted = match dial {
        // Sent back when whoever dialled has stopped waiting.
        Some(dial) => dial.answer.send(answer).err(),
        None => Some(answer),
    };
    if matches!(unwanted, Some(Answer::Accepted(_))) {
        if let Ok(mut sessions) = shared.sessions.lock() {
            sessions.remove(&id);
        }
        let close = Frame::Close { id, reason: Reason::Ordinary }.encode();
        let _ = shared.outbound.send(Out::Reply(*peer, close));
    }
}

/// Whether the access policy lets `initiator` open a session to this device.
fn allowed(shared: &Shared, initiator: &DeviceId, shown: &[u8]) -> bool {
    shared.policy.read().is_ok_and(|policy| policy.allows(initiator, shown))
}

/// This node's evidence, as it stands.
fn own_evidence(shared: &Shared) -> Vec<u8> {
    shared.evidence.lock().map(|held| held.clone()).unwrap_or_default()
}

/// The device a peer's evidence shows it to be, for a node holding no roster;
/// `None` for one that judges by its state.
///
/// The leaf must name, for the transport purpose, the very key the handshake
/// authenticated: a valid proof of another device's leaf shows nothing about
/// this peer.
fn judged(
    shared: &Shared,
    peer: &PublicKey,
    evidence: &[u8],
) -> Option<core::result::Result<DeviceId, Error>> {
    let judge = shared.judge.as_ref()?;
    Some(transport::auth::authenticate_by_shown(evidence, &peer.key_id(), &|shown| judge(shown)))
}

/// [`judged`], for the evidence a dialled peer answered with: where it rests on
/// a root this node cannot place, the roots after its own are asked for on
/// the session, taken, and the evidence judged again.
async fn judged_catching_up(
    shared: &Shared,
    peer: &PublicKey,
    address: Address,
    id: SessionId,
    evidence: &[u8],
) -> Option<core::result::Result<DeviceId, Error>> {
    let first = judged(shared, peer, evidence);
    if !matches!(first, Some(Err(_))) {
        return first;
    }
    let Some(catching) = shared.catching.read().ok().and_then(|held| held.clone()) else {
        return first;
    };
    let Some(root) = (catching.behind)(evidence) else { return first };
    let (tell, told) = oneshot::channel();
    if let Ok(mut waiting) = shared.catch_ups.lock() {
        waiting.insert(id, (address.peer_id(), tell));
    }
    let behind = Frame::Behind { id, root }.encode();
    let asked = send_framed(shared, address, behind).await.is_ok();
    let roots = if asked { tokio::time::timeout(CATCH_UP_PATIENCE, told).await.ok() } else { None };
    if let Ok(mut waiting) = shared.catch_ups.lock() {
        waiting.remove(&id);
    }
    match roots {
        Some(Ok(roots)) if (catching.take)(evidence, &roots) => judged(shared, peer, evidence),
        _ => first,
    }
}

/// Holds an open whose evidence rests on a root this node cannot place, and
/// asks the dialler for the roots after its own. Whether it was held: where
/// not, it is refused as any other.
fn held_for_roots(
    shared: &Shared,
    peer: PeerId,
    version: u8,
    id: SessionId,
    evidence: &[u8],
) -> bool {
    let Some(catching) = shared.catching.read().ok().and_then(|held| held.clone()) else {
        return false;
    };
    let Some(root) = (catching.behind)(evidence) else { return false };
    let Ok(mut held) = shared.held_opens.lock() else { return false };
    // An open nobody answered for is let go once its dialler has given up.
    held.retain(|_, open| open.since.elapsed() < DIAL_PATIENCE);
    if held.len() >= MAX_HELD_OPENS || held.contains_key(&id) {
        return false;
    }
    held.insert(
        id,
        HeldOpen { peer, version, evidence: evidence.to_vec(), since: tokio::time::Instant::now() },
    );
    drop(held);
    let behind = Frame::Behind { id, root }.encode();
    let _ = shared.outbound.send(Out::Reply(peer, behind));
    true
}

/// Answers a peer that cannot place this node's root, with the roots after
/// its own: once per session, and only for a session, or a dial, this node
/// has with that peer.
fn answer_behind(shared: &Shared, peer: PeerId, id: SessionId, root: [u8; 32]) {
    let Some(source) = shared.roots.read().ok().and_then(|held| held.clone()) else { return };
    let ours = session_of(shared, id, &peer).is_some()
        || shared
            .dials
            .lock()
            .is_ok_and(|dials| dials.get(&id).is_some_and(|dial| dial.peer == peer));
    if !ours {
        return;
    }
    let first = shared.answered.lock().is_ok_and(|mut answered| {
        if answered.len() >= MAX_ANSWERED {
            answered.clear();
        }
        answered.insert(id)
    });
    if !first {
        return;
    }
    let outbound = shared.outbound.clone();
    // As many as the peer puts back together in one frame.
    let room = crate::frame::MAX_ROOTS
        .min(shared.wire.limits(&peer).frame_len().saturating_sub(crate::frame::PAYLOAD_HEADER));
    tokio::spawn(async move {
        let roots = source(root, room).await;
        // Whole roots fitting one frame are the source's to choose: cut here,
        // the last would be half a root, and the rest unreadable with it.
        if roots.len() <= room {
            let _ = outbound.send(Out::Reply(peer, Frame::Roots { id, roots }.encode()));
        }
    });
}

/// Roots that arrived for a dial or an open waiting on them; anything else is
/// dropped.
fn roots_arrived(shared: &Arc<Shared>, peer: PeerId, id: SessionId, roots: Vec<u8>) {
    let waiting = shared.catch_ups.lock().ok().and_then(|mut waiting| {
        if waiting.get(&id).is_some_and(|(from, _)| *from == peer) {
            waiting.remove(&id)
        } else {
            None
        }
    });
    if let Some((_, tell)) = waiting {
        let _ = tell.send(roots);
        return;
    }
    let held = shared.held_opens.lock().ok().and_then(|mut held| {
        if held.get(&id).is_some_and(|open| open.peer == peer) { held.remove(&id) } else { None }
    });
    let Some(open) = held else { return };
    let taken = shared
        .catching
        .read()
        .ok()
        .and_then(|held| held.clone())
        .is_some_and(|catching| (catching.take)(&open.evidence, &roots));
    if taken {
        opened(shared, peer, open.version, id, &open.evidence, false);
    } else {
        refused(shared, peer, id, Reason::NotAMember);
    }
}

/// The transport key behind an authenticated convesso peer, read from the
/// evidence it shows: the one of its leaf's transport keys that is this peer.
fn key_shown_by(peer: &PeerId, evidence: &[u8]) -> Option<(PublicKey, Address)> {
    let shown = roster::membership::Shown::from_bytes(evidence).ok()?;
    shown.leaf.record.keys.iter().find_map(|entry| {
        if entry.purpose != roster::types::KeyPurpose::Transport || entry.alg != Algorithm::Ed25519
        {
            return None;
        }
        let bytes = <[u8; 32]>::try_from(entry.value.as_slice()).ok()?;
        let address = Address::parse(bytes).ok()?;
        (address.peer_id() == *peer)
            .then(|| {
                PublicKey::new(Algorithm::Ed25519, bytes.to_vec()).ok().map(|key| (key, address))
            })
            .flatten()
    })
}

/// Refuses `peer`'s open `id`, and where this node will not talk to it, closes
/// convesso's session with it once the refusal has had time to reach it, if
/// nothing else has been said to it since, nor anything opened with it.
///
/// A peer this node will not talk to keeps no session keys here: it passed the
/// handshake (another version, groups that do not allow it, a revocation since,
/// or a node holding no roster, which admits every handshake), and left open,
/// the session would outlive the refusal on this side alone. Closed at once,
/// the close overtakes the refusal, and the peer is told nothing. A member
/// refused for want of room keeps its session, and opens again on it.
fn refused(shared: &Arc<Shared>, peer: PeerId, id: SessionId, reason: Reason) {
    let _ = shared.outbound.send(Out::Reply(peer, Frame::Refuse { id, reason }.encode()));
    if reason == Reason::Ordinary {
        return;
    }
    let at = tokio::time::Instant::now();
    let Ok(mut refusals) = shared.refusals.lock() else { return };
    refusals.insert(peer, at);
    drop(refusals);
    let shared = Arc::clone(shared);
    tokio::spawn(async move {
        tokio::time::sleep(REFUSED_GRACE).await;
        // A later refusal closes in its own time.
        let latest = shared.refusals.lock().is_ok_and(|mut refusals| {
            let latest = refusals.get(&peer) == Some(&at);
            if latest {
                refusals.remove(&peer);
            }
            latest
        });
        if latest && !speaks_to(&shared, &peer) {
            let _ = shared.outbound.send(Out::Close(peer, CLOSE_REFUSED));
        }
    });
}

/// A peer opens a session with this node.
///
/// Where this node holds no roster and cannot place the root the evidence
/// rests on, the open is held while the roots are asked for, unless
/// `may_catch_up` is false: once they are taken, it is judged again here.
fn opened(
    shared: &Arc<Shared>,
    peer: PeerId,
    version: u8,
    id: SessionId,
    evidence: &[u8],
    may_catch_up: bool,
) {
    let refuse = |reason: Reason| refused(shared, peer, id, reason);
    if version != VERSION {
        refuse(Reason::Version);
        return;
    }
    let entry = if shared.judge.is_some() {
        // No roster to look the key up in: the evidence names the key, and must
        // name the one the handshake authenticated.
        Some(match key_shown_by(&peer, evidence) {
            Some((key, address)) => {
                (judged(shared, &key, evidence).unwrap_or(Err(Error::NotAMember)), Some(address))
            }
            None => (Err(Error::NotAMember), None),
        })
    } else {
        shared.members.read().ok().map(|members| (members.verdict(&peer), members.address(&peer)))
    };
    let (device, address) = match entry {
        Some((Ok(device), Some(address))) => (device, address),
        Some((Err(error), _)) => {
            if !(may_catch_up && held_for_roots(shared, peer, version, id, evidence)) {
                refuse(reason_of(&error));
            }
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
    // The receiver's check, once, as the session opens: the initiator's groups
    // from the leaf it verified, against this device's own.
    if !allowed(shared, &device, evidence) {
        refuse(Reason::NotAllowed);
        return;
    }
    let live = Live::new(id, device, address, shared.context.clone(), Arc::clone(&shared.wire));
    live.set_evidence(evidence.to_vec());
    live.set_inbound();
    sessions.insert(id, Arc::clone(&live));
    let replaced = shared.accepted_from.lock().ok().and_then(|mut from| from.insert(peer, id));
    if let Some(older) = replaced.and_then(|older| sessions.get(&older).cloned()) {
        // The dialler is told. It may still hold the older one: two dials in
        // flight at once, and, not told, it kept a session this side no
        // longer reads (`convesso-reach` 5.4).
        if older.shut(Error::ClosedByPeer) {
            let close = Frame::Close { id: older.id, reason: Reason::Ordinary }.encode();
            let _ = shared.outbound.send(Out::Reply(peer, close));
        }
    }
    drop(sessions);

    if shared.incoming.try_send(Arc::clone(&live)).is_err() {
        // Nobody is accepting fast enough: refused rather than queued without
        // end.
        live.shut(Error::SessionClosed);
        refuse(Reason::Ordinary);
        return;
    }
    let accept = Frame::Accept { id, limits: OWN, evidence: own_evidence(shared) };
    let _ = shared.outbound.send(Out::Reply(peer, accept.encode()));
}

/// A reliable message from `peer`.
async fn on_message(shared: &Arc<Shared>, peer: PeerId, data: &[u8]) {
    // A part waits for the rest of its frame. From a peer this node does not
    // yet speak to, nothing larger than an opening: a node holding no roster
    // admits every handshake, and a stranger would make it hold frames' worth
    // of memory for nothing.
    let largest = if speaks_to(shared, &peer) {
        crate::frame::OWN.frame_len()
    } else {
        transport_wire::parts::MAX_OPENING
    };
    let Some(data) = shared.wire.join(peer, data, largest) else { return };
    match Frame::decode(&data) {
        Some(Frame::Open { version, id, limits, evidence }) => {
            if version == VERSION {
                shared.wire.heard(peer, limits);
            }
            opened(shared, peer, version, id, &evidence, true);
        }
        Some(Frame::Behind { id, root }) => answer_behind(shared, peer, id, root),
        Some(Frame::Roots { id, roots }) => roots_arrived(shared, peer, id, roots),
        Some(Frame::Accept { id, limits, evidence }) => {
            shared.wire.heard(peer, limits);
            answer_dial(shared, id, &peer, Answer::Accepted(evidence));
        }
        Some(Frame::Refuse { id, reason }) => {
            answer_dial(shared, id, &peer, Answer::Refused(refusal_of(reason)));
        }
        Some(Frame::Close { id, .. }) => {
            if let Some(live) = session_of(shared, id, &peer) {
                live.shut(Error::ClosedByPeer);
            }
        }
        // A session this node closed is one it does not hold: the sender is
        // told, as for one it never had. Dropped in silence, a board that had
        // not heard the close went on asking for its proof over it, unanswered,
        // and held no IPv4 address for minutes (testbed, 2026-11-09).
        Some(Frame::Payload { id, bytes }) => match open_session(shared, id, &peer) {
            Some(live) => live.deliver_payload(bytes).await,
            None => unknown_session(shared, peer, id),
        },
        // A packet sent as a message is not one: ignored.
        Some(Frame::Packet { .. }) | None => {}
    }
}

/// Whether this node speaks to `peer`: a session with it, a dial to it, or
/// its open held while roots are asked for.
fn speaks_to(shared: &Shared, peer: &PeerId) -> bool {
    shared.sessions.lock().is_ok_and(|sessions| sessions.values().any(|live| live.peer == *peer))
        || shared.dials.lock().is_ok_and(|dials| dials.values().any(|dial| dial.peer == *peer))
        || shared.held_opens.lock().is_ok_and(|held| held.values().any(|open| open.peer == *peer))
}

/// A datagram from `peer`.
fn on_datagram(shared: &Shared, peer: PeerId, data: &[u8]) {
    if let Some(Frame::Packet { id, fragment }) = Frame::decode(data) {
        match open_session(shared, id, &peer) {
            Some(live) => live.deliver_fragment(&fragment),
            None => unknown_session(shared, peer, id),
        }
    }
}

/// A frame for a session this node does not hold: one it closed, or one it
/// lost by restarting. The sender is told, and told again every
/// [`TELL_AGAIN`] while it goes on sending, so that it ends the session rather
/// than carry on into nothing: told once, the close could be lost as convesso
/// opened the session again.
///
/// convesso tells a restart only when a message was cut half way: a peer that
/// restarted between messages takes the next one as a new start, silently. A
/// node that kept a session with it would otherwise send into it until that
/// session closed on its own, which, held open, is never.
fn unknown_session(shared: &Shared, peer: PeerId, id: SessionId) {
    let now = tokio::time::Instant::now();
    let due = shared.unknown.lock().is_ok_and(|mut told| {
        if told.len() >= MAX_ANSWERED && !told.contains_key(&id) {
            told.clear();
        }
        let due = told.get(&id).is_none_or(|at| now.duration_since(*at) >= TELL_AGAIN);
        if due {
            told.insert(id, now);
        }
        due
    });
    if due {
        let close = Frame::Close { id, reason: Reason::Ordinary }.encode();
        let _ = shared.outbound.send(Out::Reply(peer, close));
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
        // A peer with no room is there, and is tried again soon.
        assert_eq!(
            dial_failed(&DialError::Refused(RefusalCode::CAPACITY_EXHAUSTED)),
            Error::PeerBusy
        );
        assert_eq!(dial_failed(&DialError::Refused(RefusalCode::BUSY)), Error::PeerBusy);
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

    /// The roster's relay is read through `crate::relay`, and anything else is
    /// refused.
    #[test]
    fn a_relay_is_its_string() {
        let key = convesso_core::identity::Identity::from_ed25519_seed(&[3; 32]).unwrap();
        let written = crate::relay::written(key.address().as_bytes(), "relay.example:7400", true);
        let read = relay_location(&written).unwrap();
        assert_eq!((read.host.as_str(), read.tls), ("relay.example:7400", true));
        assert!(matches!(
            relay_location("https://relay.example:443"),
            Err(BuildError::UnusableRelay { .. })
        ));
    }
}

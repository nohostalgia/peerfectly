//! A transport that runs entirely in one process.
//!
//! Not a mock. It implements the interface completely — a registry pairing
//! endpoints, a real mutual handshake with nonces and signatures, payloads
//! carried with their boundaries intact, close propagating both ways, and every
//! failure the specification names reachable through it.
//!
//! That completeness is the point. A stub that only did the happy path would let
//! the interface drift into describing the stub, which is the failure mode that
//! makes an abstraction worthless. The behavioural suite is written against the
//! trait and run against this; `transport-iroh` will be expected to pass the same
//! suite unchanged, so its remaining job is connectivity rather than semantics.
//!
//! What it does **not** provide is confidentiality. There is no wire here to
//! protect, and the interface promises none.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use identity::NodeIdentity;
use roster::id::{DeviceId, KeyId};
use roster::sign::PublicKey;
use roster::state::RosterState;
use tokio::sync::{Mutex, mpsc};

use crate::auth::{self, CHALLENGE_LEN, Handshake};
use crate::error::{Error, Result};
use crate::limits;
use crate::session::{Session, Transport};

/// What a peer's endpoint receives when someone dials it.
struct Incoming {
    /// The dialler's handshake, answering the nonce below.
    handshake: Handshake,
    /// The nonce the dialler chose for *this* node to answer.
    peer_nonce: [u8; CHALLENGE_LEN],
    /// Where to send this node's answering handshake.
    reply: tokio::sync::oneshot::Sender<Result<Handshake>>,
    /// The channels the dialler has prepared, if the session goes ahead.
    to_dialler: mpsc::Sender<Vec<u8>>,
    from_dialler: mpsc::Receiver<Vec<u8>>,
    /// The packet channels, the same way.
    packets_to_dialler: mpsc::Sender<Vec<u8>>,
    packets_from_dialler: mpsc::Receiver<Vec<u8>>,
}

/// The shared fabric two or more in-memory nodes connect through.
///
/// Stands in for "the network": who can be reached, and who cannot.
#[derive(Clone, Default)]
pub struct MemoryFabric {
    /// Endpoints by transport key id.
    endpoints: Arc<Mutex<HashMap<KeyId, mpsc::Sender<Incoming>>>>,
}

impl MemoryFabric {
    /// An empty fabric with nobody reachable.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl core::fmt::Debug for MemoryFabric {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MemoryFabric")
    }
}

/// One node's endpoint on a [`MemoryFabric`].
pub struct MemoryTransport {
    /// The fabric this node is reachable on.
    fabric: MemoryFabric,
    /// This node's keys.
    identity: Arc<NodeIdentity>,
    /// The roster state membership decisions are taken from.
    ///
    /// **This is the only membership state a transport may hold, and no decision
    /// taken from it may be cached.** A transport that remembered "this peer is
    /// allowed" would be a second, quieter roster, consulted far more often than
    /// the signed one — and when the two disagreed, the cache would be the thing
    /// actually deciding who is in the network. The way to not have that bug is
    /// to have nowhere to put it.
    ///
    /// Held behind a lock so a daemon can hand the transport newer state.
    state: Arc<Mutex<RosterState>>,
    /// Sessions opened so far, so a membership change can reach them.
    open: Arc<Mutex<Vec<Arc<MemorySession>>>>,
    /// Dials arriving for this node.
    inbox: Mutex<mpsc::Receiver<Incoming>>,
    /// A deterministic source of nonces, so tests reproduce.
    nonce: Arc<Mutex<u64>>,
}

impl MemoryTransport {
    /// Registers a node on a fabric.
    pub async fn join(
        fabric: &MemoryFabric,
        identity: Arc<NodeIdentity>,
        state: RosterState,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(limits::MAX_PENDING_DIALS);
        let key = identity.transport_key().key_id();
        fabric.endpoints.lock().await.insert(key, sender);
        Self {
            fabric: fabric.clone(),
            identity,
            state: Arc::new(Mutex::new(state)),
            open: Arc::new(Mutex::new(Vec::new())),
            inbox: Mutex::new(receiver),
            nonce: Arc::new(Mutex::new(0)),
        }
    }

    /// The roster state decisions are currently taken from.
    pub async fn state(&self) -> RosterState {
        self.state.lock().await.clone()
    }

    /// This node's transport public key.
    #[must_use]
    pub fn transport_key(&self) -> PublicKey {
        self.identity.transport_key().public_key()
    }

    /// Draws the next nonce.
    async fn next_nonce(&self) -> [u8; CHALLENGE_LEN] {
        let mut counter = self.nonce.lock().await;
        *counter = counter.wrapping_add(1);
        let mut nonce = [0u8; CHALLENGE_LEN];
        nonce.get_mut(..8).unwrap_or(&mut []).copy_from_slice(&counter.to_be_bytes());
        nonce
    }

    /// Answers a challenge with this node's transport key.
    fn answer(&self, nonce: &[u8; CHALLENGE_LEN]) -> Result<Handshake> {
        let challenge = auth::challenge_bytes(nonce);
        let signature = self.identity.transport_key().signer().sign(&challenge)?;
        Ok(Handshake { key: self.transport_key(), signature })
    }

    /// Records a session so a later membership change can reach it.
    async fn remember(&self, session: &Arc<MemorySession>) {
        self.open.lock().await.push(Arc::clone(session));
    }
}

#[async_trait]
impl Transport for MemoryTransport {
    /// Hands the transport newer roster state.
    ///
    /// Declared only on the interface, never as an inherent method too. A caller
    /// holding the concrete type and one holding a `dyn Transport` must reach the
    /// same operation: two ways in is how the daemon came to hold a transport
    /// whose membership view it had no way to refresh.
    async fn update_state(&self, state: RosterState) {
        let mut sessions = self.open.lock().await;
        for session in sessions.iter() {
            if !auth::is_member(&state, &session.peer) {
                session.shut(Error::ClosedOnMembershipLoss).await;
            }
        }
        sessions.retain(|session| !session.is_closed_now());
        *self.state.lock().await = state;
    }

    async fn connect(&self, peer: &PublicKey) -> Result<Box<dyn Session>> {
        let endpoint = {
            let endpoints = self.fabric.endpoints.lock().await;
            endpoints.get(&peer.key_id()).cloned()
        };
        // Reachability is answered before membership: this is what can be known
        // before the peer says anything at all.
        let endpoint = endpoint.ok_or(Error::PeerUnreachable { cause: None })?;

        let our_nonce = self.next_nonce().await;
        let (reply, answer) = tokio::sync::oneshot::channel();
        let (to_dialler, from_acceptor) = mpsc::channel(limits::SESSION_QUEUE);
        let (to_acceptor, from_dialler) = mpsc::channel(limits::SESSION_QUEUE);
        let (packets_to_dialler, packets_from_acceptor) = mpsc::channel(limits::PACKET_QUEUE);
        let (packets_to_acceptor, packets_from_dialler) = mpsc::channel(limits::PACKET_QUEUE);

        // The dialler answers the acceptor's challenge in the same message, so
        // the exchange is one round trip rather than two.
        let their_nonce = derive_peer_nonce(&our_nonce);
        let incoming = Incoming {
            handshake: self.answer(&their_nonce)?,
            peer_nonce: our_nonce,
            reply,
            to_dialler,
            from_dialler,
            packets_to_dialler,
            packets_from_dialler,
        };
        endpoint.send(incoming).await.map_err(|_| Error::PeerUnreachable { cause: None })?;

        let their_handshake =
            answer.await.map_err(|_| Error::PeerUnreachable { cause: None })??;
        let state = self.state.lock().await.clone();
        let device = auth::authenticate(&state, &their_handshake, &our_nonce)?;

        let session = Arc::new(MemorySession::new(
            device,
            (to_acceptor, from_acceptor),
            (packets_to_acceptor, packets_from_acceptor),
        ));
        self.remember(&session).await;
        Ok(Box::new(SessionHandle(session)))
    }

    async fn accept(&self) -> Result<Box<dyn Session>> {
        let incoming = {
            let mut inbox = self.inbox.lock().await;
            inbox.recv().await.ok_or(Error::PeerUnreachable { cause: None })?
        };

        let their_nonce = derive_peer_nonce(&incoming.peer_nonce);
        let state = self.state.lock().await.clone();
        let outcome = auth::authenticate(&state, &incoming.handshake, &their_nonce);

        let device = match outcome {
            Ok(device) => device,
            Err(refusal) => {
                // Tell the dialler why, rather than dropping the channel and
                // leaving it to guess at a timeout.
                let _ = incoming.reply.send(Err(refusal.clone()));
                return Err(refusal);
            }
        };

        let answer = self.answer(&incoming.peer_nonce)?;
        incoming.reply.send(Ok(answer)).map_err(|_| Error::PeerUnreachable { cause: None })?;

        let session = Arc::new(MemorySession::new(
            device,
            (incoming.to_dialler, incoming.from_dialler),
            (incoming.packets_to_dialler, incoming.packets_from_dialler),
        ));
        self.remember(&session).await;
        Ok(Box::new(SessionHandle(session)))
    }
}

/// The nonce the dialler must answer, derived from the one it issued.
///
/// One round trip instead of two. Distinct from the dialler's own nonce, so
/// neither side can be made to sign the challenge it issued.
fn derive_peer_nonce(nonce: &[u8; CHALLENGE_LEN]) -> [u8; CHALLENGE_LEN] {
    let mut derived = *nonce;
    if let Some(last) = derived.last_mut() {
        *last ^= 0xff;
    }
    derived
}

/// One end of an in-memory session.
struct MemorySession {
    /// The device this session belongs to, fixed at establishment.
    peer: DeviceId,
    /// Outbound payloads.
    outbound: mpsc::Sender<Vec<u8>>,
    /// Inbound payloads.
    inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Outbound packets, dropped when the far end's queue is full.
    packets_out: mpsc::Sender<Vec<u8>>,
    /// Inbound packets.
    packets_in: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Why the session ended, once it has.
    closed: Mutex<Option<Error>>,
}

/// A sending half and a receiving half.
type Channel = (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>);

impl MemorySession {
    /// Builds a session end from its payload and packet channels.
    fn new(peer: DeviceId, payloads: Channel, packets: Channel) -> Self {
        Self {
            peer,
            outbound: payloads.0,
            inbound: Mutex::new(payloads.1),
            packets_out: packets.0,
            packets_in: Mutex::new(packets.1),
            closed: Mutex::new(None),
        }
    }

    /// Ends the session with a reason, if it has not ended already.
    async fn shut(&self, reason: Error) {
        let mut closed = self.closed.lock().await;
        if closed.is_none() {
            *closed = Some(reason);
        }
    }

    /// Whether this end has already been shut, without waiting.
    fn is_closed_now(&self) -> bool {
        self.closed.try_lock().is_ok_and(|closed| closed.is_some())
    }

    /// The reason this session ended, if it has.
    async fn closure(&self) -> Option<Error> {
        self.closed.lock().await.clone()
    }
}

/// A handle a caller holds, keeping the session alive while it does.
struct SessionHandle(Arc<MemorySession>);

#[async_trait]
impl Session for SessionHandle {
    fn peer(&self) -> DeviceId {
        self.0.peer
    }

    async fn send(&self, payload: &[u8]) -> Result<()> {
        if payload.len() > limits::MAX_PAYLOAD {
            // Refused here, whole. Nothing partial reaches the peer.
            return Err(Error::PayloadTooLarge { len: payload.len(), limit: limits::MAX_PAYLOAD });
        }
        if let Some(reason) = self.0.closure().await {
            return Err(reason);
        }
        self.0.outbound.send(payload.to_vec()).await.map_err(|_| Error::ClosedByPeer)
    }

    async fn recv(&self) -> Result<Vec<u8>> {
        if let Some(reason) = self.0.closure().await {
            return Err(reason);
        }
        let mut inbound = self.0.inbound.lock().await;
        match inbound.recv().await {
            Some(payload) => Ok(payload),
            None => {
                drop(inbound);
                // The far end went away. If we already know a reason, keep it —
                // "the network expelled this device" outranks "the other end
                // hung up" when both are true.
                let reason = self.0.closure().await.unwrap_or(Error::ClosedByPeer);
                self.0.shut(reason.clone()).await;
                Err(reason)
            }
        }
    }

    async fn send_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() > limits::MAX_PACKET {
            return Err(Error::PacketTooLarge { len: packet.len(), limit: limits::MAX_PACKET });
        }
        if let Some(reason) = self.0.closure().await {
            return Err(reason);
        }
        match self.0.packets_out.try_send(packet.to_vec()) {
            // A full queue drops the packet, as a congested path would.
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(Error::ClosedByPeer),
        }
    }

    async fn recv_packet(&self) -> Result<Vec<u8>> {
        if let Some(reason) = self.0.closure().await {
            return Err(reason);
        }
        let mut inbound = self.0.packets_in.lock().await;
        match inbound.recv().await {
            Some(packet) => Ok(packet),
            None => {
                drop(inbound);
                let reason = self.0.closure().await.unwrap_or(Error::ClosedByPeer);
                self.0.shut(reason.clone()).await;
                Err(reason)
            }
        }
    }

    async fn close(&self) -> Result<()> {
        // Closing twice is not an error: a caller tidying up should not have to
        // track whether the far end got there first.
        self.0.shut(Error::SessionClosed).await;
        Ok(())
    }
}

//! A second implementation, built differently on purpose.
//!
//! [`crate::memory`] carries payloads through bounded `mpsc` channels and settles
//! its handshake over a `oneshot`. This one uses a shared deque behind a mutex
//! with a `Notify` to wake readers, and pairs endpoints through a broker that
//! matches a waiting dialler with a waiting acceptor.
//!
//! Nothing above the interface can tell them apart, which is the point. The
//! behavioural suite is written against the trait and run against both; a
//! behaviour that only one of them has fails immediately, so the interface
//! cannot quietly become a description of whichever implementation happened to
//! be written first.
//!
//! Like its sibling, it provides no confidentiality — there is no wire here.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;
use identity::NodeIdentity;
use roster::id::{DeviceId, KeyId};
use roster::sign::PublicKey;
use roster::state::RosterState;
use tokio::sync::{Mutex, Notify};

use crate::auth::{self, CHALLENGE_LEN, Handshake};
use crate::error::{Error, Result};
use crate::limits;
use crate::session::{Session, Transport};

/// A pending dial waiting for its acceptor.
struct Pending {
    /// The dialler's handshake.
    handshake: Handshake,
    /// The nonce the acceptor must answer.
    nonce: [u8; CHALLENGE_LEN],
    /// The nonce the dialler issued, for its own check.
    dialler_nonce: [u8; CHALLENGE_LEN],
    /// The shared pipes, once both sides agree.
    pipes: Arc<Pipes>,
    /// Set once the acceptor has answered.
    answer: Arc<Mutex<Option<Result<Handshake>>>>,
    /// Wakes the dialler when the answer lands.
    settled: Arc<Notify>,
}

/// The shared fabric these nodes meet on.
#[derive(Clone, Default)]
pub struct DirectFabric {
    /// Dials waiting per destination key.
    waiting: Arc<Mutex<HashMap<KeyId, VecDeque<Pending>>>>,
    /// Wakes an acceptor when a dial arrives for it.
    arrivals: Arc<Notify>,
}

impl DirectFabric {
    /// An empty fabric.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers that a key is reachable here.
    async fn open(&self, key: KeyId) {
        self.waiting.lock().await.entry(key).or_default();
    }

    /// Whether anyone is listening on a key.
    async fn reachable(&self, key: &KeyId) -> bool {
        self.waiting.lock().await.contains_key(key)
    }
}

impl core::fmt::Debug for DirectFabric {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DirectFabric")
    }
}

/// Payloads in flight between two ends, in both directions.
#[derive(Default)]
struct Pipes {
    /// Toward the acceptor.
    to_acceptor: Mutex<VecDeque<Vec<u8>>>,
    /// Toward the dialler.
    to_dialler: Mutex<VecDeque<Vec<u8>>>,
    /// Packets toward the acceptor, bounded and dropping when full.
    packets_to_acceptor: Mutex<VecDeque<Vec<u8>>>,
    /// Packets toward the dialler.
    packets_to_dialler: Mutex<VecDeque<Vec<u8>>>,
    /// Why the session ended, once it has.
    closed: Mutex<Option<Error>>,
    /// Wakes whichever side is waiting.
    activity: Notify,
}

impl Pipes {
    /// Ends the session with a reason, if it has not ended already.
    async fn shut(&self, reason: Error) {
        {
            let mut closed = self.closed.lock().await;
            if closed.is_none() {
                *closed = Some(reason);
            }
        }
        // Wake both sides so neither waits on a session that has ended.
        self.activity.notify_waiters();
    }

    /// The reason this session ended, if it has.
    async fn closure(&self) -> Option<Error> {
        self.closed.lock().await.clone()
    }
}

/// One node on a [`DirectFabric`].
pub struct DirectTransport {
    /// The fabric.
    fabric: DirectFabric,
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
    state: Arc<Mutex<RosterState>>,
    /// Sessions opened so far, so a membership change can reach them.
    open: Arc<Mutex<Vec<Arc<Pipes>>>>,
    /// Peers of those sessions, positionally matching `open`.
    peers: Arc<Mutex<Vec<DeviceId>>>,
    /// A deterministic nonce source.
    nonce: Arc<Mutex<u64>>,
}

impl DirectTransport {
    /// Registers a node on a fabric.
    pub async fn join(
        fabric: &DirectFabric,
        identity: Arc<NodeIdentity>,
        state: RosterState,
    ) -> Self {
        fabric.open(identity.transport_key().key_id()).await;
        Self {
            fabric: fabric.clone(),
            identity,
            state: Arc::new(Mutex::new(state)),
            open: Arc::new(Mutex::new(Vec::new())),
            peers: Arc::new(Mutex::new(Vec::new())),
            nonce: Arc::new(Mutex::new(0)),
        }
    }

    /// The state decisions are currently taken from.
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
        let mut nonce = [0x5au8; CHALLENGE_LEN];
        nonce.get_mut(..8).unwrap_or(&mut []).copy_from_slice(&counter.to_be_bytes());
        nonce
    }

    /// Answers a challenge with this node's transport key.
    fn answer(&self, nonce: &[u8; CHALLENGE_LEN]) -> Result<Handshake> {
        let challenge = auth::challenge_bytes(nonce);
        let signature = self.identity.transport_key().signer().sign(&challenge)?;
        Ok(Handshake { key: self.transport_key(), signature })
    }

    /// Records a session so a membership change can reach it.
    async fn remember(&self, pipes: &Arc<Pipes>, peer: DeviceId) {
        self.open.lock().await.push(Arc::clone(pipes));
        self.peers.lock().await.push(peer);
    }
}

#[async_trait]
impl Transport for DirectTransport {
    /// Hands the transport newer roster state, closing sessions whose peer has
    /// stopped being a member.
    ///
    /// Declared only on the interface, never as an inherent method too, so a
    /// caller holding the concrete type and one holding a `dyn Transport` reach
    /// the same operation.
    async fn update_state(&self, state: RosterState) {
        let sessions = self.open.lock().await;
        let peers = self.peers.lock().await;
        for (pipes, peer) in sessions.iter().zip(peers.iter()) {
            if !auth::is_member(&state, peer) {
                pipes.shut(Error::ClosedOnMembershipLoss).await;
            }
        }
        drop(peers);
        drop(sessions);
        *self.state.lock().await = state;
    }

    async fn connect(&self, peer: &PublicKey) -> Result<Box<dyn Session>> {
        if !self.fabric.reachable(&peer.key_id()).await {
            return Err(Error::PeerUnreachable { cause: None });
        }

        let dialler_nonce = self.next_nonce().await;
        let acceptor_nonce = {
            let mut derived = dialler_nonce;
            if let Some(first) = derived.first_mut() {
                *first ^= 0xff;
            }
            derived
        };

        let pipes = Arc::new(Pipes::default());
        let answer = Arc::new(Mutex::new(None));
        let settled = Arc::new(Notify::new());

        {
            let mut waiting = self.fabric.waiting.lock().await;
            let queue =
                waiting.get_mut(&peer.key_id()).ok_or(Error::PeerUnreachable { cause: None })?;
            queue.push_back(Pending {
                handshake: self.answer(&acceptor_nonce)?,
                nonce: dialler_nonce,
                dialler_nonce,
                pipes: Arc::clone(&pipes),
                answer: Arc::clone(&answer),
                settled: Arc::clone(&settled),
            });
        }
        self.fabric.arrivals.notify_waiters();

        // Wait for the acceptor to answer.
        loop {
            if let Some(outcome) = answer.lock().await.take() {
                let their_handshake = outcome?;
                let state = self.state.lock().await.clone();
                let device = auth::authenticate(&state, &their_handshake, &dialler_nonce)?;
                self.remember(&pipes, device).await;
                return Ok(Box::new(DirectSession { peer: device, pipes, dialler: true }));
            }
            settled.notified().await;
        }
    }

    async fn accept(&self) -> Result<Box<dyn Session>> {
        let key = self.identity.transport_key().key_id();
        loop {
            let pending = {
                let mut waiting = self.fabric.waiting.lock().await;
                waiting.get_mut(&key).and_then(VecDeque::pop_front)
            };
            let Some(pending) = pending else {
                self.fabric.arrivals.notified().await;
                continue;
            };

            let mut derived = pending.dialler_nonce;
            if let Some(first) = derived.first_mut() {
                *first ^= 0xff;
            }

            let state = self.state.lock().await.clone();
            match auth::authenticate(&state, &pending.handshake, &derived) {
                Ok(device) => {
                    let reply = self.answer(&pending.nonce)?;
                    *pending.answer.lock().await = Some(Ok(reply));
                    pending.settled.notify_waiters();
                    self.remember(&pending.pipes, device).await;
                    return Ok(Box::new(DirectSession {
                        peer: device,
                        pipes: pending.pipes,
                        dialler: false,
                    }));
                }
                Err(refusal) => {
                    // Tell the dialler why rather than leaving it to time out.
                    *pending.answer.lock().await = Some(Err(refusal.clone()));
                    pending.settled.notify_waiters();
                    return Err(refusal);
                }
            }
        }
    }
}

/// One end of a direct session.
struct DirectSession {
    /// The device this session belongs to.
    peer: DeviceId,
    /// The shared pipes.
    pipes: Arc<Pipes>,
    /// Which end this is, deciding which queue it reads and writes.
    dialler: bool,
}

#[async_trait]
impl Session for DirectSession {
    fn peer(&self) -> DeviceId {
        self.peer
    }

    async fn send(&self, payload: &[u8]) -> Result<()> {
        if payload.len() > limits::MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge { len: payload.len(), limit: limits::MAX_PAYLOAD });
        }
        if let Some(reason) = self.pipes.closure().await {
            return Err(reason);
        }
        let queue = if self.dialler { &self.pipes.to_acceptor } else { &self.pipes.to_dialler };
        queue.lock().await.push_back(payload.to_vec());
        self.pipes.activity.notify_waiters();
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>> {
        let queue = if self.dialler { &self.pipes.to_dialler } else { &self.pipes.to_acceptor };
        loop {
            if let Some(payload) = queue.lock().await.pop_front() {
                return Ok(payload);
            }
            if let Some(reason) = self.pipes.closure().await {
                return Err(reason);
            }
            self.pipes.activity.notified().await;
        }
    }

    async fn send_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() > limits::MAX_PACKET {
            return Err(Error::PacketTooLarge { len: packet.len(), limit: limits::MAX_PACKET });
        }
        if let Some(reason) = self.pipes.closure().await {
            return Err(reason);
        }
        let queue = if self.dialler {
            &self.pipes.packets_to_acceptor
        } else {
            &self.pipes.packets_to_dialler
        };
        {
            let mut queue = queue.lock().await;
            // A full queue drops the packet, as a congested path would.
            if queue.len() < limits::PACKET_QUEUE {
                queue.push_back(packet.to_vec());
            }
        }
        self.pipes.activity.notify_waiters();
        Ok(())
    }

    async fn recv_packet(&self) -> Result<Vec<u8>> {
        let queue = if self.dialler {
            &self.pipes.packets_to_dialler
        } else {
            &self.pipes.packets_to_acceptor
        };
        loop {
            // Registered before looking, so a packet pushed between the look and
            // the wait still wakes this reader.
            let woken = self.pipes.activity.notified();
            tokio::pin!(woken);
            woken.as_mut().enable();
            if let Some(packet) = queue.lock().await.pop_front() {
                return Ok(packet);
            }
            if let Some(reason) = self.pipes.closure().await {
                return Err(reason);
            }
            woken.await;
        }
    }

    async fn close(&self) -> Result<()> {
        self.pipes.shut(Error::SessionClosed).await;
        Ok(())
    }
}

//! One session of the interface, carried inside a convesso session.
//!
//! Several of these may share one convesso session with a peer: they are told
//! apart by the id in every frame (`crate::frame`). The peer's reader fills a
//! session's two queues; the caller empties them.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use convesso_core::endpoint::SendError;
use convesso_core::identity::{Address, PeerId};
use convesso_tokio::{Context, NodeError};
use roster::id::DeviceId;
use tokio::sync::{Mutex, mpsc, watch};
use transport::error::{Error, Result};
use transport::fragment::{self, Reassembler};
use transport::limits;
use transport::session::Session;

use crate::frame::{Frame, PACKET_HEADER, Reason, SessionId};

/// The datagram data a relayed convesso packet carries: 1,380 bytes on the
/// relay (`PROTOCOL.md §6`), less the 31 of convesso's own transport framing.
/// The relay is the narrowest path, so a fragment cut to this fits on every
/// path a session may take (design D7).
pub const DATAGRAM_ROOM: usize = 1_380 - 31;

/// The room a fragment has inside a datagram, its own header included.
pub const FRAGMENT_ROOM: usize = DATAGRAM_ROOM - PACKET_HEADER;

/// One session, as the transport and the peer's reader share it.
pub struct Live {
    /// Its id, the dialler's choice.
    pub id: SessionId,
    /// The device at the other end.
    pub device: DeviceId,
    /// The same peer, as convesso authenticates it.
    pub peer: PeerId,
    /// And as convesso dials it.
    pub address: Address,
    /// The context, to send in.
    context: Context,
    /// Payloads arrived, waiting for the caller.
    payloads_in: mpsc::Sender<Vec<u8>>,
    payloads_out: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Packets arrived, waiting for the caller; full means dropped.
    packets_in: mpsc::Sender<Vec<u8>>,
    packets_out: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Packet fragments being joined. Only the peer's reader touches it.
    reassembler: std::sync::Mutex<Reassembler>,
    /// The id the next packet sent is given.
    next_packet: AtomicU32,
    /// Why the session ended, once it has. Watched, so a waiting receive wakes.
    closed: watch::Sender<Option<Error>>,
}

impl Live {
    /// A session with `device`, open.
    pub fn new(id: SessionId, device: DeviceId, address: Address, context: Context) -> Arc<Self> {
        let (payloads_in, payloads_out) = mpsc::channel(limits::SESSION_QUEUE);
        let (packets_in, packets_out) = mpsc::channel(limits::PACKET_QUEUE);
        Arc::new(Self {
            id,
            device,
            peer: address.peer_id(),
            address,
            context,
            payloads_in,
            payloads_out: Mutex::new(payloads_out),
            packets_in,
            packets_out: Mutex::new(packets_out),
            reassembler: std::sync::Mutex::new(Reassembler::new()),
            next_packet: AtomicU32::new(0),
            closed: watch::Sender::new(None),
        })
    }

    /// Why the session ended, if it has.
    pub fn closure(&self) -> Option<Error> {
        self.closed.borrow().clone()
    }

    /// Ends the session with `reason`, unless it has ended already. Returns
    /// whether this call ended it.
    pub fn shut(&self, reason: Error) -> bool {
        self.closed.send_if_modified(|closed| {
            if closed.is_some() {
                return false;
            }
            *closed = Some(reason);
            true
        })
    }

    /// Takes a payload from the peer.
    ///
    /// Waits while the caller has not read the payloads before it. Only this
    /// peer's reader waits, and convesso's per-peer delivery holds back this
    /// peer's sender alone: a session nobody reads slows its own peer and no
    /// other.
    pub async fn deliver_payload(&self, payload: Vec<u8>) {
        if self.closure().is_some() {
            return;
        }
        tokio::select! {
            _ = self.payloads_in.send(payload) => {}
            _ = self.ended() => {}
        }
    }

    /// Takes a packet fragment from the peer. A full queue drops the packet, as
    /// a router would.
    pub fn deliver_fragment(&self, fragment: &[u8]) {
        if self.closure().is_some() {
            return;
        }
        let packet = self
            .reassembler
            .lock()
            .ok()
            .and_then(|mut reassembler| reassembler.accept(fragment, Instant::now()));
        if let Some(packet) = packet {
            let _ = self.packets_in.try_send(packet);
        }
    }

    /// Waits for the session to end, and says why.
    async fn ended(&self) -> Error {
        let mut watching = self.closed.subscribe();
        match watching.wait_for(Option::is_some).await {
            Ok(reason) => reason.clone().unwrap_or(Error::SessionClosed),
            Err(_) => Error::SessionClosed,
        }
    }
}

/// What a caller holds.
pub struct SessionHandle(pub Arc<Live>);

/// A node error, as the interface says it.
fn sending_failed(error: &NodeError) -> Error {
    match error {
        NodeError::Stopped | NodeError::ContextClosed => Error::ClosedByPeer,
        other => Error::PeerUnreachable { cause: Some(other.to_string()) },
    }
}

#[async_trait]
impl Session for SessionHandle {
    fn peer(&self) -> DeviceId {
        self.0.device
    }

    async fn send(&self, payload: &[u8]) -> Result<()> {
        if payload.len() > limits::MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge { len: payload.len(), limit: limits::MAX_PAYLOAD });
        }
        if let Some(reason) = self.0.closure() {
            return Err(reason);
        }
        let message = Frame::Payload { id: self.0.id, bytes: payload.to_vec() }.encode();
        self.0
            .context
            .send_message(self.0.address, message)
            .await
            .map_err(|error| sending_failed(&error))
    }

    async fn recv(&self) -> Result<Vec<u8>> {
        if let Some(reason) = self.0.closure() {
            return Err(reason);
        }
        let mut payloads = self.0.payloads_out.lock().await;
        tokio::select! {
            biased;
            reason = self.0.ended() => Err(reason),
            payload = payloads.recv() => payload.ok_or(Error::SessionClosed),
        }
    }

    async fn send_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() > limits::MAX_PACKET {
            return Err(Error::PacketTooLarge { len: packet.len(), limit: limits::MAX_PACKET });
        }
        if let Some(reason) = self.0.closure() {
            return Err(reason);
        }
        let number = self.0.next_packet.fetch_add(1, Ordering::Relaxed);
        let mut room = FRAGMENT_ROOM;
        // At most twice: once at the size every path takes, and once more at
        // the size convesso names if that assumption ever proves wrong.
        for _ in 0..2 {
            let Some(pieces) = fragment::split(number, packet, room) else {
                return Err(Error::PacketTooLarge {
                    len: packet.len(),
                    limit: room
                        .saturating_sub(fragment::HEADER)
                        .saturating_mul(fragment::MAX_FRAGMENTS),
                });
            };
            let mut smaller = None;
            for piece in pieces {
                let length = piece.len();
                let datagram = Frame::Packet { id: self.0.id, fragment: piece }.encode();
                match self.0.context.send(self.0.address, datagram).await {
                    Ok(()) => {}
                    Err(NodeError::Send(SendError::TooLarge { packet: sent, path })) => {
                        // The path is narrower than this binding assumed: cut
                        // again by what it said, less what was added around
                        // the fragment on the way to the wire.
                        let overhead = sent.saturating_sub(length);
                        smaller = Some(path.saturating_sub(overhead));
                        break;
                    }
                    Err(NodeError::Stopped | NodeError::ContextClosed) => {
                        return Err(Error::ClosedByPeer);
                    }
                    // Anything else the path cannot take now: dropped, as a
                    // network drops a packet.
                    Err(_) => return Ok(()),
                }
            }
            match smaller {
                None => return Ok(()),
                Some(size) if size < room && size > fragment::HEADER => room = size,
                Some(_) => return Ok(()),
            }
        }
        Ok(())
    }

    async fn recv_packet(&self) -> Result<Vec<u8>> {
        if let Some(reason) = self.0.closure() {
            return Err(reason);
        }
        let mut packets = self.0.packets_out.lock().await;
        tokio::select! {
            biased;
            reason = self.0.ended() => Err(reason),
            packet = packets.recv() => packet.ok_or(Error::SessionClosed),
        }
    }

    async fn close(&self) -> Result<()> {
        if self.0.shut(Error::SessionClosed) {
            // The peer is told, so it reports a close rather than silence. Best
            // effort: a peer that never hears it ends its side when its own
            // convesso session does.
            let close = Frame::Close { id: self.0.id, reason: Reason::Ordinary }.encode();
            let context = self.0.context.clone();
            let address = self.0.address;
            tokio::spawn(async move {
                let _ = context.send_message(address, close).await;
            });
        }
        Ok(())
    }
}

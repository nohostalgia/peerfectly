//! A session over a QUIC connection.
//!
//! # Framing
//!
//! The interface promises that what is sent as one payload arrives as one
//! payload, at sizes up to `transport::limits::MAX_PAYLOAD`. QUIC offers two
//! ways to carry bytes and neither gives that for free:
//!
//! * **Datagrams** preserve boundaries but are bounded by the path MTU — around
//!   1200 bytes against the 262 144 the interface promises. Not usable.
//! * **Streams** are reliable and ordered but are byte streams: they preserve no
//!   boundaries at all.
//!
//! So: one bidirectional stream per session, each payload preceded by a
//! four-byte big-endian length. One stream rather than one per payload, because
//! separate streams have no ordering relative to each other and the interface
//! promises order.
//!
//! **Packets** are the other way round. They promise neither order nor delivery,
//! and on the stream they would inherit both — so one lost QUIC packet would stall
//! every tunnel packet behind it, and the TCP inside the tunnel would retransmit on
//! top of QUIC's own retransmission. They travel as datagrams instead, cut to fit
//! and put back together by [`crate::fragment`].
//!
//! A declared length is checked against the bound **before** any buffer is
//! reserved for it, which is the standard shape of refusing a peer that claims
//! to be sending a gigabyte.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use iroh::endpoint::{Connection, RecvStream, SendDatagramError, SendStream};
use roster::id::DeviceId;
use tokio::sync::Mutex;
use transport::error::{Error, Result};
use transport::limits;
use transport::session::{Path, Session};

use crate::fragment::{self, Reassembler};

/// The length prefix's width. Four bytes covers the payload bound many times
/// over; the bound, not the prefix, is what limits a payload.
const PREFIX: usize = 4;

/// One end of a session carried over a QUIC connection.
pub struct IrohSession {
    /// The device this session belongs to, fixed at establishment.
    peer: DeviceId,
    /// The connection, kept so the session can be closed and its path observed.
    connection: Connection,
    /// The outbound half of the single stream.
    outbound: Mutex<SendStream>,
    /// The inbound half.
    inbound: Mutex<RecvStream>,
    /// The id the next packet sent is given.
    next_packet: AtomicU32,
    /// Packets arriving in pieces, held while their other pieces arrive.
    ///
    /// Behind the lock a packet receive holds for as long as it reads, so there is
    /// one reader of the connection's datagrams at a time.
    reassembler: Mutex<Reassembler>,
    /// Why the session ended, once it has.
    closed: Mutex<Option<Error>>,
}

impl IrohSession {
    /// Wraps an established connection and its stream.
    pub(crate) fn new(
        peer: DeviceId,
        connection: Connection,
        outbound: SendStream,
        inbound: RecvStream,
    ) -> Arc<Self> {
        Arc::new(Self {
            peer,
            connection,
            outbound: Mutex::new(outbound),
            inbound: Mutex::new(inbound),
            next_packet: AtomicU32::new(0),
            reassembler: Mutex::new(Reassembler::new()),
            closed: Mutex::new(None),
        })
    }

    /// Ends the session with a reason, if it has not ended already.
    pub(crate) async fn shut(&self, reason: Error) {
        let mut closed = self.closed.lock().await;
        if closed.is_none() {
            // The peer is told, so it reports a close rather than a timeout.
            self.connection.close(0u32.into(), b"closed");
            *closed = Some(reason);
        }
    }

    /// The reason this session ended, if it has.
    pub(crate) async fn closure(&self) -> Option<Error> {
        self.closed.lock().await.clone()
    }

    /// Whether the session is currently carrying traffic on a direct path
    /// rather than through the relay.
    ///
    /// Needed by two different readers: the measurement DESIGN.md §10.4 gates
    /// this work on, and an operator asking why a session is slow. Without it
    /// "it connected" is the only thing anyone can say, and that is the one fact
    /// that was never in doubt.
    ///
    /// **The path that is selected, not one that merely exists.** This used to
    /// answer "direct" whenever any non-relay path was open, which is a different
    /// question: hole punching opens a path about once a minute whether or not
    /// anything will travel over it, so a session sitting on the relay reported
    /// itself direct for as long as that path lasted. On a phone it showed as the
    /// device row flickering between the two — and before the path rule landed,
    /// the flicker marked precisely the fifteen seconds when nothing was moving.
    #[must_use]
    pub fn path(&self) -> Path {
        // No selection at all — briefly, at the start — reads as relayed rather
        // than direct. Saying "direct" about a session that is not carrying
        // anything yet is the error that mattered here.
        if self.connection.paths().iter().any(|path| path.is_selected() && !path.is_relay()) {
            Path::Direct
        } else {
            Path::Relay
        }
    }

    /// The device this session belongs to.
    #[must_use]
    pub const fn device(&self) -> DeviceId {
        self.peer
    }
}

/// A handle a caller holds, keeping the session alive while it does.
pub struct SessionHandle(pub(crate) Arc<IrohSession>);

#[async_trait]
impl Session for SessionHandle {
    fn peer(&self) -> DeviceId {
        self.0.peer
    }

    async fn send(&self, payload: &[u8]) -> Result<()> {
        if payload.len() > limits::MAX_PAYLOAD {
            // Refused here, whole. A payload truncated to fit would become a
            // decoding failure at the far end, blamed on the sender, and
            // diagnosed nowhere near where it went wrong.
            return Err(Error::PayloadTooLarge { len: payload.len(), limit: limits::MAX_PAYLOAD });
        }
        if let Some(reason) = self.0.closure().await {
            return Err(reason);
        }

        let length = u32::try_from(payload.len()).map_err(|_| Error::PayloadTooLarge {
            len: payload.len(),
            limit: limits::MAX_PAYLOAD,
        })?;

        let mut outbound = self.0.outbound.lock().await;
        outbound.write_all(&length.to_be_bytes()).await.map_err(|_| Error::ClosedByPeer)?;
        outbound.write_all(payload).await.map_err(|_| Error::ClosedByPeer)?;
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>> {
        if let Some(reason) = self.0.closure().await {
            return Err(reason);
        }

        let mut inbound = self.0.inbound.lock().await;

        let mut prefix = [0u8; PREFIX];
        if inbound.read_exact(&mut prefix).await.is_err() {
            drop(inbound);
            // The far end went away. A reason already recorded outranks this
            // one: "the network expelled this device" is more useful than "the
            // other end hung up" when both are true.
            let reason = self.0.closure().await.unwrap_or(Error::ClosedByPeer);
            self.0.shut(reason.clone()).await;
            return Err(reason);
        }
        let declared = u32::from_be_bytes(prefix) as usize;

        // Checked before a buffer of that size exists. A peer claiming to send
        // four gigabytes must cost this node nothing but the refusal.
        if declared > limits::MAX_PAYLOAD {
            drop(inbound);
            let reason = Error::PayloadTooLarge { len: declared, limit: limits::MAX_PAYLOAD };
            self.0.shut(reason.clone()).await;
            return Err(reason);
        }

        let mut payload = vec![0u8; declared];
        if inbound.read_exact(&mut payload).await.is_err() {
            drop(inbound);
            // A frame that began and did not finish. Delivering what arrived
            // would hand the caller bytes that are not what was sent.
            let reason = self.0.closure().await.unwrap_or(Error::ClosedByPeer);
            self.0.shut(reason.clone()).await;
            return Err(reason);
        }
        Ok(payload)
    }

    async fn send_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() > limits::MAX_PACKET {
            return Err(Error::PacketTooLarge { len: packet.len(), limit: limits::MAX_PACKET });
        }
        if let Some(reason) = self.0.closure().await {
            return Err(reason);
        }
        // Read at every send: the path's limit grows as its MTU is discovered and
        // changes when the session moves between a direct path and the relay.
        let Some(datagram) = self.0.connection.max_datagram_size() else {
            return Err(Error::PacketsNotAccepted);
        };
        let id = self.0.next_packet.fetch_add(1, Ordering::Relaxed);
        let Some(pieces) = fragment::split(id, packet, datagram) else {
            let room = datagram.saturating_sub(fragment::HEADER);
            return Err(Error::PacketTooLarge {
                len: packet.len(),
                limit: room.saturating_mul(fragment::MAX_FRAGMENTS),
            });
        };
        for piece in pieces {
            match self.0.connection.send_datagram(bytes::Bytes::from(piece)) {
                Ok(()) => {}
                // The path shrank between reading its limit and sending: dropped,
                // as a router drops a packet it cannot forward.
                Err(SendDatagramError::TooLarge) => return Ok(()),
                Err(SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled) => {
                    return Err(Error::PacketsNotAccepted);
                }
                Err(SendDatagramError::ConnectionLost(_)) => {
                    let reason = self.0.closure().await.unwrap_or(Error::ClosedByPeer);
                    self.0.shut(reason.clone()).await;
                    return Err(reason);
                }
            }
        }
        Ok(())
    }

    async fn recv_packet(&self) -> Result<Vec<u8>> {
        if let Some(reason) = self.0.closure().await {
            return Err(reason);
        }
        let mut reassembler = self.0.reassembler.lock().await;
        loop {
            match self.0.connection.read_datagram().await {
                Ok(datagram) => {
                    if let Some(packet) = reassembler.accept(&datagram, Instant::now()) {
                        return Ok(packet);
                    }
                }
                Err(_) => {
                    drop(reassembler);
                    let reason = self.0.closure().await.unwrap_or(Error::ClosedByPeer);
                    self.0.shut(reason.clone()).await;
                    return Err(reason);
                }
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

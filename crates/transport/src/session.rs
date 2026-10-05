//! The interface a connectivity layer must satisfy.
//!
//! DESIGN.md §2.1 requires the transport to sit behind an internal interface of
//! about four methods, so that replacing it does not touch the rest. This is
//! that interface: `connect`, `send`, `recv`, `close` — plus `accept`, because a
//! transport that can only dial is half a transport, and giving the in-memory
//! implementation a private back channel the real one lacks is how an interface
//! stops describing reality.
//!
//! # What this interface does not promise
//!
//! **Confidentiality.** Nothing here encrypts anything. A real transport gets it
//! from QUIC and TLS 1.3 (§2.1); the in-memory one has no wire to protect and
//! provides none. This is stated rather than left implicit, because *"it goes
//! through the transport"* is exactly the sort of phrase a later reader takes to
//! mean *"it is encrypted"*. Anything needing confidentiality independent of the
//! connectivity layer must arrange it above this interface.
//!
//! **Authority.** A session proves the peer holds a transport key the roster
//! names. It says nothing about what that device may *do* — roles, admin rights
//! and founder status are derived state, and asking the transport about them
//! would make it a second authority.
//!
//! # Async, and dyn-compatible
//!
//! QUIC, hole punching and connection migration are asynchronous; a synchronous
//! facade would hide a runtime behind blocking calls, and blocking a phone's UI
//! thread on a relay handshake is a failure mode worth designing out. The traits
//! use `async_trait` so they remain usable behind a trait object, which is what
//! §2.1's "replaceable without touching the rest" actually requires.

use async_trait::async_trait;
use roster::id::DeviceId;
use roster::sign::PublicKey;
use roster::state::RosterState;

use crate::error::Result;
use crate::range::Range;

/// A connectivity layer.
///
/// Held behind a trait object by everything above it, so swapping the layer
/// changes nothing else.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Opens a session with the peer holding a transport key.
    ///
    /// Fails with [`crate::Error::PeerUnreachable`] when the peer cannot be
    /// reached at all, and with a membership refusal when it can be reached but
    /// the roster does not name it.
    async fn connect(&self, peer: &PublicKey) -> Result<Box<dyn Session>>;

    /// Waits for a peer to open a session with this node.
    async fn accept(&self) -> Result<Box<dyn Session>>;

    /// Where this node believes it can be reached, as opaque strings.
    ///
    /// Published to a rendezvous and announced on the local network by the layer
    /// above, which does not read them: only the implementation that produced an
    /// address knows what it means, and one that parsed them would need changing
    /// whenever the addressing did.
    ///
    /// Empty by default and empty for the in-memory implementations, which have
    /// no addresses to speak of. An empty answer means "nothing to say", never
    /// "unreachable".
    fn addresses(&self) -> Vec<String> {
        Vec::new()
    }

    /// Offers addresses where a peer was seen.
    ///
    /// A hint, not an instruction: the implementation decides whether to try
    /// them, and reaching the peer any other way stays correct. Nothing here is
    /// authority — an address is not membership, and a peer is authorised by the
    /// roster after the session is established, exactly as before.
    ///
    /// The default ignores them, which is right for a transport that has no
    /// notion of an address.
    fn learned(&self, _peer: &PublicKey, _addresses: &[String]) {}

    /// Hands the transport newer roster state.
    ///
    /// Membership decisions are the transport's to make and the state they are
    /// made from is the caller's to hold, so there has to be a way to say that
    /// the network changed. Without one on *this* trait, a node holding a
    /// `dyn Transport` cannot say it, and the transport keeps deciding from
    /// whatever it was given when it was built — which is a cached membership
    /// decision no matter what it is called, and is exactly the state two
    /// machines were found in: each refusing the other as a non-member, minutes
    /// after a person had enrolled one into the other's network.
    ///
    /// Every session whose peer has stopped being a member MUST be closed here,
    /// reported as a loss of membership. That duty is why this is a call and not
    /// a shared reference the transport could read at its leisure: a transport
    /// that merely re-read state would notice a revocation at its next decision,
    /// and for a session already carrying traffic that may be never.
    ///
    /// The default does nothing, which is right for an implementation that holds
    /// no state of its own — a test double, or one reading state it shares with
    /// its caller. Every implementation that keeps its own copy must override it.
    async fn update_state(&self, _state: RosterState) {}

    /// Says which blocks of addresses are served by tunnels the caller runs.
    ///
    /// A transport that finds its own caller's tunnel among the machine's
    /// addresses will offer it as a candidate, reach it — through that tunnel,
    /// which works — and conclude it has found a path. It has found a loop: the
    /// session it would carry is the only thing that can serve it, so nothing
    /// crosses until a timeout takes it away. This was measured, not imagined:
    /// a path from this device's overlay address to the peer's was selected
    /// every sixty seconds and abandoned fifteen seconds later, each time.
    ///
    /// Told rather than worked out, because only the caller knows: the addresses
    /// of a tunnel adapter look exactly like any other address of the machine,
    /// and a transport guessing at ranges would be guessing at a signed network
    /// parameter it has no business reading.
    ///
    /// Replaces what was said before, so a tunnel going down takes its range
    /// with it. The default ignores them, which is right for an implementation
    /// with no notion of an address — and means a transport that is never told
    /// refuses nothing on this ground.
    fn avoid(&self, _ranges: &[Range]) {}

    /// Whether the session with `peer` is carried on a direct path or through a
    /// relay, as the connection stands now.
    ///
    /// `None` when there is no session with `peer`, or when the implementation
    /// has no notion of a path — which is the default, and right for the
    /// in-memory implementations. A caller shows nothing for `None` rather than
    /// guessing.
    async fn path_to(&self, _peer: &DeviceId) -> Option<Path> {
        None
    }
}

/// How a session's bytes travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// Straight to the peer's address.
    Direct,
    /// Through the relay the network names.
    Relay,
}

/// An authenticated channel with exactly one device.
///
/// The peer is fixed when the session is established and never changes, so every
/// byte received is attributable to that device and no other.
#[async_trait]
pub trait Session: Send + Sync {
    /// The device this session belongs to.
    ///
    /// Synchronous and infallible: the identity was settled at establishment, so
    /// asking for it can neither fail nor wait.
    fn peer(&self) -> DeviceId;

    /// Sends a payload.
    ///
    /// Payload boundaries are preserved: what is sent as one payload arrives as
    /// one payload. A payload larger than [`crate::limits::MAX_PAYLOAD`] is
    /// refused here rather than truncated, because a truncated payload becomes a
    /// decoding failure at the far end, blamed on the sender, and diagnosed
    /// nowhere near where it went wrong.
    async fn send(&self, payload: &[u8]) -> Result<()>;

    /// Receives the next payload.
    ///
    /// Reports the close rather than waiting forever once the session has ended,
    /// distinguishing a peer that hung up from one the network expelled.
    async fn recv(&self) -> Result<Vec<u8>>;

    /// Sends a packet, best effort.
    ///
    /// Carried apart from payloads: a packet never waits for a payload or for
    /// another packet, and may be lost or arrive out of order. What arrives is a
    /// whole packet that was sent, never a part of one. For bytes that recover
    /// their own losses — tunnel traffic — and not for anything that needs order
    /// or delivery.
    ///
    /// A packet larger than [`crate::limits::MAX_PACKET`] is refused whole. A
    /// packet the path cannot take right now may be dropped with success, as a
    /// network would drop it.
    async fn send_packet(&self, packet: &[u8]) -> Result<()>;

    /// Receives the next packet.
    ///
    /// Reports the close rather than waiting forever once the session has ended.
    async fn recv_packet(&self) -> Result<Vec<u8>>;

    /// Closes the session.
    ///
    /// Closing an already-closed session is not an error: a caller tidying up
    /// should not have to track whether the far end got there first.
    async fn close(&self) -> Result<()>;
}

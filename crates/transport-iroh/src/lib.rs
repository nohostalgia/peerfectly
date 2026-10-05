//! The iroh binding: the transport interface over a real network.
//!
//! Six earlier changes built a network that could not reach anything. This one
//! connects it, and it is the first code in the workspace that touches a socket.
//!
//! # It is gated, and the gate is not a formality
//!
//! `DESIGN.md` §0 forbids merging network code without a test against a
//! real-world NAT edge case. DESIGN.md §10.4 explains why: the measurement it
//! asks for — the fraction of connections that go direct rather than through the
//! relay — can invalidate the architecture. *If real networks almost never let a
//! direct path through, the whole plan changes.* A container matrix cannot answer that, because a
//! percentage measured across topologies someone chose is a percentage of that
//! person's assumptions. See `README.md`.
//!
//! # What makes this small
//!
//! **A transport key is an endpoint identity.** DESIGN.md §2.3 fixes device
//! transport keys as ed25519, which is what iroh identifies endpoints by. So a
//! roster transport key *is* an endpoint id, and dialling by key needs no lookup
//! table — no second answer to "who is this peer", maintained outside the signed
//! log and able to disagree with it.
//!
//! **Possession is already proven when a connection arrives.** The QUIC
//! handshake establishes that the peer holds the private half of the identity it
//! presents, and establishes it *bound to that channel*. The in-memory
//! transports sign a nonce because they have no channel to bind to; a
//! challenge-and-signature exchange carried inside an already-established
//! channel would prove strictly less and cost a round trip. What remains is
//! membership, and that is the roster's, exactly as everywhere else.
//!
//! # No third-party infrastructure
//!
//! The endpoint is built from the connectivity layer's `Minimal` preset rather
//! than its own defaults, which would bring third-party relay servers and a
//! third-party address lookup. §2.8 requires a self-hosted relay; §2.6c requires
//! that a node speak to no infrastructure the user did not choose. The relay
//! address comes from the signed network parameters and nowhere else.
//!
//! # Deliberately elsewhere
//!
//! - Operating the relay — provisioning, TLS, per-key bandwidth and session
//!   limits — is deployment work, not this crate. §2.8 is explicit that the
//!   relay is `iroh-relay`, self-hosted, and that nobody should write their own.
//! - Finding *where* a peer is when it is not already known: `rendezvous-service`
//!   for the signed-record path, `local-discovery` for multicast on a LAN.
//! - Packet-level source validation at the TUN interface — `tunnel`.
//! - Deciding when to connect, to whom, and how often — `windows-daemon`.

pub mod enrolment;
pub mod error;
pub mod fragment;
pub mod node;
pub mod paths;
pub(crate) mod relays;
pub mod session;

pub use error::{BuildError, Result};
pub use node::{ALPN, IrohTransport};
pub use session::{IrohSession, SessionHandle};

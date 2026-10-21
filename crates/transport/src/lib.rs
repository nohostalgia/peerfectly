//! The interface a connectivity layer must satisfy, and what a session means.
//!
//! Four changes built a roster that decides which keys belong to a network, and
//! an identity that gives a node its keys. This turns "this peer holds a key the
//! roster knows" into a channel you can send bytes over — and refuses to, when
//! it does not.
//!
//! # Held behind an interface on purpose
//!
//! DESIGN.md §2.1 requires the transport to sit behind an interface of about four
//! methods so replacing it does not touch the rest. [`Transport`] and
//! [`Session`] are that interface. An interface with one implementation is an
//! untested claim, so this crate ships two and runs one behavioural suite
//! against both.
//!
//! **No network code is here.** `DESIGN.md` §0 forbids merging network code
//! without a test against a real-world NAT edge case, and that test cannot run
//! in CI. The binding is `transport-convesso`, which carries that obligation and
//! runs this suite, so its job is connectivity rather than semantics.
//!
//! # What a session proves, and what it does not
//!
//! A session proves its peer holds a transport key that the roster state this
//! node derived names, and that the device is not revoked. It says nothing about
//! what that device may *do*: roles, admin rights and founder status are derived
//! state, and asking the transport about them would make it a second authority.
//!
//! It also promises **no confidentiality**. `transport-convesso` gets that from
//! Noise; the in-memory one has no wire to protect.
//!
//! # Deliberately elsewhere
//!
//! - **The binding to the real network**, with path selection (§2.9) —
//!   `transport-convesso`.
//! - **§4.7's operation gossip**, and the per-peer quota on the roster's pending
//!   set that `roster`'s `FORMAT.md` §19 records as this capability's debt —
//!   `roster-sync`, which runs over these sessions. Bounding that set fairly
//!   needs the authenticated peer identity established here, which is why it
//!   could not have been done sooner.
//! - **Packet-level source validation** (§2.5: a packet whose source does not
//!   match the session key's hash is dropped) — `tunnel`, at the TUN interface.
//!   This crate establishes the session-level equivalent that makes it
//!   meaningful.

pub mod auth;
pub mod direct;
pub mod error;
pub mod fragment;
pub mod limits;
pub mod memory;
pub mod range;
pub mod session;
pub mod suite;

pub use direct::{DirectFabric, DirectTransport};
pub use error::{Error, Result};
pub use memory::{MemoryFabric, MemoryTransport};
pub use range::Range;
pub use session::{Path, Session, Transport};

// The types a caller needs on the ordinary path.
pub use roster::id::DeviceId;
pub use roster::sign::PublicKey;
pub use roster::state::RosterState;

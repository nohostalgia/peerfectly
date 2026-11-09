//! The byte-level contract of the roster: the signed operation log that decides
//! which keys belong to a network and what authority they hold.
//!
//! This crate handles one operation at a time, in isolation. It defines the
//! seven operation types, their canonical CBOR encoding and strict decoding,
//! content-addressed identifiers, and the domain-separated signature envelope.
//! It has no networking, no async runtime, and no dependency on the transport.
//!
//! # Two layers, and the boundary between them
//!
//! [`state::derive`] is a free function of a [`dag::Dag`]: the roster is a pure
//! function of the operation set, with no access to configuration, no clock, and
//! no knowledge of what arrived when. [`roster::Roster`] wraps that graph and
//! owns everything local — the pending set, and the staleness filter that
//! refuses operations anchored too far behind what this node already knows.
//!
//! **Do not move the staleness check inside derivation.** The two read like the
//! same concern and are not. Two nodes may legitimately disagree about whether
//! to *admit* an operation, because they know different things; they must never
//! disagree about the *roster* a set of operations implies. A policy knob that
//! could reach derivation would make identical operation sets produce different
//! households, order-dependently — a consensus split dressed as configuration.
//! `derive` takes the graph and not the node so that the mistake does not
//! compile.
//!
//! # Authentic is not authorized
//!
//! The type names invite the wrong reading. [`sign::VerifiedOperation`] means
//! *this signature was produced by the holder of this key over exactly these
//! bytes*. It does **not** mean the key was allowed to author the operation.
//! Authority is a property of the state implied by an operation's causal
//! ancestors, and [`state::derive`] is what decides it.
//!
//! # Snapshots sit outside the graph
//!
//! [`snapshot::Snapshot`] — a root — is an admin's signed statement, not a tenth
//! operation type: it never enters the DAG, is never a parent, and never
//! merges. A node may discard what a snapshot covers, but only under the three
//! gates in [`roster::Roster::compact`], and only after verifying the snapshot
//! by deriving it. Compaction discards whole operations — never a skeleton of
//! unsigned parent links — so that every byte a node retains stays covered by
//! some signature.
//!
//! **A node bootstrapping from a snapshot it cannot verify trusts the signing
//! admin alone.** That is an accepted limit, not a mitigated one; it is
//! detected on the first sync with a peer holding the underlying operations.
//! See `FORMAT.md` §24.
//!
//! # What this crate still does not do
//!
//! Equivocation detection, key custody, and all transport. It also cannot bound
//! its pending set fairly: doing that needs per-peer accounting, and peer
//! identity is authenticated by the transport. See `FORMAT.md` §19.
//!
//! The `MAX_OPERATIONS` ceiling bounds the window, not the history: each
//! compaction moves the base forward, so a network that keeps publishing roots
//! stays under it. See `FORMAT.md` §30.
//!
//! # Why the strictness
//!
//! Every rule here exists because two implementations that disagree about which
//! bytes are valid do not produce a parsing bug — they produce two different
//! histories that can silently drop a revocation. So:
//!
//! * one logical value has exactly one encoding, and the decoder rejects every
//!   other spelling rather than repairing it;
//! * signatures are verified over the bytes as received, never over a
//!   re-encoding;
//! * an operation this build cannot parse is an error, never something to skip,
//!   because the thing skipped might be a revocation;
//! * nothing is optional, so an absent field is never read as a default.
//!
//! The wire format is specified in `FORMAT.md`, and the shared test-vector
//! corpus in `vectors/` is what holds independent implementations to it.
//!
//! # Example
//!
//! ```
//! use roster::id::{NetworkId, OperationId};
//! use roster::sign::{sign_operation, Ed25519Signer, RawOperation, Signer};
//! use roster::types::{
//!     Algorithm, Capability, DeviceSpec, KeyEntry, KeyPurpose, OperationBody,
//!     OperationCore, Role,
//! };
//!
//! let signer = Ed25519Signer::from_seed([7u8; 32]);
//! let device_key = KeyEntry::new(
//!     Algorithm::Ed25519,
//!     KeyPurpose::Signing,
//!     signer.public_key().as_bytes().to_vec(),
//! )?;
//! // Every device carries a key that dates the roster, and it is never the
//! // key that signs: that one asks a person, and dating a roster must not.
//! let attestation_key = KeyEntry::new(
//!     Algorithm::Ed25519,
//!     KeyPurpose::Attestation,
//!     Ed25519Signer::from_seed([8u8; 32]).public_key().as_bytes().to_vec(),
//! )?;
//! let mut keys = vec![device_key, attestation_key];
//! keys.sort_by_key(KeyEntry::order_key);
//! let device = DeviceSpec::new(
//!     keys,
//!     "laptop",
//!     Role::Member,
//!     false,
//!     vec![Capability::new("serves")?],
//! )?;
//!
//! let core = OperationCore::new(
//!     1_735_689_600_000,
//!     Algorithm::Ed25519,
//!     OperationBody::AddDevice(device),
//!     vec![],
//!     signer.key_id(),
//!     NetworkId::from_bytes([0x11; 32]),
//! )?;
//!
//! let bytes = sign_operation(&core, &signer)?;
//! let raw = RawOperation::decode(&bytes)?;
//!
//! // The decoded operation carries the bytes that arrived, not a re-encoding.
//! assert_eq!(raw.to_bytes(), bytes);
//!
//! // Verification proves authenticity. It says nothing about authority.
//! let verified = raw.verify(&signer.public_key())?;
//! assert_eq!(verified.id(), core.id());
//! # Ok::<(), roster::Error>(())
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

/// The part of `std`'s prelude that comes from `alloc`, named where a module
/// needs it, so a module reads the same with `std` and without.
mod prelude {
    pub(crate) use alloc::borrow::ToOwned;
    pub(crate) use alloc::boxed::Box;
    pub(crate) use alloc::string::String;
    pub(crate) use alloc::vec;
    pub(crate) use alloc::vec::Vec;
}

/// The shared pointer: `std`'s where there is `std`. Without it, on any
/// microcontroller, `portable-atomic-util`'s, whose counts are native atomics
/// where the chip has them and a critical section where it has none. It does
/// not turn an `Arc<T>` into an `Arc<dyn Trait>` by itself on stable Rust, so
/// the crate makes those through a `Box`.
pub mod sync {
    #[cfg(feature = "std")]
    pub use alloc::sync::Arc;
    #[cfg(not(feature = "std"))]
    pub use portable_atomic_util::Arc;
}

/// Hash maps where there is `std`. Without it, ordered maps from `alloc`, which
/// the keys here allow: a microcontroller member holds few.
mod collections {
    #[cfg(not(feature = "std"))]
    pub(crate) use alloc::collections::{BTreeMap as HashMap, BTreeSet as HashSet};
    #[cfg(feature = "std")]
    pub(crate) use std::collections::{HashMap, HashSet};
}

pub mod attestation;
pub mod batch;
pub mod cbor;
pub mod dag;
pub mod error;
pub mod hex;
pub mod id;
pub mod leaf;
pub mod light;
pub mod limits;
pub mod member;
pub mod members;
pub mod membership;
pub mod merkle;
pub mod parameters;
pub mod params;
pub mod roster;
pub mod sign;
pub mod snapshot;
pub mod state;
pub mod transfer;
pub mod types;

pub use error::{Error, Result};

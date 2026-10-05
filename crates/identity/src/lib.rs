//! Node identity: how a node obtains, holds and uses the keys that make it a
//! device.
//!
//! A node needs an identity before a roster can hold it. This crate generates
//! one from system entropy, keeps the signing key and the transport key apart,
//! derives the device a roster will recognise, and stores the private material
//! with owner-only access.
//!
//! # The `roster` crate is not disturbed
//!
//! Identity depends on `roster`; roster never depends on identity. That keeps
//! roster's audited dependency list — no networking, no async runtime, no
//! `iroh` — exactly as it is, while this crate is free to touch the filesystem
//! and, later, a platform keystore.
//!
//! The types a caller needs from roster are re-exported here, so an ordinary
//! daemon depends on one crate rather than two.
//!
//! # Signing twice over
//!
//! [`roster::sign::Signer`] is synchronous, which suits a key this process
//! holds. It does not suit a key in a phone's secure enclave: the private
//! material is unreachable from here by design, and a biometric prompt is not
//! synchronous. So there is a second path — see [`detached`] — where this crate
//! produces the exact bytes to be signed, someone else signs them, and the
//! artifact is assembled from the result.
//!
//! ```
//! use identity::{NodeIdentity, Role};
//!
//! let node = NodeIdentity::generate()?;
//! let spec = node.device_spec("laptop", Role::Member, false, vec![])?;
//!
//! // The device a node presents is built from the keys it actually holds.
//! assert_eq!(spec.device_id()?, node.device_id());
//! # Ok::<(), identity::Error>(())
//! ```

pub mod detached;
pub mod encodings;
pub mod error;
pub mod identity;
pub mod passphrase;
pub mod seal;
pub mod secret;
pub mod store;

pub use error::{Error, Result};
pub use identity::{CustodianKey, NodeIdentity, PrivateKey, SigningKey, fresh_key_name};
pub use secret::SecretBytes;

// The roster types a caller needs on the ordinary path, so a daemon depends on
// this crate alone rather than on both.
pub use roster::id::{DeviceId, KeyId, NetworkId, OperationId};
pub use roster::sign::{PublicKey, Signer};
pub use roster::types::{Algorithm, Capability, DeviceSpec, KeyEntry, KeyPurpose, Role};

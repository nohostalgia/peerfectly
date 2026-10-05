//! Content-addressed identifiers.
//!
//! Every identifier in this format is an untruncated 256-bit BLAKE3 digest.
//! None of them is ever a signature, and none is ever shortened.
//!
//! Not truncating matters more than it looks. An operation id is what fixes
//! that operation's position in the DAG, so a collision is not a lookup
//! nuisance — it is two different histories that later merge into one.
//!
//! Excluding the signature matters just as much. ECDSA is not required to be
//! deterministic: this crate's software P-256 signer derives its nonce per
//! RFC 6979 and is reproducible, but the root key that matters lives in a
//! phone's secure enclave, which signs with a random nonce. If the signature
//! were part of the hashed bytes, the same revocation signed twice would enter
//! the DAG as two unrelated operations. The id therefore covers the core and
//! nothing else.

use crate::cbor::{Reader, Writer};
use crate::error::Result;
use crate::limits::ID_LEN;

/// Declares a 32-byte content-addressed identifier newtype.
///
/// The types are distinct so that a key id cannot be passed where a device id
/// is meant. They are all the same shape, and all derived the same way.
macro_rules! digest_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; ID_LEN]);

        impl $name {
            /// Wraps raw digest bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
                Self(bytes)
            }

            /// The digest bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
                &self.0
            }

            /// Lowercase hex, for logs, vectors, and anything a person reads.
            #[must_use]
            pub fn to_hex(&self) -> String {
                use core::fmt::Write as _;
                let mut out = String::with_capacity(ID_LEN.saturating_mul(2));
                for byte in &self.0 {
                    let _ = write!(out, "{byte:02x}");
                }
                out
            }

            /// Parses lowercase hex back into an identifier.
            ///
            /// Used by the vector corpus, which stores every byte string as
            /// hex so a person can read it.
            pub fn from_hex(text: &str) -> Option<Self> {
                let raw = crate::hex::decode(text)?;
                let bytes: [u8; ID_LEN] = raw.try_into().ok()?;
                Some(Self(bytes))
            }

            /// Writes the identifier as a fixed-width byte string.
            pub(crate) fn encode(&self, writer: &mut Writer) {
                writer.bytes(&self.0);
            }

            /// Reads a fixed-width identifier, rejecting any other length.
            pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self> {
                let raw = reader.fixed_bytes(ID_LEN)?;
                let mut bytes = [0u8; ID_LEN];
                bytes.copy_from_slice(raw);
                Ok(Self(bytes))
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.to_hex())
            }
        }
    };
}

digest_newtype! {
    /// Identifies one operation: BLAKE3 over its canonical core bytes.
    ///
    /// The core excludes both `id` and `sig`, so this is stable across
    /// re-signings of the same content.
    OperationId
}

digest_newtype! {
    /// Identifies one public key: BLAKE3 over the key's value bytes.
    ///
    /// An operation's `author` is a key id, not a device id. The two coincide
    /// for a device holding a single signing key, and differ for a device that
    /// also holds an enclave key. Resolving a key id to the device that owns
    /// it needs the derived roster state, which this crate does not build.
    KeyId
}

digest_newtype! {
    /// Identifies one device: the key id of its identifying signing key.
    ///
    /// A device's key set is fixed when it is added — none of the seven
    /// operations adds a key to an existing device — so this is stable for the
    /// device's lifetime.
    DeviceId
}

digest_newtype! {
    /// Identifies one network.
    ///
    /// Carried in every operation and in every signing input, so a signature
    /// valid in one network cannot be replayed into another.
    NetworkId
}

/// Hashes bytes to a 32-byte digest.
#[must_use]
pub(crate) fn digest(bytes: &[u8]) -> [u8; ID_LEN] {
    *blake3::hash(bytes).as_bytes()
}

impl OperationId {
    /// Derives an operation id from its canonical core bytes.
    #[must_use]
    pub fn of_core(core_bytes: &[u8]) -> Self {
        Self::from_bytes(digest(core_bytes))
    }
}

impl KeyId {
    /// Derives a key id from a public key's value bytes.
    #[must_use]
    pub fn of_public_key(value: &[u8]) -> Self {
        Self::from_bytes(digest(value))
    }
}

impl DeviceId {
    /// Derives a device id from its identifying signing key.
    #[must_use]
    pub fn of_signing_key(value: &[u8]) -> Self {
        Self::from_bytes(digest(value))
    }

    /// The same digest read as a key id.
    #[must_use]
    pub const fn as_key_id(&self) -> KeyId {
        KeyId::from_bytes(*self.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn digests_are_full_width() {
        let id = OperationId::of_core(b"anything");
        assert_eq!(id.as_bytes().len(), 32, "identifiers are never truncated");
        assert_eq!(id.to_hex().len(), 64);
    }

    #[test]
    fn digest_matches_blake3() {
        let id = KeyId::of_public_key(b"key material");
        assert_eq!(id.as_bytes(), blake3::hash(b"key material").as_bytes());
    }

    #[test]
    fn hex_is_lowercase_and_padded() {
        let id = DeviceId::from_bytes([0x0a; 32]);
        assert_eq!(id.to_hex(), "0a".repeat(32));
    }

    #[test]
    fn identifier_round_trips() {
        let id = OperationId::from_bytes([7u8; 32]);
        let mut w = Writer::new();
        id.encode(&mut w);
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        assert_eq!(OperationId::decode(&mut r), Ok(id));
        assert_eq!(r.finish(), Ok(()));
    }

    /// A 128-bit id is not a short id, it is a different thing. Accepting it
    /// would let two operations share a prefix and therefore a position.
    #[test]
    fn truncated_identifier_is_rejected() {
        let mut w = Writer::new();
        w.bytes(&[0u8; 16]);
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        assert_eq!(OperationId::decode(&mut r), Err(Error::IdentifierLength));
    }
}

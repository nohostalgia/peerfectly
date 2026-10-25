//! Sealing under a key that a piece of hardware wraps.
//!
//! The transport and attestation keys have to be in memory while the daemon
//! runs — sessions are Noise over Curve25519, which no TPM computes — so the
//! hardware cannot hold them. What it can do is hold the key they are
//! encrypted under: the file on disk is ChaCha20-Poly1305 under a fresh key,
//! and that key is wrapped by the hardware, which unwraps it only on this
//! machine. A copy of the disk is then not the keys.
//!
//! Bytes sealed some other way before — DPAPI, or a Unix file mode — are still
//! opened, by the sealer that wrote them: refusing them would lose every
//! identity on the machine, and reading them gives nothing an attacker could
//! not already have taken from the same file.
//!
//! # Layout
//!
//! `MAGIC ‖ u32be(len(wrapped)) ‖ wrapped ‖ nonce(12) ‖ ciphertext`, with the
//! magic as the AEAD's associated data.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
pub use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::store::Sealer;

/// What begins bytes sealed here, and is authenticated with them.
const MAGIC: &[u8] = b"peerfectly wrapped v1\0";

/// ChaCha20-Poly1305's nonce.
const NONCE_LEN: usize = 12;

/// Hardware that wraps and unwraps a 32-byte key.
pub trait KeyWrap: Send + Sync {
    /// Wraps `key` so that only this hardware unwraps it.
    ///
    /// # Errors
    ///
    /// When the hardware will not.
    fn wrap(&self, key: &[u8; 32]) -> Result<Vec<u8>>;

    /// Reverses [`Self::wrap`].
    ///
    /// # Errors
    ///
    /// When the hardware will not, which is what a copy taken elsewhere meets.
    fn unwrap(&self, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>>;
}

/// A sealer whose key the hardware wraps, opening what `earlier` sealed before.
pub struct WrappedSealer<W> {
    wrap: W,
    earlier: Box<dyn Sealer>,
}

impl<W: KeyWrap> WrappedSealer<W> {
    /// Seals with `wrap`, and opens bytes `earlier` sealed.
    #[must_use]
    pub fn new(wrap: W, earlier: Box<dyn Sealer>) -> Self {
        Self { wrap, earlier }
    }
}

impl<W: KeyWrap> Sealer for WrappedSealer<W> {
    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>> {
        let mut key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(key.as_mut()).map_err(|_| Error::NoEntropy)?;
        let mut nonce = [0_u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| Error::NoEntropy)?;
        let wrapped = self.wrap.wrap(&key)?;
        let length = u32::try_from(wrapped.len())
            .map_err(|_| Error::Storage { detail: "the wrapped key is too long".to_owned() })?;
        let sealed = ChaCha20Poly1305::new(&(*key).into())
            .encrypt(&nonce.into(), Payload { msg: plain, aad: MAGIC })
            .map_err(|_| Error::Storage {
                detail: "the material could not be encrypted".to_owned(),
            })?;
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&wrapped);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    fn unseal(&self, stored: &[u8]) -> Result<Vec<u8>> {
        let Some(rest) = stored.strip_prefix(MAGIC) else {
            return self.earlier.unseal(stored);
        };
        let (length, rest) = rest.split_first_chunk::<4>().ok_or(Error::CorruptIdentity)?;
        let length =
            usize::try_from(u32::from_be_bytes(*length)).map_err(|_| Error::CorruptIdentity)?;
        let (wrapped, rest) = rest.split_at_checked(length).ok_or(Error::CorruptIdentity)?;
        let (nonce, sealed) =
            rest.split_first_chunk::<NONCE_LEN>().ok_or(Error::CorruptIdentity)?;
        let key = self.wrap.unwrap(wrapped)?;
        ChaCha20Poly1305::new(&(*key).into())
            .decrypt(&(*nonce).into(), Payload { msg: sealed, aad: MAGIC })
            .map_err(|_| Error::CorruptIdentity)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "a test reports failure by panicking"
    )]

    use super::*;

    /// A chip in a test: wraps by XOR with its own secret.
    struct Chip([u8; 32]);

    impl KeyWrap for Chip {
        fn wrap(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
            Ok(key.iter().zip(self.0).map(|(k, s)| k ^ s).collect())
        }

        fn unwrap(&self, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
            let mut out = Zeroizing::new([0_u8; 32]);
            if wrapped.len() != 32 {
                return Err(Error::CorruptIdentity);
            }
            for (index, byte) in wrapped.iter().enumerate() {
                out[index] = byte ^ self.0[index];
            }
            Ok(out)
        }
    }

    /// What a Unix file mode does: nothing to the bytes.
    struct Plain;

    impl Sealer for Plain {
        fn seal(&self, plain: &[u8]) -> Result<Vec<u8>> {
            Ok(plain.to_vec())
        }

        fn unseal(&self, stored: &[u8]) -> Result<Vec<u8>> {
            Ok(stored.to_vec())
        }
    }

    #[test]
    fn sealed_material_opens_only_on_the_chip_that_wrapped_it() {
        let ours = WrappedSealer::new(Chip([7; 32]), Box::new(Plain));
        let stored = ours.seal(b"the transport key").unwrap();
        assert!(!stored.windows(17).any(|window| window == b"the transport key"), "not in clear");
        assert_eq!(ours.unseal(&stored).unwrap(), b"the transport key");

        let elsewhere = WrappedSealer::new(Chip([9; 32]), Box::new(Plain));
        assert!(elsewhere.unseal(&stored).is_err(), "a copy on another machine");

        let mut altered = stored.clone();
        let last = altered.len() - 1;
        altered[last] ^= 1;
        assert!(ours.unseal(&altered).is_err(), "an altered file");
    }

    #[test]
    fn what_was_sealed_before_still_opens() {
        let ours = WrappedSealer::new(Chip([7; 32]), Box::new(Plain));
        assert_eq!(ours.unseal(b"written before").unwrap(), b"written before");
    }
}

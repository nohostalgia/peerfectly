//! A signing key sealed with a passphrase, for a machine with no key store able
//! to hold one.
//!
//! # What it defends against, and what it does not
//!
//! **Weaker than a key store, and said so.** Whoever obtains the stored bytes —
//! root on the machine, a backup, a disk — can try passphrases on hardware of
//! their own choosing for as long as they like. Nothing limits the attempts, and
//! the passphrase is the whole of what stands in the way. A TPM that locks out
//! after a few wrong guesses, or a key store that never releases the key, does
//! not have that weakness; this is what a machine without either can still do.
//!
//! What it does defend against: the file taken alone is not the key, and nothing
//! on the machine can sign without the person typing the passphrase — this
//! program included.
//!
//! # The shape
//!
//! Canonical CBOR, like every other stored thing in this crate:
//!
//! ```text
//! [ version, [memory KiB, passes, lanes], salt(16), nonce(12),
//!   [algorithm tag, public key], sealed ]
//! ```
//!
//! The passphrase is stretched with **Argon2id** under a fresh salt, and the key
//! is encrypted with **ChaCha20-Poly1305** under the result. **Every byte before
//! `sealed` is the authenticated data**, behind a domain string: the public half
//! and the parameters cannot be changed without the passphrase being needed to
//! notice, and the parameters a file names are checked — floor and ceiling —
//! before anything is derived.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use minicbor::{Decoder, Encoder};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::identity::PrivateKey;
use roster::sign::PublicKey;
use roster::types::Algorithm;

/// The only version this build writes and reads.
const VERSION: u64 = 1;

/// What the authenticated data begins with, so that nothing sealed for another
/// purpose can be taken for this.
const DOMAIN: &[u8] = b"peerfectly sealed signing key v1";

/// The salt's length: the length Argon2's own guidance asks for.
const SALT_LEN: usize = 16;

/// ChaCha20-Poly1305's nonce.
const NONCE_LEN: usize = 12;

/// How hard the passphrase is stretched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stretch {
    /// Memory, in KiB.
    pub memory_kib: u32,
    /// Passes over that memory.
    pub passes: u32,
    /// Lanes.
    pub lanes: u32,
}

impl Stretch {
    /// What a key is sealed with: 64 MiB and three passes.
    ///
    /// A key is opened once per act a person signs, so the cost is paid by a
    /// person waiting a moment, and by an attacker on every guess.
    pub const SEALING: Self = Self { memory_kib: 64 * 1_024, passes: 3, lanes: 1 };

    /// The least a stored key may name: OWASP's floor for Argon2id.
    ///
    /// Below it a file is refused **before deriving**, because the parameters
    /// travel with the file, and a file whose parameters were lowered is a file
    /// somebody is making cheaper to attack.
    pub const FLOOR: Self = Self { memory_kib: 19 * 1_024, passes: 2, lanes: 1 };

    /// The most a stored key may name: 1 GiB, sixteen passes, eight lanes.
    ///
    /// Above it a file is refused before deriving too. A file naming a
    /// terabyte would otherwise be a way to make whoever opens it try to
    /// allocate one.
    pub const CEILING: Self = Self { memory_kib: 1_024 * 1_024, passes: 16, lanes: 8 };

    /// Whether these parameters lie between the floor and the ceiling.
    #[must_use]
    pub const fn acceptable(&self) -> bool {
        self.memory_kib >= Self::FLOOR.memory_kib
            && self.passes >= Self::FLOOR.passes
            && self.lanes >= Self::FLOOR.lanes
            && self.memory_kib <= Self::CEILING.memory_kib
            && self.passes <= Self::CEILING.passes
            && self.lanes <= Self::CEILING.lanes
    }
}

/// Seals a signing key with a passphrase, stretched as [`Stretch::SEALING`].
///
/// # Errors
///
/// When the system has no randomness to give, or the stretching fails.
pub fn seal(key: &PrivateKey, passphrase: &[u8]) -> Result<Vec<u8>> {
    seal_with(key, passphrase, Stretch::SEALING)
}

/// The same, stretched as asked.
///
/// # Errors
///
/// When the parameters are outside what [`open`] accepts — sealing something
/// that could never be opened is refused here rather than discovered later —
/// when the system has no randomness, or when the stretching fails.
pub fn seal_with(key: &PrivateKey, passphrase: &[u8], stretch: Stretch) -> Result<Vec<u8>> {
    if !stretch.acceptable() {
        return Err(Error::UnacceptableStretch);
    }
    let mut salt = [0_u8; SALT_LEN];
    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_| Error::NoEntropy)?;
    getrandom::fill(&mut nonce).map_err(|_| Error::NoEntropy)?;

    let mut out = Vec::new();
    let mut encoder = Encoder::new(&mut out);
    let _ = encoder.array(6);
    let _ = encoder.u64(VERSION);
    let _ = encoder.array(3);
    let _ = encoder.u32(stretch.memory_kib);
    let _ = encoder.u32(stretch.passes);
    let _ = encoder.u32(stretch.lanes);
    let _ = encoder.bytes(&salt);
    let _ = encoder.bytes(&nonce);
    let _ = encoder.array(2);
    let _ = encoder.u8(algorithm_tag(key.algorithm()));
    let _ = encoder.bytes(key.public_key().as_bytes());
    // Everything so far is the header, and the header is what is authenticated.

    let derived = stretched(passphrase, &salt, stretch)?;
    let sealed = cipher(&derived)
        .encrypt(&nonce.into(), Payload { msg: key.material().expose(), aad: &authenticated(&out) })
        .map_err(|_| Error::CorruptIdentity)?;
    let _ = Encoder::new(&mut out).bytes(&sealed);
    Ok(out)
}

/// The public half a sealed key declares, read without the passphrase.
///
/// **What the file says, not what the passphrase proves.** It is bound into the
/// sealing, so a file whose public half was changed will not open — but that is
/// learned only by opening it. Whoever reads it here without the passphrase is
/// trusting where the file is kept.
///
/// # Errors
///
/// When the bytes are not a sealed key this build reads.
pub fn public_of(stored: &[u8]) -> Result<PublicKey> {
    Ok(read(stored)?.public)
}

/// Opens a sealed key with its passphrase.
///
/// # Errors
///
/// - [`Error::UnacceptableStretch`] when the file names parameters outside the
///   floor and the ceiling, before anything is derived;
/// - [`Error::WrongPassphraseOrAltered`] when the passphrase is wrong **or** the
///   bytes were changed: an authenticated cipher cannot tell the two apart, and
///   naming only one would be a guess;
/// - [`Error::CorruptIdentity`] and [`Error::UnknownStoredVersion`] when the
///   bytes are not a sealed key this build reads.
pub fn open(stored: &[u8], passphrase: &[u8]) -> Result<PrivateKey> {
    let read = read(stored)?;
    if !read.stretch.acceptable() {
        return Err(Error::UnacceptableStretch);
    }
    let derived = stretched(passphrase, &read.salt, read.stretch)?;
    let plain = Zeroizing::new(
        cipher(&derived)
            .decrypt(
                &read.nonce.into(),
                Payload { msg: read.sealed, aad: &authenticated(read.header) },
            )
            .map_err(|_| Error::WrongPassphraseOrAltered)?,
    );
    let material: [u8; 32] =
        plain.as_slice().try_into().map_err(|_| Error::WrongPassphraseOrAltered)?;
    let material = Zeroizing::new(material);
    let key = PrivateKey::from_material(read.public.algorithm(), *material)?;
    // Authenticated, so this cannot differ unless the file was sealed wrongly
    // to begin with. Checked anyway: a key that opens as something other than
    // what it declared is not the key this file is about.
    if key.public_key() != read.public {
        return Err(Error::WrongPassphraseOrAltered);
    }
    Ok(key)
}

/// A sealed key, read but not opened.
struct Read<'a> {
    /// Every byte before `sealed`.
    header: &'a [u8],
    stretch: Stretch,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    public: PublicKey,
    sealed: &'a [u8],
}

/// Reads the shape, and nothing more.
fn read(stored: &[u8]) -> Result<Read<'_>> {
    let corrupt = |_| Error::CorruptIdentity;
    let mut decoder = Decoder::new(stored);
    if decoder.array().map_err(corrupt)? != Some(6) {
        return Err(Error::CorruptIdentity);
    }
    let version = decoder.u64().map_err(corrupt)?;
    if version != VERSION {
        return Err(Error::UnknownStoredVersion { found: version });
    }
    if decoder.array().map_err(corrupt)? != Some(3) {
        return Err(Error::CorruptIdentity);
    }
    let stretch = Stretch {
        memory_kib: decoder.u32().map_err(corrupt)?,
        passes: decoder.u32().map_err(corrupt)?,
        lanes: decoder.u32().map_err(corrupt)?,
    };
    let salt: [u8; SALT_LEN] =
        decoder.bytes().map_err(corrupt)?.try_into().map_err(|_| Error::CorruptIdentity)?;
    let nonce: [u8; NONCE_LEN] =
        decoder.bytes().map_err(corrupt)?.try_into().map_err(|_| Error::CorruptIdentity)?;
    if decoder.array().map_err(corrupt)? != Some(2) {
        return Err(Error::CorruptIdentity);
    }
    let algorithm = algorithm_from_tag(decoder.u8().map_err(corrupt)?)?;
    let public = PublicKey::new(algorithm, decoder.bytes().map_err(corrupt)?.to_vec())
        .map_err(|_| Error::CorruptIdentity)?;
    let header = stored.get(..decoder.position()).ok_or(Error::CorruptIdentity)?;
    let sealed = decoder.bytes().map_err(corrupt)?;
    if decoder.position() != stored.len() {
        // Trailing bytes mean this is not the file we think it is.
        return Err(Error::CorruptIdentity);
    }
    Ok(Read { header, stretch, salt, nonce, public, sealed })
}

/// The authenticated data: the domain, then the header as stored.
fn authenticated(header: &[u8]) -> Vec<u8> {
    [DOMAIN, header].concat()
}

/// The passphrase, stretched into a key.
fn stretched(passphrase: &[u8], salt: &[u8], stretch: Stretch) -> Result<Zeroizing<[u8; 32]>> {
    let failed = |cause: argon2::Error| Error::Storage { detail: format!("stretching: {cause}") };
    let params = argon2::Params::new(stretch.memory_kib, stretch.passes, stretch.lanes, Some(32))
        .map_err(failed)?;
    let mut derived = Zeroizing::new([0_u8; 32]);
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(passphrase, salt, derived.as_mut_slice())
        .map_err(failed)?;
    Ok(derived)
}

/// The cipher, keyed by what was derived.
fn cipher(derived: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(&(*derived).into())
}

/// The stored tag for an algorithm, as `store` writes it.
const fn algorithm_tag(algorithm: Algorithm) -> u8 {
    match algorithm {
        Algorithm::Ed25519 => 1,
        Algorithm::P256 => 2,
    }
}

/// The algorithm a stored tag names.
const fn algorithm_from_tag(tag: u8) -> Result<Algorithm> {
    match tag {
        1 => Ok(Algorithm::Ed25519),
        2 => Ok(Algorithm::P256),
        _ => Err(Error::CorruptIdentity),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// The cheapest parameters that open: the floor. Tests pay for every
    /// derivation, and the floor is what is being tested anyway.
    const CHEAP: Stretch = Stretch::FLOOR;

    fn key() -> PrivateKey {
        PrivateKey::generate(Algorithm::Ed25519).unwrap()
    }

    #[test]
    fn a_sealed_key_opens_with_its_passphrase() {
        let key = key();
        let stored = seal_with(&key, b"correct horse battery", CHEAP).unwrap();
        let opened = open(&stored, b"correct horse battery").unwrap();
        assert_eq!(key.public_key(), opened.public_key());
        assert_eq!(key.material(), opened.material(), "the same key, and it signs as it did");
        assert_eq!(key.public_key(), public_of(&stored).unwrap(), "declared without opening");
    }

    #[test]
    fn a_p256_key_round_trips_too() {
        let key = PrivateKey::generate(Algorithm::P256).unwrap();
        let stored = seal_with(&key, b"correct horse battery", CHEAP).unwrap();
        assert_eq!(key.public_key(), open(&stored, b"correct horse battery").unwrap().public_key());
    }

    #[test]
    fn a_wrong_passphrase_opens_nothing() {
        let stored = seal_with(&key(), b"correct horse battery", CHEAP).unwrap();
        assert_eq!(Some(Error::WrongPassphraseOrAltered), open(&stored, b"correct horse").err());
    }

    /// The whole file, and each field named: the parameters, the salt, the
    /// nonce, the public half, the sealed bytes.
    #[test]
    fn altering_any_field_opens_nothing() {
        let key = key();
        let stored = seal_with(&key, b"correct horse battery", CHEAP).unwrap();
        let read = read(&stored).unwrap();
        let offset =
            |part: &[u8]| (part.as_ptr() as usize).checked_sub(stored.as_ptr() as usize).unwrap();
        let public_at = offset(read.header)
            .checked_add(read.header.len())
            .unwrap()
            .checked_sub(read.public.as_bytes().len())
            .unwrap();
        let sealed_at = offset(read.sealed);

        // Byte 4 is inside the memory cost; 14 inside the salt; 32 inside the
        // nonce — see the shape in the module header.
        for (field, at) in [
            ("the memory cost", 4),
            ("the salt", 14),
            ("the nonce", 32),
            ("the public half", public_at),
            ("the sealed key", sealed_at),
        ] {
            let mut altered = stored.clone();
            let byte = altered.get_mut(at).unwrap();
            *byte ^= 0x01;
            assert!(
                open(&altered, b"correct horse battery").is_err(),
                "{field} altered, yet it opened"
            );
        }
    }

    #[test]
    fn two_sealings_of_one_key_differ() {
        let key = key();
        let first = seal_with(&key, b"correct horse battery", CHEAP).unwrap();
        let second = seal_with(&key, b"correct horse battery", CHEAP).unwrap();
        assert_ne!(first, second, "each has its own salt and nonce");
        assert_ne!(read(&first).unwrap().salt, read(&second).unwrap().salt);
    }

    /// **Refused before deriving.** Lowered parameters are a file being made
    /// cheaper to attack; raised past the ceiling, a way to make the opener
    /// allocate without bound. Either is refused on reading, and the proof that
    /// nothing was derived is that the wrong passphrase is not what is reported.
    #[test]
    fn parameters_outside_the_bounds_are_refused_without_deriving() {
        let key = key();
        let stored = seal_with(&key, b"correct horse battery", CHEAP).unwrap();
        for stretch in [
            Stretch { memory_kib: 8 * 1_024, ..Stretch::FLOOR },
            Stretch { passes: 1, ..Stretch::FLOOR },
            Stretch { memory_kib: u32::MAX, ..Stretch::FLOOR },
            Stretch { lanes: 64, ..Stretch::FLOOR },
        ] {
            let rewritten = with_stretch(&stored, stretch);
            assert_eq!(
                Some(Error::UnacceptableStretch),
                open(&rewritten, b"not the passphrase").err(),
                "{stretch:?}"
            );
        }
        assert_eq!(
            Some(Error::UnacceptableStretch),
            seal_with(&key, b"x", Stretch { passes: 1, ..CHEAP }).err()
        );
    }

    #[test]
    fn what_is_sealed_is_not_the_key() {
        let key = key();
        let stored = seal_with(&key, b"correct horse battery", CHEAP).unwrap();
        assert!(
            !stored.windows(32).any(|window| window == key.material().expose()),
            "the private material appears nowhere in the stored bytes"
        );
    }

    #[test]
    fn what_is_not_a_sealed_key_is_refused() {
        assert_eq!(Some(Error::CorruptIdentity), open(b"not cbor at all", b"x").err());
        let mut stored = seal_with(&key(), b"correct horse battery", CHEAP).unwrap();
        stored.push(0);
        assert_eq!(Some(Error::CorruptIdentity), open(&stored, b"correct horse battery").err());
    }

    /// The same file with other parameters written in, as an attacker would.
    fn with_stretch(stored: &[u8], stretch: Stretch) -> Vec<u8> {
        let read = read(stored).unwrap();
        let mut out = Vec::new();
        let mut encoder = Encoder::new(&mut out);
        let _ = encoder.array(6);
        let _ = encoder.u64(VERSION);
        let _ = encoder.array(3);
        let _ = encoder.u32(stretch.memory_kib);
        let _ = encoder.u32(stretch.passes);
        let _ = encoder.u32(stretch.lanes);
        let _ = encoder.bytes(&read.salt);
        let _ = encoder.bytes(&read.nonce);
        let _ = encoder.array(2);
        let _ = encoder.u8(algorithm_tag(read.public.algorithm()));
        let _ = encoder.bytes(read.public.as_bytes());
        let _ = encoder.bytes(read.sealed);
        out
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(12))]

        /// **Any byte, any change: nothing opens.** The named fields above are
        /// the cases a reader thinks of; this is the ones they do not.
        #[test]
        fn altering_any_byte_opens_nothing(at in 0_usize..512, flip in 1_u8..=255) {
            let key = PrivateKey::from_material(Algorithm::Ed25519, [7; 32]).unwrap();
            let stored = seal_with(&key, b"correct horse battery", CHEAP).unwrap();
            let at = at.checked_rem(stored.len()).unwrap();
            let mut altered = stored.clone();
            let byte = altered.get_mut(at).unwrap();
            *byte ^= flip;
            proptest::prop_assert!(open(&altered, b"correct horse battery").is_err());
        }
    }
}

//! The signature envelope: domain separation, algorithm dispatch, and the
//! step from received bytes to a verified operation.
//!
//! # Domain separation
//!
//! Every signature covers
//!
//! ```text
//! "roster/v1" || network_id || op_type || canonical_core
//! ```
//!
//! not the core alone. Without the prefix, a signature valid in one context is
//! valid in another: an operation could be lifted from one network into
//! another, or a `demote` re-labelled as a `promote`, with the signature still
//! checking out.
//!
//! The components are variable-length, so they are length-prefixed rather than
//! merely concatenated. Plain concatenation would let a crafted `network_id`
//! borrow bytes from the field after it and produce the same signing input as
//! a different, legitimate tuple. Each component is preceded by its length as
//! a big-endian `u16`, which makes the parse unambiguous.
//!
//! # What verification proves, and what it does not
//!
//! [`RawOperation::verify`] proves that the signature was produced by the
//! holder of a given key over exactly these bytes. It does **not** prove the
//! key had any authority to author the operation. Authority is derived from
//! the DAG — from the state implied by an operation's causal ancestors — and
//! nothing in this crate builds that state. Treat a [`VerifiedOperation`] as
//! authentic, not as authorized.

use crate::cbor::{Reader, Writer};
use crate::error::{Error, Result};
use crate::id::{KeyId, NetworkId, OperationId};
use crate::limits;
use crate::types::{Algorithm, OPERATION_SCHEMA, OperationBody, OperationCore, OperationType};

use alloc_borrow::Cow;

/// Keeps the `Cow` import in one place.
mod alloc_borrow {
    pub(crate) use std::borrow::Cow;
}

/// The version tag every signature is bound to.
///
/// This is the format's version boundary. A change to the encoding is a change
/// to this string, which invalidates every existing signature by construction
/// rather than by convention.
pub const DOMAIN_TAG: &str = "roster/v1";

/// Builds the byte string a signature covers.
///
/// Each variable-length component carries its length so the concatenation
/// cannot be re-parsed as a different tuple of components.
#[must_use]
pub fn signing_input(network: &NetworkId, op_type: OperationType, core_bytes: &[u8]) -> Vec<u8> {
    let tag = DOMAIN_TAG.as_bytes();
    let type_name = op_type.as_str().as_bytes();
    let mut out = Vec::with_capacity(
        tag.len()
            .saturating_add(limits::ID_LEN)
            .saturating_add(type_name.len())
            .saturating_add(core_bytes.len())
            .saturating_add(8),
    );
    push_framed(&mut out, tag);
    push_framed(&mut out, network.as_bytes());
    push_framed(&mut out, type_name);
    push_framed(&mut out, core_bytes);
    out
}

/// Appends a component preceded by its big-endian `u16` length.
///
/// A component longer than `u16::MAX` cannot occur: the tag and the type name
/// are short literals, the network id is 32 bytes, and the core is bounded by
/// [`limits::MAX_OPERATION_SIZE`]. The saturation is a belt-and-braces
/// measure that keeps the function total.
fn push_framed(out: &mut Vec<u8>, component: &[u8]) {
    let len = u16::try_from(component.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(component);
}

// ---------------------------------------------------------------------------
// Keys and signing
// ---------------------------------------------------------------------------

/// A public key that can verify roster signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// The algorithm this key belongs to.
    alg: Algorithm,
    /// The key's encoded bytes.
    value: Vec<u8>,
}

impl PublicKey {
    /// Wraps key bytes, checking them against the algorithm.
    ///
    /// Structural validation happens here rather than at verification time, so
    /// a malformed key is rejected once instead of on every use.
    pub fn new(alg: Algorithm, value: Vec<u8>) -> Result<Self> {
        if value.len() != alg.public_key_len() {
            return Err(Error::InvalidKey);
        }
        match alg {
            Algorithm::Ed25519 => {
                let bytes: [u8; 32] = value.as_slice().try_into().map_err(|_| Error::InvalidKey)?;
                let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                    .map_err(|_| Error::InvalidKey)?;
                // A small-order key never becomes a `PublicKey` at all. Leaving
                // this to verification time would mean such a key could be
                // carried around, compared, and hashed into a device id before
                // anyone noticed it was useless.
                if key.is_weak() {
                    return Err(Error::InvalidKey);
                }
            }
            Algorithm::P256 => {
                // The length check above already restricted this to the
                // 33-byte compressed form. That matters: `from_sec1_bytes`
                // would happily take the 65-byte uncompressed encoding too, and
                // one key with two encodings is one device with two ids.
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&value)
                    .map_err(|_| Error::InvalidKey)?;
            }
        }
        Ok(Self { alg, value })
    }

    /// The algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.alg
    }

    /// The key's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }

    /// This key's id, which is what an operation's `author` names.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        KeyId::of_public_key(&self.value)
    }

    /// Verifies a signature over `message`.
    ///
    /// The match is exhaustive: adding an algorithm without handling it here
    /// fails to compile, which is the point. A missing arm that fell through
    /// to "accept" or "skip" would let an unparseable revocation be treated as
    /// absent.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != limits::SIGNATURE_LEN {
            return Err(Error::SignatureEncoding);
        }
        match self.alg {
            Algorithm::Ed25519 => self.verify_ed25519(message, signature),
            Algorithm::P256 => self.verify_p256(message, signature),
        }
    }

    /// Ed25519 under the strict profile: small-order public keys and
    /// small-order `R` rejected, `s` required to be canonically reduced,
    /// verification not cofactored.
    ///
    /// Ed25519 has no single standard notion of a canonical signature, so two
    /// implementations that both "verify ed25519" can accept different sets of
    /// signatures. For a replicated log that is a consensus split dressed up
    /// as a crypto detail, which is why the profile is pinned rather than left
    /// to the library's default.
    fn verify_ed25519(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        let key_bytes: [u8; 32] =
            self.value.as_slice().try_into().map_err(|_| Error::InvalidKey)?;
        let key =
            ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|_| Error::InvalidKey)?;
        if key.is_weak() {
            return Err(Error::InvalidKey);
        }
        let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| Error::SignatureEncoding)?;
        // Rejects a non-reduced `s` scalar.
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|_| Error::SignatureEncoding)?;
        key.verify_strict(message, &sig).map_err(|_| Error::SignatureInvalid)
    }

    /// P-256 with signatures as fixed 64-byte `r || s`, and high-`s` refused.
    ///
    /// ECDSA signatures are malleable: `(r, s)` and `(r, n - s)` both verify.
    /// Normalizing on verification would accept both spellings, giving one
    /// logical signature two encodings. Refusing the high form leaves exactly
    /// one. DER never enters the format, so a DER blob fails on length before
    /// anything tries to parse it.
    fn verify_p256(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        use p256::ecdsa::signature::Verifier as _;

        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.value)
            .map_err(|_| Error::InvalidKey)?;
        let sig =
            p256::ecdsa::Signature::from_slice(signature).map_err(|_| Error::SignatureEncoding)?;
        // `normalize_s` returns the low-form equivalent. If that differs from
        // what arrived, what arrived was the high form: the other, equally
        // valid spelling of the same signature. Refusing it leaves exactly one
        // encoding per signature.
        if sig.normalize_s() != sig {
            return Err(Error::SignatureEncoding);
        }
        key.verify(message, &sig).map_err(|_| Error::SignatureInvalid)
    }
}

/// Produces roster signatures.
///
/// Implemented here for software keys. Enclave-held keys arrive with the
/// identity capability and implement the same trait, so nothing above this
/// line needs to know where a key lives.
///
/// `Send + Sync` because a key is shared: a transport holds one across await
/// points and across threads, and a signer that could not cross a thread would
/// make an async node impossible to build. Both software signers satisfy it
/// already, and a custodian speaking to a platform keystore must too — a key
/// usable from only one thread would be a surprising thing for a device to have.
pub trait Signer: Send + Sync {
    /// The algorithm this signer uses.
    fn algorithm(&self) -> Algorithm;

    /// The corresponding public key.
    fn public_key(&self) -> PublicKey;

    /// Signs a message.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// The id of the signing key, which becomes an operation's `author`.
    fn key_id(&self) -> KeyId {
        self.public_key().key_id()
    }
}

// ---------------------------------------------------------------------------
// Operations on the wire
// ---------------------------------------------------------------------------

/// A decoded operation whose signature has not been checked.
///
/// Holds the received core bytes, not a re-encoding of them. Signature
/// verification runs over exactly what arrived, and forwarding hands on
/// exactly what arrived: a peer that re-serialized before forwarding would
/// break every downstream signature the moment its encoder differed by a byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawOperation<'a> {
    /// The stated and recomputed operation id.
    id: OperationId,
    /// The signature bytes.
    signature: [u8; limits::SIGNATURE_LEN],
    /// The exact received bytes of the signed core.
    core_bytes: Cow<'a, [u8]>,
    /// The decoded core.
    core: OperationCore,
}

impl<'a> RawOperation<'a> {
    /// Decodes an operation, borrowing the input.
    ///
    /// Checks the total size before anything else, recomputes the id from the
    /// received bytes, and rejects a stated id that disagrees.
    pub fn decode(input: &'a [u8]) -> Result<Self> {
        if input.len() > limits::MAX_OPERATION_SIZE {
            return Err(Error::LimitExceeded("operation size"));
        }
        let mut reader = Reader::new(input);
        let mut map = reader.map(OPERATION_SCHEMA)?;
        let id = OperationId::decode(map.key("id")?)?;
        let signature_bytes = map.key("sig")?.fixed_bytes(limits::SIGNATURE_LEN)?;
        let core_bytes = map.key("core")?.bytes(limits::MAX_OPERATION_SIZE, "operation size")?;
        map.finish()?;
        reader.finish()?;

        let mut signature = [0u8; limits::SIGNATURE_LEN];
        signature.copy_from_slice(signature_bytes);

        // The id is transmitted as well as derivable. Recomputing it turns an
        // encoder that drifts out of canonical form into a loud rejection
        // instead of a silent fork.
        let recomputed = OperationId::of_core(core_bytes);
        if recomputed != id {
            return Err(Error::IdMismatch);
        }

        let core = OperationCore::decode(core_bytes)?;
        Ok(Self { id, signature, core_bytes: Cow::Borrowed(core_bytes), core })
    }

    /// The operation id.
    #[must_use]
    pub const fn id(&self) -> OperationId {
        self.id
    }

    /// The decoded core. Authentic only after [`Self::verify`] succeeds.
    #[must_use]
    pub const fn core(&self) -> &OperationCore {
        &self.core
    }

    /// The exact received bytes of the signed core.
    #[must_use]
    pub fn core_bytes(&self) -> &[u8] {
        &self.core_bytes
    }

    /// The signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; limits::SIGNATURE_LEN] {
        &self.signature
    }

    /// Re-encodes the operation for forwarding.
    ///
    /// The core is copied through untouched, so what a peer receives is what
    /// this node received.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_operation(self.id, &self.signature, &self.core_bytes)
    }

    /// Takes ownership of the borrowed bytes.
    #[must_use]
    pub fn into_owned(self) -> RawOperation<'static> {
        RawOperation {
            id: self.id,
            signature: self.signature,
            core_bytes: Cow::Owned(self.core_bytes.into_owned()),
            core: self.core,
        }
    }

    /// Checks the signature against `key` and, on success, yields a
    /// [`VerifiedOperation`].
    ///
    /// Three things must line up: the key's algorithm must be the one the core
    /// declares, the key must hash to the core's `author`, and the signature
    /// must verify over the domain-separated received bytes.
    ///
    /// This proves authenticity, never authority.
    pub fn verify(&self, key: &PublicKey) -> Result<VerifiedOperation> {
        if key.algorithm() != self.core.alg {
            return Err(Error::UnknownAlgorithm);
        }
        if key.key_id() != self.core.author {
            return Err(Error::AuthorKeyMismatch);
        }
        let message =
            signing_input(&self.core.network, self.core.operation_type(), &self.core_bytes);
        key.verify(&message, &self.signature)?;
        Ok(VerifiedOperation {
            id: self.id,
            signature: self.signature,
            core_bytes: self.core_bytes.clone().into_owned(),
            core: self.core.clone(),
        })
    }
}

/// An operation whose signature has been checked against a public key.
///
/// The only way to obtain one is [`RawOperation::verify`], so a function that
/// takes this type cannot be handed unchecked bytes by accident.
///
/// It says nothing about authority. Whether the author was an admin when this
/// operation was written is a question about the state implied by its causal
/// ancestors, and deriving that state is the next capability's work, not this
/// one's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOperation {
    /// The operation id.
    id: OperationId,
    /// The signature bytes.
    signature: [u8; limits::SIGNATURE_LEN],
    /// The exact received bytes of the signed core.
    core_bytes: Vec<u8>,
    /// The decoded core.
    core: OperationCore,
}

impl VerifiedOperation {
    /// An operation that has **not** been signed, standing in for one that will be.
    ///
    /// Crate-private, and used by exactly one thing: [`crate::roster::Roster::preview`],
    /// which derives the state a set of operations *would* imply so that a
    /// snapshot over them can be signed in the same breath as they are. The
    /// preview graph is a copy and is thrown away; nothing built here is ever
    /// admitted, offered or written. The signature is zeros, which verifies
    /// under no key, so even a value that escaped would be refused by the first
    /// check it met.
    ///
    /// Derivation never reads the signature — it judges authority from the
    /// graph — which is what makes the preview equal to the real thing. The
    /// equivalence is asserted by the preview tests.
    pub(crate) fn unsigned_for_preview(core: &OperationCore) -> Self {
        Self {
            id: core.id(),
            signature: [0; limits::SIGNATURE_LEN],
            core_bytes: core.encode(),
            core: core.clone(),
        }
    }

    /// The operation id.
    #[must_use]
    pub const fn id(&self) -> OperationId {
        self.id
    }

    /// The authenticated core.
    #[must_use]
    pub const fn core(&self) -> &OperationCore {
        &self.core
    }

    /// The operation's body.
    #[must_use]
    pub const fn body(&self) -> &OperationBody {
        &self.core.body
    }

    /// The signed core bytes, exactly as received.
    #[must_use]
    pub fn core_bytes(&self) -> &[u8] {
        &self.core_bytes
    }

    /// The signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; limits::SIGNATURE_LEN] {
        &self.signature
    }

    /// Encodes the operation for transmission.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_operation(self.id, &self.signature, &self.core_bytes)
    }
}

/// Writes the wire form of an operation.
fn encode_operation(
    id: OperationId,
    signature: &[u8; limits::SIGNATURE_LEN],
    core_bytes: &[u8],
) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.map(3);
    writer.key("id");
    id.encode(&mut writer);
    writer.key("sig").bytes(signature);
    writer.key("core").bytes(core_bytes);
    writer.finish()
}

/// Assembles a wire operation from core bytes and a signature, deriving the id.
///
/// This is the low-level constructor. It does not check that the signature
/// belongs to the core, which is exactly why it exists: the test-vector corpus
/// has to be able to build operations whose parts disagree, so that every
/// implementation can be shown rejecting them.
#[must_use]
pub fn assemble_operation(core_bytes: &[u8], signature: &[u8; limits::SIGNATURE_LEN]) -> Vec<u8> {
    encode_operation(OperationId::of_core(core_bytes), signature, core_bytes)
}

/// Assembles a wire operation with an id stated independently of the core.
///
/// For building the negative vector where the stated id does not match the
/// bytes. Nothing legitimate produces one.
#[must_use]
pub fn assemble_operation_with_id(
    id: OperationId,
    core_bytes: &[u8],
    signature: &[u8; limits::SIGNATURE_LEN],
) -> Vec<u8> {
    encode_operation(id, signature, core_bytes)
}

/// Signs a core and produces the encoded operation.
///
/// The signer's algorithm must match the one the core declares; `alg` is
/// inside the signed bytes precisely so it cannot be changed afterwards, so a
/// mismatch here would produce an operation that could never verify.
pub fn sign_operation(core: &OperationCore, signer: &dyn Signer) -> Result<Vec<u8>> {
    if signer.algorithm() != core.alg {
        return Err(Error::UnknownAlgorithm);
    }
    let core_bytes = core.encode();
    if core_bytes.len() > limits::MAX_OPERATION_SIZE {
        return Err(Error::LimitExceeded("operation size"));
    }
    let message = signing_input(&core.network, core.operation_type(), &core_bytes);
    let signature_bytes = signer.sign(&message)?;
    let signature: [u8; limits::SIGNATURE_LEN] =
        signature_bytes.as_slice().try_into().map_err(|_| Error::SignatureEncoding)?;
    let id = OperationId::of_core(&core_bytes);
    let encoded = encode_operation(id, &signature, &core_bytes);
    if encoded.len() > limits::MAX_OPERATION_SIZE {
        return Err(Error::LimitExceeded("operation size"));
    }
    Ok(encoded)
}

// ---------------------------------------------------------------------------
// Software signers
// ---------------------------------------------------------------------------

/// An ed25519 signing key held in memory.
///
/// Suitable for daemons and for generating the test-vector corpus. A phone's
/// root key lives in an enclave and never takes this form.
pub struct Ed25519Signer {
    /// The underlying key.
    key: ed25519_dalek::SigningKey,
}

impl Ed25519Signer {
    /// Wraps a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { key: ed25519_dalek::SigningKey::from_bytes(&seed) }
    }
}

impl Signer for Ed25519Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn public_key(&self) -> PublicKey {
        PublicKey { alg: Algorithm::Ed25519, value: self.key.verifying_key().to_bytes().to_vec() }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use ed25519_dalek::Signer as _;
        Ok(self.key.sign(message).to_bytes().to_vec())
    }
}

/// A P-256 signing key held in memory.
///
/// The real root key is generated inside a phone's secure enclave and cannot
/// be exported; this exists so the format can be exercised and the corpus
/// generated without one.
pub struct P256Signer {
    /// The underlying key.
    key: p256::ecdsa::SigningKey,
}

impl P256Signer {
    /// Wraps a 32-byte scalar, rejecting one outside the curve order.
    pub fn from_scalar(scalar: [u8; 32]) -> Result<Self> {
        let key = p256::ecdsa::SigningKey::from_slice(&scalar).map_err(|_| Error::InvalidKey)?;
        Ok(Self { key })
    }
}

impl Signer for P256Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::P256
    }

    fn public_key(&self) -> PublicKey {
        PublicKey {
            alg: Algorithm::P256,
            // Compressed, not `to_sec1_bytes`, which yields the 65-byte
            // uncompressed form. The format admits exactly one encoding per
            // key, and it is this one.
            value: self.key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
        }
    }

    /// Signs, then forces the signature into low-`s` form.
    ///
    /// The nonce comes from RFC 6979, so this signer is deterministic and the
    /// test-vector corpus can pin exact signature bytes. An enclave-held key
    /// signs with a random nonce instead, which is why the operation id
    /// excludes the signature: otherwise the same operation signed on a phone
    /// twice would enter the DAG under two ids.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::signature::Signer as _;
        let signature: p256::ecdsa::Signature = self.key.sign(message);
        let normalized = signature.normalize_s();
        Ok(normalized.to_bytes().to_vec())
    }
}

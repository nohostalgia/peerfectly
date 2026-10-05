//! A node's own keys: generating them, and turning them into the device a
//! roster will recognise.
//!
//! # Two keys, drawn separately
//!
//! A node holds a signing key and a transport key, generated independently and
//! never derived from one another. Deriving the second from the first would
//! make one compromise into two, and would make "the keys are distinct" an
//! accident of the derivation rather than a property.
//!
//! The separation is what stops a signature meaning something in the transport
//! protocol, and the reverse. The roster already refuses a device record that
//! reuses a key value; this refuses to build one.
//!
//! # Generation goes through the same doors as decoding
//!
//! A generated key is validated by exactly the code that validates a received
//! one — `roster`'s `PublicKey::new` and `KeyEntry::new`. Trusting our own
//! generator because it is ours is how a wrong-length encoding reaches disk and
//! is first noticed by a peer.

use core::fmt;
use std::sync::Arc;

use roster::id::{DeviceId, KeyId};
use roster::sign::{Ed25519Signer, P256Signer, PublicKey, Signer};
use roster::types::{Algorithm, Capability, DeviceSpec, KeyEntry, KeyPurpose, OperationCore, Role};

use crate::detached::{KeyCustodian, prepare_operation, sign_with_custodian};
use crate::error::{Error, Result};
use crate::secret::SecretBytes;

/// Draws key material from the operating system.
///
/// There is no fallback. A node that cannot obtain randomness must not proceed
/// with anything else available to it, because everything else available to it
/// is predictable.
fn random_bytes() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::NoEntropy)?;
    Ok(bytes)
}

/// The name a key store is asked to make a new signing key under.
///
/// **Never a name already used.** A key store asked to make a key under a name
/// it holds replaces the key there without a word — Android's keystore does,
/// and CNG does when told to overwrite — and a directory's name is reused by
/// every join, which starts in the same provisional directory. Named after the
/// directory alone, a second join replaced the first network's key, and that
/// network stopped opening for good. So the name carries 64 random bits: the
/// stored identity records it, which is how the key is found again, and nothing
/// works it out from the directory afterwards.
///
/// # Errors
///
/// When the system has no randomness to give.
pub fn fresh_key_name(directory: &str) -> Result<String> {
    let bytes = random_bytes()?;
    let tag: String = bytes.iter().take(8).map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("peerfectly.{directory}.{tag}.signing"))
}

/// One private key a node holds.
///
/// Keeps the material and the signer it drives together, so the two cannot
/// drift apart.
pub struct PrivateKey {
    /// The algorithm.
    algorithm: Algorithm,
    /// The private material, cleared on drop.
    material: SecretBytes,
    /// The signer built from it.
    signer: Box<dyn Signer>,
}

impl PrivateKey {
    /// Builds a key from caller-supplied material.
    ///
    /// **For tests and vectors, not for a device.** The shared corpus has to be
    /// reproducible, which means some keys must come from a fixed seed. A real
    /// node uses [`PrivateKey::generate`] or [`NodeIdentity::generate`], which
    /// draw from the operating system and accept nothing from the caller.
    ///
    /// A key built here is validated exactly as a generated one is, so this is
    /// safe to call — it is simply not private, because whoever chose the
    /// material knows the key.
    pub fn from_material(algorithm: Algorithm, material: [u8; 32]) -> Result<Self> {
        let signer: Box<dyn Signer> = match algorithm {
            Algorithm::Ed25519 => Box::new(Ed25519Signer::from_seed(material)),
            Algorithm::P256 => Box::new(P256Signer::from_scalar(material)?),
        };
        // Route the public key through the validating constructor rather than
        // trusting the generator.
        let produced = signer.public_key();
        let _checked = PublicKey::new(produced.algorithm(), produced.as_bytes().to_vec())?;
        Ok(Self { algorithm, material: SecretBytes::new(material), signer })
    }

    /// Generates a key from system entropy.
    ///
    /// A P-256 scalar must lie inside the curve order; the probability of a
    /// draw falling outside is around 2^-32, so a bounded retry is both correct
    /// and effectively never taken.
    pub fn generate(algorithm: Algorithm) -> Result<Self> {
        for _ in 0..8 {
            let material = random_bytes()?;
            match Self::from_material(algorithm, material) {
                Ok(key) => return Ok(key),
                Err(Error::Roster(roster::Error::InvalidKey)) => continue,
                Err(other) => return Err(other),
            }
        }
        Err(Error::NoEntropy)
    }

    /// The algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.signer.public_key()
    }

    /// The key's id.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.signer.key_id()
    }

    /// The signer, for the synchronous path.
    #[must_use]
    pub fn signer(&self) -> &dyn Signer {
        self.signer.as_ref()
    }

    /// The private material.
    ///
    /// Reachable so an identity can be written to storage, and named so that
    /// every place it is reached shows up in a search.
    #[must_use]
    pub const fn material(&self) -> &SecretBytes {
        &self.material
    }

    /// A key entry declaring this key for a purpose.
    pub fn entry(&self, purpose: KeyPurpose) -> Result<KeyEntry> {
        Ok(KeyEntry::new(self.algorithm, purpose, self.public_key().as_bytes().to_vec())?)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id())
            .finish_non_exhaustive()
    }
}

/// A signing key held by somebody else: a phone's keystore, an enclave.
///
/// Carries the public half, the name the custodian knows the key by, and the
/// custodian itself. It carries no private material and has no way to obtain
/// any, which is what `detached` requires of a custodian.
pub struct CustodianKey {
    /// What the custodian calls this key, so a stored identity can find it again.
    reference: String,
    /// The public half, validated by the roster's own constructor.
    public: PublicKey,
    /// Who signs.
    custodian: Arc<dyn KeyCustodian + Send + Sync>,
    /// What [`SigningKey::signer`] hands out for this key.
    refusing: RefusingSigner,
}

impl CustodianKey {
    /// The name the custodian knows the key by.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }
}

/// A signer that will not sign, standing in for a key this process cannot use.
///
/// The synchronous path cannot carry a person declining a prompt: `Signer::sign`
/// answers in the roster's error type, which has no word for it. So a key held
/// by a custodian signs only through [`NodeIdentity::sign_operation`] and the
/// detached path, and anything still reaching for the synchronous signer is told
/// so instead of being given a signature it would not know how to fail.
struct RefusingSigner {
    /// The key it stands in for.
    public: PublicKey,
}

impl Signer for RefusingSigner {
    fn algorithm(&self) -> Algorithm {
        self.public.algorithm()
    }

    fn public_key(&self) -> PublicKey {
        self.public.clone()
    }

    fn sign(&self, _message: &[u8]) -> roster::Result<Vec<u8>> {
        Err(roster::Error::InvalidValue(
            "this signing key is held by a custodian; sign through NodeIdentity::sign_operation",
        ))
    }
}

/// The key an identity signs with: held here, or held by a custodian.
pub enum SigningKey {
    /// Material this process holds.
    Held(PrivateKey),
    /// A key only a custodian can use.
    Custodian(CustodianKey),
}

impl SigningKey {
    /// The algorithm.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Self::Held(key) => key.algorithm(),
            Self::Custodian(key) => key.public.algorithm(),
        }
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Held(key) => key.public_key(),
            Self::Custodian(key) => key.public.clone(),
        }
    }

    /// The key's id.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.public_key().key_id()
    }

    /// The synchronous signer.
    ///
    /// For a custodian's key this refuses every signature; see
    /// [`NodeIdentity::sign_operation`].
    #[must_use]
    pub fn signer(&self) -> &dyn Signer {
        match self {
            Self::Held(key) => key.signer(),
            Self::Custodian(key) => &key.refusing,
        }
    }

    /// The private material, when this process holds it.
    #[must_use]
    pub const fn material(&self) -> Option<&SecretBytes> {
        match self {
            Self::Held(key) => Some(key.material()),
            Self::Custodian(_) => None,
        }
    }

    /// The custodian's key, when a custodian holds it.
    #[must_use]
    pub const fn custodian(&self) -> Option<&CustodianKey> {
        match self {
            Self::Held(_) => None,
            Self::Custodian(key) => Some(key),
        }
    }

    /// A key entry declaring this key for a purpose.
    pub fn entry(&self, purpose: KeyPurpose) -> Result<KeyEntry> {
        Ok(KeyEntry::new(self.algorithm(), purpose, self.public_key().as_bytes().to_vec())?)
    }

    /// Whether this key can be used from this process.
    ///
    /// True for a key held here, and for a custodian that answers on the call —
    /// a phone's keystore does, blocking while somebody is asked. False when the
    /// key is somewhere this process cannot reach at all, and a caller must then
    /// prepare the request and have it signed where the key is.
    ///
    /// Asked **before** signing. [`Self::sign_request`] refuses rather than
    /// blocking on something that will never answer, but that refusal is a net
    /// under a caller that forgot, not the way to find out.
    #[must_use]
    pub fn answers_here(&self) -> bool {
        match self {
            Self::Held(_) => true,
            Self::Custodian(key) => key.custodian.answers_here(),
        }
    }

    /// Signs what a request asks for, through whichever path this key takes.
    fn sign_request(&self, request: &crate::detached::SigningRequest) -> Result<Vec<u8>> {
        match self {
            Self::Held(key) => sign_with_custodian(request, key.signer()),
            Self::Custodian(key) => {
                // Every path that signs with a custodian's key arrives here, so
                // this is the one place the net has to be.
                if !key.custodian.answers_here() {
                    return Err(Error::SignedElsewhere);
                }
                sign_with_custodian(request, key.custodian.as_ref())
            }
        }
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Held(key) => f.debug_tuple("Held").field(key).finish(),
            Self::Custodian(key) => f
                .debug_struct("Custodian")
                .field("reference", &key.reference)
                .field("key_id", &key.public.key_id())
                .finish(),
        }
    }
}

/// A node's identity: the keys that make it a device.
pub struct NodeIdentity {
    /// Signs roster operations and snapshots.
    signing: SigningKey,
    /// Establishes transport sessions. The iroh `NodeId` is derived from this.
    transport: PrivateKey,
    /// Signs attestations, which date a roster and describe none.
    ///
    /// Held here rather than by a custodian, and deliberately: this is the key a
    /// device uses with nobody present, which is the whole reason it exists
    /// separately from [`Self::signing`]. A phone raises a lock prompt for every
    /// signature its custodian makes, so an admin phone could only date its
    /// roster while somebody was holding it — and a network whose only admin is
    /// a phone went stale whenever that person stopped opening the app.
    ///
    /// What this concedes is bounded by what an attestation can say, which is a
    /// date and nothing else. See `roster`'s attestation requirement.
    attestation: PrivateKey,
}

impl NodeIdentity {
    /// Generates an identity from system entropy.
    ///
    /// Takes no key material: a caller cannot supply, influence, or observe the
    /// bytes drawn.
    pub fn generate() -> Result<Self> {
        let signing = PrivateKey::generate(Algorithm::Ed25519)?;
        let transport = PrivateKey::generate(Algorithm::Ed25519)?;
        let attestation = PrivateKey::generate(Algorithm::Ed25519)?;
        Self::assemble(signing, transport, attestation)
    }

    /// Generates an identity whose signing key uses a chosen algorithm.
    ///
    /// A phone's enclave imposes P-256 on the root key while device and
    /// transport keys stay ed25519, so the two are chosen separately.
    pub fn generate_with(signing_algorithm: Algorithm) -> Result<Self> {
        let signing = PrivateKey::generate(signing_algorithm)?;
        let transport = PrivateKey::generate(Algorithm::Ed25519)?;
        // Ed25519 whatever the signing algorithm is. An enclave imposes P-256 on
        // a key it holds; this one is never in an enclave, because a key in one
        // is a key that asks.
        let attestation = PrivateKey::generate(Algorithm::Ed25519)?;
        Self::assemble(signing, transport, attestation)
    }

    /// Assembles an identity from three keys, refusing any reused value.
    pub fn assemble(
        signing: PrivateKey,
        transport: PrivateKey,
        attestation: PrivateKey,
    ) -> Result<Self> {
        // Pairwise. Refused here rather than left for the roster to catch, so an
        // identity that cannot be presented is never built.
        let values = [
            signing.public_key().as_bytes().to_vec(),
            transport.public_key().as_bytes().to_vec(),
            attestation.public_key().as_bytes().to_vec(),
        ];
        for (index, value) in values.iter().enumerate() {
            if values.iter().skip(index.saturating_add(1)).any(|other| other == value) {
                return Err(Error::KeyReuse);
            }
        }
        Ok(Self { signing: SigningKey::Held(signing), transport, attestation })
    }

    /// An identity whose signing key a custodian holds.
    ///
    /// The transport key stays here, because the transport uses it on every
    /// packet. The signing key never enters this process: what is kept is its
    /// public half and the name the custodian knows it by.
    ///
    /// # Errors
    ///
    /// When the custodian's public key is not one the roster accepts, or when it
    /// is the same value as the transport key.
    pub fn with_custodian(
        reference: impl Into<String>,
        custodian: Arc<dyn KeyCustodian + Send + Sync>,
        transport: PrivateKey,
        attestation: PrivateKey,
    ) -> Result<Self> {
        let offered = custodian.public_key();
        // Through the validating constructor, as a generated key is: a keystore
        // is not trusted to encode a point the roster will accept.
        let public = PublicKey::new(offered.algorithm(), offered.as_bytes().to_vec())?;
        if public.as_bytes() == transport.public_key().as_bytes()
            || public.as_bytes() == attestation.public_key().as_bytes()
            || transport.public_key().as_bytes() == attestation.public_key().as_bytes()
        {
            return Err(Error::KeyReuse);
        }
        let signing = SigningKey::Custodian(CustodianKey {
            reference: reference.into(),
            refusing: RefusingSigner { public: public.clone() },
            public,
            custodian,
        });
        Ok(Self { signing, transport, attestation })
    }

    /// Signs an operation, through the path this identity's key takes.
    ///
    /// A key held here signs synchronously. A custodian's key signs through the
    /// detached path, which verifies the signature before assembling — and a
    /// person declining the prompt comes back as [`Error::Declined`], an ordinary
    /// outcome, rather than as a failure.
    ///
    /// The bytes are the same either way, so a peer cannot tell which it was.
    ///
    /// # Errors
    ///
    /// When signing is declined, the custodian fails, or the signature does not
    /// verify.
    pub fn sign_operation(&self, core: &OperationCore) -> Result<Vec<u8>> {
        match &self.signing {
            SigningKey::Held(key) => Ok(roster::sign::sign_operation(core, key.signer())?),
            SigningKey::Custodian(_) => {
                let request = prepare_operation(core, &self.signing.public_key());
                self.signing.sign_request(&request)
            }
        }
    }

    /// Signs a snapshot, through the path this identity's key takes.
    ///
    /// The twin of [`Self::sign_operation`], and for the same reason: a key held
    /// here signs synchronously, a custodian's key signs through the detached
    /// path, and the bytes are the same either way. Without it a caller holding a
    /// custodian's key would reach for [`Self::signer`], which for that kind of
    /// key refuses — so an admin phone could hold a network and never attest to
    /// its state, which is the one thing a network needs an admin present for.
    ///
    /// # Errors
    ///
    /// When signing is declined, the custodian fails, or the signature does not
    /// verify.
    pub fn sign_snapshot(&self, body: &roster::snapshot::Snapshot) -> Result<Vec<u8>> {
        match &self.signing {
            SigningKey::Held(key) => Ok(roster::snapshot::sign_snapshot(body, key.signer())?),
            SigningKey::Custodian(_) => {
                let request = crate::detached::prepare_snapshot(body, &self.signing.public_key());
                self.signing.sign_request(&request)
            }
        }
    }

    /// Signs a prepared request with this identity's signing key.
    ///
    /// # Errors
    ///
    /// As [`Self::sign_operation`].
    pub fn sign_request(&self, request: &crate::detached::SigningRequest) -> Result<Vec<u8>> {
        self.signing.sign_request(request)
    }

    /// The signing key.
    #[must_use]
    pub const fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    /// The transport key.
    ///
    /// `transport-iroh` adapts this into an iroh `NodeId`; nothing here depends
    /// on iroh to say so.
    #[must_use]
    pub const fn transport_key(&self) -> &PrivateKey {
        &self.transport
    }

    /// The attestation key, which dates a roster and signs nothing else.
    ///
    /// Always held here, never behind a custodian: a custodian is what asks a
    /// person, and the point of this key is that it does not.
    #[must_use]
    pub const fn attestation_key(&self) -> &PrivateKey {
        &self.attestation
    }

    /// This node's device id, which follows from its signing key.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        DeviceId::of_signing_key(self.signing.public_key().as_bytes())
    }

    /// The signer for the synchronous path.
    #[must_use]
    pub fn signer(&self) -> &dyn Signer {
        self.signing.signer()
    }

    /// The device specification this node presents for enrolment.
    ///
    /// The keys in it are the keys this node holds, so a node cannot claim a
    /// key it can neither sign nor establish sessions with.
    pub fn device_spec(
        &self,
        name: impl Into<String>,
        role: Role,
        founder: bool,
        capabilities: Vec<Capability>,
    ) -> Result<DeviceSpec> {
        let mut keys = vec![
            self.signing.entry(KeyPurpose::Signing)?,
            self.transport.entry(KeyPurpose::Transport)?,
            self.attestation.entry(KeyPurpose::Attestation)?,
        ];
        // The roster requires key entries in canonical order; sorting here
        // means a caller never has to know that. The order comes from the
        // roster itself rather than being approximated — an approximation that
        // agrees for two ed25519 keys disagrees as soon as a 33-byte P-256 key
        // sits beside a 32-byte one.
        keys.sort_by_key(KeyEntry::order_key);
        Ok(DeviceSpec::new(keys, name, role, founder, capabilities)?)
    }
}

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("device_id", &self.device_id())
            .field("signing", &self.signing)
            .field("transport", &self.transport)
            .field("attestation", &self.attestation)
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test reports failure by panicking")]
mod tests {
    use super::{NodeIdentity, PrivateKey, fresh_key_name};
    use crate::error::Error;
    use roster::types::Algorithm;

    /// **A name a key store is asked to make a key under is never one it made
    /// before.** A store replaces the key under a name it already holds, and a
    /// join's directory is always the same one.
    #[test]
    fn a_new_keys_name_is_never_one_already_made() {
        let first = fresh_key_name("network").expect("named");
        let second = fresh_key_name("network").expect("named");
        assert_ne!(first, second, "the same directory, two names");
        for name in [&first, &second] {
            let tag = name
                .strip_prefix("peerfectly.network.")
                .and_then(|rest| rest.strip_suffix(".signing"))
                .unwrap_or_else(|| panic!("says which directory it was made for: {name}"));
            assert_eq!(16, tag.len(), "64 bits, in hex: {name}");
            assert!(tag.chars().all(|c| c.is_ascii_hexdigit()), "{name}");
        }
    }

    #[test]
    fn generated_keys_are_valid_under_the_rosters_own_checks() {
        let key = PrivateKey::generate(Algorithm::Ed25519).expect("generates");
        assert_eq!(key.public_key().as_bytes().len(), 32);
        let p256 = PrivateKey::generate(Algorithm::P256).expect("generates");
        assert_eq!(p256.public_key().as_bytes().len(), 33, "compressed, as the format requires");
    }

    #[test]
    fn an_identity_refuses_one_key_serving_two_purposes() {
        let material = [3u8; 32];
        let other = [4u8; 32];
        let key = |bytes| PrivateKey::from_material(Algorithm::Ed25519, bytes).expect("valid");

        // Each of the three pairs, so no pair is left unchecked by the loop
        // that checks them.
        for (a, b, c) in
            [(material, material, other), (material, other, material), (other, material, material)]
        {
            assert_eq!(
                NodeIdentity::assemble(key(a), key(b), key(c)).map(|_| ()),
                Err(Error::KeyReuse),
                "a reused value must be refused whichever pair shares it"
            );
        }
    }

    #[test]
    fn debug_output_carries_no_private_material() {
        let identity = NodeIdentity::generate().expect("generates");
        let rendered = format!("{identity:?}");
        let secret = identity.signing_key().material().expect("held").expose();
        let hex: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
        assert!(!rendered.contains(&hex), "private material must not be printed");
        assert!(rendered.contains("device_id"));
    }
}

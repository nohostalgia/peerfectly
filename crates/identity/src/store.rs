//! Writing an identity to disk and reading it back.
//!
//! # The file is not a wire format
//!
//! An identity file is local. It is never signed, never exchanged, and never
//! parsed by a second implementation, so the canonical-encoding discipline the
//! roster needs — which exists so two implementations agree on bytes — buys
//! nothing here. What it does need is to be strict: a file that does not decode
//! exactly must be refused rather than half-read.
//!
//! That is why this uses `minicbor` directly rather than reaching into
//! `roster`'s canonical encoder. Borrowing that machinery would couple the
//! crates for the appearance of consistency, and would use a tool shaped for a
//! problem this file does not have.
//!
//! # Protection is applied before the bytes land
//!
//! On Unix the file is created with mode `0600` — created that way, not created
//! and then tightened. However brief, a window where the file is world-readable
//! is a window someone can wait for.
//!
//! On Windows the material is sealed to the account before it is written, so
//! the mode of the file matters less: the bytes on disk are not the key.

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;

use roster::sign::PublicKey;
use roster::types::Algorithm;

use crate::detached::KeyCustodian;
use crate::error::{Error, Result};
use crate::identity::{NodeIdentity, PrivateKey, SigningKey};
use crate::seal;

/// The stored format this build writes and understands.
///
/// There is no key-rotation path in this crate and none is missing: a device's
/// key set is fixed when it is added, because none of the roster's seven
/// operations adds a key to an existing device. Rotating means revoking the
/// device and adding a new one under a new device id, which is roster work.
///
/// A file carrying anything else is refused rather than guessed at.
pub const STORED_VERSION: u64 = 3;

/// The stored format for an identity whose signing key may be held elsewhere.
///
/// Written only when a custodian holds the signing key. Both versions are read.
///
/// # Why versions 1 and 2 are not read
///
/// They hold two keys. An identity now holds three, and the third cannot be
/// derived from the other two — it is independent key material, which is the
/// point of it. So a file written by an older build describes a device that
/// cannot attest, and there is no reading of it that produces one that can.
///
/// Such a file comes back as [`Error::UnknownStoredVersion`], which says what
/// happened rather than failing as corruption. The networks those identities
/// belong to have to be founded again in any case: a device's key set is fixed
/// by the operation that admitted it, and none of the roster's operations adds a
/// key to a device that already exists.
pub const CUSTODIAN_VERSION: u64 = 4;

/// Protects stored bytes, the way a platform does.
///
/// The daemon on a desktop uses [`PlatformSealer`], which is what [`save`] and
/// [`load`] have always done. A phone supplies its own, backed by its keystore,
/// because the file mode that is the whole control on a Unix desktop is not the
/// right control inside an app's storage.
pub trait Sealer: Send + Sync {
    /// Protects bytes before they are written.
    ///
    /// # Errors
    ///
    /// When the protection cannot be applied. Nothing is written then.
    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>>;

    /// Reverses [`Self::seal`].
    ///
    /// # Errors
    ///
    /// When the bytes cannot be unsealed. There is no fallback to reading them as
    /// they are.
    fn unseal(&self, stored: &[u8]) -> Result<Vec<u8>>;
}

/// This platform's own protection, bound to the account: DPAPI on Windows, the
/// file mode on Unix.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlatformSealer;

impl Sealer for PlatformSealer {
    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>> {
        seal::seal(plain)
    }

    fn unseal(&self, stored: &[u8]) -> Result<Vec<u8>> {
        seal::unseal(stored)
    }
}

/// The same protection, bound to the machine rather than to a person.
///
/// **What a service needs, and what only a service should use.** The keys it
/// protects are the ones that must work with nobody present: the transport key
/// on every packet, and the attestation key that dates a roster unattended. A
/// secret bound to a person cannot be opened by something running with nobody
/// logged in.
///
/// The sealing is **not the whole protection here**, and a caller must know it:
/// any process on the machine that can read the bytes can ask for them to be
/// opened. Where the file is kept, and who may read it, is the other half. Use
/// this only for material behind an access control that says so; see
/// `seal::Bound::Machine`.
#[derive(Debug, Default, Clone, Copy)]
pub struct MachineSealer;

impl Sealer for MachineSealer {
    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>> {
        seal::seal_bound_to(plain, seal::Bound::Machine)
    }

    fn unseal(&self, stored: &[u8]) -> Result<Vec<u8>> {
        seal::unseal_bound_to(stored, seal::Bound::Machine)
    }
}

/// Finds a custodian's key by the name a stored identity recorded.
pub trait Custodians {
    /// The custodian holding the key named `reference`, if there is one.
    ///
    /// # Errors
    ///
    /// When the key store cannot be asked. A key that simply is not there is
    /// `Ok(None)`.
    fn find(&self, reference: &str) -> Result<Option<Arc<dyn KeyCustodian + Send + Sync>>>;
}

/// No custodian at all: what a desktop has.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoCustodians;

impl Custodians for NoCustodians {
    fn find(&self, _reference: &str) -> Result<Option<Arc<dyn KeyCustodian + Send + Sync>>> {
        Ok(None)
    }
}

/// Encodes an identity for storage.
fn encode(identity: &NodeIdentity) -> Vec<u8> {
    let mut out = Vec::new();
    let mut encoder = minicbor::Encoder::new(&mut out);
    // Fixed shape: version, then the three keys as (algorithm tag, material).
    let _ = encoder.array(7);
    let _ = encoder.u64(STORED_VERSION);
    let _ = encoder.u8(algorithm_tag(identity.signing_key().algorithm()));
    // This version is only ever written for a key held here; see `save_with`.
    let _ = encoder.bytes(identity.signing_key().material().map_or(&[][..], |key| key.expose()));
    let _ = encoder.u8(algorithm_tag(identity.transport_key().algorithm()));
    let _ = encoder.bytes(identity.transport_key().material().expose());
    let _ = encoder.u8(algorithm_tag(identity.attestation_key().algorithm()));
    let _ = encoder.bytes(identity.attestation_key().material().expose());
    out
}

/// Encodes an identity whose signing key a custodian holds.
///
/// `[version, [reference, algorithm tag, public key], transport algorithm tag,
/// transport material, attestation algorithm tag, attestation material]`. The
/// signing key's private half is not here, and there is nowhere in the shape to
/// put it.
///
/// The attestation key's private half **is** here, beside the transport key's,
/// because it is held in this process for the same reason: it is used where
/// nobody is present, and a custodian is what asks.
fn encode_custodian(identity: &NodeIdentity) -> Result<Vec<u8>> {
    let SigningKey::Custodian(held) = identity.signing_key() else {
        return Ok(encode(identity));
    };
    let mut out = Vec::new();
    let mut encoder = minicbor::Encoder::new(&mut out);
    let _ = encoder.array(6);
    let _ = encoder.u64(CUSTODIAN_VERSION);
    let _ = encoder.array(3);
    let _ = encoder.str(held.reference());
    let _ = encoder.u8(algorithm_tag(identity.signing_key().algorithm()));
    let _ = encoder.bytes(identity.signing_key().public_key().as_bytes());
    let _ = encoder.u8(algorithm_tag(identity.transport_key().algorithm()));
    let _ = encoder.bytes(identity.transport_key().material().expose());
    let _ = encoder.u8(algorithm_tag(identity.attestation_key().algorithm()));
    let _ = encoder.bytes(identity.attestation_key().material().expose());
    Ok(out)
}

/// Decodes a stored identity of either version.
fn decode_with(bytes: &[u8], custodians: &dyn Custodians) -> Result<NodeIdentity> {
    let mut decoder = minicbor::Decoder::new(bytes);
    let fields = decoder.array().map_err(|_| Error::CorruptIdentity)?;
    let version = decoder.u64().map_err(|_| Error::CorruptIdentity)?;
    match (version, fields) {
        (STORED_VERSION, Some(7)) => {}
        (CUSTODIAN_VERSION, Some(6)) => return decode_custodian(bytes, &mut decoder, custodians),
        (STORED_VERSION | CUSTODIAN_VERSION, _) => return Err(Error::CorruptIdentity),
        (found, _) => return Err(Error::UnknownStoredVersion { found }),
    }

    let signing = read_key(&mut decoder)?;
    let transport = read_key(&mut decoder)?;
    let attestation = read_key(&mut decoder)?;
    if decoder.position() != bytes.len() {
        // Trailing bytes mean this is not the file we think it is.
        return Err(Error::CorruptIdentity);
    }
    NodeIdentity::assemble(signing, transport, attestation)
}

/// Decodes a version 1 identity, which never names a custodian.
#[cfg(test)]
fn decode(bytes: &[u8]) -> Result<NodeIdentity> {
    decode_with(bytes, &NoCustodians)
}

/// The rest of a version 2 identity, after its version.
fn decode_custodian(
    bytes: &[u8],
    decoder: &mut minicbor::Decoder<'_>,
    custodians: &dyn Custodians,
) -> Result<NodeIdentity> {
    if decoder.array().map_err(|_| Error::CorruptIdentity)? != Some(3) {
        return Err(Error::CorruptIdentity);
    }
    let reference = decoder.str().map_err(|_| Error::CorruptIdentity)?.to_owned();
    let algorithm = algorithm_from_tag(decoder.u8().map_err(|_| Error::CorruptIdentity)?)?;
    let stored =
        PublicKey::new(algorithm, decoder.bytes().map_err(|_| Error::CorruptIdentity)?.to_vec())
            .map_err(|_| Error::CorruptIdentity)?;
    let transport = read_key(decoder)?;
    let attestation = read_key(decoder)?;
    if decoder.position() != bytes.len() {
        return Err(Error::CorruptIdentity);
    }

    let Some(custodian) = custodians.find(&reference)? else {
        return Err(Error::CustodianKeyMissing { reference });
    };
    // The key under that name must be the key this identity was stored with. A
    // different one would sign as a different device while presenting this one.
    if custodian.public_key() != stored {
        return Err(Error::CustodianKeyMismatch { reference });
    }
    NodeIdentity::with_custodian(reference, custodian, transport, attestation)
}

/// Reads one key: its algorithm tag, then its material.
fn read_key(decoder: &mut minicbor::Decoder<'_>) -> Result<PrivateKey> {
    let tag = decoder.u8().map_err(|_| Error::CorruptIdentity)?;
    let algorithm = algorithm_from_tag(tag)?;
    let raw = decoder.bytes().map_err(|_| Error::CorruptIdentity)?;
    let material: [u8; 32] = raw.try_into().map_err(|_| Error::CorruptIdentity)?;
    // Built through the validating constructor, so a stored key that is not a
    // key is refused here rather than at first use.
    PrivateKey::from_material(algorithm, material)
}

/// The stored tag for an algorithm.
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

/// Writes an identity to `path`, protected the way this platform protects a
/// local secret.
///
/// # What this protects against, and what it does not
///
/// | | Another local user or app | A privileged process | A backup or a stolen disk |
/// |---|---|---|---|
/// | Unix, mode `0600` | defended | **not** defended | **not** defended |
/// | Windows, DPAPI | defended | **not** defended | defended |
/// | Android, keystore sealer via [`save_with`] | defended | **not** defended | defended |
///
/// On Unix the material is stored in the clear and the file mode is the whole
/// control: root, a filesystem backup, or a disk pulled from a machine yields
/// the signing key, and with it the ability to author operations as that device
/// — for an admin device, including adding devices of its own. This is a
/// documented limit for the threat model, not a risk that has been mitigated.
///
/// On Unix the file is **created** with mode `0600` rather than created and then
/// tightened: however brief, a window where it is world-readable is one an
/// attacker can wait for.
pub fn save(identity: &NodeIdentity, path: &Path) -> Result<()> {
    save_with(identity, path, &PlatformSealer)
}

/// Writes an identity, protected by the given sealer.
///
/// An identity whose signing key is held here is written as version 1, exactly
/// as [`save`] always wrote it. One whose signing key a custodian holds is
/// written as version 2, which records the key's name and public half and has no
/// place for its private half.
///
/// The bytes are sealed before the file exists, so nothing unprotected ever
/// reaches it.
///
/// # Errors
///
/// When sealing or writing fails.
pub fn save_with(identity: &NodeIdentity, path: &Path, sealer: &dyn Sealer) -> Result<()> {
    let plain = match identity.signing_key() {
        SigningKey::Held(_) => encode(identity),
        SigningKey::Custodian(_) => encode_custodian(identity)?,
    };
    let protected = sealer.seal(&plain)?;
    let mut file = create_protected(path)?;
    file.write_all(&protected)?;
    file.sync_all()?;
    Ok(())
}

/// Reads an identity from `path`.
///
/// On Unix the file's permissions are checked **before** its contents are read:
/// a file another user can read is refused, not read and warned about.
pub fn load(path: &Path) -> Result<NodeIdentity> {
    load_with(path, &PlatformSealer, &NoCustodians)
}

/// Reads an identity, unsealing with the given sealer and finding a custodian's
/// key among the given custodians.
///
/// # Errors
///
/// When the file cannot be read or unsealed, does not decode, or names a
/// custodian key that is missing or different. No key is ever generated in
/// place of one that is missing.
pub fn load_with(
    path: &Path,
    sealer: &dyn Sealer,
    custodians: &dyn Custodians,
) -> Result<NodeIdentity> {
    check_permissions(path)?;
    let stored = fs::read(path)?;
    let plain = sealer.unseal(&stored)?;
    decode_with(&plain, custodians)
}

#[cfg(unix)]
/// Creates the file with owner-only permissions from the start.
fn create_protected(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    Ok(fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        // Set at creation. Creating it readable and tightening afterwards would
        // leave a window, and windows like that are what shows up in incident
        // reports.
        .mode(0o600)
        .open(path)?)
}

#[cfg(not(unix))]
/// Creates the file. On Windows the protection is in the bytes, not the mode.
fn create_protected(path: &Path) -> Result<fs::File> {
    Ok(fs::OpenOptions::new().write(true).create(true).truncate(true).open(path)?)
}

#[cfg(unix)]
/// Refuses a key file that anyone but its owner can read.
fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = fs::metadata(path)?.permissions().mode();
    // Any group or other bit at all: read, write or execute. A key file has no
    // business granting any of them.
    if mode & 0o077 != 0 {
        return Err(Error::PermissiveKeyFile { mode: mode & 0o777 });
    }
    Ok(())
}

#[cfg(not(unix))]
/// On Windows the material is sealed to the account, so the file's own
/// permissions are not what stands between it and another user.
const fn check_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{STORED_VERSION, decode, encode, load, save};
    use crate::error::Error;
    use crate::identity::NodeIdentity;
    use roster::types::Algorithm;

    #[test]
    fn an_identity_round_trips_in_memory() {
        let identity = NodeIdentity::generate().expect("generates");
        let decoded = decode(&encode(&identity)).expect("decodes");
        assert_eq!(decoded.device_id(), identity.device_id());
        assert_eq!(decoded.transport_key().public_key(), identity.transport_key().public_key());
    }

    #[test]
    fn a_p256_signing_key_round_trips() {
        let identity = NodeIdentity::generate_with(Algorithm::P256).expect("generates");
        let decoded = decode(&encode(&identity)).expect("decodes");
        assert_eq!(decoded.signing_key().algorithm(), Algorithm::P256);
        assert_eq!(decoded.device_id(), identity.device_id());
    }

    #[test]
    fn a_truncated_file_is_refused() {
        let identity = NodeIdentity::generate().expect("generates");
        let bytes = encode(&identity);
        for cut in [1usize, bytes.len() / 2, bytes.len().saturating_sub(1)] {
            assert!(decode(bytes.get(..cut).unwrap_or_default()).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let identity = NodeIdentity::generate().expect("generates");
        let mut bytes = encode(&identity);
        bytes.push(0x00);
        assert_eq!(decode(&bytes).map(|_| ()), Err(Error::CorruptIdentity));
    }

    #[test]
    fn an_unknown_version_is_refused_by_name() {
        let identity = NodeIdentity::generate().expect("generates");
        let mut bytes = encode(&identity);
        // The version is the first element after the array header.
        if let Some(slot) = bytes.get_mut(1) {
            *slot = 0x09;
        }
        assert_eq!(
            decode(&bytes).map(|_| ()),
            Err(Error::UnknownStoredVersion { found: 9 }),
            "a future format is named, not guessed at"
        );
        assert_eq!(STORED_VERSION, 3);
    }

    #[test]
    fn an_unknown_algorithm_tag_is_refused() {
        let identity = NodeIdentity::generate().expect("generates");
        let mut bytes = encode(&identity);
        if let Some(slot) = bytes.get_mut(2) {
            *slot = 0x07;
        }
        assert_eq!(decode(&bytes).map(|_| ()), Err(Error::CorruptIdentity));
    }

    #[test]
    fn saving_and_loading_preserves_the_identity() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("identity");
        let identity = NodeIdentity::generate().expect("generates");

        save(&identity, &path).expect("saves");
        let loaded = load(&path).expect("loads");

        assert_eq!(loaded.device_id(), identity.device_id());
        assert_eq!(loaded.signing_key().public_key(), identity.signing_key().public_key());
        assert_eq!(loaded.transport_key().public_key(), identity.transport_key().public_key());
        assert_eq!(
            loaded.device_spec("laptop", roster::types::Role::Member, false, vec![]).expect("spec"),
            identity
                .device_spec("laptop", roster::types::Role::Member, false, vec![])
                .expect("spec")
        );
    }

    #[test]
    fn a_corrupted_file_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("identity");
        let identity = NodeIdentity::generate().expect("generates");
        save(&identity, &path).expect("saves");

        let mut bytes = std::fs::read(&path).expect("reads");
        if let Some(first) = bytes.first_mut() {
            *first ^= 0xff;
        }
        std::fs::write(&path, &bytes).expect("writes");
        assert!(load(&path).is_err(), "a corrupted identity must not load");
    }

    /// Windows seals the material, so the bytes on disk are not the key.
    #[cfg(windows)]
    #[test]
    fn stored_material_is_sealed_on_windows() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("identity");
        let identity = NodeIdentity::generate().expect("generates");
        save(&identity, &path).expect("saves");

        let stored = std::fs::read(&path).expect("reads");
        let secret = identity.signing_key().material().expect("held").expose();
        assert!(
            !stored.windows(secret.len()).any(|window| window == secret),
            "the private key must not appear in the stored bytes"
        );
        assert!(crate::seal::material_is_sealed());
    }

    /// Unix protects the file rather than the bytes, so the mode is the control.
    #[cfg(unix)]
    #[test]
    fn a_saved_file_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("identity");
        save(&NodeIdentity::generate().expect("generates"), &path).expect("saves");

        let mode = std::fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o077, 0, "no group or other access, got {:o}", mode & 0o777);
    }

    #[cfg(unix)]
    #[test]
    fn a_permissive_file_is_refused_on_unix() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("identity");
        save(&NodeIdentity::generate().expect("generates"), &path).expect("saves");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let refused = load(&path);
        assert!(
            matches!(refused, Err(Error::PermissiveKeyFile { mode }) if mode & 0o077 == 0o044),
            "expected a refusal naming the permissions, got {refused:?}"
        );
    }
}

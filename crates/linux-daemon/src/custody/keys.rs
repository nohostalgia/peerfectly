//! The daemon's side of custody: finding a network's key, checking it, and
//! refusing what must be refused. It never signs.
//!
//! The same shape as `windows_daemon::keys`, deliberately: the portable half
//! asks *give me this network's identity*, and the answer differs only in where
//! the key is and how it is reached. The transport and attestation keys stay
//! here, as `0600` files — they are needed with nobody present, and a key that
//! asks cannot date a roster.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use daemon::error::{Error, Result};
use daemon::keys::Keys;
use daemon::state::Paths;
use identity::detached::{KeyCustodian, SigningRequest};
use identity::store::Custodians;
use identity::{NodeIdentity, PrivateKey};
use roster::sign::PublicKey;
use roster::types::Algorithm;

use super::tpm::{Stored, Tpm};
use super::{Kind, file_for, find};

/// A signing key held in a file under the keys directory, of either kind.
///
/// Carries the public half and the name, and no way to the private half — the
/// daemon cannot sign with it, and must not.
pub struct FileCustodian {
    /// Its public half.
    public: PublicKey,
    /// How it is held.
    kind: Kind,
}

impl KeyCustodian for FileCustodian {
    fn public_key(&self) -> PublicKey {
        self.public.clone()
    }

    fn sign_request(&self, request: &SigningRequest) -> identity::Result<Vec<u8>> {
        // Reached only if something ignored `answers_here`. It must not quietly
        // succeed: the key signs only where the person types the passphrase.
        let _ = request;
        Err(identity::Error::SignedElsewhere)
    }

    fn answers_here(&self) -> bool {
        false
    }
}

/// This machine's keys.
pub struct LinuxKeys {
    /// Where the key files are.
    keys: PathBuf,
    /// The TPM, when it can hold a key — asked once, at start.
    tpm: Option<Tpm>,
}

impl LinuxKeys {
    /// The keys under `state`, with the TPM when the probe says it can hold
    /// one. The directory is made `0700` if it is not there.
    ///
    /// # Errors
    ///
    /// When the directory cannot be made.
    pub fn open(state: &Path) -> Result<Self> {
        let keys = super::keys_under(state);
        make_private_directory(&keys)?;
        let tpm = Tpm::of_this_machine();
        let tpm = match tpm.usable() {
            Ok(()) => {
                tracing::info!("the TPM can hold signing keys: they are made there");
                Some(tpm)
            }
            Err(why) => {
                tracing::warn!(
                    %why,
                    "no usable TPM: signing keys are files sealed with a passphrase"
                );
                None
            }
        };
        Ok(Self { keys, tpm })
    }

    /// The same, with the TPM decided by the caller — for tests.
    #[must_use]
    pub const fn with(keys: PathBuf, tpm: Option<Tpm>) -> Self {
        Self { keys, tpm }
    }

    /// Whether signing keys here are made in the TPM.
    #[must_use]
    pub const fn in_the_tpm(&self) -> bool {
        self.tpm.is_some()
    }

    /// Opens the key called `name`, if there is one.
    fn open_key(&self, name: &str) -> identity::Result<Option<FileCustodian>> {
        let failed = |detail: String| identity::Error::CustodianFailed { detail };
        let Some((path, kind)) = find(&self.keys, name).map_err(failed)? else {
            return Ok(None);
        };
        let bytes =
            std::fs::read(&path).map_err(|cause| failed(format!("{}: {cause}", path.display())))?;
        let public = match kind {
            Kind::Tpm => {
                let stored = Stored::from_bytes(&bytes).map_err(failed)?;
                let Some(tpm) = &self.tpm else {
                    return Err(failed(format!(
                        "the key `{name}` is in a TPM, and this machine's TPM cannot be used now"
                    )));
                };
                // **Loaded, not read**: a key file only this TPM can unwrap is
                // the proof that it is this TPM's key.
                tpm.load_check(&stored).map_err(failed)?
            }
            Kind::Sealed => identity::passphrase::public_of(&bytes)?.as_bytes().to_vec(),
        };
        let algorithm = match kind {
            Kind::Tpm => Algorithm::P256,
            Kind::Sealed => identity::passphrase::public_of(&bytes)?.algorithm(),
        };
        Ok(Some(FileCustodian { public: PublicKey::new(algorithm, public)?, kind }))
    }

    /// The identity already under `paths`, if there is one.
    fn existing(&self, paths: &Paths) -> Result<Option<NodeIdentity>> {
        let path = paths.identity();
        let failed =
            |cause: identity::Error| Error::State { path: path.clone(), cause: cause.to_string() };
        if !path.exists() {
            return Ok(None);
        }
        let held = identity::store::load_with(&path, &identity::store::PlatformSealer, self)
            .map_err(failed)?;

        // A signing key in a plain file: nothing on Linux makes one, and a
        // device that can sign as an admin with a key any root process can read
        // is what this custody exists to prevent. Refused, and left alone.
        let Some(custodian) = held.signing_key().custodian() else {
            return Err(Error::State {
                path,
                cause: "this network's signing key is held in a plain file, and this machine \
                        keeps signing keys behind a passphrase. It is refused rather than \
                        carried: found or join this network again on this device. Nothing has \
                        been changed or removed."
                    .to_owned(),
            });
        };
        // A passphrase file where the TPM could hold the key: the same refusal,
        // for the same reason.
        if self.tpm.is_some()
            && find(&self.keys, custodian.reference()).ok().flatten().map(|(_, kind)| kind)
                == Some(Kind::Sealed)
        {
            return Err(Error::State {
                path,
                cause: "this network's signing key is a file sealed with a passphrase, and this \
                        machine's TPM can hold one where it cannot be copied. It is refused \
                        rather than carried: found or join this network again on this device. \
                        Nothing has been changed or removed."
                    .to_owned(),
            });
        }
        Ok(Some(held))
    }
}

impl Custodians for LinuxKeys {
    fn find(
        &self,
        reference: &str,
    ) -> identity::Result<Option<Arc<dyn KeyCustodian + Send + Sync>>> {
        // **Absent and broken are not the same answer**: a key that is gone is
        // `None`, and `identity` names it and refuses to make another; a key
        // that is there and will not open is the fault it is.
        Ok(self
            .open_key(reference)?
            .map(|held| Arc::new(held) as Arc<dyn KeyCustodian + Send + Sync>))
    }
}

impl Keys for LinuxKeys {
    fn identity(&self, paths: &Paths) -> Result<NodeIdentity> {
        if let Some(held) = self.existing(paths)? {
            return Ok(held);
        }
        Err(Error::State {
            path: paths.identity(),
            cause: "this network has no identity yet, and its signing key must be made where a \
                    person can type its passphrase. Found or join the network from the command \
                    line, with sudo."
                .to_owned(),
        })
    }

    fn must_be_made_elsewhere(&self, paths: &Paths) -> Option<daemon::keys::Asked> {
        if paths.identity().exists() {
            return None;
        }
        let directory =
            paths.root().file_name().and_then(|name| name.to_str()).unwrap_or("network");
        let name = identity::fresh_key_name(directory).ok()?;
        Some(daemon::keys::Asked { name, network: directory.to_owned() })
    }

    fn identity_from(&self, paths: &Paths, made: &daemon::keys::Made) -> Result<NodeIdentity> {
        let path = paths.identity();
        let failed =
            |cause: identity::Error| Error::State { path: path.clone(), cause: cause.to_string() };
        if let Some(held) = self.existing(paths)? {
            return Ok(held);
        }

        // **Read from the key file, not from what was sent.** The name is the
        // daemon's own; opening it here establishes that the key exists and
        // what it is — for a TPM key, by loading it.
        let custodian = self.open_key(&made.name).map_err(failed)?.ok_or_else(|| Error::State {
            path: path.clone(),
            cause: format!("the key `{}` was not made", made.name),
        })?;
        if custodian.public.as_bytes() != made.public.as_slice() {
            return Err(Error::State {
                path,
                cause:
                    "the key that was made is not the key that was reported. Nothing was created."
                        .to_owned(),
            });
        }
        if self.tpm.is_some() && custodian.kind == Kind::Sealed {
            return Err(Error::State {
                path,
                cause: "a key sealed with a passphrase was made where the TPM can hold one. \
                        Nothing was created."
                    .to_owned(),
            });
        }
        paths.create()?;

        let transport = PrivateKey::generate(Algorithm::Ed25519).map_err(failed)?;
        let attestation = PrivateKey::generate(Algorithm::Ed25519).map_err(failed)?;
        let identity = NodeIdentity::with_custodian(
            made.name.clone(),
            Arc::new(custodian) as Arc<dyn KeyCustodian + Send + Sync>,
            transport,
            attestation,
        )
        .map_err(failed)?;
        identity::store::save_with(&identity, &path, &identity::store::PlatformSealer)
            .map_err(failed)?;
        Ok(identity)
    }

    /// Deletes the network's key file, sealed or TPM-wrapped.
    ///
    /// **The one that matters is the sealed file**: it is the network's signing
    /// key behind nothing but its passphrase, and left behind it is a copy
    /// anyone with the disk can try passphrases against for as long as they
    /// like. The TPM file is useless away from this TPM and still goes.
    ///
    /// Deleting unlinks the file; a copy taken before — a backup, an image of
    /// the disk — is out of reach, and the README says so.
    fn forget(&self, paths: &Paths) -> Result<()> {
        let Some(name) = daemon::keys::signing_key_named_in(paths) else { return Ok(()) };
        for kind in [Kind::Tpm, Kind::Sealed] {
            let path = file_for(&self.keys, &name, kind)
                .map_err(|cause| Error::State { path: self.keys.clone(), cause })?;
            match std::fs::remove_file(&path) {
                Ok(()) => tracing::info!(key = %name, "the network's key file was deleted"),
                Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => {}
                Err(cause) => return Err(Error::State { path, cause: cause.to_string() }),
            }
        }
        Ok(())
    }

    fn custody_of(&self, identity: &NodeIdentity) -> daemon::control::Custody {
        let Some(custodian) = identity.signing_key().custodian() else {
            return daemon::control::Custody::HeldHere;
        };
        match find(&self.keys, custodian.reference()) {
            Ok(Some((_, kind))) => kind.custody(),
            // A key the report cannot find the file of is not described as
            // better held than it can be shown to be.
            _ => daemon::control::Custody::Passphrase,
        }
    }
}

/// Makes a directory with mode `0700`, created so rather than tightened.
///
/// # Errors
///
/// When it cannot be made.
pub fn make_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    match std::fs::DirBuilder::new().mode(0o700).recursive(true).create(path) {
        Ok(()) => Ok(()),
        Err(cause) => Err(Error::State { path: path.to_path_buf(), cause: cause.to_string() }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "a test reports failure by panicking")]
mod tests {
    use std::os::unix::fs::OpenOptionsExt as _;

    use super::*;
    use daemon::keys::Made;

    const PASSPHRASE: &[u8] = b"correct horse battery";

    /// A machine with no TPM, and a key sealed in its keys directory as the
    /// command line would have left it.
    fn sealed_machine() -> (tempfile::TempDir, LinuxKeys, Paths, Made) {
        let scratch = tempfile::tempdir().unwrap();
        let keys = scratch.path().join("keys");
        make_private_directory(&keys).unwrap();
        let machine = LinuxKeys::with(keys.clone(), None);
        let paths = Paths::under(scratch.path().join("networks").join("casa"));
        let asked =
            machine.must_be_made_elsewhere(&paths).expect("a network with no identity asks");

        let key = PrivateKey::generate(Algorithm::Ed25519).unwrap();
        let sealed = identity::passphrase::seal(&key, PASSPHRASE).unwrap();
        let path = super::super::file_for(&keys, &asked.name, Kind::Sealed).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        std::io::Write::write_all(&mut file, &sealed).unwrap();

        let made = Made { name: asked.name, public: key.public_key().as_bytes().to_vec() };
        (scratch, machine, paths, made)
    }

    /// **Removing a network deletes its sealed key file**, and only its own: a
    /// second network's file stays, and a file already gone is fine.
    #[test]
    fn forgetting_a_network_deletes_its_key_file_and_no_other() {
        let (scratch, machine, paths, made) = sealed_machine();
        machine.identity_from(&paths, &made).unwrap();
        let keys = scratch.path().join("keys");
        let mine = super::super::file_for(&keys, &made.name, Kind::Sealed).unwrap();
        let other = super::super::file_for(
            &keys,
            "peerfectly.ufficio.0011223344556677.signing",
            Kind::Sealed,
        )
        .unwrap();
        std::fs::write(&other, b"another network's key").unwrap();

        machine.forget(&paths).unwrap();

        assert!(!mine.exists(), "the network's sealed key is gone");
        assert!(other.exists(), "and another network's is not");
        machine.forget(&paths).unwrap();
    }

    /// A network whose identity cannot be read names no key, and forgetting it
    /// deletes nothing rather than guessing.
    #[test]
    fn an_unreadable_identity_names_no_key_and_nothing_is_deleted() {
        let (scratch, machine, paths, made) = sealed_machine();
        let keys = scratch.path().join("keys");
        let mine = super::super::file_for(&keys, &made.name, Kind::Sealed).unwrap();
        paths.create().unwrap();
        std::fs::write(paths.identity(), b"not an identity").unwrap();

        machine.forget(&paths).unwrap();

        assert!(mine.exists(), "nothing named it, so nothing was deleted");
    }

    #[test]
    fn a_sealed_key_makes_an_identity_the_daemon_cannot_sign_with() {
        let (_scratch, machine, paths, made) = sealed_machine();
        let identity = machine.identity_from(&paths, &made).unwrap();
        let custodian = identity.signing_key().custodian().expect("held elsewhere");
        assert_eq!(made.name, custodian.reference());
        assert_eq!(daemon::control::Custody::Passphrase, machine.custody_of(&identity));

        // Loaded again, as the daemon does on every start.
        let again = machine.identity(&paths).unwrap();
        assert_eq!(identity.device_id(), again.device_id());
        assert!(machine.must_be_made_elsewhere(&paths).is_none(), "it has one now");
    }

    /// **The public half is read from the file, not taken from what was sent.**
    #[test]
    fn a_key_that_is_not_the_one_reported_is_refused() {
        let (_scratch, machine, paths, mut made) = sealed_machine();
        made.public =
            PrivateKey::generate(Algorithm::Ed25519).unwrap().public_key().as_bytes().to_vec();
        let refused = machine.identity_from(&paths, &made).unwrap_err().to_string();
        assert!(refused.contains("not the key that was reported"), "{refused}");
        assert!(!paths.identity().exists(), "nothing was created");
    }

    /// **A passphrase file where the TPM could do better is refused**, and left
    /// as it is. The TPM is never reached to decide this, so a TPM that is not
    /// there stands in for one that is.
    #[test]
    fn a_passphrase_file_is_refused_where_a_tpm_can_hold_the_key() {
        let (scratch, machine, paths, made) = sealed_machine();
        machine.identity_from(&paths, &made).unwrap();
        let before = std::fs::read(paths.identity()).unwrap();

        let with_a_tpm = LinuxKeys::with(
            scratch.path().join("keys"),
            Some(Tpm::at(tss_esapi::tcti_ldr::TctiNameConf::Device(Default::default()))),
        );
        let refused = with_a_tpm.identity(&paths).unwrap_err().to_string();
        assert!(
            refused.contains("sealed with a passphrase") && refused.contains("found or join"),
            "{refused}"
        );
        assert_eq!(before, std::fs::read(paths.identity()).unwrap(), "nothing was rewritten");
    }

    /// A signing key in a plain file is refused on Linux whatever the machine:
    /// nothing here makes one.
    #[test]
    fn a_plain_signing_key_is_refused() {
        let (_scratch, machine, paths, _made) = sealed_machine();
        paths.create().unwrap();
        let plain = daemon::state::identity_of(&paths).unwrap();
        assert!(plain.signing_key().custodian().is_none());
        let refused = machine.identity(&paths).unwrap_err().to_string();
        assert!(refused.contains("plain file"), "{refused}");
    }

    /// A key that is gone is named, and nothing is made in its place.
    #[test]
    fn a_missing_key_is_named_and_not_replaced() {
        let (scratch, machine, paths, made) = sealed_machine();
        machine.identity_from(&paths, &made).unwrap();
        for entry in std::fs::read_dir(scratch.path().join("keys")).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        let refused = machine.identity(&paths).unwrap_err().to_string();
        assert!(refused.contains(&made.name), "{refused}");
        assert_eq!(
            0,
            std::fs::read_dir(scratch.path().join("keys")).unwrap().count(),
            "no key was made"
        );
    }

    /// The daemon never signs: whatever asks, the custodian says the signature
    /// is made elsewhere.
    #[test]
    fn the_daemon_cannot_sign() {
        let (_scratch, machine, paths, made) = sealed_machine();
        let identity = machine.identity_from(&paths, &made).unwrap();
        assert!(identity.signing_key().custodian().is_some());
        let held = machine.find(&made.name).unwrap().unwrap();
        assert!(!held.answers_here());
    }
}

//! The command line's side of custody: making a key and signing with it, as
//! root through `sudo`, with the passphrase typed on the terminal.
//!
//! **Root is checked first**, before anything is prepared: the key files and
//! the TPM are root's, and a person running `peerfectly admit` without `sudo` is told
//! so in words rather than after an exchange with the daemon that goes nowhere.
//!
//! **One passphrase per batch.** An act's signatures arrive together and have
//! been shown together by the time this is asked, so the passphrase is asked
//! once and used for every one of them — derived once, given to the TPM for each
//! signature (which checks it each time), and forgotten when the batch is
//! signed. A key made a moment ago is handed back still unlocked, for the
//! daemon's very next answer only.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;

use cli::{Asking, MadeKey, Unlocked};
use daemon::control::KeyWanted;

use super::tpm::{Authorisation, Stored, Tpm};
use super::{Kind, file_for, find, judge_new, prompt};

/// What a person who is not root is told.
pub const USE_SUDO: &str = "this act signs with the network's key, which only root can reach: run it again with sudo. \
     Nothing changed.";

/// How a passphrase is read: from the terminal, with echo off.
pub type Asks = fn(&str) -> std::io::Result<zeroize::Zeroizing<String>>;

/// This machine's custody, from the command line.
pub struct LinuxCustody {
    /// Where the key files are.
    keys: PathBuf,
    /// The TPM keys are made in and used with.
    tpm: Tpm,
    /// How a passphrase is asked for.
    asks: Asks,
}

impl LinuxCustody {
    /// Custody over the machine's own key directory and TPM, asking on the
    /// terminal.
    #[must_use]
    pub fn of_this_machine() -> Self {
        Self::with(
            super::keys_under(std::path::Path::new(crate::home::STATE)),
            Tpm::of_this_machine(),
            prompt::ask,
        )
    }

    /// Custody over a chosen directory and TPM, asking through `asks` — for the
    /// testbed, which has a software TPM and nobody at a terminal.
    #[must_use]
    pub const fn with(keys: PathBuf, tpm: Tpm, asks: Asks) -> Self {
        Self { keys, tpm, asks }
    }

    /// Refuses unless running as root.
    fn as_root() -> Result<(), String> {
        if rustix::process::geteuid().is_root() { Ok(()) } else { Err(USE_SUDO.to_owned()) }
    }
}

/// A TPM key made a moment ago, with the authorisation it was made under.
struct TpmKey {
    /// The TPM it was made in.
    tpm: Tpm,
    /// The key as this TPM wrapped it.
    stored: Stored,
    /// What the passphrase just chosen authorises; zeroised when dropped.
    authorisation: Authorisation,
}

impl Unlocked for TpmKey {
    fn sign_all(&self, messages: &[&[u8]]) -> Result<Vec<Vec<u8>>, String> {
        self.tpm.sign_all(&self.stored, &self.authorisation, messages)
    }
}

/// A key made a moment ago and sealed in a file, still open.
struct SealedKey {
    /// The key; zeroised when dropped, as every `identity` key is.
    key: identity::PrivateKey,
}

impl Unlocked for SealedKey {
    fn sign_all(&self, messages: &[&[u8]]) -> Result<Vec<Vec<u8>>, String> {
        sign_each(&self.key, messages)
    }
}

/// Signs every message with a key held here.
fn sign_each(key: &identity::PrivateKey, messages: &[&[u8]]) -> Result<Vec<Vec<u8>>, String> {
    messages
        .iter()
        .map(|message| key.signer().sign(message).map_err(|cause| cause.to_string()))
        .collect()
}

/// Opens a sealed key file with the passphrase.
fn opened(bytes: &[u8], passphrase: &[u8]) -> Result<identity::PrivateKey, String> {
    identity::passphrase::open(bytes, passphrase).map_err(|cause| match cause {
        identity::Error::WrongPassphraseOrAltered => {
            "the passphrase is wrong, or the key file was changed; nothing was signed".to_owned()
        }
        other => format!("the key would not open, so nothing was signed: {other}"),
    })
}

impl cli::Custody for LinuxCustody {
    fn make_key(&self, wanted: &KeyWanted) -> Result<MadeKey, String> {
        Self::as_root()?;
        let tpm = self.tpm.clone();
        let kind = super::kind_for(tpm.usable().is_ok());
        let path = file_for(&self.keys, &wanted.name, kind)?;

        println!();
        println!("{}", super::before_choosing(kind, &wanted.network));
        println!();
        let first = (self.asks)("Choose a passphrase: ").map_err(|cause| cause.to_string())?;
        let second = (self.asks)("Type it again: ").map_err(|cause| cause.to_string())?;
        judge_new(&first, &second, kind)?;

        let (bytes, public, unlocked): (Vec<u8>, Vec<u8>, Box<dyn Unlocked>) = match kind {
            Kind::Tpm => {
                let stored = tpm.create(first.as_bytes())?;
                let public = stored.public_key()?;
                let authorisation = Authorisation::of(first.as_bytes());
                (stored.to_bytes(), public, Box::new(TpmKey { tpm, stored, authorisation }))
            }
            Kind::Sealed => {
                let key = identity::PrivateKey::generate(roster::types::Algorithm::Ed25519)
                    .map_err(|cause| cause.to_string())?;
                let sealed = identity::passphrase::seal(&key, first.as_bytes())
                    .map_err(|cause| cause.to_string())?;
                let public = key.public_key().as_bytes().to_vec();
                (sealed, public, Box::new(SealedKey { key }))
            }
        };

        // Never over a key that is there: a name is fresh every time, and a
        // file already under it is somebody's, or a key a network depends on.
        super::keys::make_private_directory(&self.keys).map_err(|cause| cause.to_string())?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|cause| format!("{}: {cause}; no key was made", path.display()))?;
        file.write_all(&bytes).and_then(|()| file.sync_all()).map_err(|cause| cause.to_string())?;
        Ok(MadeKey { public, unlocked: Some(unlocked) })
    }

    fn sign_all(&self, asking: &Asking<'_>) -> Result<Vec<Vec<u8>>, String> {
        Self::as_root()?;
        let Some((path, kind)) = find(&self.keys, asking.key)? else {
            return Err(format!(
                "the key `{}` is not on this machine, so nothing was signed",
                asking.key
            ));
        };
        let bytes = std::fs::read(&path).map_err(|cause| format!("{}: {cause}", path.display()))?;

        println!("{}", super::why_it_is_asked(kind, asking.network));
        println!();
        let passphrase = (self.asks)(&super::prompt_for(kind, asking.network))
            .map_err(|cause| cause.to_string())?;
        // **Refused before the TPM is asked**: an empty entry is a person saying
        // no, and offering it to the TPM would count it as a wrong guess.
        if passphrase.is_empty() {
            return Err(super::REFUSED.to_owned());
        }

        match kind {
            Kind::Tpm => {
                let stored = Stored::from_bytes(&bytes)?;
                let authorisation = Authorisation::of(passphrase.as_bytes());
                self.tpm.sign_all(&stored, &authorisation, asking.messages)
            }
            // Opened once for the whole batch: the stretching is the slow part,
            // and it is the same key for every item.
            Kind::Sealed => sign_each(&opened(&bytes, passphrase.as_bytes())?, asking.messages),
        }
    }
}

/// The daemon, over the control socket.
pub struct Socket;

#[async_trait::async_trait]
impl cli::Channel for Socket {
    async fn ask(
        &self,
        command: daemon::control::Command,
    ) -> std::io::Result<daemon::control::Outcome> {
        let mut stream = crate::socket::connect().await?;
        daemon::control::framing::ask(&mut stream, &command).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::{SealedKey, opened, sign_each};
    use cli::Unlocked as _;

    /// **A sealed file is opened once for a batch**, and every signature it
    /// then makes verifies; a wrong passphrase opens nothing and signs nothing.
    #[test]
    fn a_sealed_file_signs_a_whole_batch_from_one_opening() {
        let key = identity::PrivateKey::generate(roster::types::Algorithm::Ed25519).unwrap();
        let public = key.public_key();
        let sealed = identity::passphrase::seal(&key, b"correct horse battery").unwrap();

        let messages: [&[u8]; 3] = [b"revoke", b"admit", b"snapshot"];
        let opened_once = opened(&sealed, b"correct horse battery").unwrap();
        let signatures = sign_each(&opened_once, &messages).unwrap();
        assert_eq!(3, signatures.len());
        for (message, signature) in messages.iter().zip(&signatures) {
            public.verify(message, signature).unwrap();
        }

        let refused = opened(&sealed, b"correct horse batterY").map(|_| ()).unwrap_err();
        assert!(refused.contains("nothing was signed"), "{refused}");
    }

    /// A key made a moment ago signs its batch without being opened again.
    #[test]
    fn a_key_just_sealed_signs_without_asking() {
        let key = identity::PrivateKey::generate(roster::types::Algorithm::Ed25519).unwrap();
        let public = key.public_key();
        let unlocked = SealedKey { key };
        let signatures = unlocked.sign_all(&[b"genesis", b"snapshot"]).unwrap();
        public.verify(b"genesis", signatures.first().unwrap()).unwrap();
        public.verify(b"snapshot", signatures.get(1).unwrap()).unwrap();
    }
}

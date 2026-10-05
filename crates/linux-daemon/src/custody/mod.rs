//! Where a network's signing key lives on Linux, and who can use it.
//!
//! **In the TPM, behind a passphrase**, when the machine has one that can hold
//! it; **in a file sealed with a passphrase** when it has not. Either way the
//! key is only ever used by the command line running as root through `sudo`,
//! with the person typing the passphrase — never by the daemon, which prepares
//! what is to be signed and checks what comes back, as on every platform.
//!
//! The keys are files in `/var/lib/peerfectly/keys`, one per key, named as the key
//! store names them on Windows and marked by kind:
//!
//! | file | what it is | what taking it gives |
//! |---|---|---|
//! | `<name>.tpm` | the key as this TPM wrapped it | nothing on another machine; here, a key that still needs the passphrase and counts wrong ones |
//! | `<name>.sealed` | the key sealed with the passphrase (`identity::passphrase`) | as many guesses as the taker's hardware allows |
//!
//! A machine whose TPM can hold a key refuses a network whose key is a
//! `.sealed` file: the weaker custody is for machines that have nothing better,
//! and carrying it where the TPM could do better would be keeping the finding
//! the TPM closes.

use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
pub mod command_line;
#[cfg(target_os = "linux")]
pub mod keys;
#[cfg(target_os = "linux")]
pub mod prompt;
#[cfg(target_os = "linux")]
pub mod tpm;

/// The directory keys live in, under the state directory.
pub const KEYS: &str = "keys";

/// How a key is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// In the TPM.
    Tpm,
    /// In a file sealed with the passphrase.
    Sealed,
}

impl Kind {
    /// The file's extension.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Tpm => "tpm",
            Self::Sealed => "sealed",
        }
    }

    /// The shortest passphrase this custody accepts, in characters.
    ///
    /// **Longer for the file**, because only the file can be attacked away from
    /// the machine: the TPM counts wrong guesses and stops answering, and the
    /// file answers every guess.
    #[must_use]
    pub const fn minimum(self) -> usize {
        match self {
            Self::Tpm => 8,
            Self::Sealed => 12,
        }
    }

    /// What the report says of it.
    #[must_use]
    pub const fn custody(self) -> daemon::control::Custody {
        match self {
            Self::Tpm => daemon::control::Custody::KeyStore,
            Self::Sealed => daemon::control::Custody::Passphrase,
        }
    }
}

/// The custody a machine makes keys in: the TPM when its probe passed, a
/// sealed file when it did not.
#[must_use]
pub const fn kind_for(tpm_usable: bool) -> Kind {
    if tpm_usable { Kind::Tpm } else { Kind::Sealed }
}

/// Where the keys live, under a state directory.
#[must_use]
pub fn keys_under(state: &Path) -> PathBuf {
    state.join(KEYS)
}

/// The file a key of this kind and name is kept in.
///
/// # Errors
///
/// When the name could lead anywhere but a file in the directory.
pub fn file_for(keys: &Path, name: &str, kind: Kind) -> Result<PathBuf, String> {
    let acceptable = !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        && !name.starts_with('.');
    if !acceptable {
        return Err(format!("`{name}` is not a key's name"));
    }
    Ok(keys.join(format!("{name}.{}", kind.extension())))
}

/// Which file holds a key, and of which kind, looking at the directory.
///
/// # Errors
///
/// When the name is not a key's name.
pub fn find(keys: &Path, name: &str) -> Result<Option<(PathBuf, Kind)>, String> {
    for kind in [Kind::Tpm, Kind::Sealed] {
        let path = file_for(keys, name, kind)?;
        if path.is_file() {
            return Ok(Some((path, kind)));
        }
    }
    Ok(None)
}

/// A new passphrase, typed twice, judged before any key is made.
///
/// # Errors
///
/// When the two differ, or it is shorter than the custody's minimum.
pub fn judge_new(first: &str, second: &str, kind: Kind) -> Result<(), String> {
    if first != second {
        return Err("the two passphrases differ; no key was made".to_owned());
    }
    let length = first.chars().count();
    if length < kind.minimum() {
        return Err(format!(
            "a passphrase for {} needs at least {} characters, and this has {length}; no key \
             was made",
            match kind {
                Kind::Tpm => "a key in the TPM",
                Kind::Sealed => "a key sealed in a file",
            },
            kind.minimum()
        ));
    }
    Ok(())
}

/// How a network is named to a person: as this machine names it, or — while it
/// is being joined and has no name here yet — as the one being joined.
fn named(network: &str) -> String {
    if network.is_empty() { "the network being joined".to_owned() } else { format!("`{network}`") }
}

/// What a person is told before choosing a passphrase, for each custody.
#[must_use]
pub fn before_choosing(kind: Kind, network: &str) -> String {
    let joining = network.is_empty();
    let network = named(network);
    let held = match kind {
        Kind::Tpm => format!(
            "Making the signing key for {network} inside this machine's TPM. It never leaves \
             it, and the TPM itself will ask for this passphrase every time the key signs; after \
             too many wrong ones it stops answering for a while."
        ),
        Kind::Sealed => format!(
            "This machine has no TPM that can hold the key, so the signing key for {network} \
             will be a file sealed with this passphrase. Whoever obtains that file can try \
             passphrases away from this machine for as long as they like: the passphrase is the \
             whole of the protection. Choose a long one."
        ),
    };
    if joining {
        return format!(
            "{held}\n\nYou will type it once more in a moment, when this device proves to the \
             admitting one that it holds this key, and again for any admin act it signs if it is \
             ever made an admin. It cannot be recovered."
        );
    }
    format!(
        "{held}\n\nYou will type it every time this machine signs an admin act for {network}: \
         admitting a device, revoking one, changing its settings. It cannot be recovered: a \
         network whose only admin forgets it can no longer be administered."
    )
}

/// Why a passphrase is about to be asked for, and how to refuse — said after
/// the acts are listed and before the prompt.
#[must_use]
pub fn why_it_is_asked(kind: Kind, network: &str) -> String {
    let network = named(network);
    let held = match kind {
        Kind::Tpm => format!(
            "The signing key for {network} is in this machine's TPM, and your passphrase is \
             what unlocks it."
        ),
        Kind::Sealed => format!(
            "The signing key for {network} is in a file on this machine sealed with your \
             passphrase, and the passphrase is what unlocks it."
        ),
    };
    format!("{held} Nothing is signed without it. Press Enter on an empty line to refuse.")
}

/// The prompt itself: whose passphrase, and where its key is.
#[must_use]
pub fn prompt_for(kind: Kind, network: &str) -> String {
    let held = match kind {
        Kind::Tpm => "TPM",
        Kind::Sealed => "sealed file",
    };
    let network = if network.is_empty() { "the network being joined" } else { network };
    format!("Passphrase for {network} ({held}): ")
}

/// What a person who pressed Enter on an empty line is told: nothing was
/// signed, and nothing was guessed either.
pub const REFUSED: &str = "not signed. Nothing changed.";

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// **The file's minimum is longer than the TPM's**, because only the file
    /// can be attacked away from the machine.
    #[test]
    fn a_file_asks_for_more_than_the_tpm() {
        assert!(Kind::Sealed.minimum() > Kind::Tpm.minimum());
        assert!(judge_new("12345678", "12345678", Kind::Tpm).is_ok());
        assert!(judge_new("12345678", "12345678", Kind::Sealed).is_err());
        assert!(judge_new("twelve chars", "twelve chars", Kind::Sealed).is_ok());
    }

    #[test]
    fn a_passphrase_is_counted_in_characters() {
        // Eight characters, sixteen bytes: a non-ASCII passphrase is not
        // penalised for its encoding.
        assert!(judge_new("àèìòùàèì", "àèìòùàèì", Kind::Tpm).is_ok());
        assert!(judge_new("àèìòùàè", "àèìòùàè", Kind::Tpm).is_err());
    }

    #[test]
    fn two_different_passphrases_make_nothing() {
        let said =
            judge_new("correct horse battery", "correct horse batterY", Kind::Tpm).unwrap_err();
        assert!(said.contains("differ"), "{said}");
    }

    #[test]
    fn a_name_cannot_lead_out_of_the_directory() {
        let keys = Path::new("/var/lib/peerfectly/keys");
        assert_eq!(
            PathBuf::from("/var/lib/peerfectly/keys/peerfectly.casa.0123456789abcdef.signing.tpm"),
            // A key's name with sixteen example hex digits, not a secret.
            file_for(keys, "peerfectly.casa.0123456789abcdef.signing", Kind::Tpm).unwrap() // gitleaks:allow
        );
        for bad in ["", "../etc/shadow", "a/b", ".hidden", "a b"] {
            assert!(file_for(keys, bad, Kind::Sealed).is_err(), "{bad}");
        }
    }

    /// No TPM that can hold a key means a sealed file, and never a key that is
    /// not behind a passphrase at all.
    #[test]
    fn without_a_usable_tpm_keys_are_sealed_files() {
        assert_eq!(Kind::Tpm, kind_for(true));
        assert_eq!(Kind::Sealed, kind_for(false));
    }

    /// The report never calls a passphrase a key store.
    #[test]
    fn the_file_is_reported_as_a_passphrase() {
        assert_eq!(daemon::control::Custody::Passphrase, Kind::Sealed.custody());
        assert_eq!(daemon::control::Custody::KeyStore, Kind::Tpm.custody());
    }

    #[test]
    fn the_file_custody_says_what_it_does_not_defend_against() {
        let said = before_choosing(Kind::Sealed, "casa");
        assert!(
            said.contains("away from this machine") && said.contains("whole of the protection")
        );
    }

    /// **Making a key says what the passphrase is for**, and that it cannot be
    /// recovered.
    #[test]
    fn making_a_key_says_what_the_passphrase_is_for() {
        for kind in [Kind::Tpm, Kind::Sealed] {
            let said = before_choosing(kind, "casa");
            assert!(
                said.contains("every time this machine signs an admin act for `casa`"),
                "{said}"
            );
            assert!(said.contains("cannot be recovered"), "{said}");
        }
    }

    /// **The prompt names the network and where its key is**, so a person with
    /// two networks knows whose passphrase is wanted.
    #[test]
    fn the_prompt_names_the_network_and_the_custody() {
        assert_eq!("Passphrase for ufficio (TPM): ", prompt_for(Kind::Tpm, "ufficio"));
        assert_eq!("Passphrase for casa (sealed file): ", prompt_for(Kind::Sealed, "casa"));

        let why = why_it_is_asked(Kind::Tpm, "ufficio");
        assert!(why.contains("`ufficio`") && why.contains("TPM"), "{why}");
        assert!(why.contains("empty line to refuse"), "{why}");
        let why = why_it_is_asked(Kind::Sealed, "casa");
        assert!(why.contains("sealed with your passphrase"), "{why}");
    }

    /// **A network being joined has no name here yet**, and the text says so
    /// rather than showing the placeholder it waits under — and does not tell a
    /// joining member it will sign admin acts.
    #[test]
    fn a_network_being_joined_is_called_that() {
        assert_eq!("Passphrase for the network being joined (TPM): ", prompt_for(Kind::Tpm, ""));
        let why = why_it_is_asked(Kind::Tpm, "");
        assert!(why.contains("The signing key for the network being joined"), "{why}");
        let said = before_choosing(Kind::Tpm, "");
        assert!(said.contains("for the network being joined"), "{said}");
        assert!(said.contains("proves to the admitting one"), "{said}");
        assert!(!said.contains("every time this machine signs an admin act"), "{said}");
    }
}

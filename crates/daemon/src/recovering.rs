//! Recovery: this device made an admin of its network with the founder's words.
//!
//! A member holds no signing key, and a device's keys never change, so a member
//! made an admin is a new device: a fresh identity, admitted by the founder in
//! the same batch that revokes the member's old one and the admins named. The
//! new identity is made as a join makes one, in a directory of its own under a
//! label of its own ([`temporary`]), so every platform names and keeps its key
//! exactly as it does for a join. Once the batch is in the old directory's log,
//! the roster is copied across, the old identity's keys are forgotten, and the
//! new directory takes the old one's place.
//!
//! # A stop at any point
//!
//! The batch admitted into the log is the decision. Before it, a stop leaves a
//! directory holding a new identity and no note, which the next start discards
//! with every other attempt that founded nothing. After it, the new directory
//! carries a note naming the network it replaces ([`Note`]), signed by this
//! machine's key and written before anything is copied. The network is closed
//! first, so no file of its is held open while it is copied or moved. The next
//! start finishes the swap from wherever it stopped ([`finish_interrupted`]):
//! copy again, forget the old keys, remove the old directory, rename the new
//! one.
//!
//! # Believed only through the machine's signature
//!
//! Finishing a swap forgets keys and removes a directory, so a note is believed
//! only when this machine signed it, the identity beside it is the one it
//! names, and the network's log admits that identity (`recovery-repairs`
//! design §2). A directory planted with a note file removes nothing. The
//! network's checkpoint travels with its roster, so the directory that takes
//! the network's place is vouched for as the old one was.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::checkpoint::MachineKey;
use crate::error::{Error, Result};
use crate::networks::{Home, Label};
use crate::state::Paths;

/// The note in a recovering directory naming the network it replaces.
pub const NOTE: &str = "recovering-for";

/// The suffix of the label a recovering identity is made under.
pub const SUFFIX: &str = "-recovering";

/// The context every note's signature is made under, so the machine key's
/// signature over a note can never be read as a checkpoint or a join, nor
/// theirs as a note.
const CONTEXT: &[u8] = b"peerfectly recovering v1\0";

/// What a recovering directory is for, as this machine signed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    /// The label of the network it replaces.
    pub label: String,
    /// That network, in hex.
    pub network: String,
    /// The device id of the identity it holds, in hex.
    pub device: String,
}

impl Note {
    /// The note for a recovery of `label`, in `network`, to `device`.
    #[must_use]
    pub fn new(
        label: &Label,
        network: &roster::id::NetworkId,
        device: &roster::id::DeviceId,
    ) -> Self {
        Self {
            label: label.to_string(),
            network: roster::hex::encode(network.as_bytes()),
            device: roster::hex::encode(device.as_bytes()),
        }
    }
}

/// The note and its signature, as written.
#[derive(Debug, Serialize, Deserialize)]
struct Stored {
    body: String,
    signature: String,
}

/// What is signed for `body`.
fn signed(body: &[u8]) -> Vec<u8> {
    let mut message = CONTEXT.to_vec();
    message.extend_from_slice(body);
    message
}

/// Signs `note` with `key` and keeps it in the recovering directory `paths`.
///
/// # Errors
///
/// When the key will not sign or the file cannot be written.
pub fn write_note(paths: &Paths, key: &dyn MachineKey, note: &Note) -> Result<()> {
    let path = paths.root().join(NOTE);
    let failed = |cause: String| Error::State { path: path.clone(), cause };
    let body = serde_json::to_string(note).map_err(|cause| failed(cause.to_string()))?;
    let signature = key.sign(&signed(body.as_bytes())).map_err(failed)?;
    let stored = Stored { body, signature: roster::hex::encode(&signature) };
    let bytes = serde_json::to_vec_pretty(&stored).map_err(|cause| failed(cause.to_string()))?;
    crate::state::replace_file(&path, &bytes)
}

/// Whether `paths` carries a note: a recovery decided, finished or reported at
/// start, and never surveyed as a network of its own.
#[must_use]
pub fn carries_note(paths: &Paths) -> bool {
    paths.root().join(NOTE).exists()
}

/// The note in `paths`, if this machine signed it.
///
/// # Errors
///
/// Why it is not believed, as a sentence.
pub fn read_note(paths: &Paths, key: &dyn MachineKey) -> core::result::Result<Note, String> {
    let bytes = std::fs::read(paths.root().join(NOTE))
        .map_err(|cause| format!("its note could not be read: {cause}"))?;
    let stored: Stored = serde_json::from_slice(&bytes)
        .map_err(|_| "its note is not one this daemon wrote".to_owned())?;
    let signature = roster::hex::decode(&stored.signature)
        .ok_or_else(|| "its note carries no signature".to_owned())?;
    key.public()
        .verify(&signed(stored.body.as_bytes()), &signature)
        .map_err(|_| "its note was not signed by this machine".to_owned())?;
    serde_json::from_str(&stored.body).map_err(|_| "its note does not read".to_owned())
}

/// The label a recovery of `label` makes its new identity under.
///
/// # Errors
///
/// When the label with the suffix is not a usable label.
pub fn temporary(label: &Label) -> Result<Label> {
    Label::new(&format!("{label}{SUFFIX}")).map_err(|cause| Error::State {
        path: std::path::PathBuf::from(label.as_str()),
        cause: cause.to_string(),
    })
}

/// The files of a network's directory that are the network's, not the
/// device's: what moves to the new identity's directory.
fn carried(paths: &Paths) -> Vec<std::path::PathBuf> {
    vec![
        paths.roster(),
        paths.pieces(),
        paths.snapshot(),
        paths.snapshot_at(),
        paths.base_snapshot(),
        paths.base_store(),
        paths.layers(),
        paths.attestation(),
        paths.attestation_at(),
        paths.attestation_dating(),
        paths.attestation_dating_at(),
        paths.endpoints(),
        paths.record(),
        paths.owner(),
        paths.owner_taken(),
        paths.choice(),
        paths.known(),
        paths.neighbours_in(),
        // Last: never ahead of what it vouches for.
        paths.checkpoint(),
    ]
}

/// Copies a file or a directory, replacing what is there.
fn copy_over(from: &Path, to: &Path) -> std::io::Result<()> {
    if from.is_dir() {
        std::fs::create_dir_all(to)?;
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            copy_over(&entry.path(), &to.join(entry.file_name()))?;
        }
        return Ok(());
    }
    std::fs::copy(from, to).map(|_| ())
}

/// Moves the network from `old` to `new`, whose identity replaces the old one,
/// and puts `new` where `old` was. Every step can be repeated: a stop anywhere
/// is finished by doing it again.
///
/// The note is written before, by whoever decided the swap ([`write_note`]),
/// and the network closed: nothing may hold a file of it open.
///
/// # Errors
///
/// When a file will not copy, a key will not go, or a directory will not move.
pub fn swap(home: &Home, label: &Label, keys: &dyn crate::keys::Keys) -> Result<()> {
    let old = home.paths_for(label);
    let new = home.paths_for(&temporary(label)?);
    let state = |path: &Path, cause: std::io::Error| Error::State {
        path: path.to_path_buf(),
        cause: cause.to_string(),
    };
    if old.root().exists() {
        for (from, to) in carried(&old).into_iter().zip(carried(&new)) {
            if from.exists() {
                copy_over(&from, &to).map_err(|cause| state(&from, cause))?;
            }
        }
        keys.forget(&old)?;
        std::fs::remove_dir_all(old.root()).map_err(|cause| state(old.root(), cause))?;
    }
    std::fs::rename(new.root(), old.root()).map_err(|cause| state(new.root(), cause))?;
    let note = old.root().join(NOTE);
    if note.exists() {
        std::fs::remove_file(&note).map_err(|cause| state(&note, cause))?;
    }
    Ok(())
}

/// What became of the swaps a stop interrupted.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Finished {
    /// The networks now carried under their new identity.
    pub finished: Vec<Label>,
    /// The recovering directories left as they are, by name, and why: nothing
    /// was forgotten, removed or renamed for them.
    pub refused: Vec<(String, String)>,
}

/// Finishes every swap a stop interrupted: each directory carrying a note this
/// machine signed, whose identity is the one the note names and whose
/// admission the network's log holds. Any other is left as it is, and said.
///
/// `machine` is this machine's key; without it nothing is believed, and every
/// recovering directory is reported.
///
/// # Errors
///
/// As [`swap`], for a swap that was believed.
pub fn finish_interrupted(
    home: &Home,
    keys: &dyn crate::keys::Keys,
    machine: Option<&dyn MachineKey>,
) -> Result<Finished> {
    let mut done = Finished::default();
    let Ok(entries) = std::fs::read_dir(home.networks()) else { return Ok(done) };
    for entry in entries.flatten() {
        let paths = Paths::under(entry.path());
        if !carries_note(&paths) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        match believed(home, &paths, &name, keys, machine) {
            Ok(label) => {
                swap(home, &label, keys)?;
                done.finished.push(label);
            }
            Err(why) => done.refused.push((name, why)),
        }
    }
    Ok(done)
}

/// The network a recovering directory replaces, where everything about it is
/// what this machine decided; why not, otherwise.
fn believed(
    home: &Home,
    paths: &Paths,
    name: &str,
    keys: &dyn crate::keys::Keys,
    machine: Option<&dyn MachineKey>,
) -> core::result::Result<Label, String> {
    let machine = machine.ok_or_else(|| "this machine's key will not open".to_owned())?;
    let note = read_note(paths, machine)?;
    let label = Label::new(&note.label).map_err(|cause| cause.to_string())?;
    let expected = temporary(&label).map_err(|cause| cause.to_string())?;
    if expected.as_str() != name {
        return Err("its note names another network's recovery".to_owned());
    }
    // Asked whether it is there first: a missing one would be made.
    if !paths.identity().exists() {
        return Err("it holds no identity".to_owned());
    }
    let identity =
        keys.identity(paths).map_err(|cause| format!("its identity will not open: {cause}"))?;
    let device = identity.device_id();
    if roster::hex::encode(device.as_bytes()) != note.device {
        return Err("it holds another identity than the one its note names".to_owned());
    }
    // The log the batch went into: the old directory's while it is there, and
    // the copy once it has gone.
    let old = home.paths_for(&label);
    let log = if old.root().exists() { old.roster() } else { paths.roster() };
    let operations = crate::state::Log::at(log).read().map_err(|cause| cause.to_string())?;
    let admitted = operations.iter().any(|bytes| {
        roster::sign::RawOperation::decode(bytes).is_ok_and(|raw| {
            roster::hex::encode(raw.core().network.as_bytes()) == note.network
                && matches!(
                    &raw.core().body,
                    roster::types::OperationBody::AddDevice(spec)
                        if spec.device_id().ok() == Some(device)
                )
        })
    });
    if !admitted {
        return Err("the network's log does not admit the identity its note names".to_owned());
    }
    Ok(label)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use roster::id::NetworkId;
    use roster::sign::sign_operation;
    use roster::types::{OperationBody, OperationCore, Role};

    use super::*;
    use crate::checkpoint::SoftwareKey;

    fn home() -> (Home, tempfile::TempDir) {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");
        (home, scratch)
    }

    fn machine(home: &Home) -> SoftwareKey {
        SoftwareKey::at(home.root()).expect("a key").0
    }

    const NETWORK: NetworkId = NetworkId::from_bytes([7; 32]);

    /// A directory holding a real identity, and a log admitting `admitted`.
    fn network_dir(
        home: &Home,
        label: &Label,
        admitted: Option<&identity::NodeIdentity>,
    ) -> identity::NodeIdentity {
        let paths = home.paths_for(label);
        paths.create().expect("creates");
        let made = crate::state::identity_of(&paths).expect("an identity");
        if let Some(admitted) = admitted {
            let core = OperationCore::new(
                1,
                made.signing_key().algorithm(),
                OperationBody::AddDevice(
                    admitted.device_spec("pc", Role::Admin, vec![]).expect("spec"),
                ),
                vec![],
                made.signing_key().key_id(),
                NETWORK,
            )
            .expect("core");
            crate::state::Log::at(paths.roster())
                .append(&sign_operation(&core, made.signer()).expect("signs"))
                .expect("appends");
        }
        made
    }

    /// A recovery decided: the new identity, admitted in the old log, with its
    /// note signed by `key`.
    fn decided(home: &Home, key: &dyn MachineKey) -> (Label, identity::NodeIdentity) {
        let label = Label::new("casa").expect("a label");
        let temp = temporary(&label).expect("temporary");
        let new = network_dir(home, &temp, None);
        let _old = network_dir(home, &label, Some(&new));
        let note = Note::new(&label, &NETWORK, &new.device_id());
        write_note(&home.paths_for(&temp), key, &note).expect("writes");
        (label, new)
    }

    /// The new identity takes the old one's place, with the old network's log
    /// and its checkpoint.
    #[test]
    fn the_new_identity_takes_the_old_ones_place_with_its_roster() {
        let (home, _scratch) = home();
        let key = machine(&home);
        let (label, new) = decided(&home, &key);
        let paths = home.paths_for(&label);
        std::fs::write(paths.checkpoint(), b"the old checkpoint").expect("writes");
        let log = std::fs::read(paths.roster()).expect("reads");

        swap(&home, &label, &crate::keys::PlatformKeys).expect("swaps");

        assert_eq!(
            crate::state::identity_of(&paths).expect("an identity").device_id(),
            new.device_id()
        );
        assert_eq!(std::fs::read(paths.roster()).expect("reads"), log);
        assert_eq!(std::fs::read(paths.checkpoint()).expect("reads"), b"the old checkpoint");
        assert!(!home.paths_for(&temporary(&label).expect("temporary")).root().exists());
        assert!(!paths.root().join(NOTE).exists(), "the note goes when it is done");
    }

    /// Stopped after the old directory went and before the rename: the next
    /// start finishes it, from the log carried across.
    #[test]
    fn a_swap_stopped_halfway_is_finished_on_the_next_start() {
        let (home, _scratch) = home();
        let key = machine(&home);
        let (label, new) = decided(&home, &key);
        let temp = home.paths_for(&temporary(&label).expect("temporary"));
        std::fs::copy(home.paths_for(&label).roster(), temp.roster()).expect("copies");
        std::fs::remove_dir_all(home.paths_for(&label).root()).expect("removes");

        let done =
            finish_interrupted(&home, &crate::keys::PlatformKeys, Some(&key)).expect("finishes");

        assert_eq!(done.finished, vec![label.clone()]);
        assert!(done.refused.is_empty());
        assert_eq!(
            crate::state::identity_of(&home.paths_for(&label)).expect("one").device_id(),
            new.device_id()
        );
    }

    /// Without the note, nothing was decided: nothing is finished.
    #[test]
    fn without_the_note_nothing_is_finished() {
        let (home, _scratch) = home();
        let key = machine(&home);
        let label = Label::new("casa").expect("a label");
        let new = network_dir(&home, &temporary(&label).expect("temporary"), None);
        let old = network_dir(&home, &label, Some(&new));

        let done =
            finish_interrupted(&home, &crate::keys::PlatformKeys, Some(&key)).expect("reads");

        assert_eq!(done, Finished::default());
        assert_eq!(
            crate::state::identity_of(&home.paths_for(&label)).expect("one").device_id(),
            old.device_id()
        );
    }

    /// **A planted recovering directory removes nothing**: a note file this
    /// machine did not sign — plain text, as 0.6.0 wrote it, or signed by
    /// another key — leaves the network, its directory and its keys as they
    /// were, and is reported.
    #[test]
    fn a_planted_recovering_directory_removes_nothing() {
        let (home, _scratch) = home();
        let key = machine(&home);
        let other = tempfile::tempdir().expect("a scratch directory");
        let stranger = SoftwareKey::at(other.path()).expect("a key").0;
        for plant in ["plain", "stranger"] {
            let (label, _new) = decided(&home, &stranger);
            let temp = home.paths_for(&temporary(&label).expect("temporary"));
            if plant == "plain" {
                std::fs::write(temp.root().join(NOTE), "casa").expect("writes");
            }
            let held = std::fs::read(home.paths_for(&label).identity()).expect("reads");

            let done =
                finish_interrupted(&home, &crate::keys::PlatformKeys, Some(&key)).expect("reads");

            assert!(done.finished.is_empty(), "{plant}");
            assert_eq!(done.refused.len(), 1, "{plant}: said");
            assert_eq!(
                std::fs::read(home.paths_for(&label).identity()).expect("still there"),
                held,
                "{plant}: the network is as it was"
            );
            assert!(temp.root().exists(), "{plant}: the planted directory is left for a person");
            std::fs::remove_dir_all(temp.root()).expect("removes");
            std::fs::remove_dir_all(home.paths_for(&label).root()).expect("removes");
        }
    }

    /// A note naming another identity than the one beside it is refused.
    #[test]
    fn a_note_naming_another_identity_is_refused() {
        let (home, _scratch) = home();
        let key = machine(&home);
        let (label, _new) = decided(&home, &key);
        let temp = home.paths_for(&temporary(&label).expect("temporary"));
        let someone = identity::NodeIdentity::generate().expect("generates");
        write_note(&temp, &key, &Note::new(&label, &NETWORK, &someone.device_id()))
            .expect("writes");

        let done =
            finish_interrupted(&home, &crate::keys::PlatformKeys, Some(&key)).expect("reads");

        assert!(done.finished.is_empty());
        assert!(done.refused.first().is_some_and(|(_, why)| why.contains("another identity")));
        assert!(home.paths_for(&label).root().exists(), "nothing removed");
    }

    /// A note whose identity the network's log never admitted is refused: the
    /// batch was not kept.
    #[test]
    fn a_note_the_log_does_not_bear_out_is_refused() {
        let (home, _scratch) = home();
        let key = machine(&home);
        let label = Label::new("casa").expect("a label");
        let temp = temporary(&label).expect("temporary");
        let new = network_dir(&home, &temp, None);
        let _old = network_dir(&home, &label, None);
        write_note(&home.paths_for(&temp), &key, &Note::new(&label, &NETWORK, &new.device_id()))
            .expect("writes");

        let done =
            finish_interrupted(&home, &crate::keys::PlatformKeys, Some(&key)).expect("reads");

        assert!(done.finished.is_empty());
        assert!(done.refused.first().is_some_and(|(_, why)| why.contains("does not admit")));
    }

    /// A checkpoint's signature is never read as a note's: the contexts differ.
    #[test]
    fn a_checkpoint_signature_is_not_a_note() {
        let (home, _scratch) = home();
        let key = machine(&home);
        let paths = home.paths_for(&Label::new("x").expect("a label"));
        paths.create().expect("creates");
        let body = serde_json::to_string(&Note {
            label: "casa".to_owned(),
            network: String::new(),
            device: String::new(),
        })
        .expect("encodes");
        let mut message = b"peerfectly checkpoint v1\0".to_vec();
        message.extend_from_slice(body.as_bytes());
        let signature = key.sign(&message).expect("signs");
        let stored = Stored { body, signature: roster::hex::encode(&signature) };
        std::fs::write(paths.root().join(NOTE), serde_json::to_vec(&stored).expect("encodes"))
            .expect("writes");

        assert!(read_note(&paths, &key).is_err());
    }
}

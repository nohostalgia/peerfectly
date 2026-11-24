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
//! directory holding a new identity and no record, which the next start
//! discards with every other attempt that founded nothing. After it, the new
//! directory carries a note naming the network it replaces ([`NOTE`]), written
//! before anything is copied, and the next start finishes the swap from
//! wherever it stopped ([`finish_interrupted`]): copy again, forget the old
//! keys, remove the old directory, rename the new one.

use std::path::Path;

use crate::error::{Error, Result};
use crate::networks::{Home, Label};
use crate::state::Paths;

/// The note in a recovering directory naming the network it replaces.
pub const NOTE: &str = "recovering-for";

/// The suffix of the label a recovering identity is made under.
pub const SUFFIX: &str = "-recovering";

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
    std::fs::write(new.root().join(NOTE), label.as_str())
        .map_err(|cause| state(new.root(), cause))?;
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

/// Finishes every swap a stop interrupted: each directory carrying the note.
///
/// # Errors
///
/// As [`swap`].
pub fn finish_interrupted(home: &Home, keys: &dyn crate::keys::Keys) -> Result<Vec<Label>> {
    let mut finished = Vec::new();
    let Ok(entries) = std::fs::read_dir(home.networks()) else { return Ok(finished) };
    for entry in entries.flatten() {
        let note = entry.path().join(NOTE);
        let Ok(for_label) = std::fs::read_to_string(&note) else { continue };
        let Ok(label) = Label::new(for_label.trim()) else { continue };
        swap(home, &label, keys)?;
        finished.push(label);
    }
    Ok(finished)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> (Home, tempfile::TempDir) {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");
        (home, scratch)
    }

    fn network_dir(home: &Home, label: &Label, identity: &[u8], roster: &[u8]) {
        let paths = home.paths_for(label);
        paths.create().expect("creates");
        std::fs::write(paths.identity(), identity).expect("writes");
        std::fs::write(paths.roster(), roster).expect("writes");
    }

    /// The new identity takes the old one's place, with the old network's log.
    #[test]
    fn the_new_identity_takes_the_old_ones_place_with_its_roster() {
        let (home, _scratch) = home();
        let label = Label::new("casa").expect("a label");
        network_dir(&home, &label, b"old identity", b"the log with the batch");
        network_dir(&home, &temporary(&label).expect("temporary"), b"new identity", b"");

        swap(&home, &label, &crate::keys::PlatformKeys).expect("swaps");

        let paths = home.paths_for(&label);
        assert_eq!(std::fs::read(paths.identity()).expect("reads"), b"new identity");
        assert_eq!(std::fs::read(paths.roster()).expect("reads"), b"the log with the batch");
        assert!(!home.paths_for(&temporary(&label).expect("temporary")).root().exists());
        assert!(!paths.root().join(NOTE).exists(), "the note goes when it is done");
    }

    /// Stopped after the old directory went and before the rename: the next
    /// start finishes it.
    #[test]
    fn a_swap_stopped_halfway_is_finished_on_the_next_start() {
        let (home, _scratch) = home();
        let label = Label::new("casa").expect("a label");
        let temp = temporary(&label).expect("temporary");
        network_dir(&home, &temp, b"new identity", b"the log with the batch");
        std::fs::write(home.paths_for(&temp).root().join(NOTE), "casa").expect("writes");

        let finished = finish_interrupted(&home, &crate::keys::PlatformKeys).expect("finishes");

        assert_eq!(finished, vec![label.clone()]);
        let paths = home.paths_for(&label);
        assert_eq!(std::fs::read(paths.identity()).expect("reads"), b"new identity");
        assert_eq!(std::fs::read(paths.roster()).expect("reads"), b"the log with the batch");
    }

    /// Without the note, nothing was decided: nothing is finished.
    #[test]
    fn without_the_note_nothing_is_finished() {
        let (home, _scratch) = home();
        let label = Label::new("casa").expect("a label");
        network_dir(&home, &label, b"old identity", b"log");
        network_dir(&home, &temporary(&label).expect("temporary"), b"new identity", b"");

        assert!(finish_interrupted(&home, &crate::keys::PlatformKeys).expect("reads").is_empty());
        assert_eq!(
            std::fs::read(home.paths_for(&label).identity()).expect("reads"),
            b"old identity"
        );
    }
}

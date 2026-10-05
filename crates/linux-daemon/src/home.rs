//! Where the machine keeps its networks, and where the daemon may run from.
//!
//! # The state directory
//!
//! `/var/lib/peerfectly`, owned by root and readable by nobody else. It is **created
//! with that mode**, not created and then tightened — however brief, a window in
//! which the directory is open is one somebody can wait for — and the owner and
//! mode of the directory actually used are **read back**, because a directory
//! that was already there, or one systemd made, is only as protected as it turns
//! out to be.
//!
//! What is inside keeps `identity`'s Unix row: `0600` files, refused when looser.
//!
//! # The location check
//!
//! A root process started from a place an ordinary account can write is a root
//! process somebody else chooses the code for: they replace the executable and
//! wait. So every directory from the executable's up to `/` must be owned by
//! root and writable by nobody else — a sticky world-writable directory
//! included, since the sticky bit stops deletion of others' files, not the
//! creation of a new one where the executable's path leads.
//!
//! The override is [`crate::ALLOW_UNSAFE_LOCATION`], for a build directory, and
//! taking it is warned every time, as on Windows.

use std::path::{Path, PathBuf};

/// Where the machine's state lives.
pub const STATE: &str = "/var/lib/peerfectly";

/// Whether a directory's owner and mode are what the state directory requires:
/// root's, and nothing for group or others.
///
/// # Errors
///
/// When they are not, naming the directory and what was found.
pub fn judge_state(path: &Path, owner: u32, mode: u32) -> Result<(), String> {
    if owner != 0 {
        return Err(format!(
            "{} is owned by uid {owner}, not root; the networks this machine holds are kept \
             only where root alone can reach them",
            path.display()
        ));
    }
    if mode & 0o077 != 0 {
        return Err(format!(
            "{} has mode {:o}, which lets other accounts in; it must be 700",
            path.display(),
            mode & 0o7777
        ));
    }
    Ok(())
}

/// One directory on the way from the executable to `/`, as found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// Where.
    pub path: PathBuf,
    /// Its owner.
    pub owner: u32,
    /// Its mode.
    pub mode: u32,
}

/// Who, besides root, can write somewhere on the way, in words.
///
/// Empty is the only answer the daemon starts on without the override.
#[must_use]
pub fn who_else_can_write(steps: &[Step]) -> Vec<String> {
    steps
        .iter()
        .filter_map(|step| {
            if step.owner != 0 {
                Some(format!("uid {} owns {}", step.owner, step.path.display()))
            } else if step.mode & 0o002 != 0 {
                Some(format!("every account can write {}", step.path.display()))
            } else if step.mode & 0o020 != 0 {
                Some(format!("its group can write {}", step.path.display()))
            } else {
                None
            }
        })
        .collect()
}

#[cfg(target_os = "linux")]
pub use self::real::{
    home_for_this_machine, home_under, steps_to, who_else_can_write_where_this_runs,
};

#[cfg(target_os = "linux")]
mod real {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
    use std::path::Path;

    use super::{STATE, Step, judge_state, who_else_can_write};

    /// The machine's networks, under [`STATE`].
    ///
    /// # Errors
    ///
    /// When the directory cannot be made with its mode, or is not what it must
    /// be.
    pub fn home_for_this_machine() -> daemon::Result<daemon::networks::Home> {
        home_under(Path::new(STATE))
    }

    /// The same, at a path the caller names — for tests, which cannot use the
    /// machine's own.
    ///
    /// # Errors
    ///
    /// As [`home_for_this_machine`].
    pub fn home_under(root: &Path) -> daemon::Result<daemon::networks::Home> {
        let failed = |cause: String| daemon::Error::State { path: root.to_path_buf(), cause };
        match std::fs::DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => {}
            Err(cause) if cause.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(cause) => return Err(failed(format!("could not be made: {cause}"))),
        }
        let found = std::fs::symlink_metadata(root).map_err(|cause| failed(cause.to_string()))?;
        if !found.is_dir() {
            return Err(failed("is not a directory".to_owned()));
        }
        judge_state(root, found.uid(), found.mode()).map_err(failed)?;
        Ok(daemon::networks::Home::under(root.to_path_buf()))
    }

    /// Every directory from `path`'s up to `/`, as found. One that cannot be
    /// read is left out, which leaves it unjudged rather than judged safe —
    /// see [`who_else_can_write_where_this_runs`].
    #[must_use]
    pub fn steps_to(path: &Path) -> Vec<Step> {
        path.ancestors()
            .filter_map(|directory| {
                let found = std::fs::metadata(directory).ok()?;
                Some(Step { path: directory.to_path_buf(), owner: found.uid(), mode: found.mode() })
            })
            .collect()
    }

    /// Who else can write where this program is, from the executable itself
    /// up to `/`.
    ///
    /// An executable whose location cannot be established answers with that
    /// fact, and the daemon does not start without the override: on Linux
    /// `/proc/self/exe` is always there, so not finding it is not a case to be
    /// generous about.
    #[must_use]
    pub fn who_else_can_write_where_this_runs() -> Vec<String> {
        let Ok(program) = std::env::current_exe() else {
            return vec!["this program cannot tell where it is".to_owned()];
        };
        let steps = steps_to(&program);
        let mut named = who_else_can_write(&steps);
        if steps.len() != program.ancestors().count() {
            named.push(format!(
                "a directory on the way to {} could not be read, so who can write it is unknown",
                program.display()
            ));
        }
        named
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    fn step(path: &str, owner: u32, mode: u32) -> Step {
        Step { path: PathBuf::from(path), owner, mode }
    }

    #[test]
    fn the_state_directory_is_roots_alone() {
        let path = Path::new("/var/lib/peerfectly");
        assert!(judge_state(path, 0, 0o40700).is_ok());
        let said = judge_state(path, 0, 0o40755).unwrap_err();
        assert!(said.contains("/var/lib/peerfectly") && said.contains("755"), "{said}");
        assert!(judge_state(path, 0, 0o40710).is_err(), "group can enter");
        assert!(judge_state(path, 1000, 0o40700).unwrap_err().contains("uid 1000"));
    }

    #[test]
    fn a_root_only_location_is_clean() {
        let steps = [
            step("/usr/local/bin/peerfectlyd", 0, 0o100755),
            step("/usr/local/bin", 0, 0o40755),
            step("/usr/local", 0, 0o40755),
            step("/usr", 0, 0o40755),
            step("/", 0, 0o40755),
        ];
        assert!(who_else_can_write(&steps).is_empty());
    }

    /// Anywhere on the way counts, and each is named with who can write it.
    #[test]
    fn anyone_else_who_can_write_on_the_way_is_named() {
        let steps = [
            step("/home/alice/peerfectly/target/release/peerfectlyd", 1000, 0o100755),
            step("/home/alice/peerfectly/target/release", 1000, 0o40755),
            step("/srv/shared", 0, 0o40775),
            step("/tmp", 0, 0o41777),
            step("/", 0, 0o40755),
        ];
        let named = who_else_can_write(&steps);
        assert_eq!(4, named.len(), "{named:?}");
        assert!(
            named
                .iter()
                .any(|line| line.contains("uid 1000 owns /home/alice/peerfectly/target/release"))
        );
        assert!(named.iter().any(|line| line.contains("its group can write /srv/shared")));
        assert!(
            named.iter().any(|line| line.contains("every account can write /tmp")),
            "sticky is not enough"
        );
    }
}

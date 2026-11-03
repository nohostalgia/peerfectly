//! A join in progress, kept so it outlives a restart.
//!
//! A join waits for as long as it takes an admin to approve it — hours, a
//! weekend — so it cannot live only in a running task. What it needs to go on
//! is kept here, in the directory made for it: the invite, the name it
//! proposes, and the signing key's proof over its request, made once, when a
//! person asked for the join. Its keys are beside it, as any network's are.
//!
//! # Signed by this machine
//!
//! The file is signed with this machine's key every time it is written, as a
//! checkpoint is, and a join whose file does not verify is not resumed: it is
//! reported, for a person to cancel. Someone who could write here could
//! otherwise point a waiting device at a relay and an invite of their own
//! choosing; the device would still adopt only a roster that admits its keys,
//! but it would be waiting for the wrong admin.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::checkpoint::MachineKey;
use crate::error::{Error, Result};
use crate::state::Paths;

/// The file a join is kept in, in the directory made for it.
pub const FILE_NAME: &str = "join.json";

/// The context every join signature is made under, so the machine key's
/// signature over a join can never be read as anything else.
const CONTEXT: &[u8] = b"peerfectly join v1\0";

/// A join, as kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Join {
    /// The invite, as text.
    pub invite: String,
    /// The name this device proposes. The admin's record decides.
    pub name: String,
    /// The signing key's proof over the join's request, in hex.
    pub proof: String,
    /// When the join began, in seconds since the epoch.
    pub started_at: u64,
    /// When the admin's daemon said the request was received, once it has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_at: Option<u64>,
    /// Where the invite's IPv4 block coincides with this device's other
    /// networks or the subnets it is on, as the join began: told to its person
    /// then, and carried in the request for the admin approving it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<String>,
}

/// The file and its signature, as written.
#[derive(Debug, Serialize, Deserialize)]
struct Stored {
    body: String,
    signature: String,
}

/// Where the join for `paths` is kept.
#[must_use]
pub fn path(paths: &Paths) -> PathBuf {
    paths.root().join(FILE_NAME)
}

/// Whether `paths` is a join in progress rather than a network: what the
/// survey and the tidying at start ask, so that neither reports nor removes it.
#[must_use]
pub fn in_progress(paths: &Paths) -> bool {
    path(paths).exists()
}

/// Signs `join` with `key` and keeps it for `paths`, in place of what was kept.
///
/// # Errors
///
/// When the key will not sign or the file cannot be written.
pub fn write(paths: &Paths, key: &dyn MachineKey, join: &Join) -> Result<()> {
    let failed = |cause: String| Error::State { path: path(paths), cause };
    let body = serde_json::to_string(join).map_err(|cause| failed(cause.to_string()))?;
    let signature = key.sign(&signed(body.as_bytes())).map_err(failed)?;
    let stored = Stored { body, signature: roster::hex::encode(&signature) };
    let bytes = serde_json::to_vec_pretty(&stored).map_err(|cause| failed(cause.to_string()))?;
    crate::state::replace_file(&path(paths), &bytes)
}

/// The join kept for `paths`, if there is one.
///
/// # Errors
///
/// When there is one and it does not read, or was not signed by `key`: then it
/// is not resumed.
pub fn read(paths: &Paths, key: &dyn MachineKey) -> core::result::Result<Option<Join>, String> {
    let bytes = match std::fs::read(path(paths)) {
        Ok(bytes) => bytes,
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(cause) => return Err(format!("the join could not be read: {cause}")),
    };
    let stored: Stored = serde_json::from_slice(&bytes)
        .map_err(|_| "the join is not one this daemon wrote".to_owned())?;
    let signature = roster::hex::decode(&stored.signature)
        .ok_or_else(|| "the join carries no signature".to_owned())?;
    key.public()
        .verify(&signed(stored.body.as_bytes()), &signature)
        .map_err(|_| "the join was changed outside the daemon".to_owned())?;
    serde_json::from_str(&stored.body).map(Some).map_err(|_| "the join does not read".to_owned())
}

/// Ends the join kept for `paths`: what is left is a network, or nothing.
///
/// # Errors
///
/// When the file is there and cannot be removed.
pub fn remove(paths: &Paths) -> Result<()> {
    match std::fs::remove_file(path(paths)) {
        Ok(()) => Ok(()),
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(cause) => Err(Error::State { path: path(paths), cause: cause.to_string() }),
    }
}

/// What is signed for `body`.
fn signed(body: &[u8]) -> Vec<u8> {
    let mut message = CONTEXT.to_vec();
    message.extend_from_slice(body);
    message
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    fn join() -> Join {
        Join {
            invite: "an invite".to_owned(),
            name: "laptop".to_owned(),
            proof: "00ff".to_owned(),
            started_at: 1_800_000_000,
            requested_at: None,
            conflicts: Vec::new(),
        }
    }

    fn machine(scratch: &std::path::Path) -> crate::checkpoint::SoftwareKey {
        crate::checkpoint::SoftwareKey::at(&scratch.join("home")).unwrap().0
    }

    #[test]
    fn a_join_written_by_the_daemon_reads_back() {
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path().join("network"));
        paths.create().unwrap();
        let key = machine(scratch.path());
        assert_eq!(read(&paths, &key).unwrap(), None, "none before it is written");
        assert!(!in_progress(&paths));

        write(&paths, &key, &join()).unwrap();
        assert!(in_progress(&paths));
        assert_eq!(read(&paths, &key).unwrap(), Some(join()));

        remove(&paths).unwrap();
        assert!(!in_progress(&paths));
    }

    /// Changed outside the daemon, it is not resumed.
    #[test]
    fn an_altered_join_does_not_read() {
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path().join("network"));
        paths.create().unwrap();
        let key = machine(scratch.path());
        write(&paths, &key, &join()).unwrap();

        let text = std::fs::read_to_string(path(&paths)).unwrap();
        std::fs::write(path(&paths), text.replace("laptop", "planted")).unwrap();
        let refused = read(&paths, &key).unwrap_err();
        assert!(refused.contains("changed outside"), "{refused}");

        // Signed by another machine is the same thing.
        let other = crate::checkpoint::SoftwareKey::at(&scratch.path().join("other")).unwrap().0;
        write(&paths, &other, &join()).unwrap();
        assert!(read(&paths, &key).is_err());
    }
}

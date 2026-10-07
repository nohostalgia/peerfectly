//! What survives a restart, and where it lives.
//!
//! Three things: the device's identity, the operations that make up the roster,
//! and the endpoints last known to work. The first is sealed by `identity`, which
//! seals with whatever its platform offers. The other two are written here.
//!
//! # The roster is stored as the bytes that arrived
//!
//! Not as a derived state, and not as re-encoded operations. `DESIGN.md` §0 says to
//! sign and verify over the exact received bytes and never over a re-serialized
//! structure; a store that decoded and re-encoded on the way to disk would break
//! that quietly, on restart, in a way no test of the encoder would catch.
//!
//! So this is an append-only log of the operation bytes exactly as they were
//! admitted, replayed into a fresh roster on start. Replay runs the same
//! validation the network path runs, which means a tampered file is refused
//! rather than trusted for having been on the local disk.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use identity::NodeIdentity;

use crate::error::{Error, Result};

/// The identity this machine holds, creating one only when it has none.
///
/// **The distinction is the whole point.** "There is no identity here" and "there
/// is one and it will not open" are different events, and treating them alike is
/// how a machine silently becomes a different device: the caller generates a
/// fresh identity, writes it over the old one, and comes up with new keys. The
/// roster is not sealed, so it loads regardless — and the machine then holds a
/// network it is no longer a member of, refusing every peer and refused by all of
/// them. That is the symptom `membership-freshness` spent a day chasing, from a
/// different cause, and it would be indistinguishable from the outside.
///
/// So the decision is made on whether the file is there, not on how a read
/// failed. A sealed identity that will not unseal — the account changed, the
/// profile was restored, the platform's sealing refused — is a reason to stop and say
/// so, never a reason to mint new keys.
///
/// # Errors
///
/// When an identity exists and cannot be read, when one cannot be generated, or
/// when a fresh one cannot be written.
pub fn identity_of(paths: &Paths) -> Result<NodeIdentity> {
    let path = paths.identity();

    if path.exists() {
        return identity::store::load(&path).map_err(|cause| Error::State {
            path: path.clone(),
            cause: format!(
                "this device has an identity and it could not be read ({cause}). Refusing to replace it: a new identity would make this a different device, and the roster would still load, so nothing would look wrong until every peer refused it."
            ),
        });
    }

    let fresh = NodeIdentity::generate()
        .map_err(|cause| Error::State { path: path.clone(), cause: cause.to_string() })?;
    identity::store::save(&fresh, &path)
        .map_err(|cause| Error::State { path, cause: cause.to_string() })?;
    Ok(fresh)
}

/// The largest operation the log will read back.
///
/// A frame claiming more than the roster would ever accept is a corrupt or
/// hostile file, and reading it would mean allocating whatever it asked for.
const MAX_FRAME: usize = 1 << 20;

/// Where the daemon keeps what it needs to start again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The directory everything sits under.
    root: PathBuf,
}

impl Paths {
    /// State under a given directory.
    ///
    /// Used by tests and by anything that needs a second instance on one machine.
    pub fn under(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory everything sits under.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The sealed identity.
    #[must_use]
    pub fn identity(&self) -> PathBuf {
        self.root.join("identity")
    }

    /// The operation log the roster is rebuilt from.
    #[must_use]
    pub fn roster(&self) -> PathBuf {
        self.root.join("roster.log")
    }

    /// The endpoints last known to work.
    #[must_use]
    pub fn endpoints(&self) -> PathBuf {
        self.root.join("endpoints.json")
    }

    /// What this directory says about which network it holds.
    #[must_use]
    pub fn record(&self) -> PathBuf {
        self.root.join("network.json")
    }

    /// The snapshot this network last accepted.
    ///
    /// Beside the log rather than in it, because a snapshot is not an operation:
    /// it is never named as a parent and takes no part in merge, so replaying the
    /// log neither produces one nor has anywhere to put one.
    #[must_use]
    pub fn snapshot(&self) -> PathBuf {
        self.root.join("snapshot")
    }

    /// When that snapshot was accepted, on this device's wall clock.
    ///
    /// Kept because freshness is measured from local receipt, and a receipt time
    /// measured from process start means nothing after the process ends. Without
    /// it a restart would re-date the snapshot to the restart — which would make
    /// turning a device off and on a way out of a stale roster.
    #[must_use]
    pub fn snapshot_at(&self) -> PathBuf {
        self.root.join("snapshot_at")
    }

    /// The attestation this network last accepted.
    ///
    /// Beside the snapshot rather than replacing it: the two answer different
    /// questions, and only this one is what freshness is measured from.
    pub fn attestation(&self) -> PathBuf {
        self.root.join("attestation")
    }

    /// When that attestation was accepted, on this device's wall clock.
    ///
    /// The whole of what makes freshness outlive a process. Without it a node
    /// that restarted would hold no attestation at all, and one that re-accepted
    /// its own would date it from the restart — which would make turning a
    /// device off and on the way out of a stale roster.
    pub fn attestation_at(&self) -> PathBuf {
        self.root.join("attestation_at")
    }

    /// The last attestation that dated this device's roster, where it is not
    /// the one above.
    ///
    /// They differ on an admin of a network with other admins, whose own
    /// attestation is held — it is relayed, and its sequence is what the next one
    /// follows — but does not keep its own roster fresh. Without this a restart
    /// would forget the other admin's word that did.
    pub fn attestation_dating(&self) -> PathBuf {
        self.root.join("attestation_dating")
    }

    /// When that one counts as having arrived, as [`Self::attestation_at`].
    pub fn attestation_dating_at(&self) -> PathBuf {
        self.root.join("attestation_dating_at")
    }

    /// The members that chose this device as a neighbour, one id a line.
    ///
    /// Kept so that a restart still pushes to them: they are learned only when
    /// they make contact, and a device that forgot them would leave out of every
    /// push the devices nobody else chose.
    pub fn neighbours_in(&self) -> PathBuf {
        self.root.join("neighbours_in")
    }

    /// Who this network is for, as the platform names a person.
    ///
    /// Absent where the platform draws no distinction between people — a phone
    /// has one person and no second account — and absent on a network made
    /// before a machine could hold networks for more than one. Absent is not
    /// *anybody*: see `control::Caller::is`.
    #[must_use]
    pub fn owner(&self) -> PathBuf {
        self.root.join("owner")
    }

    /// Present where this network was taken from somebody rather than always
    /// having been this person's.
    #[must_use]
    pub fn owner_taken(&self) -> PathBuf {
        self.root.join("owner_taken")
    }

    /// Whether the person last left the tunnel up or down.
    #[must_use]
    pub fn choice(&self) -> PathBuf {
        self.root.join("choice")
    }

    /// When this network last knew anything for certain: the moment its tunnel
    /// last came up or went down.
    #[must_use]
    pub fn known(&self) -> PathBuf {
        self.root.join("known_at")
    }

    /// Creates the directory if it is not there.
    ///
    /// # What this half requires of the place, and what it does not do
    ///
    /// The keys and the roster kept here must be readable **only by whoever owns
    /// the device**. This crate does not obtain that and does not check it: it
    /// creates a directory and takes the access its parent gives.
    ///
    /// That is a **requirement placed on whoever chooses the parent**, and it is
    /// deliberately stated as one rather than as an argument. The argument is
    /// necessarily about a platform — a profile directory, a keystore, an app's
    /// private storage — and an argument that travels with code it was not
    /// written about is worse than no argument, because it reads as though
    /// somebody had checked. Each edge states how its own platform satisfies
    /// this, and what that protection does and does not defend against.
    ///
    /// `identity` is the model: it carries a table saying, per platform, what the
    /// protection holds against and where it does not.
    ///
    /// # Errors
    ///
    /// When the directory cannot be created.
    pub fn create(&self) -> Result<()> {
        fs::create_dir_all(&self.root)
            .map_err(|cause| Error::State { path: self.root.clone(), cause: cause.to_string() })
    }
}

/// The append-only log of operation bytes.
///
/// Deliberately not a database. The roster is a DAG that tolerates any order and
/// refuses anything it cannot verify, so the only thing a store must do is not
/// lose bytes and not change them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
    /// The file it appends to.
    path: PathBuf,
}

impl Log {
    /// A log at a path.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Where it is kept.
    ///
    /// Read by whatever keeps a record beside the log, so that the daemon's own
    /// paths and a node assembled over a temporary directory agree on one
    /// location without either having to be told it twice.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one operation exactly as it arrived.
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    pub fn append(&self, operation: &[u8]) -> Result<()> {
        let len = u32::try_from(operation.len()).map_err(|_| Error::State {
            path: self.path.clone(),
            cause: "an operation larger than the log frames".to_owned(),
        })?;

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|cause| self.failure(&cause))?;

        file.write_all(&len.to_be_bytes()).map_err(|cause| self.failure(&cause))?;
        file.write_all(operation).map_err(|cause| self.failure(&cause))?;
        file.flush().map_err(|cause| self.failure(&cause))
    }

    /// Every operation in the log, in the order it was written.
    ///
    /// A missing file is an empty log: a daemon starting for the first time has
    /// nothing, and that is not an error.
    ///
    /// # Errors
    ///
    /// When the file exists and cannot be read, or is not a log.
    pub fn read(&self) -> Result<Vec<Vec<u8>>> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(cause) => return Err(self.failure(&cause)),
        };

        let mut out = Vec::new();
        let mut rest: &[u8] = &bytes;
        while !rest.is_empty() {
            let (header, body) = rest.split_at_checked(4).ok_or_else(|| Error::State {
                path: self.path.clone(),
                cause: "the log ends inside a frame header".to_owned(),
            })?;
            let len: [u8; 4] = header.try_into().map_err(|_| Error::State {
                path: self.path.clone(),
                cause: "unreadable frame header".to_owned(),
            })?;
            let len = usize::try_from(u32::from_be_bytes(len)).unwrap_or(usize::MAX);

            if len > MAX_FRAME {
                return Err(Error::State {
                    path: self.path.clone(),
                    cause: format!("a frame claims {len} bytes, past anything the roster accepts"),
                });
            }
            let (operation, tail) = body.split_at_checked(len).ok_or_else(|| Error::State {
                path: self.path.clone(),
                cause: "the log ends inside an operation".to_owned(),
            })?;

            out.push(operation.to_vec());
            rest = tail;
        }
        Ok(out)
    }
}

impl Log {
    /// Wraps a filesystem error with the path it concerns.
    fn failure(&self, cause: &std::io::Error) -> Error {
        Error::State { path: self.path.clone(), cause: cause.to_string() }
    }
}

/// Whether the person left the tunnel up or down.
///
/// Restored on start rather than defaulting. A daemon that comes back down after
/// a reboot when the person left it up has quietly overruled them, and one that
/// comes back up when they left it down has done something worse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// They left it up.
    Up,
    /// They left it down.
    Down,
}

impl Choice {
    /// Reads what was last chosen.
    ///
    /// Nothing recorded means down: a daemon that has never been told to come up
    /// has not been told to come up.
    #[must_use]
    pub fn read(path: &Path) -> Self {
        match fs::read_to_string(path) {
            Ok(text) if text.trim() == "up" => Self::Up,
            _ => Self::Down,
        }
    }

    /// Records a choice.
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    pub fn write(self, path: &Path) -> Result<()> {
        let text = match self {
            Self::Up => "up",
            Self::Down => "down",
        };
        fs::write(path, text)
            .map_err(|cause| Error::State { path: path.to_path_buf(), cause: cause.to_string() })
    }
}

/// When a network last knew anything, as recorded, or the epoch when nothing is.
///
/// Kept on disk because "last known" is what a network that is off shows, and a
/// process that starts again — a phone ends apps as a matter of course — would
/// otherwise show every network as never known, which is false. The epoch is the
/// report's "nothing known yet", never a date to draw.
#[must_use]
pub fn read_known(path: &Path) -> std::time::SystemTime {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .and_then(|seconds| {
            std::time::UNIX_EPOCH.checked_add(core::time::Duration::from_secs(seconds))
        })
        .unwrap_or(std::time::UNIX_EPOCH)
}

/// Records when a network last knew anything.
///
/// # Errors
///
/// When the file cannot be written.
pub fn write_known(path: &Path, at: std::time::SystemTime) -> Result<()> {
    let seconds = at.duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs());
    fs::write(path, seconds.to_string())
        .map_err(|cause| Error::State { path: path.to_path_buf(), cause: cause.to_string() })
}

/// The snapshot a network last accepted and when, if both are there.
///
/// Both or neither: a snapshot with no time cannot be dated, and dating it now
/// is the mistake this exists to prevent.
#[must_use]
pub fn read_snapshot(paths: &Paths) -> Option<(Vec<u8>, u64)> {
    let bytes = fs::read(paths.snapshot()).ok()?;
    let at = fs::read_to_string(paths.snapshot_at()).ok()?.trim().parse::<u64>().ok()?;
    (!bytes.is_empty()).then_some((bytes, at))
}

/// Records the snapshot a network has accepted, and when.
///
/// The time is written **after** the bytes, so a write cut in half leaves a
/// snapshot with no time — which reads as none at all — rather than a time
/// pointing at a snapshot that is not there.
///
/// # Errors
///
/// When either file cannot be written.
pub fn write_snapshot(paths: &Paths, bytes: &[u8], at: u64) -> Result<()> {
    let path = paths.snapshot();
    fs::write(&path, bytes).map_err(|cause| Error::State { path, cause: cause.to_string() })?;
    let path = paths.snapshot_at();
    fs::write(&path, at.to_string())
        .map_err(|cause| Error::State { path, cause: cause.to_string() })
}

/// The attestation a network has accepted, and when, where both are readable.
///
/// `None` where either is missing or unreadable: a receipt time without an
/// attestation dates nothing, and an attestation without one would have to be
/// dated from now, which is the restart hole this exists to close.
#[must_use]
pub fn read_attestation(paths: &Paths) -> Option<(Vec<u8>, u64)> {
    read_dated(&paths.attestation(), &paths.attestation_at())
}

/// The last attestation that dated this roster, where it differs from the one
/// held, as [`Paths::attestation_dating`] describes.
#[must_use]
pub fn read_dating_attestation(paths: &Paths) -> Option<(Vec<u8>, u64)> {
    read_dated(&paths.attestation_dating(), &paths.attestation_dating_at())
}

/// Bytes and the time they are dated by, where both are readable.
fn read_dated(bytes: &std::path::Path, at: &std::path::Path) -> Option<(Vec<u8>, u64)> {
    let bytes = fs::read(bytes).ok()?;
    let at = fs::read_to_string(at).ok()?.trim().parse::<u64>().ok()?;
    (!bytes.is_empty()).then_some((bytes, at))
}

/// The members that chose this device as a neighbour, where the record is
/// readable. A missing or unreadable record is an empty one: those members are
/// learned again the next time they make contact.
#[must_use]
pub fn read_in_neighbours(paths: &Paths) -> BTreeSet<roster::id::DeviceId> {
    fs::read_to_string(paths.neighbours_in())
        .map(|text| {
            text.lines().filter_map(|line| roster::id::DeviceId::from_hex(line.trim())).collect()
        })
        .unwrap_or_default()
}

/// Records the members that chose this device as a neighbour.
///
/// # Errors
///
/// When the file cannot be written.
pub fn write_in_neighbours(paths: &Paths, members: &BTreeSet<roster::id::DeviceId>) -> Result<()> {
    let path = paths.neighbours_in();
    let text: String = members
        .iter()
        .map(|id| {
            format!(
                "{}
",
                id.to_hex()
            )
        })
        .collect();
    fs::write(&path, text).map_err(|cause| Error::State { path, cause: cause.to_string() })
}

/// Who a network is for, if it says.
///
/// Trimmed, because it is compared: a trailing newline is not a different
/// person, and a file that grew one would silently make a network nobody's.
#[must_use]
pub fn read_owner(paths: &Paths) -> Option<String> {
    let text = fs::read_to_string(paths.owner()).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Records who a network is for.
///
/// Written **before the network is usable**, so that a directory holding a
/// roster always says whose it is. Written afterwards it would leave a window in
/// which the network exists and belongs to nobody, which is a window in which
/// somebody else could be given it.
///
/// # Errors
///
/// When it cannot be written. Nothing else should be written after a failure
/// here.
pub fn write_owner(paths: &Paths, owner: &str) -> Result<()> {
    let path = paths.owner();
    fs::write(&path, owner).map_err(|cause| Error::State { path, cause: cause.to_string() })
}

/// Whether this network was taken from somebody.
#[must_use]
pub fn was_taken(paths: &Paths) -> bool {
    paths.owner_taken().exists()
}

/// Hands a network to somebody else, and records that it was handed over.
///
/// The marker is written **first**. A hand-over recorded as an ordinary owner
/// would be a network that changed hands quietly, and the order is what keeps
/// that from being the outcome of a write cut in half.
///
/// # Errors
///
/// When either file cannot be written.
pub fn take_ownership(paths: &Paths, owner: &str) -> Result<()> {
    let path = paths.owner_taken();
    fs::write(&path, owner).map_err(|cause| Error::State { path, cause: cause.to_string() })?;
    write_owner(paths, owner)
}

/// Records the attestation a network has accepted, and when.
///
/// The time is written **after** the bytes, for the reason `write_snapshot`
/// gives: a write cut in half leaves an attestation with no time — which reads
/// as none at all — rather than a time pointing at one that is not there.
///
/// # Errors
///
/// When either file cannot be written.
pub fn write_attestation(paths: &Paths, bytes: &[u8], at: u64) -> Result<()> {
    write_dated(paths.attestation(), paths.attestation_at(), bytes, at)
}

/// Keeps the attestation that dated this roster, as [`read_dating_attestation`]
/// reads it back.
///
/// # Errors
///
/// When either file cannot be written.
pub fn write_dating_attestation(paths: &Paths, bytes: &[u8], at: u64) -> Result<()> {
    write_dated(paths.attestation_dating(), paths.attestation_dating_at(), bytes, at)
}

/// Writes bytes and the time they are dated by.
fn write_dated(bytes_path: PathBuf, at_path: PathBuf, bytes: &[u8], at: u64) -> Result<()> {
    fs::write(&bytes_path, bytes)
        .map_err(|cause| Error::State { path: bytes_path, cause: cause.to_string() })?;
    fs::write(&at_path, at.to_string())
        .map_err(|cause| Error::State { path: at_path, cause: cause.to_string() })
}

/// This device's wall clock in whole seconds, which is the frame a stored
/// receipt time is read in.
#[must_use]
pub fn wall_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The clock a daemon's roster measures freshness on.
///
/// The roster's own default counts seconds since the process started, which is
/// monotonic and therefore the better answer for anything inside one run — and
/// worthless across runs, which is where the measurement has to survive. A
/// snapshot accepted yesterday must still read as a day old after a restart.
///
/// The cost is a clock that can move. That is not swept up: a receipt time later
/// than the clock's own reading is reported by the roster as the anomaly it is,
/// rather than read as no time having passed.
///
/// Nothing derived depends on this. The roster's own rules forbid a timestamp
/// influencing ordering, conflict resolution or validity, and freshness
/// influences none of them: it decides only what this device is willing to act
/// on, never what the roster says.
#[derive(Debug, Clone, Copy, Default)]
pub struct WallClock;

impl roster::roster::Clock for WallClock {
    fn now_seconds(&self) -> u64 {
        wall_seconds()
    }

    /// The same reading: this clock is the wall clock, so it is also what an
    /// attestation signed here is dated with, and what one received is aged by.
    fn unix_seconds(&self) -> Option<u64> {
        Some(wall_seconds())
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    /// A device with no identity is given one.
    #[test]
    fn a_device_with_no_identity_is_given_one() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());
        paths.create().expect("creates");

        let made = identity_of(&paths).expect("an identity is created");
        assert!(paths.identity().exists(), "and written down");

        let again = identity_of(&paths).expect("loads the one just written");
        assert_eq!(made.device_id(), again.device_id(), "the same device, not a second one");
    }

    /// An identity that exists and will not open stops the caller, and is left
    /// exactly as it was.
    ///
    /// The old behaviour generated a fresh one and wrote it over the top. That
    /// turns "I cannot read your identity" into "you are now a different device",
    /// silently: the roster is not sealed, so it loads regardless, and the
    /// machine comes up holding a network it is no longer a member of. Every peer
    /// refuses it and it refuses every peer, with nothing anywhere saying why.
    #[test]
    fn an_identity_that_will_not_open_is_not_replaced() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());
        paths.create().expect("creates");

        let rubbish = b"this is not a sealed identity";
        fs::write(paths.identity(), rubbish).expect("writes");

        let refusal = identity_of(&paths).expect_err("an unreadable identity must stop this");
        let said = refusal.to_string();
        assert!(said.contains("could not be read"), "{said}");
        assert!(said.contains("different device"), "and say what replacing it would cost: {said}");

        assert_eq!(
            fs::read(paths.identity()).expect("still there"),
            rubbish,
            "the stored identity must be left exactly as it was"
        );
    }

    /// The decision is made on whether the file is there, not on how a read
    /// failed — so no future error variant can be mistaken for "absent".
    #[test]
    fn the_decision_is_made_on_the_file_existing() {
        let code = crate::code_of(include_str!("state.rs"));
        let deciding = code
            .split_once("pub fn identity_of")
            .map(|(_, rest)| rest.split("pub fn ").next().unwrap_or(rest))
            .expect("the function exists");
        assert!(
            deciding.contains("path.exists()"),
            "existence is what decides whether to create one"
        );
        assert!(
            !deciding.contains("if let Ok("),
            "a read that failed must never be read as a device having no identity"
        );
    }

    use super::*;

    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir().expect("a scratch directory")
    }

    #[test]
    fn every_path_sits_under_one_root() {
        let paths = Paths::under("C:/somewhere");
        for path in [paths.identity(), paths.roster(), paths.endpoints(), paths.choice()] {
            assert!(path.starts_with(paths.root()), "{path:?} escaped the state directory");
        }
    }

    #[test]
    fn the_directory_is_created_once_and_again() {
        let dir = scratch();
        let paths = Paths::under(dir.path().join("state"));
        paths.create().expect("creates");
        paths.create().expect("creating twice is not an error");
        assert!(paths.root().is_dir());
    }

    /// The property the store exists for: what went in comes out unchanged.
    #[test]
    fn the_log_returns_the_bytes_that_went_in() {
        let dir = scratch();
        let log = Log::at(dir.path().join("roster.log"));

        let operations: Vec<Vec<u8>> = vec![b"first".to_vec(), Vec::new(), vec![0xff; 300]];
        for operation in &operations {
            log.append(operation).expect("appends");
        }

        assert_eq!(log.read().expect("reads"), operations, "byte for byte, in order");
    }

    #[test]
    fn a_log_that_was_never_written_is_empty() {
        let dir = scratch();
        let log = Log::at(dir.path().join("absent.log"));
        assert!(log.read().expect("a missing log is an empty one").is_empty());
    }

    /// A truncated file is refused rather than half-read. Half a roster is a
    /// roster missing revocations.
    #[test]
    fn a_truncated_log_is_refused() {
        let dir = scratch();
        let path = dir.path().join("roster.log");
        let log = Log::at(&path);
        log.append(b"an operation").expect("appends");

        let bytes = fs::read(&path).expect("reads");
        let cut = bytes.len().saturating_sub(3);
        fs::write(&path, bytes.get(..cut).expect("shorter")).expect("writes");

        match log.read() {
            Err(Error::State { cause, .. }) => {
                assert!(cause.contains("inside"), "the refusal says where it ran out: {cause}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// A frame header claiming more than the roster would ever accept is a
    /// corrupt or hostile file, and honouring it means allocating what it asked.
    #[test]
    fn an_absurd_frame_is_refused_without_allocating_it() {
        let dir = scratch();
        let path = dir.path().join("roster.log");
        fs::write(&path, [0xff, 0xff, 0xff, 0xff]).expect("writes");

        match Log::at(&path).read() {
            Err(Error::State { cause, .. }) => assert!(cause.contains("past anything"), "{cause}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_choice_survives_a_restart() {
        let dir = scratch();
        let path = dir.path().join("choice");

        Choice::Up.write(&path).expect("writes");
        assert_eq!(Choice::read(&path), Choice::Up);

        Choice::Down.write(&path).expect("writes");
        assert_eq!(Choice::read(&path), Choice::Down);
    }

    /// A daemon that has never been told to come up has not been told to.
    #[test]
    fn nothing_recorded_means_down() {
        let dir = scratch();
        assert_eq!(Choice::read(&dir.path().join("never-written")), Choice::Down);
    }

    #[test]
    fn an_unreadable_choice_does_not_bring_the_tunnel_up() {
        let dir = scratch();
        let path = dir.path().join("choice");
        fs::write(&path, "garbage").expect("writes");
        assert_eq!(Choice::read(&path), Choice::Down, "an unreadable choice is not consent");
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod identity_tests {
    use super::*;

    /// The identity survives a restart, and what is written is not the key.
    ///
    /// `identity` seals with what its platform offers and its own tests cover that. What
    /// is checked here is the thing a *daemon* gets wrong: writing to the path it
    /// will read back, and writing the sealed form rather than the raw one.
    #[test]
    fn the_identity_round_trips_and_nothing_unsealed_is_written() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(dir.path());
        paths.create().expect("creates");

        let identity = identity::NodeIdentity::generate().expect("generates");
        let signing = identity.signing_key().material().expect("held").expose().to_vec();
        let transport = identity.transport_key().material().expose().to_vec();

        identity::store::save(&identity, &paths.identity()).expect("saves");
        let back = identity::store::load(&paths.identity()).expect("loads");

        assert_eq!(back.device_id(), identity.device_id(), "the same device came back");

        // What protects it differs, and asserting one platform's answer
        // everywhere is how a portable crate acquires an assumption. `identity`
        // says so in its own table: sealed where the platform seals, and the
        // file mode alone where it does not. This checks whichever holds here.
        let written = fs::read(paths.identity()).expect("reads");

        #[cfg(windows)]
        {
            assert!(
                !contains(&written, &signing),
                "the platform seals here, so the signing key must not be on disk in the clear"
            );
            assert!(!contains(&written, &transport), "nor the transport key");
        }

        #[cfg(unix)]
        {
            // Deliberately not asserted as absent: `identity` records that on
            // Unix the material is stored in the clear and the mode is the whole
            // control. Asserting otherwise would be asserting a defence that is
            // documented as not existing.
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(paths.identity()).expect("reads").permissions().mode();
            assert_eq!(
                mode & 0o077,
                0,
                "the mode is the whole control here, so nobody but the owner may read it"
            );
            let _ = (&signing, &transport, &written);
        }
    }

    /// A missing identity is a device that has not been enrolled, not a failure
    /// to diagnose.
    #[test]
    fn an_absent_identity_is_reported_rather_than_invented() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(dir.path());
        assert!(identity::store::load(&paths.identity()).is_err());
    }

    /// Whether a run of bytes appears in another.
    ///
    /// Only the Windows branch asks: on Unix the material is stored in the clear,
    /// by design, and that test checks the file mode instead.
    #[cfg(windows)]
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|window| window == needle)
    }

    /// What is written is what comes back, and an empty file is not a person.
    #[test]
    fn an_owner_round_trips_and_emptiness_is_nobody() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());
        paths.create().expect("makes it");

        assert_eq!(None, read_owner(&paths), "nothing is recorded yet");

        write_owner(&paths, "S-1-5-21-alice").expect("writes");
        assert_eq!(Some("S-1-5-21-alice".to_owned()), read_owner(&paths));

        // A file that exists and says nothing is nobody, not somebody named "".
        std::fs::write(paths.owner(), "   \n").expect("writes");
        assert_eq!(None, read_owner(&paths), "whitespace names nobody");
    }

    /// Trimmed, because it is compared.
    ///
    /// A file that grew a trailing newline — an editor, a shell redirect — would
    /// otherwise make a network belong to a person who does not exist, and its
    /// real owner would be locked out of their own network.
    #[test]
    fn a_trailing_newline_is_not_a_different_person() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());
        paths.create().expect("makes it");

        std::fs::write(paths.owner(), "S-1-5-21-alice\r\n").expect("writes");
        assert_eq!(Some("S-1-5-21-alice".to_owned()), read_owner(&paths));
    }
}

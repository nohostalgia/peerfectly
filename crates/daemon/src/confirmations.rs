//! What each device has been observed to hold, across a restart.
//!
//! The daemon reports how many operations authored here have not reached another
//! device. That report is only worth having if it is true, and the truth of it
//! rests on two things this module supplies: evidence rather than optimism, and a
//! memory that a reboot does not wipe.
//!
//! # Per device, not per network
//!
//! A confirmation is a pair — this operation, that device — and never a single
//! flag for the network. An aggregate is zeroed by whichever device claims
//! first, so one compromised member could silence a revocation warning for every
//! other member at once; per device, it silences only its own row. It is also the
//! answer a person actually has a use for: not how many operations are
//! outstanding, but which devices have yet to hear about the laptop that was
//! stolen.
//!
//! # Monotone, because a peer that compacts stops naming what it discarded
//!
//! Pairs are added and never removed on the strength of a later offer. A peer
//! that has compacted no longer names the discarded operations, so recomputing
//! from the most recent offer alone would make a delivered operation outstanding
//! again the moment any peer tidied its history. Once seen, a pair stands.
//!
//! Pairs *are* dropped for a device that leaves the roster, which is not the same
//! event: there is no longer anybody for the operation to be outstanding toward.
//!
//! # Losing the file over-reports
//!
//! A missing or unreadable file reads as an empty record, which reports every
//! locally-authored operation as outstanding toward every member. That direction
//! is chosen. Over-reporting costs a person a look at a device that is already
//! fine; under-reporting costs them a revocation they believe is in force and is
//! not, which is the failure this whole path exists to prevent. It also
//! self-corrects: one contact with a peer re-confirms everything that peer holds,
//! because an offer carries the whole id set rather than a delta.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use roster::id::{DeviceId, OperationId};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The file name kept beside the log.
const FILE_NAME: &str = "confirmations.json";

/// One device's confirmed set, as written.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    /// The device, in hex.
    device: String,
    /// The operations it was observed to hold, in hex.
    operations: Vec<String>,
}

/// Which devices have been observed to hold which operations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Confirmed {
    /// Confirmed operation ids, by the device whose offer named them.
    by_device: BTreeMap<DeviceId, BTreeSet<OperationId>>,
}

impl Confirmed {
    /// Records that `device` was observed to hold `ids`.
    ///
    /// Returns whether anything was new, so a caller can decide whether the file
    /// is worth rewriting. Existing pairs are never removed: see the module
    /// documentation on compaction.
    pub fn confirm(
        &mut self,
        device: DeviceId,
        ids: impl IntoIterator<Item = OperationId>,
    ) -> bool {
        let held = self.by_device.entry(device).or_default();
        let before = held.len();
        held.extend(ids);
        held.len() != before
    }

    /// Whether `device` has been observed to hold `id`.
    #[must_use]
    pub fn holds(&self, device: &DeviceId, id: &OperationId) -> bool {
        self.by_device.get(device).is_some_and(|held| held.contains(id))
    }

    /// Forgets devices that are no longer in `members`.
    ///
    /// Returns whether anything was dropped. A revoked or departed device is not
    /// somebody an operation can still be outstanding toward, and keeping its
    /// pairs would grow the file against devices that no longer exist.
    pub fn retain_members(&mut self, members: &BTreeSet<DeviceId>) -> bool {
        let before = self.by_device.len();
        self.by_device.retain(|device, _| members.contains(device));
        self.by_device.len() != before
    }

    /// Devices this record knows anything about.
    pub fn devices(&self) -> impl Iterator<Item = &DeviceId> {
        self.by_device.keys()
    }
}

/// The record on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmations {
    /// The file it is kept in.
    path: PathBuf,
}

impl Confirmations {
    /// The record at a path.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The record kept beside a log.
    ///
    /// One rule, in one place: the daemon's own paths and a node assembled from a
    /// log in a temporary directory both land on the same file, so a test cannot
    /// be reading a different record from the one the daemon writes.
    #[must_use]
    pub fn beside(log: &Path) -> Self {
        let directory = log.parent().unwrap_or_else(|| Path::new("."));
        Self::at(directory.join(FILE_NAME))
    }

    /// Writes what has been confirmed.
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    pub fn save(&self, confirmed: &Confirmed) -> Result<()> {
        let entries: Vec<Entry> = confirmed
            .by_device
            .iter()
            .map(|(device, operations)| Entry {
                device: device.to_hex(),
                operations: operations.iter().map(OperationId::to_hex).collect(),
            })
            .collect();

        let encoded = serde_json::to_vec_pretty(&entries)
            .map_err(|cause| self.failure(&cause.to_string()))?;
        std::fs::write(&self.path, encoded).map_err(|cause| self.failure(&cause.to_string()))
    }

    /// Reads back what has been confirmed.
    ///
    /// A missing file is an empty record. A daemon starting for the first time
    /// has confirmed nothing, and that is not an error — it reports everything as
    /// outstanding, which is true.
    ///
    /// # Errors
    ///
    /// When the file exists and cannot be read or parsed. The caller is expected
    /// to record the failure and carry on with an empty record rather than refuse
    /// to start: an unreadable record must over-report, never under-report.
    pub fn load(&self) -> Result<Confirmed> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Confirmed::default());
            }
            Err(cause) => return Err(self.failure(&cause.to_string())),
        };

        let entries: Vec<Entry> =
            serde_json::from_slice(&bytes).map_err(|cause| self.failure(&cause.to_string()))?;

        let mut confirmed = Confirmed::default();
        for entry in entries {
            let Some(device) = DeviceId::from_hex(&entry.device) else { continue };
            let ids = entry.operations.iter().filter_map(|id| OperationId::from_hex(id));
            confirmed.confirm(device, ids);
        }
        Ok(confirmed)
    }

    /// Where it is kept.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Wraps a filesystem or encoding failure with the path it concerns.
    fn failure(&self, cause: &str) -> Error {
        Error::State { path: self.path.clone(), cause: cause.to_owned() }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "a test reports failure by panicking")]

    use super::*;

    fn device(tag: u8) -> DeviceId {
        DeviceId::from_bytes([tag; 32])
    }

    fn operation(tag: u8) -> OperationId {
        OperationId::from_bytes([tag; 32])
    }

    #[test]
    fn a_record_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let store = Confirmations::at(directory.path().join(FILE_NAME));

        let mut confirmed = Confirmed::default();
        confirmed.confirm(device(1), [operation(0xa), operation(0xb)]);
        confirmed.confirm(device(2), [operation(0xa)]);

        store.save(&confirmed).unwrap();
        assert_eq!(store.load().unwrap(), confirmed);
    }

    /// A daemon starting for the first time has confirmed nothing, and that is
    /// a true statement rather than a failure.
    #[test]
    fn a_missing_file_is_an_empty_record() {
        let directory = tempfile::tempdir().unwrap();
        let store = Confirmations::at(directory.path().join(FILE_NAME));
        assert_eq!(store.load().unwrap(), Confirmed::default());
    }

    /// The direction is the decision: a record that cannot be parsed must not
    /// come back as "everything is delivered".
    #[test]
    fn an_unreadable_file_is_an_error_rather_than_an_empty_success() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(FILE_NAME);
        std::fs::write(&path, b"not json at all").unwrap();

        assert!(
            Confirmations::at(path).load().is_err(),
            "a corrupt record is reported, so the caller over-reports deliberately \
             rather than mistaking junk for an empty set"
        );
    }

    #[test]
    fn confirming_is_monotone() {
        let mut confirmed = Confirmed::default();
        assert!(confirmed.confirm(device(1), [operation(0xa)]), "the first pair is new");
        assert!(!confirmed.confirm(device(1), [operation(0xa)]), "the same pair is not");

        // The peer compacted and no longer names it. It stays confirmed.
        confirmed.confirm(device(1), []);
        assert!(confirmed.holds(&device(1), &operation(0xa)));
    }

    #[test]
    fn one_device_confirming_says_nothing_about_another() {
        let mut confirmed = Confirmed::default();
        confirmed.confirm(device(1), [operation(0xa)]);

        assert!(confirmed.holds(&device(1), &operation(0xa)));
        assert!(!confirmed.holds(&device(2), &operation(0xa)));
    }

    #[test]
    fn a_departed_device_is_forgotten_and_nothing_else_is() {
        let mut confirmed = Confirmed::default();
        confirmed.confirm(device(1), [operation(0xa)]);
        confirmed.confirm(device(2), [operation(0xa)]);

        let members = BTreeSet::from([device(1)]);
        assert!(confirmed.retain_members(&members));
        assert!(confirmed.holds(&device(1), &operation(0xa)), "the member is kept");
        assert!(!confirmed.holds(&device(2), &operation(0xa)), "the departed device is not");
        assert!(!confirmed.retain_members(&members), "and a second pass drops nothing");
    }

    /// The same file whichever way it is addressed, so a test and the daemon
    /// cannot be looking at two different records.
    #[test]
    fn the_record_lands_beside_the_log() {
        let directory = tempfile::tempdir().unwrap();
        let log = directory.path().join("roster.log");
        assert_eq!(Confirmations::beside(&log).path(), directory.path().join(FILE_NAME));
    }
}

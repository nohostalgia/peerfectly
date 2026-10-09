//! When this device was last in contact with each member, across a restart.
//!
//! A person deciding whether a laptop is lost asks when it was last seen, and
//! the pending screen answers "not in contact since" — so the answer has to
//! exist, and it has to survive the reboot after which that person goes looking.
//!
//! # Only a peer that has spoken counts
//!
//! A contact is recorded when an authenticated session opens, and when roster
//! traffic arrives on one. Both reach this only through the node, and only for a
//! session the transport established after checking the peer against the roster.
//!
//! Nothing else counts, and one thing in particular must not. A local-network
//! announcement is obfuscated under a key derived from the network id, and every
//! device ever revoked from the network holds that id. A last contact an
//! announcement could refresh is one a stolen, revoked laptop could keep current.
//!
//! Nor is the end of a session a contact. A session is noticed to have ended some
//! time after the peer stopped speaking, and recording "now" then would put the
//! last contact after the last word.
//!
//! # It decides nothing
//!
//! It is a wall-clock value, and nothing in this system lets one influence
//! membership, ordering or validity. The files allowed to name it are listed in
//! the test at the bottom of this module, and it is a list rather than a set of
//! forbidden places so that the next module which decides something starts out
//! excluded.
//!
//! # As small as the need
//!
//! One minute per device, replaced, with no history and no address. Replaced
//! rather than kept as the maximum: a clock set far ahead once would otherwise
//! pin a device's last contact in the future for good, while a clock set back
//! makes one reading early and corrects at the next contact.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use roster::id::DeviceId;

use crate::error::{Error, Result};

/// The file name kept beside the log.
const FILE_NAME: &str = "contacts.json";

/// The last minute of contact with each device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LastContacts {
    /// Whole minutes since the epoch, by device.
    by_device: BTreeMap<DeviceId, u64>,
}

impl LastContacts {
    /// Records contact with `device` in `minute`.
    ///
    /// Returns whether the stored minute changed, so a caller writes the file at
    /// most once a minute however much traffic a session carries.
    pub(crate) fn touch(&mut self, device: DeviceId, minute: u64) -> bool {
        self.by_device.insert(device, minute) != Some(minute)
    }

    /// The last minute of contact with `device`, if any is recorded.
    #[must_use]
    pub(crate) fn minute(&self, device: &DeviceId) -> Option<u64> {
        self.by_device.get(device).copied()
    }

    /// Forgets every device not in `kept`. Returns whether anything went.
    pub(crate) fn retain(&mut self, kept: &BTreeSet<DeviceId>) -> bool {
        let before = self.by_device.len();
        self.by_device.retain(|device, _| kept.contains(device));
        self.by_device.len() != before
    }
}

/// The record on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContactRecord {
    /// The file it is kept in.
    path: PathBuf,
}

impl ContactRecord {
    /// The record kept beside a log, in the network's own directory.
    #[must_use]
    pub(crate) fn beside(log: &Path) -> Self {
        let directory = log.parent().unwrap_or_else(|| Path::new("."));
        Self { path: directory.join(FILE_NAME) }
    }

    /// Where it is kept.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Writes the record.
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    pub(crate) fn save(&self, contacts: &LastContacts) -> Result<()> {
        let written: BTreeMap<String, u64> =
            contacts.by_device.iter().map(|(device, minute)| (device.to_hex(), *minute)).collect();
        let encoded = serde_json::to_vec_pretty(&written)
            .map_err(|cause| self.failure(&cause.to_string()))?;
        std::fs::write(&self.path, encoded).map_err(|cause| self.failure(&cause.to_string()))
    }

    /// Reads the record back.
    ///
    /// A missing file is an empty record, and so is an unreadable one — with the
    /// failure returned beside it for the caller to report. Unlike confirmations,
    /// neither direction of this loss misleads anybody: every device reads as "no
    /// contact recorded", which is true of what this device now knows.
    pub(crate) fn load(&self) -> (LastContacts, Option<Error>) {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => {
                return (LastContacts::default(), None);
            }
            Err(cause) => return (LastContacts::default(), Some(self.failure(&cause.to_string()))),
        };

        let written: BTreeMap<String, u64> = match serde_json::from_slice(&bytes) {
            Ok(written) => written,
            Err(cause) => return (LastContacts::default(), Some(self.failure(&cause.to_string()))),
        };

        let by_device = written
            .into_iter()
            .filter_map(|(device, minute)| DeviceId::from_hex(&device).map(|id| (id, minute)))
            .collect();
        (LastContacts { by_device }, None)
    }

    /// Wraps a filesystem or encoding failure with the path it concerns.
    fn failure(&self, cause: &str) -> Error {
        Error::State { path: self.path.clone(), cause: cause.to_owned() }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    fn device(tag: u8) -> DeviceId {
        DeviceId::from_bytes([tag; 32])
    }

    #[test]
    fn a_record_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let record = ContactRecord::beside(&directory.path().join("roster.log"));

        let mut contacts = LastContacts::default();
        contacts.touch(device(1), 29_000_000);
        contacts.touch(device(2), 29_000_004);
        record.save(&contacts).unwrap();

        let (back, failure) = record.load();
        assert!(failure.is_none());
        assert_eq!(back, contacts);
    }

    /// The file is written when a minute changes and not for every message.
    #[test]
    fn only_a_new_minute_is_a_change() {
        let mut contacts = LastContacts::default();
        assert!(contacts.touch(device(1), 100), "the first contact is new");
        assert!(!contacts.touch(device(1), 100), "the same minute is not");
        assert!(contacts.touch(device(1), 101), "the next minute is");
    }

    /// A clock set far ahead once must not pin the value in the future.
    #[test]
    fn a_clock_moved_back_replaces_rather_than_keeps_the_later_minute() {
        let mut contacts = LastContacts::default();
        contacts.touch(device(1), 900_000_000);
        contacts.touch(device(1), 29_000_000);
        assert_eq!(contacts.minute(&device(1)), Some(29_000_000));
    }

    #[test]
    fn a_missing_file_is_an_empty_record_and_not_a_failure() {
        let directory = tempfile::tempdir().unwrap();
        let (contacts, failure) =
            ContactRecord::beside(&directory.path().join("roster.log")).load();
        assert_eq!(contacts, LastContacts::default());
        assert!(failure.is_none());
    }

    /// Losing it under-informs and misleads nobody, so it is never a reason to
    /// stop a network — but it is still said.
    #[test]
    fn a_corrupt_file_is_an_empty_record_with_the_failure_beside_it() {
        let directory = tempfile::tempdir().unwrap();
        let log = directory.path().join("roster.log");
        std::fs::write(ContactRecord::beside(&log).path(), b"not json at all").unwrap();

        let (contacts, failure) = ContactRecord::beside(&log).load();
        assert_eq!(contacts, LastContacts::default());
        assert!(failure.is_some(), "the loss is reported");
    }

    #[test]
    fn only_the_kept_devices_survive() {
        let mut contacts = LastContacts::default();
        contacts.touch(device(1), 1);
        contacts.touch(device(2), 1);
        assert!(contacts.retain(&BTreeSet::from([device(1)])));
        assert_eq!(contacts.minute(&device(1)), Some(1));
        assert_eq!(contacts.minute(&device(2)), None);
        assert!(!contacts.retain(&BTreeSet::from([device(1)])), "a second pass drops nothing");
    }

    /// Nothing is kept but one number per device: no history and no address.
    #[test]
    fn the_file_holds_one_minute_per_device_and_nothing_else() {
        let directory = tempfile::tempdir().unwrap();
        let record = ContactRecord::beside(&directory.path().join("roster.log"));
        let mut contacts = LastContacts::default();
        contacts.touch(device(1), 7);
        contacts.touch(device(1), 8);
        record.save(&contacts).unwrap();

        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(record.path()).unwrap()).unwrap();
        let object = written.as_object().expect("a map of device to minute");
        assert_eq!(object.len(), 1);
        for value in object.values() {
            assert!(value.is_u64(), "a single minute, not a history or an address: {value}");
        }
    }

    /// It lives in the network's own directory, so it goes with the network.
    #[test]
    fn the_record_lands_beside_the_log() {
        let directory = tempfile::tempdir().unwrap();
        let log = directory.path().join("roster.log");
        assert_eq!(ContactRecord::beside(&log).path(), directory.path().join(FILE_NAME));
    }

    /// The files allowed to name the record, and nothing else.
    ///
    /// An allowlist rather than a list of decision modules, because a list of
    /// forbidden places protects only the decisions that exist today. Inside
    /// `node.rs`, the functions that pace, dial or authorise are checked by name
    /// as well, since that file is allowed to write the record.
    #[test]
    fn nothing_that_decides_reads_last_contact() {
        // `views.rs` draws the record and decides nothing from it, which is what
        // this list is for.
        const ALLOWED: &[&str] = &[
            "contacts.rs",
            "node.rs",
            "service.rs",
            "control.rs",
            "describing.rs",
            "views.rs",
            "lib.rs",
        ];
        const TOKENS: &[&str] = &["contacts", "LastContacts", "ContactRecord", "last_contact"];

        let sources: &[(&str, &str)] = &[
            ("admitting.rs", include_str!("admitting.rs")),
            ("attesting.rs", include_str!("attesting.rs")),
            ("channel.rs", include_str!("channel.rs")),
            ("clock.rs", include_str!("clock.rs")),
            ("confirmations.rs", include_str!("confirmations.rs")),
            ("conflicts.rs", include_str!("conflicts.rs")),
            ("connectivity.rs", include_str!("connectivity.rs")),
            ("discovery.rs", include_str!("discovery.rs")),
            ("drawing.rs", include_str!("drawing.rs")),
            ("endpoints.rs", include_str!("endpoints.rs")),
            ("error.rs", include_str!("error.rs")),
            ("exposing.rs", include_str!("exposing.rs")),
            ("founding.rs", include_str!("founding.rs")),
            ("gateway.rs", include_str!("gateway.rs")),
            ("joining.rs", include_str!("joining.rs")),
            ("keys.rs", include_str!("keys.rs")),
            ("lifecycle.rs", include_str!("lifecycle.rs")),
            ("limits.rs", include_str!("limits.rs")),
            ("logging.rs", include_str!("logging.rs")),
            ("machine.rs", include_str!("machine.rs")),
            ("names.rs", include_str!("names.rs")),
            ("neighbours.rs", include_str!("neighbours.rs")),
            ("networks.rs", include_str!("networks.rs")),
            ("relay.rs", include_str!("relay.rs")),
            ("resolving.rs", include_str!("resolving.rs")),
            ("renaming.rs", include_str!("renaming.rs")),
            ("revoking.rs", include_str!("revoking.rs")),
            ("router.rs", include_str!("router.rs")),
            ("routes.rs", include_str!("routes.rs")),
            ("rule.rs", include_str!("rule.rs")),
            ("schedule.rs", include_str!("schedule.rs")),
            ("signing.rs", include_str!("signing.rs")),
            ("snapshots.rs", include_str!("snapshots.rs")),
            ("state.rs", include_str!("state.rs")),
            ("wire.rs", include_str!("wire.rs")),
        ];

        for (file, source) in sources {
            assert!(!ALLOWED.contains(file), "{file} is both allowed and scanned");
            let code = crate::code_of(source);
            for token in TOKENS {
                assert!(
                    !code.contains(token),
                    "`{file}` names `{token}`. Last contact is a wall-clock value and decides \
                     nothing; if this file only displays it, add it to ALLOWED deliberately"
                );
            }
        }

        // Every module the crate declares is either scanned or allowed, so a new
        // module cannot slip past by not being listed.
        let lib = include_str!("lib.rs");
        for line in lib.lines().map(str::trim) {
            let Some(rest) = line
                .strip_prefix("pub mod ")
                .or_else(|| line.strip_prefix("pub(crate) mod "))
                .or_else(|| line.strip_prefix("mod "))
            else {
                continue;
            };
            let Some(name) = rest.strip_suffix(';') else { continue };
            let file = format!("{name}.rs");
            assert!(
                ALLOWED.contains(&file.as_str())
                    || sources.iter().any(|(scanned, _)| *scanned == file),
                "`{file}` is declared and neither scanned nor allowed"
            );
        }

        // Inside the service, only the report may name it.
        let service = crate::code_of(include_str!("service.rs"));
        let outside_the_report = service.replace(body_of(&service, "async fn describe("), "");
        for token in TOKENS {
            assert!(
                !outside_the_report.contains(token),
                "`service.rs` names `{token}` outside `describe`, where only the report is built"
            );
        }

        // Inside the node, the functions that pace, dial, route or authorise.
        let node = crate::code_of(include_str!("node.rs"));
        for function in [
            "async fn lagging(",
            "pub async fn owed(",
            "pub async fn pressed(",
            "pub async fn press(",
            "async fn dial(",
            "pub async fn enforce_roster(",
            "async fn received_packet(",
            "pub async fn carry_one(",
            "pub async fn connect(",
            "pub async fn accept(",
        ] {
            let body = body_of(&node, function);
            for token in ["contacts", "last_contact", "touch("] {
                assert!(
                    !body.contains(token),
                    "`{function}` names `{token}`: nothing that paces, dials or authorises may"
                );
            }
        }

        // Renaming it on the way in would defeat everything above.
        for (file, source) in sources.iter().chain(
            [("node.rs", include_str!("node.rs")), ("service.rs", include_str!("service.rs"))]
                .iter(),
        ) {
            let code = crate::code_of(source);
            assert!(
                !code.contains("contacts as ")
                    && !code.contains("LastContacts as ")
                    && !code.contains("ContactRecord as "),
                "`{file}` renames the contact record on import"
            );
        }
    }

    /// The text of one function, from its signature to the next function.
    fn body_of<'a>(code: &'a str, signature: &str) -> &'a str {
        let Some((_, rest)) = code.split_once(signature) else {
            panic!("`{signature}` is not in node.rs any more; update the guard");
        };
        let end = rest
            .find("\nfn ")
            .into_iter()
            .chain(rest.find("\npub fn "))
            .chain(rest.find("\nasync fn "))
            .chain(rest.find("\npub async fn "))
            .chain(rest.find("\npub(crate) async fn "))
            .chain(rest.find("\npub const fn "))
            .min()
            .unwrap_or(rest.len());
        rest.get(..end).unwrap_or(rest)
    }
}

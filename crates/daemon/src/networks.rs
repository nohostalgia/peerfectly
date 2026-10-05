//! Which networks this device holds, and where each one's files are.
//!
//! A device used to hold one network, and the daemon's state directory was that
//! network's state directory. Holding several means the root becomes a place that
//! *contains* networks, and each network gets a directory of its own beneath it.
//!
//! # The label is local and belongs to nobody but this device
//!
//! A network is identified by its network id, which is the id of the operation
//! that founded it. That is unreadable and, worse, unknown at the moment a person
//! needs a directory to put things in: at founding the id is the genesis
//! operation's, and the genesis cannot be signed before the keys exist; at
//! joining it arrives with the roster, after the enrolment has already needed
//! somewhere to write.
//!
//! So a network's directory is named by a **label** the person supplies —
//! `casa`, `lavoro` — and the id is recorded inside it once it is known. The
//! label is not part of what the network agrees on and never leaves this machine.
//! Two of a person's devices may call one network by different names, and neither
//! is wrong.
//!
//! # A label becomes a directory name, so it is checked like one
//!
//! It is the only place a person's free text becomes a path component, which
//! makes it the only place a path traversal could start. It is held to ASCII
//! letters, digits, `-` and `_`: no separators, no `.` (so `.` and `..` cannot be
//! spelled and no name can end in one), and nothing outside ASCII, because two
//! labels that render identically and differ in bytes would be two directories a
//! person could not tell apart.

use core::fmt;
use std::path::{Path, PathBuf};

use roster::id::NetworkId;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::limits;
use crate::state::Paths;

/// The directory that holds the network directories.
const NETWORKS: &str = "networks";

/// A name a person gives one of this device's networks.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Label(String);

impl Label {
    /// Checks a label and takes it.
    ///
    /// # Errors
    ///
    /// When it is empty, too long, contains anything but ASCII letters, digits,
    /// `-` or `_`, or names a device the platform reserves.
    pub fn new(text: &str) -> Result<Self> {
        let refuse = |cause: &str| Error::Label { label: text.to_owned(), cause: cause.to_owned() };

        if text.is_empty() {
            return Err(refuse("a network needs a name to be kept under"));
        }
        if text.len() > limits::MAX_LABEL_LEN {
            return Err(refuse("longer than a name for a folder should be"));
        }
        if !text.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(refuse(
                "only letters, digits, - and _ — it becomes the name of a folder, and a \
                 separator or a dot in one is how a name reaches outside the folder it was \
                 meant for",
            ));
        }
        if is_reserved(text) {
            return Err(refuse("a name the operating system reserves for a device"));
        }
        Ok(Self(text.to_owned()))
    }

    /// The label as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether a name is one the platform reserves for a device.
///
/// Reachable with the characters a label allows, and a directory by one of these
/// names cannot be created on Windows — which would be a refusal arriving from
/// the filesystem, at founding, with nothing explaining it.
fn is_reserved(text: &str) -> bool {
    const RESERVED: [&str; 22] = [
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
        "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];
    let lowered = text.to_ascii_lowercase();
    RESERVED.contains(&lowered.as_str())
}

/// What a network's directory says it is, as written.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stored {
    /// The label, so a directory renamed by hand is noticed.
    label: String,
    /// The network id, in hex.
    network: String,
}

/// What a network's directory says it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The label this device keeps the network under.
    pub label: Label,
    /// The network itself.
    pub network: NetworkId,
}

impl Record {
    /// Reads the record from a network's directory.
    ///
    /// # Errors
    ///
    /// When it is missing, unreadable, or does not describe a network. A missing
    /// one is an error rather than an empty default: a directory under `networks`
    /// with no record is not a device that has never joined, it is a network
    /// whose identity on this machine has been lost, and treating the two alike
    /// is how a daemon would quietly stop holding something.
    pub fn read(paths: &Paths) -> Result<Self> {
        let path = paths.record();
        let bytes = std::fs::read(&path)
            .map_err(|cause| Error::State { path: path.clone(), cause: cause.to_string() })?;
        let stored: Stored = serde_json::from_slice(&bytes)
            .map_err(|cause| Error::State { path: path.clone(), cause: cause.to_string() })?;

        let label = Label::new(&stored.label)?;
        let network = NetworkId::from_hex(&stored.network).ok_or_else(|| Error::State {
            path,
            cause: "the record does not name a network".to_owned(),
        })?;
        Ok(Self { label, network })
    }

    /// Writes the record into a network's directory.
    ///
    /// # Errors
    ///
    /// When it cannot be written.
    pub fn write(&self, paths: &Paths) -> Result<()> {
        let path = paths.record();
        let stored = Stored { label: self.label.to_string(), network: self.network.to_hex() };
        let encoded = serde_json::to_vec_pretty(&stored)
            .map_err(|cause| Error::State { path: path.clone(), cause: cause.to_string() })?;
        std::fs::write(&path, encoded)
            .map_err(|cause| Error::State { path, cause: cause.to_string() })
    }
}

/// A network this device holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// What its directory says it is.
    pub record: Record,
    /// Where its files are.
    pub paths: Paths,
}

/// A directory under `networks` that does not describe a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable {
    /// The directory's name, which is all that could be read of it.
    pub name: String,
    /// Why it could not be taken as a network.
    pub cause: String,
}

/// What this device holds, and what it could not make sense of.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Survey {
    /// The networks, by label.
    pub held: Vec<Held>,
    /// Directories that are not networks, reported rather than skipped.
    pub unreadable: Vec<Unreadable>,
}

impl Survey {
    /// The network kept under a label, if any.
    #[must_use]
    pub fn holding(&self, label: &Label) -> Option<&Held> {
        self.held.iter().find(|held| held.record.label == *label)
    }

    /// The network with a given id, if this device holds it.
    #[must_use]
    pub fn with_network(&self, network: &NetworkId) -> Option<&Held> {
        self.held.iter().find(|held| held.record.network == *network)
    }
}

/// The directory that holds this device's networks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Home {
    /// The directory everything sits under.
    root: PathBuf,
}

impl Home {
    /// A home under a given directory.
    pub fn under(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory everything sits under.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where the network directories live.
    #[must_use]
    pub fn networks(&self) -> PathBuf {
        self.root.join(NETWORKS)
    }

    /// Where one network's files live.
    #[must_use]
    pub fn paths_for(&self, label: &Label) -> Paths {
        Paths::under(self.networks().join(label.as_str()))
    }

    /// Removes a network directory an attempt left behind without founding anything.
    ///
    /// Founding and joining make the identity before they sign or hear anything, so
    /// an attempt that fails afterwards — a person declining the lock, a relay that
    /// will not answer, parameters the roster refuses — leaves a directory holding
    /// keys and no network. Left there, it is reported on every start as a network
    /// that could not be carried, which is a network the person never had.
    ///
    /// Only a directory with no record and an empty log is removed. One that holds
    /// either is a network, and is never touched here.
    ///
    /// Returns whether anything was removed.
    ///
    /// # Errors
    ///
    /// When the directory exists and cannot be read or removed.
    pub fn discard_unfounded(&self, label: &Label) -> Result<bool> {
        let paths = self.paths_for(label);
        if !paths.root().exists() || paths.record().exists() {
            return Ok(false);
        }
        if !crate::state::Log::at(paths.roster()).read()?.is_empty() {
            return Ok(false);
        }
        std::fs::remove_dir_all(paths.root()).map_err(|cause| Error::State {
            path: paths.root().to_path_buf(),
            cause: cause.to_string(),
        })?;
        Ok(true)
    }

    /// Removes every directory an interrupted attempt left behind.
    ///
    /// [`Self::discard_unfounded`] covers an attempt that ends; a process that dies
    /// in the middle of one — a phone ending the app while a join waits — leaves a
    /// directory holding keys and no network, reported on every start as a network
    /// that could not be carried and holding its name. Run before the survey.
    ///
    /// Returns how many were removed.
    ///
    /// # Errors
    ///
    /// When the networks directory exists and cannot be read.
    pub fn discard_every_unfounded(&self) -> Result<usize> {
        let networks = self.networks();
        let entries = match std::fs::read_dir(&networks) {
            Ok(entries) => entries,
            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(cause) => return Err(Error::State { path: networks, cause: cause.to_string() }),
        };
        let mut removed = 0_usize;
        for entry in entries.flatten() {
            let Ok(label) = Label::new(&entry.file_name().to_string_lossy()) else { continue };
            if entry.path().is_dir() && self.discard_unfounded(&label).unwrap_or(false) {
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }

    /// Creates the directory the networks sit under.
    ///
    /// # Errors
    ///
    /// When it cannot be created.
    pub fn create(&self) -> Result<()> {
        let path = self.networks();
        std::fs::create_dir_all(&path)
            .map_err(|cause| Error::State { path, cause: cause.to_string() })
    }

    /// Moves a network kept in the older, single-network layout into one of its
    /// own, and says what it was called.
    ///
    /// A device that held one network kept its files in the root, because the
    /// root *was* that network's directory. This finds that, gives it a
    /// directory, and records which network it is.
    ///
    /// **The identity is moved, never regenerated.** Fresh keys would make this a
    /// different device in a network whose roster would load regardless — the
    /// machine would come up holding a network it can no longer prove it belongs
    /// to, refusing every peer and refused by all of them. So the one network a
    /// device had before this keeps the identity it had, which means the
    /// unlinkability that separate identities buy applies to networks acquired
    /// afterwards and not to that one. That is a weaker property than a fresh
    /// install has, and it is said here rather than left to be discovered.
    ///
    /// The label is taken from the network's own suffix — `casa.internal` becomes
    /// `casa` — because that is the closest thing to a name the person has
    /// already chosen. Where the suffix yields nothing usable, or the label is
    /// taken, a plain fallback is used: a name a person can change is better than
    /// a network that will not load.
    ///
    /// # Errors
    ///
    /// When something is in the old layout and cannot be moved.
    pub fn adopt_anything_in_the_old_shape(&self) -> Result<Option<Label>> {
        let old = Paths::under(&self.root);
        if !old.roster().exists() {
            return Ok(None);
        }

        let (network, suffix) = match describe(&old) {
            Some(described) => described,
            None => {
                return Err(Error::State {
                    path: old.roster(),
                    cause: "there is a roster here and it describes no network, so there is nothing to adopt. Move it aside rather than let a daemon start without it."
                        .to_owned(),
                });
            }
        };
        let label = self.free_label(Some(&suffix))?;
        let paths = self.paths_for(&label);
        paths.create()?;

        for (from, to) in [
            (old.identity(), paths.identity()),
            (old.roster(), paths.roster()),
            (old.endpoints(), paths.endpoints()),
            (old.choice(), paths.choice()),
        ] {
            if !from.exists() {
                continue;
            }
            std::fs::rename(&from, &to)
                .map_err(|cause| Error::State { path: from, cause: cause.to_string() })?;
        }

        // Written here, where the id is known: the roster has just been replayed
        // to find the suffix, so nothing more is read to learn it.
        Record { label: label.clone(), network }.write(&paths)?;

        Ok(Some(label))
    }

    /// Moves a network's directory to another name.
    ///
    /// What a join does once the roster has arrived and the network's suffix is
    /// known: it wrote under a name this daemon chose, because a person cannot
    /// name a network they have not seen, and now there is something to name it
    /// after.
    ///
    /// # Errors
    ///
    /// When the directory cannot be moved, or the new name is already a
    /// directory — which would be one network's files landing on another's.
    pub fn rename(&self, from: &Label, to: &Label) -> Result<()> {
        if from == to {
            return Ok(());
        }
        let target = self.paths_for(to);
        if target.root().exists() {
            return Err(Error::Label {
                label: to.to_string(),
                cause: "this device already keeps a network under that name".to_owned(),
            });
        }
        std::fs::rename(self.paths_for(from).root(), target.root()).map_err(|cause| Error::State {
            path: target.root().to_path_buf(),
            cause: cause.to_string(),
        })
    }

    /// A label from the suffix where that works, and a plain one where it does
    /// not, never one this device already uses.
    pub(crate) fn free_label(&self, suffix: Option<&str>) -> Result<Label> {
        let taken = self.survey()?;
        let wanted = suffix
            .and_then(|suffix| suffix.split('.').next().map(str::to_owned))
            .and_then(|first| Label::new(&first).ok());

        if let Some(label) = wanted
            && taken.holding(&label).is_none()
        {
            return Ok(label);
        }

        let plain = Label::new("network")?;
        if taken.holding(&plain).is_none() {
            return Ok(plain);
        }
        for attempt in 2..1000u32 {
            let label = Label::new(&format!("network-{attempt}"))?;
            if taken.holding(&label).is_none() {
                return Ok(label);
            }
        }
        Err(Error::Label {
            label: "network".to_owned(),
            cause: "this device holds too many networks by that name".to_owned(),
        })
    }

    /// Writes the record for every directory that holds a proved membership and has
    /// lost the record of which network it is, and removes those that prove nothing.
    ///
    /// # Why a directory ends up like this
    ///
    /// A join appends the roster to its log only **after** the roster has been
    /// verified and adopted, and the record naming the network is written afterwards
    /// by the service. A process that ends between those two — a phone closing the
    /// app is enough — leaves a directory holding a membership a person confirmed on
    /// two screens and no record of what it belongs to.
    ///
    /// [`Home::discard_unfounded`] does not touch it, because it removes only a
    /// directory whose log is *empty*. So it survived every restart and was reported
    /// for ever as a network this device could not carry. Two were found on a test
    /// phone, each holding a valid membership that was in practice thrown away.
    ///
    /// # Nothing is taken on trust
    ///
    /// The record is not guessed: the network is the roster's own founding
    /// operation's id, and the label is the directory's own name, which was never
    /// anything but local. Everything else is checked — the log must replay to a
    /// valid state that names **this device's own keys**, which is the same question
    /// the join asked before it wrote anything. A log cut short mid-append derives
    /// nothing that names this device, and its directory is removed.
    ///
    /// # Errors
    ///
    /// When the networks directory exists and cannot be read.
    pub fn recover_every_unrecorded(&self, keys: &dyn crate::keys::Keys) -> Result<Vec<Recovered>> {
        let networks = self.networks();
        let entries = match std::fs::read_dir(&networks) {
            Ok(entries) => entries,
            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(cause) => return Err(Error::State { path: networks, cause: cause.to_string() }),
        };

        let mut done = Vec::new();
        for entry in entries.flatten() {
            let Ok(label) = Label::new(&entry.file_name().to_string_lossy()) else { continue };
            if !entry.path().is_dir() {
                continue;
            }
            let paths = self.paths_for(&label);
            if paths.record().exists() {
                continue;
            }
            // No identity means no membership this device could hold, and asking for
            // one here would *create* keys in a directory about to be removed.
            if !paths.identity().exists() {
                continue;
            }

            match Self::provable(&paths, keys) {
                Some(network) => {
                    // Under the network's own name, not the one it happens to sit
                    // under. A directory in this state was named by the daemon and
                    // not by a person: a join writes somewhere before it knows
                    // what is arriving, and a join that got this far knows now.
                    //
                    // And **one directory per network**: where this device already
                    // holds the same network somewhere else, that is a membership
                    // this one supersedes — the residue of enrolling again — and
                    // keeping both leaves a dead identity beside a live one for a
                    // person to clean up after. The one being replaced gives up
                    // its name, which is the name a person knows the network by.
                    let superseded = self
                        .survey()
                        .ok()
                        .and_then(|held| {
                            held.with_network(&network).map(|one| one.record.label.clone())
                        })
                        .filter(|other| *other != label);
                    if let Some(other) = &superseded {
                        let old = self.paths_for(other);
                        let _gone = std::fs::remove_dir_all(old.root());
                    }
                    let wanted = superseded.or_else(|| {
                        describe(&paths).and_then(|(_, suffix)| self.free_label(Some(&suffix)).ok())
                    });
                    let label = match wanted.filter(|wanted| *wanted != label) {
                        // A membership held under a name nobody would have chosen
                        // is still held: nothing here is worth failing a recovery.
                        Some(wanted) => match self.rename(&label, &wanted) {
                            Ok(()) => wanted,
                            Err(_kept) => label,
                        },
                        None => label,
                    };
                    let paths = self.paths_for(&label);
                    Record { label: label.clone(), network }.write(&paths)?;
                    done.push(Recovered::Carried(label));
                }
                None => {
                    std::fs::remove_dir_all(paths.root()).map_err(|cause| Error::State {
                        path: paths.root().to_path_buf(),
                        cause: cause.to_string(),
                    })?;
                    done.push(Recovered::Discarded(label));
                }
            }
        }
        Ok(done)
    }

    /// The network a directory's roster proves this device belongs to, if it does.
    fn provable(paths: &Paths, keys: &dyn crate::keys::Keys) -> Option<NetworkId> {
        let (network, _suffix) = describe(paths)?;
        let identity = keys.identity(paths).ok()?;
        let log = crate::state::Log::at(paths.roster());
        let mut roster = roster::roster::Roster::new();
        for operation in log.read().ok()? {
            roster.offer_bytes(&operation);
        }
        let state = roster.state().ok()?;
        // The same question the join asked before it wrote anything: does what
        // arrived name this device's own keys.
        state.devices.contains_key(&identity.device_id()).then_some(network)
    }

    /// Everything under `networks`, sorted by label, with what could not be read.
    ///
    /// A directory that is not a network is **reported**, never skipped. Skipping
    /// would turn a network whose record was lost into a device that had simply
    /// never joined it — the same class of silence as replacing an identity that
    /// would not open.
    ///
    /// # Errors
    ///
    /// When the containing directory exists and cannot be listed. A missing one
    /// is a device that holds nothing, which is not a failure.
    pub fn survey(&self) -> Result<Survey> {
        let networks = self.networks();
        let entries = match std::fs::read_dir(&networks) {
            Ok(entries) => entries,
            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Survey::default());
            }
            Err(cause) => {
                return Err(Error::State { path: networks, cause: cause.to_string() });
            }
        };

        let mut survey = Survey::default();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(cause) => {
                    survey
                        .unreadable
                        .push(Unreadable { name: "?".to_owned(), cause: cause.to_string() });
                    continue;
                }
            };
            if !entry.path().is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let paths = Paths::under(entry.path());

            match Record::read(&paths) {
                Ok(record) => survey.held.push(Held { record, paths }),
                Err(cause) => {
                    survey.unreadable.push(Unreadable { name, cause: cause.to_string() });
                }
            }
        }

        // Sorted, so a report and a listing do not depend on the order a
        // filesystem happened to hand things back.
        survey.held.sort_by(|left, right| left.record.label.cmp(&right.record.label));
        survey.unreadable.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(survey)
    }
}

/// What became of a directory that held a roster and no record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovered {
    /// The record was written from what the roster already proved.
    Carried(Label),
    /// The roster proved no membership, so the directory was removed.
    Discarded(Label),
}

/// The network a set of paths holds, if its roster proves one.
///
/// Public because a join has to ask it of a directory it has just written, before
/// that directory has a record: what it needs to know is whether this device
/// already holds the network that has just arrived.
#[must_use]
pub fn network_of(paths: &Paths) -> Option<NetworkId> {
    describe(paths).map(|(network, _suffix)| network)
}

/// Which network a set of paths holds, and what it answers for.
///
/// Replayed through the roster rather than trusted, the same way a start-up
/// replay is: a log that does not describe a network yields nothing, and this
/// answers with nothing rather than guessing.
fn describe(paths: &Paths) -> Option<(NetworkId, String)> {
    let log = crate::state::Log::at(paths.roster());
    let mut roster = roster::roster::Roster::new();
    for operation in log.read().ok()? {
        roster.offer_bytes(&operation);
    }
    roster.state().ok().map(|state| (state.network, state.params.suffix))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    fn label(text: &str) -> Label {
        Label::new(text).expect("a usable label")
    }

    fn network(tag: u8) -> NetworkId {
        NetworkId::from_bytes([tag; 32])
    }

    /// Written down because it is the only place a person's text becomes a path.
    #[test]
    fn a_label_may_not_reach_outside_its_folder() {
        for hostile in ["..", ".", "a/b", "a\\b", "a:b", "c..", "", "a.b"] {
            assert!(Label::new(hostile).is_err(), "`{hostile}` must be refused");
        }
    }

    #[test]
    fn a_label_may_not_name_a_device_the_platform_reserves() {
        for reserved in ["con", "CON", "Nul", "com1", "LPT9"] {
            assert!(Label::new(reserved).is_err(), "`{reserved}` must be refused");
        }
    }

    #[test]
    fn an_ordinary_label_is_taken() {
        for ordinary in ["casa", "lavoro", "cliente-acme", "rete_2"] {
            assert_eq!(Label::new(ordinary).expect("usable").as_str(), ordinary);
        }
    }

    /// Two labels that look the same and differ in bytes would be two folders a
    /// person could not tell apart.
    #[test]
    fn a_label_is_ascii() {
        assert!(Label::new("caffè").is_err());
        assert!(Label::new("каса").is_err());
    }

    #[test]
    fn two_networks_land_in_different_directories() {
        let scratch = tempfile::tempdir().unwrap();
        let home = Home::under(scratch.path());

        let casa = home.paths_for(&label("casa"));
        let lavoro = home.paths_for(&label("lavoro"));

        assert_ne!(casa.root(), lavoro.root());

        // The records kept beside the log, found the way the node finds them. Last
        // contact is metadata about the people in one network, and removing the
        // network's directory has to remove it too.
        let contacts = crate::contacts::ContactRecord::beside(&casa.roster()).path().to_path_buf();
        let confirmations =
            crate::confirmations::Confirmations::beside(&casa.roster()).path().to_path_buf();

        for one in [
            casa.roster(),
            casa.identity(),
            casa.endpoints(),
            casa.choice(),
            contacts,
            confirmations,
        ] {
            assert!(one.starts_with(casa.root()), "{} belongs to its own network", one.display());
            assert!(!one.starts_with(lavoro.root()));
        }
    }

    /// Nothing belonging to a network lands in the root, which is what makes the
    /// root a place that contains networks rather than one that is a network.
    #[test]
    fn no_network_file_lands_in_the_root() {
        let scratch = tempfile::tempdir().unwrap();
        let home = Home::under(scratch.path());
        let paths = home.paths_for(&label("casa"));

        for one in [paths.roster(), paths.identity(), paths.endpoints(), paths.choice()] {
            assert_eq!(one.parent(), Some(paths.root()));
            assert_ne!(one.parent(), Some(home.root()));
        }
    }

    #[test]
    fn a_record_round_trips() {
        let scratch = tempfile::tempdir().unwrap();
        let home = Home::under(scratch.path());
        let paths = home.paths_for(&label("casa"));
        paths.create().unwrap();

        let record = Record { label: label("casa"), network: network(7) };
        record.write(&paths).unwrap();
        assert_eq!(Record::read(&paths).unwrap(), record);
    }

    /// A directory with no record is a network whose identity on this machine
    /// was lost, not a device that never joined one.
    #[test]
    fn a_missing_record_is_reported_rather_than_read_as_nothing() {
        let scratch = tempfile::tempdir().unwrap();
        let home = Home::under(scratch.path());
        let paths = home.paths_for(&label("casa"));
        paths.create().unwrap();

        assert!(Record::read(&paths).is_err());
    }

    #[test]
    fn a_device_holding_nothing_surveys_empty() {
        let scratch = tempfile::tempdir().unwrap();
        let survey = Home::under(scratch.path()).survey().unwrap();
        assert_eq!(survey, Survey::default());
    }

    #[test]
    fn what_is_held_is_listed_and_what_is_not_is_reported() {
        let scratch = tempfile::tempdir().unwrap();
        let home = Home::under(scratch.path());
        home.create().unwrap();

        for (name, tag) in [("casa", 1u8), ("lavoro", 2), ("cliente", 3)] {
            let paths = home.paths_for(&label(name));
            paths.create().unwrap();
            Record { label: label(name), network: network(tag) }.write(&paths).unwrap();
        }

        // A fourth directory with nothing in it.
        let broken = home.paths_for(&label("rotta"));
        broken.create().unwrap();

        let survey = home.survey().unwrap();
        let labels: Vec<String> =
            survey.held.iter().map(|held| held.record.label.to_string()).collect();
        assert_eq!(labels, vec!["casa", "cliente", "lavoro"], "sorted, and all three");
        assert_eq!(survey.unreadable.len(), 1, "the fourth is reported, not skipped");
        assert_eq!(survey.unreadable.first().expect("one").name, "rotta");
    }

    #[test]
    fn a_label_already_in_use_can_be_named() {
        let scratch = tempfile::tempdir().unwrap();
        let home = Home::under(scratch.path());
        home.create().unwrap();

        let paths = home.paths_for(&label("casa"));
        paths.create().unwrap();
        Record { label: label("casa"), network: network(9) }.write(&paths).unwrap();

        let survey = home.survey().unwrap();
        let taken = survey.holding(&label("casa")).expect("it is held");
        assert_eq!(taken.record.network, network(9), "the refusal can say what holds it");
        assert!(survey.holding(&label("lavoro")).is_none());
        assert!(survey.with_network(&network(9)).is_some(), "and it is found by network too");
    }

    /// A directory in the state a join leaves when it is cut short after the
    /// roster is written and before the record is: identity, log, no record.
    fn stranded(home: &Home, label: &Label) -> Paths {
        let paths = home.paths_for(label);
        paths.create().expect("creates");

        let founder = identity::NodeIdentity::generate().expect("generates");
        let params = roster::types::NetworkParams::new(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            "casa.internal",
            2_592_000,
        )
        .expect("valid");
        let genesis = roster::types::OperationCore::new(
            1,
            founder.signing_key().algorithm(),
            roster::types::OperationBody::CreateNetwork {
                device: founder
                    .device_spec("nas", roster::types::Role::Admin, true, vec![])
                    .expect("spec"),
                params,
            },
            vec![],
            founder.signing_key().key_id(),
            roster::id::NetworkId::from_bytes([0; 32]),
        )
        .expect("well-formed");
        let genesis_bytes = founder.sign_operation(&genesis).expect("signs");

        // This directory's own identity, as a join would have created it, and the
        // admission that names it — which is what makes the membership provable.
        let joiner = crate::keys::Keys::identity(&crate::keys::PlatformKeys, &paths)
            .expect("an identity is made");
        let network = roster::id::NetworkId::from_bytes(*genesis.id().as_bytes());
        let add = roster::types::OperationCore::new(
            2,
            founder.signing_key().algorithm(),
            roster::types::OperationBody::AddDevice(
                joiner
                    .device_spec("telefono", roster::types::Role::Member, false, vec![])
                    .expect("spec"),
            ),
            vec![genesis.id()],
            founder.signing_key().key_id(),
            network,
        )
        .expect("well-formed");
        let add_bytes = founder.sign_operation(&add).expect("signs");

        let log = crate::state::Log::at(paths.roster());
        log.append(&genesis_bytes).expect("writes");
        log.append(&add_bytes).expect("writes");
        paths
    }

    /// A network is kept under a name taken from its own suffix, which is the
    /// closest thing to a name the network has — and the only one available at
    /// the moment there is something to name.
    #[test]
    fn a_network_is_kept_under_a_name_from_its_suffix() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");

        assert_eq!(label("casa"), home.free_label(Some("casa.internal")).expect("a name"));
        // And where the suffix yields nothing usable, a plain one rather than a
        // refusal: the network has arrived and has to be kept somewhere.
        assert_eq!(label("network"), home.free_label(Some("..")).expect("a name"));
        assert_eq!(label("network"), home.free_label(None).expect("a name"));
    }

    /// Two networks that answer for the same suffix are two directories. The
    /// second is not refused and does not land on the first.
    #[test]
    fn a_second_network_with_the_same_suffix_gets_its_own_name() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");

        let first = home.free_label(Some("casa.internal")).expect("a name");
        let paths = home.paths_for(&first);
        paths.create().expect("creates");
        Record { label: first.clone(), network: roster::id::NetworkId::from_bytes([1; 32]) }
            .write(&paths)
            .expect("writes");

        let second = home.free_label(Some("casa.internal")).expect("a name");

        assert_ne!(first, second, "the second network is kept somewhere else");
        assert!(home.paths_for(&first).record().exists(), "and the first is untouched");
    }

    /// The rename a join does once the suffix is known: the provisional name the
    /// daemon chose becomes the network's own, with the files carried across.
    #[test]
    fn a_provisional_directory_is_renamed_once_the_network_arrives() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");

        let provisional = home.free_label(None).expect("a name");
        let paths = home.paths_for(&provisional);
        paths.create().expect("creates");
        std::fs::write(paths.roster(), b"the roster that arrived").expect("writes");

        let wanted = home.free_label(Some("casa.internal")).expect("a name");
        home.rename(&provisional, &wanted).expect("renames");

        assert!(!paths.root().exists(), "nothing is left under the provisional name");
        let now = home.paths_for(&wanted);
        assert_eq!(
            b"the roster that arrived".to_vec(),
            std::fs::read(now.roster()).expect("reads"),
            "and the files came with it"
        );
    }

    /// One network's files must never land on another's.
    #[test]
    fn renaming_onto_a_directory_that_exists_is_refused() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");
        let from = label("network");
        let onto = label("casa");
        home.paths_for(&from).create().expect("creates");
        home.paths_for(&onto).create().expect("creates");

        assert!(home.rename(&from, &onto).is_err(), "refused");
        assert!(home.paths_for(&from).root().exists(), "and nothing moved");
    }

    /// The case found on a real phone, twice: a membership confirmed on two    /// The case found on a real phone, twice: a membership confirmed on two
    /// screens, thrown away in practice because nothing could complete it and
    /// nothing could remove it.
    #[test]
    fn a_directory_that_proves_a_membership_is_recovered() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");
        let label = label("casa");
        let paths = stranded(&home, &label);
        assert!(!paths.record().exists(), "this is what the join did not get to");

        let done = home.recover_every_unrecorded(&crate::keys::PlatformKeys).expect("recovers");

        assert_eq!(vec![Recovered::Carried(label.clone())], done);
        let record = Record::read(&paths).expect("the record was written");
        assert_eq!(label, record.label, "the directory's own name, which was always local");
        assert_eq!(
            describe(&paths).expect("describes").0,
            record.network,
            "and the network the roster itself proves"
        );
    }

    /// A directory in this state was named by the daemon, not by a person: a join
    /// writes somewhere before it knows what is arriving. By the time it can be
    /// recovered the suffix is known, so it is kept under the network's own name.
    ///
    /// Left alone, the first real recovery produced a membership called `network`
    /// and nothing could ever rename it.
    #[test]
    fn a_recovered_directory_takes_the_network_s_name() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");
        // The name a join writes under before it knows anything.
        let provisional = home.free_label(None).expect("a name");
        assert_eq!(label("network"), provisional);
        let _paths = stranded(&home, &provisional);

        let done = home.recover_every_unrecorded(&crate::keys::PlatformKeys).expect("recovers");

        // `stranded` founds a network whose suffix is `casa.internal`.
        assert_eq!(vec![Recovered::Carried(label("casa"))], done);
        assert!(!home.paths_for(&provisional).root().exists(), "nothing is left behind");
        let record = Record::read(&home.paths_for(&label("casa"))).expect("the record moved too");
        assert_eq!(label("casa"), record.label, "and the record agrees with the directory");
    }

    /// Recovery runs the join's own check. A roster that derives a network this
    /// device is not in proves nothing, whatever else it proves.
    ///
    /// The log here is a real one, lifted off the test phone: it derives a valid
    /// network, and the device it names holds its keys in that phone's keystore
    /// and not here.
    ///
    /// Replaced on 2026-09-19, after `membership-freshness` made an attestation
    /// key part of every device record and no roster operation adds a key to a
    /// device that already exists — so the log this test used before, written by
    /// the same phone under the older format, stopped deriving. It was not
    /// synthesised: a built log would pass this test while proving nothing about
    /// a log a phone actually wrote, which is the whole reason the fixture is
    /// real. The network was refounded and the new log taken off the phone.
    #[test]
    fn a_roster_that_does_not_name_this_device_is_removed() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");
        let label = label("studio");
        let paths = home.paths_for(&label);
        paths.create().expect("creates");
        std::fs::write(
            paths.roster(),
            include_bytes!("../tests/fixtures/stranded-join/roster.log"),
        )
        .expect("writes");
        // A key of this machine's own, which that network has never heard of.
        let _made = crate::keys::Keys::identity(&crate::keys::PlatformKeys, &paths)
            .expect("an identity is made");

        assert!(describe(&paths).is_some(), "the log does derive a network");

        let done = home.recover_every_unrecorded(&crate::keys::PlatformKeys).expect("recovers");

        assert_eq!(vec![Recovered::Discarded(label)], done);
        assert!(!paths.root().exists(), "and the directory is gone");
    }

    /// A log cut short mid-append derives nothing, and its directory goes.
    #[test]
    fn a_log_that_derives_nothing_is_removed() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");
        let label = label("mezzo");
        let paths = home.paths_for(&label);
        paths.create().expect("creates");
        std::fs::write(paths.roster(), b"\x00\x00\x00not an operation").expect("writes");
        let _made = crate::keys::Keys::identity(&crate::keys::PlatformKeys, &paths)
            .expect("an identity is made");

        let done = home.recover_every_unrecorded(&crate::keys::PlatformKeys).expect("recovers");

        assert_eq!(vec![Recovered::Discarded(label)], done);
        assert!(!paths.root().exists());
    }

    /// The existing rule is untouched: a directory whose log is empty is an
    /// abandoned attempt, and is still cleaned up the way it always was.
    #[test]
    fn a_directory_with_no_roster_at_all_is_left_to_the_older_rule() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");
        let vuoto = label("vuoto");
        let paths = home.paths_for(&vuoto);
        paths.create().expect("creates");
        let _made = crate::keys::Keys::identity(&crate::keys::PlatformKeys, &paths)
            .expect("an identity is made");

        // Nothing to prove and nothing to disprove: recovery removes it as
        // proving no membership, which is what it is.
        let done = home.recover_every_unrecorded(&crate::keys::PlatformKeys).expect("recovers");
        assert_eq!(vec![Recovered::Discarded(vuoto)], done);

        // And the older rule still removes one with no identity either.
        let bare = label("bare2");
        home.paths_for(&bare).create().expect("creates");
        assert!(home.discard_unfounded(&bare).expect("discards"), "the empty-log rule is intact");
    }
}

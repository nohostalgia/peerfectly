//! What binds a network's directory to this machine.
//!
//! # The gap this closes
//!
//! Everything a network says is signed: operations by admins, roots by
//! admins' attestation keys. What is not signed is which network a directory
//! holds. Somebody who can write the daemon's state without running as the
//! daemon — offline access to a disk, a backup restored — could put another
//! network's roster there that names this device's public keys, drop in a
//! whole directory, edit what a light member keeps, move freshness receipt
//! times forward, or plant an invite. None of that needs a key the network
//! knows, so nothing the network signed could notice.
//!
//! # What closes it
//!
//! A **checkpoint** per network: where its state stood the last time this
//! daemon changed it, signed by a key only this machine's daemon can use. A
//! network is carried only when its checkpoint verifies and its directory
//! agrees with it; a directory with none is never adopted.
//!
//! The roster's log may have grown past the checkpoint — it grows only by
//! operations their admins signed, and a stop between appending one and
//! rewriting the checkpoint is ordinary — but must not have lost any of it.
//! The base a compacted log rests on and what a light member keeps are
//! replaced whole, so the checkpoint names each new one **before** it is
//! written, beside the one it replaces, until the write has landed.
//!
//! The small values a person or freshness depends on — the receipt times,
//! the up or down choice — live in the checkpoint itself, and are put back
//! into the files the rest of the daemon reads before a network is carried.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use roster::id::{NetworkId, OperationId};
use roster::sign::PublicKey;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::state::{Choice, Paths};

/// The context every checkpoint signature is made under, so the machine key's
/// signature over a checkpoint can never be read as anything else.
const CONTEXT: &[u8] = b"peerfectly checkpoint v1\0";

/// Where the software machine key is kept, under the daemon's home.
const KEY_FILE: &str = "machine.key";

/// Where the daemon notes which kind of machine key it made: `hardware` or
/// `software`. What it guards against is a quiet fall back: a machine whose
/// hardware key is gone must say so, never make a software key and trust what
/// is on disk once more.
const KIND_FILE: &str = "machine.kind";

/// The name a platform gives the machine key in its hardware.
pub const HARDWARE_NAME: &str = "peerfectly.machine";

/// How long changes are grouped before the checkpoint is written again.
pub const GROUPING: Duration = Duration::from_secs(5);

/// A 32-byte hash.
pub type Hash = [u8; 32];

/// Why a directory is not carried.
pub type Refusal = String;

/// The key a machine signs its checkpoints with.
///
/// One per machine, used by the daemon with nobody present, signing
/// checkpoints and nothing else. Held by hardware where the machine has it;
/// a software key where it does not.
pub trait MachineKey: Send + Sync {
    /// Its public half, as the thing holding it says.
    fn public(&self) -> PublicKey;

    /// Signs `message`.
    ///
    /// # Errors
    ///
    /// When whatever holds the key will not sign.
    fn sign(&self, message: &[u8]) -> core::result::Result<Vec<u8>, String>;
}

/// Hardware that can hold this machine's key: a TPM, a hardware keystore.
pub trait HardwareKeys {
    /// The key the hardware holds, if it holds one.
    ///
    /// # Errors
    ///
    /// When the hardware answered something other than "none".
    fn open(&self) -> core::result::Result<Option<Arc<dyn MachineKey>>, String>;

    /// Makes the key: non-exportable, needing no person, not bound to boot
    /// measurements.
    ///
    /// # Errors
    ///
    /// When the hardware will not make it.
    fn create(&self) -> core::result::Result<Arc<dyn MachineKey>, String>;
}

/// This machine's key, held by `hardware` where there is any; and whether it
/// was made now, which is what tells a first start from any other.
///
/// - Hardware that holds the key: that key, always — whatever any file says,
///   so a file cannot talk the daemon down to a key somebody wrote.
/// - Hardware that holds none, where a hardware key was made before: lost — the
///   TPM was cleared or the hardware replaced — and said so.
/// - Hardware that holds none, never made before: made now.
/// - No hardware, where a hardware key was made before: lost, likewise.
/// - No hardware: the software key, made if there is none.
///
/// # Errors
///
/// When the key is lost, will not open, or cannot be made.
pub fn machine_key(
    home: &Path,
    hardware: Option<&dyn HardwareKeys>,
) -> Result<(Arc<dyn MachineKey>, bool)> {
    let kind_path = home.join(KIND_FILE);
    let failed = |cause: String| Error::State { path: kind_path.clone(), cause };
    let kind = std::fs::read_to_string(&kind_path).ok().map(|text| text.trim().to_owned());
    let lost = || {
        failed(
            "this machine's own key is gone: its TPM was cleared, or the hardware changed. \
             Nothing it vouched for can be believed; each network must be joined again."
                .to_owned(),
        )
    };
    let note = |kind: &str| {
        std::fs::create_dir_all(home)
            .and_then(|()| std::fs::write(&kind_path, kind))
            .map_err(|cause| failed(cause.to_string()))
    };
    match hardware {
        Some(hardware) => {
            if let Some(key) = hardware.open().map_err(failed)? {
                note("hardware")?;
                return Ok((key, false));
            }
            if kind.as_deref() == Some("hardware") {
                return Err(lost());
            }
            let key = hardware.create().map_err(failed)?;
            note("hardware")?;
            // A software key from before is not this machine's any more.
            let _gone = std::fs::remove_file(home.join(KEY_FILE));
            Ok((key, true))
        }
        None => {
            if kind.as_deref() == Some("hardware") {
                return Err(lost());
            }
            let (key, made) = SoftwareKey::at(home)?;
            note("software")?;
            Ok((Arc::new(key), made))
        }
    }
}

/// A machine key kept in a file, protected as an identity is.
///
/// For a machine with no hardware to hold one. Someone holding such a
/// machine's disk can read it — which is what disk encryption is for, and what
/// the threat model says.
pub struct SoftwareKey {
    key: identity::PrivateKey,
}

impl SoftwareKey {
    /// The key kept under `home`, made when there is none; and whether it was
    /// made now, which is what tells a first start from any other.
    ///
    /// # Errors
    ///
    /// When a key is there and will not open — which is never answered by
    /// making a new one — or when one cannot be made.
    pub fn at(home: &Path) -> Result<(Self, bool)> {
        let path = home.join(KEY_FILE);
        let failed =
            |cause: identity::Error| Error::State { path: path.clone(), cause: cause.to_string() };
        if path.exists() {
            let key = identity::store::load_key(&path, &identity::store::PlatformSealer)
                .map_err(failed)?;
            return Ok((Self { key }, false));
        }
        std::fs::create_dir_all(home)
            .map_err(|cause| Error::State { path: home.to_path_buf(), cause: cause.to_string() })?;
        let key =
            identity::PrivateKey::generate(roster::types::Algorithm::Ed25519).map_err(failed)?;
        identity::store::save_key(&key, &path, &identity::store::PlatformSealer).map_err(failed)?;
        Ok((Self { key }, true))
    }
}

impl MachineKey for SoftwareKey {
    fn public(&self) -> PublicKey {
        self.key.public_key()
    }

    fn sign(&self, message: &[u8]) -> core::result::Result<Vec<u8>, String> {
        self.key.signer().sign(message).map_err(|cause| cause.to_string())
    }
}

/// Where a network's state stood the last time this daemon changed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// The network, in hex.
    network: String,
    /// The label it is kept under.
    label: String,
    /// The roots the base may rest on, in hex; the empty string for none. One,
    /// except while a new base is being written.
    bases: Vec<String>,
    /// The roster's heads, in hex. Empty for a light member.
    heads: Vec<String>,
    /// The hashes what a light member keeps may have, in hex. One, except
    /// while it is being rewritten; empty for a full member.
    light: Vec<String>,
    /// The hash of the invite records, in hex; empty for none.
    invites: String,
    /// When the held snapshot was accepted, in seconds.
    snapshot_at: Option<u64>,
    /// When the held attestation was accepted.
    attestation_at: Option<u64>,
    /// When the attestation that dated the roster was accepted.
    dating_at: Option<u64>,
    /// Whether the person last left the network up.
    up: bool,
}

/// What a checkpoint is made from, read off a running network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Values {
    /// The network.
    pub network: NetworkId,
    /// The label it is kept under.
    pub label: String,
    /// The root its base rests on, if it was compacted.
    pub base: Option<Hash>,
    /// The roster's heads.
    pub heads: Vec<OperationId>,
    /// The hash of what a light member keeps, for a light member.
    pub light: Option<Hash>,
    /// The hash of the invite records, where there are any.
    pub invites: Option<Hash>,
    /// The receipt times, as the files say them while the daemon runs.
    pub snapshot_at: Option<u64>,
    /// See [`Checkpoint::attestation_at`].
    pub attestation_at: Option<u64>,
    /// See [`Checkpoint::dating_at`].
    pub dating_at: Option<u64>,
    /// The person's choice.
    pub up: bool,
}

impl Values {
    /// What a running network's checkpoint says now.
    pub async fn of(node: &crate::node::Node, paths: &Paths, label: &str) -> Option<Self> {
        let light = node.is_light();
        let (network, base, heads) = if light {
            (node.light_network()?, None, Vec::new())
        } else {
            (node.state().await.ok()?.network, node.base_root().await, node.heads().await)
        };
        Some(Self {
            network,
            label: label.to_owned(),
            base,
            heads,
            light: if light { file_hash(&paths.light()) } else { None },
            invites: file_hash(&invites_path(paths)),
            snapshot_at: read_seconds(&paths.snapshot_at()),
            attestation_at: read_seconds(&paths.attestation_at()),
            dating_at: read_seconds(&paths.attestation_dating_at()),
            up: Choice::read(&paths.choice()) == Choice::Up,
        })
    }
}

impl Checkpoint {
    /// The checkpoint for `values`, also allowing `bases` and `light`.
    fn of(values: &Values, bases: &[Option<Hash>], light: &[Hash]) -> Self {
        let mut all_bases = vec![optional_hex(values.base.as_ref())];
        for base in bases {
            let written = optional_hex(base.as_ref());
            if !all_bases.contains(&written) {
                all_bases.push(written);
            }
        }
        let mut all_light: Vec<String> = values.light.iter().map(|hash| hex(hash)).collect();
        for hash in light {
            let written = hex(hash);
            if !all_light.contains(&written) {
                all_light.push(written);
            }
        }
        Self {
            network: hex(values.network.as_bytes()),
            label: values.label.clone(),
            bases: all_bases,
            heads: values.heads.iter().map(|head| hex(head.as_bytes())).collect(),
            light: all_light,
            invites: optional_hex(values.invites.as_ref()),
            snapshot_at: values.snapshot_at,
            attestation_at: values.attestation_at,
            dating_at: values.dating_at,
            up: values.up,
        }
    }

    /// Whether it is the checkpoint of `network`.
    ///
    /// The label is kept for whoever reads the file, and not checked: a
    /// recovered directory may be renamed, and a directory moved to another
    /// name is the same network, which is all that matters.
    #[must_use]
    pub fn names(&self, network: &NetworkId) -> bool {
        self.network == hex(network.as_bytes())
    }

    /// Whether the base may rest on `root` — `None` for no base at all.
    #[must_use]
    pub fn allows_base(&self, root: Option<&Hash>) -> bool {
        self.bases.contains(&optional_hex(root))
    }

    /// Whether what a light member keeps may hash to `hash`.
    #[must_use]
    pub fn allows_light(&self, hash: &Hash) -> bool {
        self.light.contains(&hex(hash))
    }

    /// The roster's heads, as they stood.
    #[must_use]
    pub fn heads(&self) -> Vec<OperationId> {
        self.heads
            .iter()
            .filter_map(|head| roster::hex::decode(head))
            .filter_map(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .map(OperationId::from_bytes)
            .collect()
    }

    /// Whether the roster's heads all survive in a roster holding `holds`.
    #[must_use]
    pub fn heads_survive(&self, holds: impl Fn(&OperationId) -> bool) -> bool {
        let heads = self.heads();
        heads.len() == self.heads.len() && heads.iter().all(holds)
    }

    /// The invite records it names, as their hash; `None` for none.
    #[must_use]
    pub fn invites_hash(&self) -> Option<Hash> {
        roster::hex::decode(&self.invites).and_then(|bytes| <Hash>::try_from(bytes).ok())
    }

    /// Whether the invite records hashing to `hash` are the ones it names.
    #[must_use]
    pub fn allows_invites(&self, hash: Option<&Hash>) -> bool {
        self.invites == optional_hex(hash)
    }

    /// Whether the person last left the network up.
    #[must_use]
    pub const fn up(&self) -> bool {
        self.up
    }
}

/// The checkpoint kept for `paths`, if there is one.
///
/// # Errors
///
/// When there is one and it does not verify with `key`, or does not read.
pub fn read(
    paths: &Paths,
    key: &dyn MachineKey,
) -> core::result::Result<Option<Checkpoint>, Refusal> {
    let bytes = match std::fs::read(paths.checkpoint()) {
        Ok(bytes) => bytes,
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(cause) => return Err(format!("its checkpoint could not be read: {cause}")),
    };
    let stored: Stored = serde_json::from_slice(&bytes)
        .map_err(|_| "its checkpoint is not one this daemon wrote".to_owned())?;
    let signature = roster::hex::decode(&stored.signature)
        .ok_or_else(|| "its checkpoint carries no signature".to_owned())?;
    key.public()
        .verify(&signed(stored.body.as_bytes()), &signature)
        .map_err(|_| "its checkpoint was not signed by this machine".to_owned())?;
    serde_json::from_str(&stored.body)
        .map(Some)
        .map_err(|_| "its checkpoint does not read".to_owned())
}

/// Signs `checkpoint` with `key` and keeps it for `paths`, in place of the
/// one before.
///
/// # Errors
///
/// When the key will not sign or the file cannot be written.
pub fn write(paths: &Paths, key: &dyn MachineKey, checkpoint: &Checkpoint) -> Result<()> {
    let failed = |cause: String| Error::State { path: paths.checkpoint(), cause };
    let body = serde_json::to_string(checkpoint).map_err(|cause| failed(cause.to_string()))?;
    let signature = key.sign(&signed(body.as_bytes())).map_err(failed)?;
    let stored = Stored { body, signature: roster::hex::encode(&signature) };
    let bytes = serde_json::to_vec_pretty(&stored).map_err(|cause| failed(cause.to_string()))?;
    crate::state::replace_file(&paths.checkpoint(), &bytes)
}

/// Puts what the checkpoint keeps back into the files the rest of the daemon
/// reads, before a network is carried: the receipt times and the choice. And
/// empties the invite records when they are not the ones it names, saying so.
///
/// A time the checkpoint does not have is removed rather than kept: an older
/// or missing receipt is the cautious direction.
///
/// # Errors
///
/// When a file cannot be written.
pub fn restore(paths: &Paths, checkpoint: &Checkpoint) -> Result<bool> {
    for (path, seconds) in [
        (paths.snapshot_at(), checkpoint.snapshot_at),
        (paths.attestation_at(), checkpoint.attestation_at),
        (paths.attestation_dating_at(), checkpoint.dating_at),
    ] {
        match seconds {
            Some(seconds) => crate::state::replace_file(&path, seconds.to_string().as_bytes())?,
            None => remove(&path)?,
        }
    }
    let choice = if checkpoint.up { Choice::Up } else { Choice::Down };
    choice.write(&paths.choice())?;
    let invites = invites_path(paths);
    let planted = !checkpoint.allows_invites(file_hash(&invites).as_ref());
    if planted {
        remove(&invites)?;
    }
    Ok(planted)
}

/// What checking a directory against its checkpoint needs: this machine's key.
///
/// **Nothing is trusted for being there.** Not even on the first start after
/// the key was made: whatever tells a first start from another is a file, or a
/// key whose wrapped form is a file, and somebody holding the disk can remove
/// both — and would then have the daemon vouch for what they planted. A
/// directory is vouched for only by the daemon's own founding or joining, or by
/// [`crate::service::Service::vouch`], which is a person's deliberate act.
#[derive(Clone)]
pub struct Integrity {
    /// This machine's key.
    pub key: Arc<dyn MachineKey>,
}

impl Integrity {
    /// The checkpoint a directory holding `network` keeps, checked.
    ///
    /// # Errors
    ///
    /// When it has none, has one this machine did not sign, or has one naming
    /// another network.
    pub fn checked(
        &self,
        paths: &Paths,
        network: &NetworkId,
    ) -> core::result::Result<Checkpoint, Refusal> {
        match read(paths, self.key.as_ref())? {
            Some(checkpoint) if checkpoint.names(network) => Ok(checkpoint),
            Some(_) => Err("its checkpoint names another network than its roster".to_owned()),
            None => Err("it has no checkpoint this machine signed".to_owned()),
        }
    }
}

/// Keeps a running network's checkpoint current.
///
/// Changes are grouped: the checkpoint is written when what it would say has
/// changed and [`GROUPING`] has passed since the last write, or at once when
/// asked to be. A base or a light member's state about to be replaced is named
/// first, beside the one it replaces, until the write is said to have landed.
pub struct Keeper {
    key: Arc<dyn MachineKey>,
    paths: Paths,
    held: Mutex<Kept>,
}

/// How many of the invite records this daemon wrote are believed at once: the
/// one being written, and the one before it, which a reader may still find in
/// place while the new one lands.
const INVITES_BELIEVED: usize = 2;

/// What a keeper last wrote, and what it is allowing beside it.
#[derive(Default)]
struct Kept {
    written: Option<Checkpoint>,
    values: Option<Values>,
    at: Option<Instant>,
    bases: Vec<Option<Hash>>,
    light: Vec<Hash>,
    /// The invite records this daemon wrote, newest last: what a checkpoint
    /// vouches for, whatever the file holds when it is written. `None` until
    /// there is a checkpoint or a write to go by.
    invites: Option<Vec<Option<Hash>>>,
    /// What a light member keeps, as this daemon last wrote it or found it at
    /// start where the checkpoint names it: what a checkpoint vouches for,
    /// whatever the file holds when it is written.
    light_held: Option<Hash>,
}

impl Keeper {
    /// A keeper for the network at `paths`, which last wrote `written`.
    #[must_use]
    pub fn new(key: Arc<dyn MachineKey>, paths: Paths, written: Option<Checkpoint>) -> Self {
        let invites = written.as_ref().map(|checkpoint| vec![checkpoint.invites_hash()]);
        Self { key, paths, held: Mutex::new(Kept { written, invites, ..Kept::default() }) }
    }

    /// Says the daemon is about to write invite records hashing to `hash`
    /// (`None`: no file). Called before the write, so a checkpoint never
    /// vouches for what somebody else put there.
    pub fn writing_invites(&self, hash: Option<Hash>) {
        if let Ok(mut held) = self.held.lock() {
            let written = held.invites.get_or_insert_with(Vec::new);
            written.push(hash);
            let keep = written.len().saturating_sub(INVITES_BELIEVED);
            written.drain(..keep);
        }
    }

    /// Whether invite records hashing to `hash` are ones this daemon wrote:
    /// what is read is believed only then. True where there is nothing yet
    /// to go by.
    #[must_use]
    pub fn vouches_invites(&self, hash: Option<&Hash>) -> bool {
        self.held.lock().is_ok_and(|held| {
            held.invites.as_ref().is_none_or(|written| written.contains(&hash.copied()))
        })
    }

    /// Says what a light member keeps hashes to `hash` now: written by this
    /// daemon and landed, or found at start as the checkpoint names it.
    pub fn holds_light(&self, hash: Hash) {
        if let Ok(mut held) = self.held.lock() {
            held.light_held = Some(hash);
        }
    }

    /// Writes the checkpoint for `values` where it would say something new.
    /// Whether it was written.
    ///
    /// # Errors
    ///
    /// When it cannot be signed or written.
    pub fn keep(&self, values: Values, now: bool) -> Result<bool> {
        let mut values = values;
        let mut held = self.held.lock().map_err(|_| self.poisoned())?;
        // The invite records the daemon wrote, not whatever the file holds now:
        // a file changed while the daemon runs is not vouched for by the next
        // checkpoint, and is dropped at the next start.
        if let Some(written) = held.invites.as_ref().and_then(|written| written.last()) {
            values.invites = *written;
        }
        // The same for what a light member keeps.
        if values.light.is_some()
            && let Some(kept) = held.light_held
        {
            values.light = Some(kept);
        }
        let checkpoint = Checkpoint::of(&values, &held.bases, &held.light);
        if held.written.as_ref() == Some(&checkpoint) {
            held.values = Some(values);
            return Ok(false);
        }
        if !now && held.at.is_some_and(|at| at.elapsed() < GROUPING) {
            return Ok(false);
        }
        write(&self.paths, self.key.as_ref(), &checkpoint)?;
        held.written = Some(checkpoint);
        held.values = Some(values);
        held.at = Some(Instant::now());
        Ok(true)
    }

    /// Names `root` as a base the network may rest on, before it is written.
    ///
    /// # Errors
    ///
    /// When the checkpoint cannot be written, in which case the base must not
    /// be either.
    pub fn allow_base(&self, root: Option<Hash>) -> Result<()> {
        self.allow(|held| held.bases.push(root))
    }

    /// Names `hash` as what a light member may keep, before it is written.
    ///
    /// # Errors
    ///
    /// As [`Self::allow_base`].
    pub fn allow_light(&self, hash: Hash) -> Result<()> {
        self.allow(|held| held.light.push(hash))
    }

    /// Says a write named beforehand has landed: what it replaced may go at the
    /// next checkpoint.
    pub fn landed(&self) {
        if let Ok(mut held) = self.held.lock() {
            held.bases.clear();
            held.light.clear();
            held.at = None;
        }
    }

    fn allow(&self, add: impl FnOnce(&mut Kept)) -> Result<()> {
        let mut held = self.held.lock().map_err(|_| self.poisoned())?;
        add(&mut held);
        let Some(values) = held.values.clone() else {
            // Nothing written yet in this process: what the directory held at
            // start is what the checkpoint already names, plus this.
            let Some(mut written) = held.written.clone() else { return Ok(()) };
            for base in &held.bases {
                let base = optional_hex(base.as_ref());
                if !written.bases.contains(&base) {
                    written.bases.push(base);
                }
            }
            for hash in &held.light {
                let hash = hex(hash);
                if !written.light.contains(&hash) {
                    written.light.push(hash);
                }
            }
            write(&self.paths, self.key.as_ref(), &written)?;
            held.written = Some(written);
            return Ok(());
        };
        let checkpoint = Checkpoint::of(&values, &held.bases, &held.light);
        write(&self.paths, self.key.as_ref(), &checkpoint)?;
        held.written = Some(checkpoint);
        held.at = Some(Instant::now());
        Ok(())
    }

    fn poisoned(&self) -> Error {
        Error::State {
            path: self.paths.checkpoint(),
            cause: "the keeper's lock was poisoned".to_owned(),
        }
    }
}

/// A checkpoint as the file keeps it: the body, exactly as signed.
#[derive(Serialize, Deserialize)]
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

/// The hash of a file's contents, if it is there.
#[must_use]
pub fn file_hash(path: &Path) -> Option<Hash> {
    std::fs::read(path).ok().map(|bytes| *blake3::hash(&bytes).as_bytes())
}

/// The hash of what a light member keeps, as it will be written.
#[must_use]
pub fn light_hash(member: &roster::member::LightMember) -> Hash {
    *blake3::hash(&member.to_bytes()).as_bytes()
}

/// Where a network's invite records are.
fn invites_path(paths: &Paths) -> std::path::PathBuf {
    paths.root().join(crate::invites::FILE_NAME)
}

fn read_seconds(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn remove(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(cause) => Err(Error::State { path: path.to_path_buf(), cause: cause.to_string() }),
    }
}

fn hex(bytes: &[u8]) -> String {
    roster::hex::encode(bytes)
}

fn optional_hex(hash: Option<&Hash>) -> String {
    hash.map_or_else(String::new, |hash| hex(hash))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    fn values(paths: &Paths) -> Values {
        let _ = paths;
        Values {
            network: NetworkId::from_bytes([7; 32]),
            label: "casa".to_owned(),
            base: None,
            heads: vec![OperationId::from_bytes([1; 32])],
            light: None,
            invites: None,
            snapshot_at: Some(100),
            attestation_at: None,
            dating_at: None,
            up: true,
        }
    }

    fn key(home: &Path) -> Arc<dyn MachineKey> {
        Arc::new(SoftwareKey::at(home).unwrap().0)
    }

    #[test]
    fn a_checkpoint_reads_back_only_with_the_key_that_signed_it() {
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path().join("casa"));
        paths.create().unwrap();
        let ours = key(scratch.path());
        let checkpoint = Checkpoint::of(&values(&paths), &[], &[]);
        write(&paths, ours.as_ref(), &checkpoint).unwrap();
        assert_eq!(read(&paths, ours.as_ref()).unwrap(), Some(checkpoint.clone()));

        let elsewhere = tempfile::tempdir().unwrap();
        let theirs = key(elsewhere.path());
        assert!(read(&paths, theirs.as_ref()).is_err(), "another machine's key");

        // An edited body no longer verifies.
        let text = std::fs::read_to_string(paths.checkpoint()).unwrap();
        std::fs::write(paths.checkpoint(), text.replace("casa", "lavoro")).unwrap();
        assert!(read(&paths, ours.as_ref()).is_err(), "edited");
    }

    #[test]
    fn the_machine_key_is_made_once() {
        let scratch = tempfile::tempdir().unwrap();
        let (first, made) = SoftwareKey::at(scratch.path()).unwrap();
        assert!(made);
        let (again, made) = SoftwareKey::at(scratch.path()).unwrap();
        assert!(!made, "kept, not made again");
        assert_eq!(first.public(), again.public());
    }

    #[test]
    fn a_base_named_before_it_is_written_is_allowed_beside_the_old_one() {
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path().join("casa"));
        paths.create().unwrap();
        let keeper = Keeper::new(key(scratch.path()), paths.clone(), None);
        keeper.keep(values(&paths), true).unwrap();
        keeper.allow_base(Some([9; 32])).unwrap();
        let key = SoftwareKey::at(scratch.path()).unwrap().0;
        let held = read(&paths, &key).unwrap().unwrap();
        assert!(held.allows_base(None) && held.allows_base(Some(&[9; 32])));

        // Landed, and the next checkpoint names only the new one.
        keeper.landed();
        let mut now = values(&paths);
        now.base = Some([9; 32]);
        keeper.keep(now, true).unwrap();
        let held = read(&paths, &key).unwrap().unwrap();
        assert!(!held.allows_base(None) && held.allows_base(Some(&[9; 32])));
    }

    /// What a light member keeps is vouched for as the daemon wrote it, not
    /// as the file holds it when the checkpoint is written: a file changed
    /// behind a running daemon is not named, and is refused at the next start.
    #[test]
    fn a_light_member_is_vouched_for_as_the_daemon_wrote_it() {
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path().join("casa"));
        paths.create().unwrap();
        let keeper = Keeper::new(key(scratch.path()), paths.clone(), None);
        let key = SoftwareKey::at(scratch.path()).unwrap().0;
        let kept = [3; 32];
        let planted = [4; 32];
        keeper.holds_light(kept);

        let mut now = values(&paths);
        now.light = Some(planted);
        keeper.keep(now.clone(), true).unwrap();
        let held = read(&paths, &key).unwrap().unwrap();
        assert!(held.allows_light(&kept), "what the daemon holds");
        assert!(!held.allows_light(&planted), "not what the file was made to hold");

        // A write named and not landed: the one in place stays named beside it.
        keeper.allow_light([5; 32]).unwrap();
        keeper.keep(now.clone(), true).unwrap();
        let held = read(&paths, &key).unwrap().unwrap();
        assert!(held.allows_light(&kept) && held.allows_light(&[5; 32]));
        assert!(!held.allows_light(&planted));

        // Landed: only the new one.
        keeper.holds_light([5; 32]);
        keeper.landed();
        keeper.keep(now, true).unwrap();
        let held = read(&paths, &key).unwrap().unwrap();
        assert!(held.allows_light(&[5; 32]) && !held.allows_light(&kept));
    }

    #[test]
    fn changes_are_grouped_unless_asked_for_at_once() {
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path().join("casa"));
        paths.create().unwrap();
        let keeper = Keeper::new(key(scratch.path()), paths.clone(), None);
        assert!(keeper.keep(values(&paths), false).unwrap(), "the first is written");
        let mut changed = values(&paths);
        changed.up = false;
        assert!(!keeper.keep(changed.clone(), false).unwrap(), "grouped");
        assert!(keeper.keep(changed.clone(), true).unwrap(), "unless asked for at once");
        assert!(!keeper.keep(changed, true).unwrap(), "and nothing new is not written");
    }

    #[test]
    fn restoring_puts_back_the_times_and_choice_and_drops_planted_invites() {
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path().join("casa"));
        paths.create().unwrap();
        let checkpoint = Checkpoint::of(&values(&paths), &[], &[]);
        std::fs::write(paths.snapshot_at(), "999999").unwrap();
        std::fs::write(paths.attestation_at(), "5").unwrap();
        Choice::Down.write(&paths.choice()).unwrap();
        std::fs::write(invites_path(&paths), "[]").unwrap();

        assert!(restore(&paths, &checkpoint).unwrap(), "the invites were not the checkpoint's");
        assert_eq!(read_seconds(&paths.snapshot_at()), Some(100));
        assert_eq!(read_seconds(&paths.attestation_at()), None, "a time it does not have goes");
        assert_eq!(Choice::read(&paths.choice()), Choice::Up);
        assert!(!invites_path(&paths).exists());
    }

    /// Hardware in a test: holds a software key it makes when asked.
    struct Chip {
        held: std::sync::Mutex<Option<Arc<dyn MachineKey>>>,
        home: tempfile::TempDir,
    }

    impl Chip {
        fn new() -> Self {
            Self { held: std::sync::Mutex::new(None), home: tempfile::tempdir().unwrap() }
        }
    }

    impl HardwareKeys for Chip {
        fn open(&self) -> core::result::Result<Option<Arc<dyn MachineKey>>, String> {
            Ok(self.held.lock().unwrap().clone())
        }

        fn create(&self) -> core::result::Result<Arc<dyn MachineKey>, String> {
            let made: Arc<dyn MachineKey> = Arc::new(SoftwareKey::at(self.home.path()).unwrap().0);
            *self.held.lock().unwrap() = Some(Arc::clone(&made));
            Ok(made)
        }
    }

    #[test]
    fn a_hardware_key_is_made_once_and_always_preferred() {
        let scratch = tempfile::tempdir().unwrap();
        let chip = Chip::new();
        let (first, made) = machine_key(scratch.path(), Some(&chip)).unwrap();
        assert!(made);
        let (again, made) = machine_key(scratch.path(), Some(&chip)).unwrap();
        assert!(!made);
        assert_eq!(first.public(), again.public());

        // A file saying otherwise does not talk it down to a key somebody wrote.
        std::fs::write(scratch.path().join(KIND_FILE), "software").unwrap();
        let (held, made) = machine_key(scratch.path(), Some(&chip)).unwrap();
        assert!(!made);
        assert_eq!(held.public(), first.public());
    }

    #[test]
    fn a_hardware_key_that_is_gone_is_lost_and_not_replaced() {
        let scratch = tempfile::tempdir().unwrap();
        let chip = Chip::new();
        machine_key(scratch.path(), Some(&chip)).unwrap();

        // The TPM cleared.
        let cleared = Chip::new();
        let lost = machine_key(scratch.path(), Some(&cleared)).err().expect("lost");
        assert!(lost.to_string().contains("joined again"), "{lost}");
        // And no TPM at all now.
        assert!(machine_key(scratch.path(), None).is_err(), "no quiet fall back to software");
        assert!(!scratch.path().join(KEY_FILE).exists(), "and no software key was made");
    }

    #[test]
    fn without_hardware_the_software_key_is_used() {
        let scratch = tempfile::tempdir().unwrap();
        let (first, made) = machine_key(scratch.path(), None).unwrap();
        assert!(made);
        let (again, made) = machine_key(scratch.path(), None).unwrap();
        assert!(!made);
        assert_eq!(first.public(), again.public());
    }
}

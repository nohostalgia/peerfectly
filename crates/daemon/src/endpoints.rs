//! The endpoint cache, across a restart.
//!
//! §2.6b puts the restore path under 500 ms **using the endpoints in cache,
//! without waiting for the rendezvous**. A cache that only lives in memory is
//! empty every time the daemon starts, which is exactly when that budget is being
//! spent — so the fast path would never once be taken on the path it was designed
//! for.
//!
//! # A wall clock, used for nothing that decides anything
//!
//! [`local_discovery::Cache`] ages entries on `Instant`, which is monotonic and
//! meaningless across processes. Persisting requires a wall clock, and
//! `DESIGN.md` §0 is emphatic that timestamps must not influence ordering, conflict
//! resolution or validity.
//!
//! They do not here. This clock decides only how long to keep a *hint* about
//! where a peer was. A wrong answer costs one failed connection attempt while the
//! other paths proceed; it cannot admit a device, resolve a conflict, or make a
//! revoked key acceptable. The sequence numbers that stop an old announcement
//! walking a peer backwards are the cache's own, and they are persisted with it.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use local_discovery::Cache;
use roster::id::KeyId;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// One peer, as last heard from.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    /// The transport key, in hex.
    key: String,
    /// The sequence its announcement carried.
    sequence: u64,
    /// Where it said it was.
    addresses: Vec<String>,
    /// When, on the wall clock, in seconds since the epoch.
    seen_at: u64,
}

/// The cache on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    /// The file it is kept in.
    path: PathBuf,
}

impl Endpoints {
    /// The cache at a path.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Writes what is currently known.
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    pub fn save(&self, cache: &Cache, now: Instant) -> Result<()> {
        let wall = seconds_now();
        let mut entries = Vec::new();

        for key in cache.keys() {
            let Some(seen) = cache.entry(key) else { continue };
            let age = now.saturating_duration_since(seen.at).as_secs();

            entries.push(Entry {
                key: hex_of(key),
                sequence: seen.sequence,
                addresses: seen.addresses.clone(),
                seen_at: wall.saturating_sub(age),
            });
        }

        let encoded = serde_json::to_vec_pretty(&entries)
            .map_err(|cause| self.failure(&cause.to_string()))?;
        std::fs::write(&self.path, encoded).map_err(|cause| self.failure(&cause.to_string()))
    }

    /// Reads back what is still worth trying.
    ///
    /// An entry older than the cache's own age bound is dropped rather than
    /// loaded: it would be tried first and fail first, which is the opposite of
    /// what the cache is for.
    ///
    /// A missing file is an empty cache. A daemon starting for the first time has
    /// nothing, and that is not an error.
    ///
    /// # Errors
    ///
    /// When the file exists and cannot be read or parsed.
    pub fn load(&self, now: Instant) -> Result<Cache> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => return Ok(Cache::new()),
            Err(cause) => return Err(self.failure(&cause.to_string())),
        };

        let entries: Vec<Entry> =
            serde_json::from_slice(&bytes).map_err(|cause| self.failure(&cause.to_string()))?;

        let wall = seconds_now();
        let bound = Duration::from_secs(local_discovery::limits::CACHE_ENTRY_MAX_AGE_SECS);
        let mut cache = Cache::new();

        for entry in entries {
            let age = Duration::from_secs(wall.saturating_sub(entry.seen_at));
            if age > bound {
                continue;
            }
            let (Some(key), Some(at)) = (key_of(&entry.key), now.checked_sub(age)) else {
                continue;
            };
            // A full or out-of-order cache is not a reason to fail a start.
            let _recorded = cache.record(key, entry.sequence, entry.addresses, at);
        }
        Ok(cache)
    }

    /// Wraps a filesystem or encoding failure with the path it concerns.
    fn failure(&self, cause: &str) -> Error {
        Error::State { path: self.path.clone(), cause: cause.to_owned() }
    }

    /// Where it is kept.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Seconds since the epoch, or zero if the clock is before it.
fn seconds_now() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

/// A key as hex.
fn hex_of(key: &KeyId) -> String {
    let mut out = String::new();
    for byte in key.as_bytes() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// A key from hex, if it is one.
fn key_of(text: &str) -> Option<KeyId> {
    if text.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (slot, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let pair = core::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(KeyId::from_bytes(bytes))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    fn key(tag: u8) -> KeyId {
        KeyId::from_bytes([tag; 32])
    }

    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir().expect("a scratch directory")
    }

    /// The property §2.6b depends on: what was known before the restart is known
    /// after it, without asking the rendezvous.
    #[test]
    fn what_was_cached_survives_a_restart() {
        let dir = scratch();
        let store = Endpoints::at(dir.path().join("endpoints.json"));
        let now = Instant::now();

        let mut cache = Cache::new();
        cache.record(key(1), 7, vec!["1.2.3.4:41641".to_owned()], now).expect("records");
        store.save(&cache, now).expect("saves");

        let back = store.load(Instant::now()).expect("loads");
        assert_eq!(back.addresses_for(&key(1), Instant::now()), vec!["1.2.3.4:41641".to_owned()]);
    }

    /// The sequence goes with it, or a replayed old announcement could walk a
    /// peer's addresses backwards on the first sync after a restart.
    #[test]
    fn the_sequence_survives_the_restart_too() {
        let dir = scratch();
        let store = Endpoints::at(dir.path().join("endpoints.json"));
        let now = Instant::now();

        let mut cache = Cache::new();
        cache.record(key(1), 9, vec!["a".to_owned()], now).expect("records");
        store.save(&cache, now).expect("saves");

        let mut back = store.load(Instant::now()).expect("loads");
        assert!(
            back.record(key(1), 8, vec!["b".to_owned()], Instant::now()).is_err(),
            "an older announcement must still be refused after a restart"
        );
    }

    #[test]
    fn a_cache_that_was_never_written_is_empty() {
        let dir = scratch();
        let store = Endpoints::at(dir.path().join("absent.json"));
        assert!(store.load(Instant::now()).expect("a missing file is an empty cache").is_empty());
    }

    /// An entry past the age bound would be tried first and fail first.
    #[test]
    fn an_entry_older_than_the_bound_is_dropped() {
        let dir = scratch();
        let path = dir.path().join("endpoints.json");

        let ancient = seconds_now()
            .saturating_sub(local_discovery::limits::CACHE_ENTRY_MAX_AGE_SECS.saturating_mul(2));
        let entries = vec![Entry {
            key: hex_of(&key(1)),
            sequence: 1,
            addresses: vec!["stale".to_owned()],
            seen_at: ancient,
        }];
        std::fs::write(&path, serde_json::to_vec(&entries).expect("encodes")).expect("writes");

        assert!(Endpoints::at(&path).load(Instant::now()).expect("loads").is_empty());
    }

    #[test]
    fn an_unreadable_file_is_refused_rather_than_ignored() {
        let dir = scratch();
        let path = dir.path().join("endpoints.json");
        std::fs::write(&path, b"not json at all").expect("writes");

        match Endpoints::at(&path).load(Instant::now()) {
            Err(Error::State { .. }) => {}
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// A key that is not a key is skipped, not guessed at.
    #[test]
    fn a_malformed_key_is_skipped() {
        let dir = scratch();
        let path = dir.path().join("endpoints.json");

        let entries = vec![Entry {
            key: "not hex".to_owned(),
            sequence: 1,
            addresses: vec!["x".to_owned()],
            seen_at: seconds_now(),
        }];
        std::fs::write(&path, serde_json::to_vec(&entries).expect("encodes")).expect("writes");

        assert!(Endpoints::at(&path).load(Instant::now()).expect("loads").is_empty());
    }

    #[test]
    fn a_key_round_trips_through_hex() {
        assert_eq!(key_of(&hex_of(&key(0xab))), Some(key(0xab)));
        assert_eq!(key_of("short"), None);
    }
}

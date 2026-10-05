//! The last place each peer was seen.
//!
//! §8 is blunt that multicast on wireless networks is unreliable — filtered by
//! the access point outright, or delivered at the lowest available bitrate. A
//! design that waited to hear an announcement before trying anything would be
//! slowest exactly where §2.6b's 500 ms budget is measured.
//!
//! So this is offered **first**, before listening, and announcements repeat so a
//! device that missed one learns from the next.
//!
//! # Being wrong is cheap
//!
//! A cached address that no longer works costs one attempt. §2.9's other paths
//! are being tried alongside it, so a stale entry delays nothing — which is why
//! the age bound here is generous rather than cautious.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use roster::id::KeyId;

use crate::error::{Error, Result};
use crate::limits;

/// Where a peer was last seen, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// The addresses it announced.
    pub addresses: Vec<String>,
    /// The sequence that announcement carried.
    pub sequence: u64,
    /// When it was recorded. Monotonic, so a clock changing underneath cannot
    /// make an entry look newly fresh.
    pub at: Instant,
}

/// The peers this node has heard from.
#[derive(Debug)]
pub struct Cache {
    /// Entries by the transport key they belong to.
    peers: BTreeMap<KeyId, Seen>,
    /// The most peers this cache will hold.
    capacity: usize,
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

impl Cache {
    /// An empty cache holding at most [`limits::MAX_CACHED_PEERS`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(limits::MAX_CACHED_PEERS)
    }

    /// An empty cache with a chosen bound.
    ///
    /// Configurable so the bound can be tested without inventing two hundred
    /// and fifty-six keys.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self { peers: BTreeMap::new(), capacity }
    }

    /// How many peers are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Records what an announcement said, if it is newer than what is held.
    ///
    /// The same sequence rule the rendezvous applies, and for the same reason: a
    /// replayed older announcement must not be able to walk a peer's addresses
    /// backwards to somewhere it no longer is.
    pub fn record(
        &mut self,
        key: KeyId,
        sequence: u64,
        addresses: Vec<String>,
        at: Instant,
    ) -> Result<()> {
        let mut addresses = addresses;
        addresses.truncate(limits::MAX_ADDRESSES_PER_PEER);

        match self.peers.get(&key) {
            Some(held) if sequence <= held.sequence => {
                Err(Error::NotNewer { offered: sequence, cached: held.sequence })
            }
            Some(_) => {
                self.peers.insert(key, Seen { addresses, sequence, at });
                Ok(())
            }
            None => {
                if self.peers.len() >= self.capacity {
                    // Reported, never a silent discard: a cache that quietly
                    // drops is a cache that quietly stops making the first path
                    // fast, and nobody would notice.
                    return Err(Error::CacheFull { limit: self.capacity });
                }
                self.peers.insert(key, Seen { addresses, sequence, at });
                Ok(())
            }
        }
    }

    /// Where a peer was last seen, if recently enough to be worth trying.
    ///
    /// An entry past the age bound is not *wrong*, only unlikely — and trying it
    /// costs one attempt while the other paths proceed. The bound exists so a
    /// cache does not grow a long tail of addresses from other places, not
    /// because a slightly old entry is dangerous.
    #[must_use]
    pub fn addresses_for(&self, key: &KeyId, now: Instant) -> Vec<String> {
        self.peers
            .get(key)
            .filter(|seen| {
                now.saturating_duration_since(seen.at)
                    <= Duration::from_secs(limits::CACHE_ENTRY_MAX_AGE_SECS)
            })
            .map(|seen| seen.addresses.clone())
            .unwrap_or_default()
    }

    /// The full entry for a peer, whatever its age.
    #[must_use]
    pub fn entry(&self, key: &KeyId) -> Option<&Seen> {
        self.peers.get(key)
    }

    /// Every peer heard from.
    pub fn keys(&self) -> impl Iterator<Item = &KeyId> {
        self.peers.keys()
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test reports a failed expectation by panicking")]
mod tests {
    use super::*;

    fn key(tag: u8) -> KeyId {
        KeyId::from_bytes([tag; 32])
    }

    fn addresses(one: &str) -> Vec<String> {
        vec![one.to_owned()]
    }

    fn later(base: Instant, seconds: u64) -> Instant {
        base.checked_add(Duration::from_secs(seconds)).unwrap_or(base)
    }

    /// The whole reason this exists: something to try before anything is heard.
    #[test]
    fn a_cached_address_is_available_at_once() {
        let mut cache = Cache::new();
        let now = Instant::now();
        cache.record(key(1), 1, addresses("ip:192.168.1.5:41641"), now).expect("recorded");

        assert_eq!(cache.addresses_for(&key(1), now), addresses("ip:192.168.1.5:41641"));
    }

    #[test]
    fn an_unknown_peer_has_no_addresses() {
        let cache = Cache::new();
        assert!(cache.addresses_for(&key(9), Instant::now()).is_empty());
    }

    #[test]
    fn a_newer_announcement_replaces_what_is_held() {
        let mut cache = Cache::new();
        let now = Instant::now();
        cache.record(key(1), 1, addresses("ip:a"), now).expect("recorded");
        cache.record(key(1), 2, addresses("ip:b"), later(now, 1)).expect("recorded");

        assert_eq!(cache.addresses_for(&key(1), now), addresses("ip:b"));
    }

    /// A replayed older announcement must not walk a peer's addresses backwards
    /// to somewhere it no longer is.
    #[test]
    fn an_older_announcement_changes_nothing() {
        let mut cache = Cache::new();
        let now = Instant::now();
        cache.record(key(1), 5, addresses("ip:a"), now).expect("recorded");

        match cache.record(key(1), 4, addresses("ip:b"), later(now, 1)) {
            Err(Error::NotNewer { offered, cached }) => {
                assert_eq!(offered, 4);
                assert_eq!(cached, 5);
            }
            other => panic!("expected a sequence refusal, got {other:?}"),
        }
        assert_eq!(cache.addresses_for(&key(1), now), addresses("ip:a"));
    }

    /// §8 requires announcements to repeat, so hearing the same one again is the
    /// design working — it simply changes nothing.
    #[test]
    fn a_repeated_announcement_changes_nothing() {
        let mut cache = Cache::new();
        let now = Instant::now();
        cache.record(key(1), 3, addresses("ip:a"), now).expect("recorded");
        assert!(cache.record(key(1), 3, addresses("ip:a"), later(now, 1)).is_err());
        assert_eq!(cache.addresses_for(&key(1), now), addresses("ip:a"));
    }

    #[test]
    fn an_entry_past_its_age_is_not_offered() {
        let mut cache = Cache::new();
        let now = Instant::now();
        cache.record(key(1), 1, addresses("ip:a"), now).expect("recorded");

        let much_later = later(now, limits::CACHE_ENTRY_MAX_AGE_SECS + 1);
        assert!(cache.addresses_for(&key(1), much_later).is_empty());
        assert!(cache.entry(&key(1)).is_some(), "but it is still remembered");
    }

    #[test]
    fn reaching_the_bound_is_reported() {
        let mut cache = Cache::with_capacity(2);
        let now = Instant::now();
        cache.record(key(1), 1, addresses("ip:a"), now).expect("recorded");
        cache.record(key(2), 1, addresses("ip:a"), now).expect("recorded");

        match cache.record(key(3), 1, addresses("ip:a"), now) {
            Err(Error::CacheFull { limit }) => assert_eq!(limit, 2),
            other => panic!("expected the cache to report being full, got {other:?}"),
        }
        assert_eq!(cache.len(), 2, "and nothing already held was displaced");
    }

    /// A full cache still updates peers it already knows: the bound is on how
    /// many peers are remembered, not on hearing from them.
    #[test]
    fn a_full_cache_still_updates_a_known_peer() {
        let mut cache = Cache::with_capacity(1);
        let now = Instant::now();
        cache.record(key(1), 1, addresses("ip:a"), now).expect("recorded");
        assert!(cache.record(key(2), 1, addresses("ip:x"), now).is_err());

        cache.record(key(1), 2, addresses("ip:b"), later(now, 1)).expect("a known peer updates");
        assert_eq!(cache.addresses_for(&key(1), now), addresses("ip:b"));
    }

    #[test]
    fn addresses_are_bounded_per_peer() {
        let mut cache = Cache::new();
        let many: Vec<String> =
            (0..limits::MAX_ADDRESSES_PER_PEER + 5).map(|i| format!("ip:{i}")).collect();
        cache.record(key(1), 1, many, Instant::now()).expect("recorded");

        assert_eq!(
            cache.entry(&key(1)).expect("held").addresses.len(),
            limits::MAX_ADDRESSES_PER_PEER
        );
    }
}

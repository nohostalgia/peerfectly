//! What the service holds, and the one rule that governs it.
//!
//! # The sequence is the whole defence
//!
//! A record is accepted only when its sequence exceeds the one already held.
//! That is what makes rolling a client back impossible: a record carrying an
//! address the device has moved on from no longer has a high enough sequence to
//! be accepted anywhere.
//!
//! The sequence is inside the signed payload. One the service could edit would
//! let the service reorder a device's history, which is exactly what the rule
//! exists to prevent.
//!
//! # Equivocation is refused, not resolved
//!
//! Two different records at the same sequence are **both** refused. A device
//! that signed both has equivocated, and choosing a winner would hide the
//! evidence that it did — evidence `equivocation-detection` will want.
//!
//! # Storage is in memory, and losing it is survivable
//!
//! Every record is ephemeral by §4.1's definition and is republished by its
//! device, so a restart costs one publication interval of staleness rather than
//! correctness. A database would add backups, migrations and disk exhaustion to
//! a service whose entire argument is that there is nothing in it worth
//! stealing.
//!
//! The consequence is stated rather than hidden: **a restart resets every
//! sequence**, so a device whose record was at 40 can publish 41 into an empty
//! store. That is not a rollback. The client's own rule — refuse anything not
//! above the highest it has seen — is what protects it, and that survives the
//! service.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use roster::id::KeyId;

use crate::error::{Error, Limit, Result};
use crate::limits;
use crate::record::SignedRecord;

/// One stored record and what is needed to judge the next one.
#[derive(Debug, Clone)]
struct Held {
    /// The record, kept as the exact bytes the device signed.
    record: SignedRecord,
    /// When it was accepted, for the publication rate. Monotonic, so a clock
    /// changing underneath cannot make a key look newly quiet.
    accepted: std::time::Instant,
}

/// The records the service holds.
///
/// Deliberately small. Its whole security argument is that it verifies a
/// signature and compares an integer.
#[derive(Debug)]
pub struct Store {
    /// Records by the transport key they belong to.
    records: BTreeMap<KeyId, Held>,
    /// The most records this store will hold.
    ///
    /// Configurable so the bound can be tested without creating a hundred
    /// thousand keys, which would take longer than the rest of the suite.
    capacity: usize,
    /// How many distinct keys each source address has created.
    ///
    /// The only thing here keyed on something the service *observes* rather than
    /// something a record *proves*. Without it, one host can fill the store with
    /// keys nobody will ever fetch, and every record would verify perfectly.
    keys_by_source: BTreeMap<String, usize>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    /// An empty store holding at most [`limits::MAX_RECORDS`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(limits::MAX_RECORDS)
    }

    /// An empty store with a chosen bound.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self { records: BTreeMap::new(), keys_by_source: BTreeMap::new(), capacity }
    }

    /// How many records are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the store holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The record held for a key, if any.
    #[must_use]
    pub fn get(&self, key: &KeyId) -> Option<&SignedRecord> {
        self.records.get(key).map(|held| &held.record)
    }

    /// Offers a verified record, from a source address.
    ///
    /// The caller has already checked the signature; this decides whether the
    /// record may replace what is held, and whether the source may create a key.
    pub fn publish(&mut self, record: SignedRecord, source: &str) -> Result<()> {
        self.publish_at(record, source, std::time::Instant::now())
    }

    /// [`Self::publish`] with the clock supplied, so the rate limit is testable
    /// without sleeping.
    pub fn publish_at(
        &mut self,
        record: SignedRecord,
        source: &str,
        now: std::time::Instant,
    ) -> Result<()> {
        let key = record.key().key_id();
        let offered = record.sequence();
        // Read before the entry is taken: the borrow checker will not allow it
        // afterwards, and the value cannot change in between.
        let occupied = self.records.len();

        match self.records.entry(key) {
            Entry::Occupied(mut existing) => {
                let held = existing.get();
                let stored = held.record.sequence();

                if offered == stored {
                    // Same sequence. If the contents differ the device signed
                    // two different things at one number, and both are refused
                    // rather than one being chosen.
                    if held.record.signed_bytes() == record.signed_bytes() {
                        return Err(Error::SequenceNotNewer { offered, held: stored });
                    }
                    return Err(Error::Equivocation { sequence: offered });
                }
                if offered < stored {
                    return Err(Error::SequenceNotNewer { offered, held: stored });
                }

                // Only a genuinely newer record reaches the rate limit, so a
                // replayed old one cannot be used to exhaust a key's allowance.
                let elapsed = now.saturating_duration_since(held.accepted);
                if elapsed.as_secs() < limits::MIN_PUBLISH_INTERVAL_SECS {
                    return Err(Limit::PublishRate {
                        interval_secs: limits::MIN_PUBLISH_INTERVAL_SECS,
                    }
                    .into());
                }

                existing.insert(Held { record, accepted: now });
                Ok(())
            }
            Entry::Vacant(slot) => {
                if occupied >= self.capacity {
                    // Reported, never a silent discard: a store that quietly
                    // drops is a store that quietly stops working.
                    return Err(Limit::StorageFull { limit: self.capacity }.into());
                }
                let created = self.keys_by_source.entry(source.to_owned()).or_insert(0);
                if *created >= limits::MAX_KEYS_PER_SOURCE {
                    return Err(Limit::KeysPerSource { limit: limits::MAX_KEYS_PER_SOURCE }.into());
                }
                *created = created.saturating_add(1);
                slot.insert(Held { record, accepted: now });
                Ok(())
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test reports a failed expectation by panicking")]
mod tests {
    use std::time::Duration;

    use identity::PrivateKey;
    use roster::id::NetworkId;
    use roster::types::Algorithm;

    use super::*;
    use crate::record::Record;

    fn network() -> NetworkId {
        NetworkId::from_bytes([9; 32])
    }

    /// A device with a real transport key, and a record it signed.
    fn signed(device: &PrivateKey, sequence: u64, address: &str) -> SignedRecord {
        let record =
            Record::new(device.public_key(), network(), sequence, vec![address.to_owned()])
                .expect("within bounds");
        SignedRecord::sign(record, device.signer()).expect("signs")
    }

    fn device() -> PrivateKey {
        PrivateKey::generate(Algorithm::Ed25519).expect("generates")
    }

    /// Far enough ahead that the rate limit never interferes with a test about
    /// something else.
    fn later(base: std::time::Instant, seconds: u64) -> std::time::Instant {
        base.checked_add(Duration::from_secs(seconds)).unwrap_or(base)
    }

    #[test]
    fn a_first_record_is_stored() {
        let mut store = Store::new();
        let device = device();
        let now = std::time::Instant::now();

        store.publish_at(signed(&device, 1, "ip:a"), "1.2.3.4", now).expect("accepted");

        let held = store.get(&device.key_id()).expect("held");
        assert_eq!(held.sequence(), 1);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_later_record_replaces_an_earlier_one() {
        let mut store = Store::new();
        let device = device();
        let now = std::time::Instant::now();

        store.publish_at(signed(&device, 1, "ip:a"), "1.2.3.4", now).expect("accepted");
        store.publish_at(signed(&device, 2, "ip:b"), "1.2.3.4", later(now, 10)).expect("accepted");

        let held = store.get(&device.key_id()).expect("held");
        assert_eq!(held.sequence(), 2);
        assert_eq!(held.open(&network()).expect("opens").addresses, vec!["ip:b".to_owned()]);
    }

    #[test]
    fn an_earlier_record_is_refused_and_changes_nothing() {
        let mut store = Store::new();
        let device = device();
        let now = std::time::Instant::now();

        store.publish_at(signed(&device, 5, "ip:a"), "1.2.3.4", now).expect("accepted");
        let outcome = store.publish_at(signed(&device, 4, "ip:b"), "1.2.3.4", later(now, 10));

        match outcome {
            Err(Error::SequenceNotNewer { offered, held }) => {
                assert_eq!(offered, 4);
                assert_eq!(held, 5);
            }
            other => panic!("expected a sequence refusal, got {other:?}"),
        }
        let held = store.get(&device.key_id()).expect("held");
        assert_eq!(
            held.open(&network()).expect("opens").addresses,
            vec!["ip:a".to_owned()],
            "unchanged"
        );
    }

    #[test]
    fn the_same_record_again_is_refused() {
        let mut store = Store::new();
        let device = device();
        let now = std::time::Instant::now();
        let record = signed(&device, 1, "ip:a");

        store.publish_at(record.clone(), "1.2.3.4", now).expect("accepted");
        assert!(matches!(
            store.publish_at(record, "1.2.3.4", later(now, 10)),
            Err(Error::SequenceNotNewer { .. })
        ));
    }

    /// A device that signed two different records at one sequence has
    /// equivocated. Both are refused; choosing a winner would hide it.
    #[test]
    fn two_different_records_at_one_sequence_are_both_refused() {
        let mut store = Store::new();
        let device = device();
        let now = std::time::Instant::now();

        store.publish_at(signed(&device, 7, "ip:a"), "1.2.3.4", now).expect("accepted");
        let outcome = store.publish_at(signed(&device, 7, "ip:b"), "1.2.3.4", later(now, 10));

        match outcome {
            Err(Error::Equivocation { sequence }) => assert_eq!(sequence, 7),
            other => panic!("expected an equivocation refusal, got {other:?}"),
        }
        assert_eq!(
            store.get(&device.key_id()).expect("held").open(&network()).expect("opens").addresses,
            vec!["ip:a".to_owned()],
            "and the first is not replaced by the second"
        );
    }

    #[test]
    fn publishing_too_soon_is_refused_and_recoverable() {
        let mut store = Store::new();
        let device = device();
        let now = std::time::Instant::now();

        store.publish_at(signed(&device, 1, "ip:a"), "1.2.3.4", now).expect("accepted");

        let too_soon = store.publish_at(signed(&device, 2, "ip:b"), "1.2.3.4", now);
        match too_soon {
            Err(Error::Limit(Limit::PublishRate { interval_secs })) => {
                assert_eq!(interval_secs, limits::MIN_PUBLISH_INTERVAL_SECS);
            }
            other => panic!("expected a rate refusal, got {other:?}"),
        }

        // The same publication succeeds once the interval has passed: a
        // rate-limited publisher is behaving normally.
        store
            .publish_at(
                signed(&device, 2, "ip:b"),
                "1.2.3.4",
                later(now, limits::MIN_PUBLISH_INTERVAL_SECS),
            )
            .expect("accepted after waiting");
    }

    /// A replayed old record must not consume the key's allowance, or an
    /// attacker could rate-limit a device out of publishing by replaying it.
    #[test]
    fn a_replayed_record_does_not_consume_the_rate_allowance() {
        let mut store = Store::new();
        let device = device();
        let now = std::time::Instant::now();

        store.publish_at(signed(&device, 5, "ip:a"), "1.2.3.4", now).expect("accepted");
        // An old record, replayed repeatedly, well inside the interval.
        for _ in 0..10 {
            let _ = store.publish_at(signed(&device, 1, "ip:x"), "9.9.9.9", now);
        }
        // The device's genuine next publication still succeeds on schedule.
        store
            .publish_at(
                signed(&device, 6, "ip:b"),
                "1.2.3.4",
                later(now, limits::MIN_PUBLISH_INTERVAL_SECS),
            )
            .expect("the device is not locked out by someone else replaying");
    }

    #[test]
    fn one_source_cannot_create_unbounded_keys() {
        let mut store = Store::new();
        let now = std::time::Instant::now();
        let mut first = None;

        for index in 0..limits::MAX_KEYS_PER_SOURCE {
            let device = device();
            store.publish_at(signed(&device, 1, "ip:a"), "1.2.3.4", now).expect("accepted");
            if index == 0 {
                first = Some(device);
            }
        }

        let extra = device();
        match store.publish_at(signed(&extra, 1, "ip:a"), "1.2.3.4", now) {
            Err(Error::Limit(Limit::KeysPerSource { limit })) => {
                assert_eq!(limit, limits::MAX_KEYS_PER_SOURCE);
            }
            other => panic!("expected a per-source refusal, got {other:?}"),
        }

        // Keys it already created keep working.
        let first = first.expect("a first device");
        store
            .publish_at(
                signed(&first, 2, "ip:b"),
                "1.2.3.4",
                later(now, limits::MIN_PUBLISH_INTERVAL_SECS),
            )
            .expect("an existing key still publishes");
    }

    /// The limits are per key and per source, never global, so exhausting one
    /// costs another nothing.
    #[test]
    fn one_source_exhausting_its_allowance_leaves_another_alone() {
        let mut store = Store::new();
        let now = std::time::Instant::now();

        for _ in 0..limits::MAX_KEYS_PER_SOURCE {
            store.publish_at(signed(&device(), 1, "ip:a"), "1.2.3.4", now).expect("accepted");
        }
        assert!(store.publish_at(signed(&device(), 1, "ip:a"), "1.2.3.4", now).is_err());

        store
            .publish_at(signed(&device(), 1, "ip:a"), "5.6.7.8", now)
            .expect("a different source is unaffected");
    }

    /// A record is served back as the exact bytes the device signed, so a client
    /// verifies what was signed rather than a re-encoding.
    #[test]
    fn a_record_is_held_as_the_bytes_that_were_signed() {
        let mut store = Store::new();
        let device = device();
        let published = signed(&device, 1, "ip:a");
        let expected = published.to_bytes();

        store.publish_at(published, "1.2.3.4", std::time::Instant::now()).expect("accepted");

        assert_eq!(store.get(&device.key_id()).expect("held").to_bytes(), expected);
    }

    /// Reaching the global bound is reported, never a silent discard: a store
    /// that quietly drops is a store that quietly stops working.
    #[test]
    fn reaching_the_storage_bound_is_reported() {
        let mut store = Store::with_capacity(2);
        let now = std::time::Instant::now();

        for _ in 0..2 {
            store.publish_at(signed(&device(), 1, "ip:a"), "1.2.3.4", now).expect("accepted");
        }

        match store.publish_at(signed(&device(), 1, "ip:a"), "1.2.3.4", now) {
            Err(Error::Limit(Limit::StorageFull { limit })) => assert_eq!(limit, 2),
            other => panic!("expected the store to report being full, got {other:?}"),
        }
        assert_eq!(store.len(), 2, "and nothing already held was displaced");
    }

    /// An existing key still publishes when the store is full: the bound is on
    /// creating keys, not on updating them.
    #[test]
    fn a_full_store_still_accepts_an_update() {
        let mut store = Store::with_capacity(1);
        let held = device();
        let stranger = device();
        let now = std::time::Instant::now();

        store.publish_at(signed(&held, 1, "ip:a"), "1.2.3.4", now).expect("accepted");
        assert!(store.publish_at(signed(&stranger, 1, "ip:x"), "1.2.3.4", now).is_err());

        store
            .publish_at(
                signed(&held, 2, "ip:b"),
                "1.2.3.4",
                later(now, limits::MIN_PUBLISH_INTERVAL_SECS),
            )
            .expect("an existing key updates even when the store is full");
    }

    /// A restart resets every sequence, so the store accepts a number it had
    /// previously passed. That is not a rollback — the client's own rule is what
    /// protects it, and it survives the service.
    #[test]
    fn a_restart_accepts_a_sequence_it_had_already_passed() {
        let device = device();
        let now = std::time::Instant::now();

        let mut before = Store::new();
        before.publish_at(signed(&device, 40, "ip:a"), "1.2.3.4", now).expect("accepted");
        assert!(before.publish_at(signed(&device, 5, "ip:b"), "1.2.3.4", now).is_err());

        // The service restarts with nothing.
        let mut after = Store::new();
        after
            .publish_at(signed(&device, 5, "ip:b"), "1.2.3.4", now)
            .expect("an empty store has nothing to compare against");

        assert_eq!(after.get(&device.key_id()).expect("held").sequence(), 5);
    }
}

//! Dividing the pending set fairly between peers.
//!
//! An operation whose parents are absent is held pending, and those entries are
//! **unverified by necessity** — the author's key is resolved from state derived
//! from the very ancestors that are missing. The set is bounded. Without
//! per-peer accounting one peer fills it, and the `revoke_device` naming that
//! peer arrives to find nowhere to wait. Reserving space for revocations
//! specifically does not help: an attacker labels junk as one.
//!
//! `roster`'s `FORMAT.md` §19 states this as a requirement it cannot satisfy
//! alone, because bounding the set fairly needs authenticated peer identity, and
//! that lives in the transport. This is where it is discharged.
//!
//! # Refuse at the door, never evict
//!
//! Over quota, the operation is refused before the roster ever sees it. Nothing
//! already pending is displaced.
//!
//! The asymmetry is the whole point. A refused operation stays with its sender,
//! which offers it again — after supplying the parents it was waiting for, or at
//! the next reconciliation. An evicted one is gone from a node that has already
//! reported accepting it, and the entry displaced might have been the
//! revocation. So this is admission control, not cache management — which also
//! removes any need to decide *what* to evict, a question with no safe answer.

use std::collections::{BTreeMap, BTreeSet};

use roster::id::{DeviceId, OperationId};

use crate::limits;

/// Which peer each pending entry is charged to.
///
/// Keyed on the **device**, not the session. Sessions are cheap to open, and a
/// per-session quota would be renewed by reconnecting — which is the same as
/// having no quota at all.
#[derive(Debug, Clone, Default)]
pub struct Quota {
    /// Per device, the operation ids this node is holding pending on its behalf.
    charged: BTreeMap<DeviceId, BTreeSet<OperationId>>,
}

impl Quota {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Releases every charge the roster no longer holds pending.
    ///
    /// Derived from the roster's own view rather than tracked separately: a
    /// counter maintained alongside it would drift, and the likely drift is a
    /// leak — a well-behaved peer throttled for something that resolved long
    /// ago. Two records of the same fact eventually disagree; one cannot.
    pub fn settle(&mut self, still_pending: &BTreeSet<OperationId>) {
        for charges in self.charged.values_mut() {
            charges.retain(|id| still_pending.contains(id));
        }
        self.charged.retain(|_, charges| !charges.is_empty());
    }

    /// How many pending entries a peer currently occupies.
    #[must_use]
    pub fn charged_to(&self, peer: &DeviceId) -> usize {
        self.charged.get(peer).map_or(0, BTreeSet::len)
    }

    /// Whether a peer may place another pending entry.
    #[must_use]
    pub fn has_room(&self, peer: &DeviceId) -> bool {
        self.charged_to(peer) < limits::PENDING_PER_PEER
    }

    /// Charges a pending entry to the peer that supplied it.
    pub fn charge(&mut self, peer: DeviceId, operation: OperationId) {
        self.charged.entry(peer).or_default().insert(operation);
    }

    /// Every peer currently holding a charge.
    pub fn peers(&self) -> impl Iterator<Item = &DeviceId> {
        self.charged.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(tag: u8) -> DeviceId {
        DeviceId::from_bytes([tag; 32])
    }

    fn operation(tag: u8) -> OperationId {
        OperationId::from_bytes([tag; 32])
    }

    #[test]
    fn a_fresh_ledger_charges_nobody() {
        let quota = Quota::new();
        assert_eq!(quota.charged_to(&device(1)), 0);
        assert!(quota.has_room(&device(1)));
    }

    /// One peer's charges stop at its share, whatever it does.
    #[test]
    fn a_peer_stops_at_its_share() {
        let mut quota = Quota::new();
        for index in 0..limits::PENDING_PER_PEER {
            assert!(quota.has_room(&device(1)), "room ran out early at {index}");
            quota.charge(device(1), operation(u8::try_from(index).unwrap_or(0)));
        }
        assert_eq!(quota.charged_to(&device(1)), limits::PENDING_PER_PEER);
        assert!(!quota.has_room(&device(1)), "a peer must not exceed its share");
    }

    /// The share is per device. One peer exhausting its own leaves every other
    /// peer untouched — which is the entire reason the quota exists.
    #[test]
    fn one_peer_exhausting_its_share_leaves_others_alone() {
        let mut quota = Quota::new();
        for index in 0..limits::PENDING_PER_PEER {
            quota.charge(device(1), operation(u8::try_from(index).unwrap_or(0)));
        }
        assert!(!quota.has_room(&device(1)));
        assert!(quota.has_room(&device(2)), "a second peer must still be able to make progress");
        assert_eq!(quota.charged_to(&device(2)), 0);
    }

    /// Charges are released when the roster stops holding them pending — because
    /// they were integrated, or refused. A peer that supplies the parents its
    /// operations were waiting for gets its room back.
    #[test]
    fn settling_releases_what_is_no_longer_pending() {
        let mut quota = Quota::new();
        quota.charge(device(1), operation(1));
        quota.charge(device(1), operation(2));
        assert_eq!(quota.charged_to(&device(1)), 2);

        let still_pending: BTreeSet<_> = [operation(2)].into_iter().collect();
        quota.settle(&still_pending);
        assert_eq!(quota.charged_to(&device(1)), 1);

        quota.settle(&BTreeSet::new());
        assert_eq!(quota.charged_to(&device(1)), 0);
        assert!(quota.has_room(&device(1)));
    }

    /// Charging the same operation twice is not two charges. A peer that
    /// re-offers something already pending must not be billed again for it.
    #[test]
    fn the_same_operation_is_charged_once() {
        let mut quota = Quota::new();
        quota.charge(device(1), operation(1));
        quota.charge(device(1), operation(1));
        assert_eq!(quota.charged_to(&device(1)), 1);
    }

    /// A peer with no charges left is forgotten entirely, so the ledger does not
    /// grow without bound over a long-running node.
    #[test]
    fn a_peer_with_nothing_pending_is_forgotten() {
        let mut quota = Quota::new();
        quota.charge(device(1), operation(1));
        quota.settle(&BTreeSet::new());
        assert_eq!(quota.peers().count(), 0);
    }
}

//! Which members a device stays in touch with when nothing asks it to.
//!
//! Every device used to keep a session with every other member and offer them
//! everything it held every minute. That costs per member, so it multiplies with
//! the size of the network: measured on 2026-10-07, one idle peer cost about
//! 3.7 GB a month. Now a device contacts, in the background, only its
//! **neighbours**, and the roster still spreads to everyone because neighbours
//! pass on what they receive.
//!
//! # How they are chosen
//!
//! Rendezvous hashing. For each of [`SLOTS`] slots, a device scores every other
//! member and takes the highest score. The score is a hash, under its own tag, of
//! the network, the slot, and the ids of the two devices' **admission
//! operations** — never their keys. An admission's id depends on the admitting
//! admin's signature and on the roster at that moment, neither of which a device
//! controls when it makes its key, so nobody can generate keys until one lands
//! beside a chosen victim.
//!
//! Every device computes everyone's choices from the roster alone, so the choice
//! needs no coordination, and a claim to have been chosen can be checked.
//!
//! Each slot chooses on its own. Two slots may land on the same member; letting
//! one skip what another took would tie them together, so that a join moving one
//! slot's choice could move another's to a member the join has nothing to do
//! with. A membership change therefore moves only the choices that involve the
//! members that joined or left.
//!
//! # Mutual
//!
//! A device pushes to the members it chose **and** to those that chose it. Out
//! of three random choices each, about one device in twenty is chosen by nobody
//! (e⁻³); pushing only along one's own choices would leave it out. The members
//! that chose a device are learned when they contact it, and their claim is
//! checked with [`claim_holds`] before it counts.
//!
//! Pure: everything is handed in, so the rule is exercised without a network and
//! without a clock.

use roster::id::{DeviceId, NetworkId, OperationId};
use roster::state::RosterState;

/// How many neighbours a device chooses.
///
/// Three, because a graph in which every device chooses three others at random
/// is connected with high probability whatever its size, and an operation
/// crosses it in about log₃ N hops — eight for five thousand devices. Two leaves
/// it fragile; four adds contacts without adding much.
pub const SLOTS: u8 = 3;

/// Up to this many members, this device included, every other member is a
/// neighbour.
///
/// A network that small gains nothing from choosing: every other member is
/// within three, and choosing could leave one out of a slot that happened to
/// land twice on the same device.
pub const FULLY_CONNECTED_UP_TO: usize = 4;

/// How far down its order a claimant may have gone and still be believed.
///
/// A device skips members that do not answer, so the one it ends up contacting
/// may not be its first choice. Eight leaves room for that, and a claim from
/// further down than eight in every slot is not a neighbour's.
pub const CLAIM_RANK: usize = 8;

/// The tag the score is hashed under, so it cannot be confused with any other
/// hash in the protocol.
const DOMAIN: &str = "peerfectly neighbour v1";

/// A member as the choice sees it: who, and the operation that admitted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    /// The device.
    pub device: DeviceId,
    /// The id of the operation that admitted it — for the founder, the network's
    /// creation.
    pub admitted_by: OperationId,
}

/// The non-revoked members of a roster.
#[must_use]
pub fn members_of(state: &RosterState) -> Vec<Member> {
    state
        .devices
        .values()
        .filter(|record| !state.revoked.contains(&record.id))
        .map(|record| Member { device: record.id, admitted_by: record.added_by })
        .collect()
}

/// The score `me` gives `them` in a slot.
fn score(network: &NetworkId, slot: u8, me: &Member, them: &Member) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DOMAIN);
    hasher.update(network.as_bytes());
    hasher.update(&[slot]);
    hasher.update(me.admitted_by.as_bytes());
    hasher.update(them.admitted_by.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Every other member, best first, for one of `me`'s slots.
#[must_use]
pub fn order(network: &NetworkId, slot: u8, me: &Member, members: &[Member]) -> Vec<DeviceId> {
    let mut scored: Vec<([u8; 32], DeviceId)> = members
        .iter()
        .filter(|member| member.device != me.device)
        .map(|member| (score(network, slot, me, member), member.device))
        .collect();
    // Highest score first; the device id breaks a tie, which a 256-bit hash
    // will not produce in practice but which must still have one answer.
    scored.sort_unstable_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    scored.into_iter().map(|(_, device)| device).collect()
}

/// The highest-scored member of a slot that is not silent.
///
/// One pass rather than [`order`]'s sort: a device recomputes its choices on
/// every change of membership, and the first of an order is all a choice needs.
/// Ties break on the device id, exactly as in [`order`], so the two agree.
fn best(
    network: &NetworkId,
    slot: u8,
    me: &Member,
    members: &[Member],
    silent: &dyn Fn(&DeviceId) -> bool,
) -> Option<DeviceId> {
    members
        .iter()
        .filter(|member| member.device != me.device && !silent(&member.device))
        .map(|member| (score(network, slot, me, member), member.device))
        .max_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)))
        .map(|(_, device)| device)
}

/// The members `me` chooses, skipping those `silent` says do not answer.
///
/// In a network of [`FULLY_CONNECTED_UP_TO`] members or fewer, every other
/// member. Otherwise, for each slot, the first member of that slot's order that
/// is not silent; a slot whose every member is silent chooses nobody. The
/// result has no repeats and is sorted, so two calls on the same inputs compare
/// equal.
#[must_use]
pub fn choose(
    network: &NetworkId,
    me: &Member,
    members: &[Member],
    silent: &dyn Fn(&DeviceId) -> bool,
) -> Vec<DeviceId> {
    let mut chosen: Vec<DeviceId> = if members.len() <= FULLY_CONNECTED_UP_TO {
        // Everyone else, less those resting: a small network is no reason to
        // dial a member that is switched off every time a neighbour is wanted.
        members
            .iter()
            .filter(|member| member.device != me.device && !silent(&member.device))
            .map(|member| member.device)
            .collect()
    } else {
        (0..SLOTS).filter_map(|slot| best(network, slot, me, members, silent)).collect()
    };
    chosen.sort_unstable();
    chosen.dedup();
    chosen
}

/// Whether `claimant` could have chosen `me` as a neighbour.
///
/// True where `me` is among the first [`CLAIM_RANK`] of one of the claimant's
/// slots, or where the network is small enough that everyone is a neighbour of
/// everyone. A claimant that is not a member at all is never believed.
#[must_use]
pub fn claim_holds(
    network: &NetworkId,
    claimant: &DeviceId,
    me: &DeviceId,
    members: &[Member],
) -> bool {
    let Some(claimant) = members.iter().find(|member| member.device == *claimant) else {
        return false;
    };
    if !members.iter().any(|member| member.device == *me) {
        return false;
    }
    if members.len() <= FULLY_CONNECTED_UP_TO {
        return claimant.device != *me;
    }
    (0..SLOTS).any(|slot| {
        order(network, slot, claimant, members).iter().take(CLAIM_RANK).any(|device| device == me)
    })
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "a test reports failure by panicking, and the simulation indexes members it built"
)]
mod tests {
    use super::*;

    fn network() -> NetworkId {
        NetworkId::from_bytes([7; 32])
    }

    /// A member whose device and admission ids are derived from `n`.
    fn member(n: u32) -> Member {
        let mut device = [0u8; 32];
        device[..4].copy_from_slice(&n.to_be_bytes());
        let admitted = blake3::hash(&n.to_be_bytes());
        Member {
            device: DeviceId::from_bytes(device),
            admitted_by: OperationId::from_bytes(*admitted.as_bytes()),
        }
    }

    fn network_of(count: u32) -> Vec<Member> {
        (0..count).map(member).collect()
    }

    fn nobody_silent(_: &DeviceId) -> bool {
        false
    }

    #[test]
    fn two_devices_compute_the_same_neighbours() {
        let members = network_of(50);
        let me = member(7);
        let mut shuffled = members.clone();
        shuffled.reverse();
        assert_eq!(
            choose(&network(), &me, &members, &nobody_silent),
            choose(&network(), &me, &shuffled, &nobody_silent),
            "the order members are listed in decides nothing"
        );
    }

    #[test]
    fn a_device_never_chooses_itself_and_chooses_at_most_three() {
        let members = network_of(50);
        for n in 0..50 {
            let me = member(n);
            let chosen = choose(&network(), &me, &members, &nobody_silent);
            assert!(!chosen.contains(&me.device));
            assert!(!chosen.is_empty() && chosen.len() <= usize::from(SLOTS));
        }
    }

    #[test]
    fn a_small_network_leaves_out_who_is_resting() {
        let members = network_of(4);
        let me = member(0);
        let resting = member(1).device;
        let chosen = choose(&network(), &me, &members, &|device| *device == resting);
        assert_eq!(chosen.len(), 2, "the other two: {chosen:?}");
        assert!(!chosen.contains(&resting));
    }

    #[test]
    fn a_small_network_is_fully_connected() {
        let members = network_of(4);
        let me = member(0);
        let chosen = choose(&network(), &me, &members, &nobody_silent);
        assert_eq!(chosen.len(), 3, "the other three: {chosen:?}");
        assert!(claim_holds(&network(), &member(1).device, &me.device, &members));
    }

    /// The score depends on admission ids and on nothing a device chose alone:
    /// the same admissions under other device ids order identically.
    #[test]
    fn the_score_is_the_admission_not_the_key() {
        let members = network_of(30);
        let renamed: Vec<Member> = members
            .iter()
            .map(|m| {
                let mut device = *m.device.as_bytes();
                device[31] ^= 0xff;
                Member { device: DeviceId::from_bytes(device), admitted_by: m.admitted_by }
            })
            .collect();
        let position = |list: &[Member], me: &Member| -> Vec<OperationId> {
            order(&network(), 0, me, list)
                .iter()
                .map(|device| list.iter().find(|m| m.device == *device).unwrap().admitted_by)
                .collect()
        };
        assert_eq!(position(&members, &members[3]), position(&renamed, &renamed[3]));
    }

    #[test]
    fn a_join_moves_only_choices_that_involve_the_new_member() {
        let before = network_of(50);
        let mut after = before.clone();
        let joined = member(1_000);
        after.push(joined);
        for me in &before {
            let old = choose(&network(), me, &before, &nobody_silent);
            let new = choose(&network(), me, &after, &nobody_silent);
            if old != new {
                assert!(
                    new.contains(&joined.device),
                    "{old:?} moved to {new:?} without the joiner"
                );
                let kept = old.iter().filter(|device| new.contains(device)).count();
                assert!(kept + 1 >= new.len(), "only the slot the joiner took moved");
            }
        }
    }

    #[test]
    fn a_silent_member_is_replaced_by_the_next_in_its_slot() {
        let members = network_of(50);
        let me = member(0);
        let first = order(&network(), 0, &me, &members);
        let silent = first[0];
        let chosen = choose(&network(), &me, &members, &|device| *device == silent);
        assert!(!chosen.contains(&silent));
        assert!(
            chosen.contains(&first[1]) || {
                // The next in slot 0 may coincide with another slot's choice; either
                // way slot 0 now names the second of its order.
                order(&network(), 1, &me, &members)[0] == first[1]
                    || order(&network(), 2, &me, &members)[0] == first[1]
            }
        );
    }

    #[test]
    fn a_claim_from_a_device_that_chose_this_one_holds() {
        let members = network_of(60);
        let claimant = member(9);
        for target in choose(&network(), &claimant, &members, &nobody_silent) {
            assert!(claim_holds(&network(), &claimant.device, &target, &members));
        }
    }

    #[test]
    fn a_claim_from_far_down_every_order_is_ignored() {
        let members = network_of(200);
        let claimant = member(9);
        // The member furthest down every one of the claimant's slots.
        let last = (0..SLOTS)
            .map(|slot| order(&network(), slot, &claimant, &members))
            .map(|o| o[CLAIM_RANK..].to_vec())
            .reduce(|a, b| a.into_iter().filter(|d| b.contains(d)).collect())
            .and_then(|common| common.first().copied())
            .expect("some member is far down every slot");
        assert!(!claim_holds(&network(), &claimant.device, &last, &members));
    }

    #[test]
    fn a_stranger_claims_nothing() {
        let members = network_of(20);
        let stranger = member(9_999);
        assert!(!claim_holds(&network(), &stranger.device, &members[0].device, &members));
    }

    /// Pushes from `source` along `edges` and returns how many devices hold it.
    fn reached(source: usize, edges: &[Vec<usize>]) -> usize {
        let mut seen = vec![false; edges.len()];
        let mut queue = std::collections::VecDeque::from([source]);
        seen[source] = true;
        let mut count = 1usize;
        while let Some(at) = queue.pop_front() {
            for &next in &edges[at] {
                if !seen[next] {
                    seen[next] = true;
                    count += 1;
                    queue.push_back(next);
                }
            }
        }
        count
    }

    /// Each member's neighbours, as indices: its own choices and, where
    /// `mutual`, the members that chose it.
    fn neighbour_graph(members: &[Member], mutual: bool) -> Vec<Vec<usize>> {
        let index: std::collections::BTreeMap<DeviceId, usize> =
            members.iter().enumerate().map(|(i, m)| (m.device, i)).collect();
        let mut edges = vec![Vec::new(); members.len()];
        for (i, me) in members.iter().enumerate() {
            for device in choose(&network(), me, members, &nobody_silent) {
                let j = index[&device];
                edges[i].push(j);
                if mutual {
                    edges[j].push(i);
                }
            }
        }
        edges
    }

    fn spreads_to_everyone(count: u32) {
        let members = network_of(count);
        let edges = neighbour_graph(&members, true);
        for source in [0, members.len() / 2, members.len() - 1] {
            assert_eq!(reached(source, &edges), members.len(), "from {source}");
        }
        // Nobody pushes to more than its neighbours: its three, and those that
        // chose it. With three random choices each, the second is small.
        let most = edges.iter().map(Vec::len).max().unwrap_or(0);
        assert!(most <= 3 + 20, "a member with {most} neighbours");
    }

    #[test]
    fn an_operation_reaches_every_member_of_fifty() {
        spreads_to_everyone(50);
    }

    #[test]
    fn an_operation_reaches_every_member_of_five_thousand() {
        spreads_to_everyone(5_000);
    }

    /// Without mutuality the devices nobody chose are left out. This is the
    /// test that fails if pushing to the members that chose a device is ever
    /// taken away.
    #[test]
    fn without_mutual_neighbours_someone_is_left_out() {
        let members = network_of(5_000);
        let one_way = neighbour_graph(&members, false);
        assert!(
            reached(0, &one_way) < members.len(),
            "pushing only along one's own choices misses the devices nobody chose"
        );
    }
}

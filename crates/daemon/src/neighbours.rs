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
//! full member and takes the highest score. The score is a hash, under its own
//! tag, of the network, the slot, and the two devices' **admissions** — the id of
//! the operation that admitted each, with the device's position — never their
//! keys alone. An admission's id depends on the admitting admin's signature and
//! on the roster at that moment, neither of which a device controls when it
//! makes its key, so nobody can generate keys until one lands beside a chosen
//! victim. The position is what tells apart the devices one batch admitted.
//!
//! # Full members only
//!
//! A light member holds no operations to pass on, so it is never chosen and
//! chooses nobody: it relies on its anchors and the full members it talks to.
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

/// The tag a device's admission is hashed under.
const ADMISSION: &str = "peerfectly neighbour admission v1";

/// A member as the choice sees it: who, and its admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    /// The device.
    pub device: DeviceId,
    /// Its admission: the id of the operation that admitted it — for the
    /// founder, the network's creation — with its position, as [`admission`]
    /// gives it.
    pub admitted_by: OperationId,
}

/// A device's admission, as the score reads it: the operation that admitted it,
/// with the device's position.
///
/// A batch admits thousands of devices with one operation; without the
/// position they would all score alike, and every full member would choose
/// the same few. The operation's id still decides: nothing the device chose
/// alone moves it.
#[must_use]
pub fn admission(admitted_by: &OperationId, device: &DeviceId) -> OperationId {
    let mut hasher = blake3::Hasher::new_derive_key(ADMISSION);
    hasher.update(admitted_by.as_bytes());
    hasher.update(&roster::leaf::DeviceLeaf::position(device));
    OperationId::from_bytes(*hasher.finalize().as_bytes())
}

#[cfg(test)]
/// The full members of a roster: the only ones that choose neighbours, and
/// the only ones chosen.
#[must_use]
pub fn members_of(state: &RosterState) -> Vec<Member> {
    state
        .devices
        .values()
        .filter(|record| state.settings_of(&record.id).mode == roster::leaf::Mode::Full)
        .map(|record| Member {
            device: record.id,
            admitted_by: admission(&record.added_by, &record.id),
        })
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

/// A full member of a state, as the choice sees it; `None` for a device that
/// is not one.
fn full_member(state: &RosterState, device: &DeviceId) -> Option<Member> {
    let leaf = state.devices.get(device)?;
    (leaf.settings.mode == roster::leaf::Mode::Full)
        .then(|| Member { device: *device, admitted_by: admission(&leaf.record.added_by, device) })
}

/// Every full member of a state, read as it goes: a million are not listed.
fn full_members(state: &RosterState) -> impl Iterator<Item = Member> + '_ {
    state.devices.iter().filter(|(_, leaf)| leaf.settings.mode == roster::leaf::Mode::Full).map(
        |(device, leaf)| Member { device, admitted_by: admission(&leaf.record.added_by, &device) },
    )
}

/// Where a member stands in a slot: best first, the device id breaking a tie,
/// as [`order`] sorts.
type Standing = (core::cmp::Reverse<[u8; 32]>, DeviceId);

fn standing(network: &NetworkId, slot: u8, me: &Member, them: &Member) -> Standing {
    (core::cmp::Reverse(score(network, slot, me, them)), them.device)
}

/// How many of each slot's best are kept: enough to skip the silent and to
/// answer every claim [`CLAIM_RANK`] allows without walking every member.
const KEPT: usize = 16;

/// One slot's best members.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Slot {
    /// Every other full member standing at or above `floor`, best first.
    kept: Vec<Standing>,
    /// The lowest standing kept, where some members stand below it; `None`
    /// where every other full member is kept.
    floor: Option<Standing>,
}

impl Slot {
    /// The best `KEPT` of `members`, walked once.
    fn of(
        network: &NetworkId,
        slot: u8,
        me: &Member,
        members: impl Iterator<Item = Member>,
    ) -> Self {
        let mut kept: Vec<Standing> = Vec::with_capacity(KEPT.saturating_add(1));
        let mut below = false;
        for member in members.filter(|member| member.device != me.device) {
            let standing = standing(network, slot, me, &member);
            let at = kept.partition_point(|held| *held < standing);
            if at < KEPT {
                kept.insert(at, standing);
                if kept.len() > KEPT {
                    kept.pop();
                    below = true;
                }
            } else {
                below = true;
            }
        }
        let floor = if below { kept.last().copied() } else { None };
        Self { kept, floor }
    }

    /// Whether every member standing as high as `standing` is kept.
    fn covers(&self, standing: &Standing) -> bool {
        self.floor.is_none_or(|floor| *standing <= floor)
    }
}

/// A device's neighbour choices, kept as a roster changes.
///
/// [`choose`] and [`claim_holds`] read every member, which a device does on
/// every change and every greeting. These are their answers, kept: for each
/// slot, the members standing best, followed through the devices a change
/// touched, and read again whole only when what is kept runs out. They agree
/// with the rule on every state, which a test holds them to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choices {
    network: NetworkId,
    me: Member,
    /// How many full members there are, this device among them.
    full: usize,
    slots: Vec<Slot>,
}

impl Choices {
    /// The choices of `me` in `state`; `None` where it is not a full member.
    #[must_use]
    pub fn of(state: &RosterState, me: &DeviceId) -> Option<Self> {
        let mine = full_member(state, me)?;
        let slots = (0..SLOTS)
            .map(|slot| Slot::of(&state.network, slot, &mine, full_members(state)))
            .collect();
        Some(Self { network: state.network, me: mine, full: full_members(state).count(), slots })
    }

    /// The choices in `state`, where these are the choices in `previous`:
    /// followed through the devices that changed, where the two rest on one
    /// base; read whole otherwise.
    #[must_use]
    pub fn updated(&self, previous: &RosterState, state: &RosterState) -> Option<Self> {
        let mine = full_member(state, &self.me.device)?;
        let changed = state.devices.differing(&previous.devices);
        let (Some(changed), true) = (changed, mine == self.me && state.network == self.network)
        else {
            return Self::of(state, &self.me.device);
        };
        let mut next = self.clone();
        for device in changed.iter().filter(|device| **device != mine.device) {
            let was = full_member(previous, device);
            let now = full_member(state, device);
            if was.is_some() {
                next.full = next.full.saturating_sub(1);
            }
            if now.is_some() {
                next.full = next.full.saturating_add(1);
            }
            for (slot, kept) in (0..SLOTS).zip(next.slots.iter_mut()) {
                kept.kept.retain(|(_, held)| held != device);
                if let Some(member) = now {
                    let standing = standing(&self.network, slot, &mine, &member);
                    if kept.covers(&standing) {
                        let at = kept.kept.partition_point(|held| *held < standing);
                        kept.kept.insert(at, standing);
                    }
                }
                // Grown well past what is kept: the rest is let go, and the
                // last kept is the new floor.
                if kept.kept.len() > KEPT.saturating_mul(2) {
                    kept.kept.truncate(KEPT);
                    kept.floor = kept.kept.last().copied();
                }
            }
        }
        // A slot that lost too many of its best to answer a claim is read
        // again.
        let short = next.slots.iter().any(|slot| slot.floor.is_some() && slot.kept.len() < KEPT);
        if short {
            return Self::of(state, &self.me.device);
        }
        Some(next)
    }

    /// The members this device chooses in `state`, the state these choices
    /// are of, skipping those `silent` says do not answer: what [`choose`]
    /// says.
    #[must_use]
    pub fn choose(&self, state: &RosterState, silent: &dyn Fn(&DeviceId) -> bool) -> Vec<DeviceId> {
        let mut chosen: Vec<DeviceId> = if self.full <= FULLY_CONNECTED_UP_TO {
            // Few enough that every other full member is kept.
            self.slots
                .first()
                .map(|slot| {
                    slot.kept
                        .iter()
                        .map(|(_, device)| *device)
                        .filter(|device| !silent(device))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            (0..SLOTS)
                .zip(&self.slots)
                .filter_map(|(slot, kept)| {
                    let found =
                        kept.kept.iter().map(|(_, device)| *device).find(|device| !silent(device));
                    // Every one kept is silent, and some are not kept: only a
                    // walk finds the best of the rest.
                    match (found, kept.floor) {
                        (Some(device), _) => Some(device),
                        (None, None) => None,
                        (None, Some(_)) => full_members(state)
                            .filter(|member| {
                                member.device != self.me.device && !silent(&member.device)
                            })
                            .map(|member| standing(&self.network, slot, &self.me, &member))
                            .min()
                            .map(|(_, device)| device),
                    }
                })
                .collect()
        };
        chosen.sort_unstable();
        chosen.dedup();
        chosen
    }

    /// Whether this device could have chosen `peer`: what [`claim_holds`]
    /// says with this device as the claimant.
    #[must_use]
    pub fn could_choose(&self, peer: &DeviceId) -> bool {
        if *peer == self.me.device {
            return false;
        }
        if self.full <= FULLY_CONNECTED_UP_TO {
            return self
                .slots
                .first()
                .is_some_and(|slot| slot.kept.iter().any(|(_, device)| device == peer));
        }
        self.slots
            .iter()
            .any(|slot| slot.kept.iter().take(CLAIM_RANK).any(|(_, device)| device == peer))
    }
}

/// Whether `claimant` could have chosen `me` in `state`: what [`claim_holds`]
/// says, walking the members once without listing them.
#[must_use]
pub fn claim_holds_in(state: &RosterState, claimant: &DeviceId, me: &DeviceId) -> bool {
    let (Some(claimant), Some(_)) = (full_member(state, claimant), full_member(state, me)) else {
        return false;
    };
    Choices::of(state, &claimant.device).is_some_and(|choices| choices.could_choose(me))
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

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "a test reports failure by panicking"
)]
mod full_only {
    use std::collections::{BTreeMap, BTreeSet};

    use roster::id::{DeviceId, NetworkId, OperationId};
    use roster::leaf::{DeviceSettings, Mode};
    use roster::state::RosterState;
    use roster::types::{DeviceRecord, NetworkParams, Role};

    use super::{choose, members_of};

    fn device(n: u32) -> DeviceId {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&n.to_be_bytes());
        DeviceId::from_bytes(bytes)
    }

    /// Fifty full members admitted one by one, and five thousand light members
    /// admitted by one batch.
    fn mixed() -> RosterState {
        let params =
            NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 2_592_000)
                .unwrap();
        let mut state = RosterState::from_parts(
            NetworkId::from_bytes([7; 32]),
            params,
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeMap::new(),
        );
        let batch = OperationId::from_bytes([9; 32]);
        for n in 0..5_050_u32 {
            let light = n >= 50;
            let added_by = if light {
                batch
            } else {
                OperationId::from_bytes(*blake3::hash(&n.to_be_bytes()).as_bytes())
            };
            let id = device(n);
            state.devices.insert(
                id,
                DeviceRecord {
                    id,
                    keys: Vec::new(),
                    name: format!("d{n}"),
                    role: Role::Member,
                    founder: false,
                    added_by,
                    capabilities: Vec::new(),
                },
            );
            if light {
                state.set_settings(
                    id,
                    DeviceSettings::new(Mode::Light, Vec::new(), None, None).unwrap(),
                );
            }
        }
        state
    }

    #[test]
    fn a_light_member_is_never_a_neighbour_and_chooses_none() {
        let state = mixed();
        let members = members_of(&state);
        assert_eq!(members.len(), 50, "only the full members take part");
        let full: BTreeSet<DeviceId> = members.iter().map(|member| member.device).collect();
        for me in &members {
            let chosen = choose(&state.network, me, &members, &|_| false);
            assert!(!chosen.is_empty());
            assert!(chosen.iter().all(|device| full.contains(device)), "every neighbour is full");
        }
        assert!(
            !members.iter().any(|member| member.device == device(60)),
            "a light one chooses none"
        );
    }

    #[test]
    fn devices_of_one_batch_score_apart() {
        let mut state = mixed();
        // The batch's devices made full: they share an operation, and must not
        // share an admission.
        let members: Vec<_> = state.devices.keys().collect();
        for device in members {
            state.set_settings(device, roster::leaf::DeviceSettings::default());
        }
        let members = members_of(&state);
        let admissions: BTreeSet<OperationId> =
            members.iter().map(|member| member.admitted_by).collect();
        assert_eq!(admissions.len(), members.len());
    }

    proptest::proptest! {
        /// The kept choices are the rule's, on every state a change leads to:
        /// joins, departures, members going light and coming back.
        #[test]
        fn kept_choices_are_the_rules(
            steps in proptest::collection::vec(
                proptest::collection::vec((0u32..60, 0u8..3), 1..12),
                1..10,
            ),
            silent in proptest::collection::btree_set(0u32..60, 0..6),
        ) {
            let params =
                NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 0).unwrap();
            let mut state = RosterState::from_parts(
                NetworkId::from_bytes([7; 32]),
                params,
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeMap::new(),
            );
            let record = |n: u32| DeviceRecord {
                id: device(n),
                keys: Vec::new(),
                name: format!("d{n}"),
                role: Role::Member,
                founder: false,
                added_by: OperationId::from_bytes(*blake3::hash(&n.to_be_bytes()).as_bytes()),
                capabilities: Vec::new(),
            };
            let me = device(0);
            state.devices.insert(me, record(0));
            state.devices.flatten();
            let mut choices = super::Choices::of(&state, &me).unwrap();
            let silent: BTreeSet<DeviceId> = silent.into_iter().map(device).collect();
            for changes in steps {
                let previous = state.clone();
                for (n, act) in changes {
                    let n = n.max(1);
                    match act {
                        0 => {
                            state.devices.remove(&device(n));
                        }
                        1 => {
                            state.devices.insert_leaf(roster::leaf::DeviceLeaf {
                                record: record(n),
                                settings: DeviceSettings::default(),
                            });
                        }
                        _ => {
                            state.devices.insert(device(n), record(n));
                            state.set_settings(
                                device(n),
                                DeviceSettings::new(Mode::Light, Vec::new(), None, None).unwrap(),
                            );
                        }
                    }
                }
                choices = choices.updated(&previous, &state).unwrap();
                let members = members_of(&state);
                let mine = members.iter().find(|member| member.device == me).copied().unwrap();
                let quiet = |device: &DeviceId| silent.contains(device);
                proptest::prop_assert_eq!(
                    choices.choose(&state, &quiet),
                    choose(&state.network, &mine, &members, &quiet)
                );
                for member in &members {
                    proptest::prop_assert_eq!(
                        choices.could_choose(&member.device),
                        super::claim_holds(&state.network, &me, &member.device, &members)
                    );
                    proptest::prop_assert_eq!(
                        super::claim_holds_in(&state, &member.device, &me),
                        super::claim_holds(&state.network, &member.device, &me, &members)
                    );
                }
            }
        }
    }
}

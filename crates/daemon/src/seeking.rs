//! Where a light member looks, and in what order.
//!
//! A light member holds no roster, so a peer it does not know is found by
//! asking — and whom to ask is decided here, from what it has to hand:
//!
//! - **to reach a peer:** what it already checked, then what it heard
//!   announced on its LAN, then a full member it holds a session with, then
//!   one of its anchors;
//! - **on every start, and when the one that admitted it is off:** its
//!   anchors, the full member that admitted it, the other full members it
//!   keeps, any full member it is in session with, then the LAN. An empty
//!   anchor list is an ordinary state: a home network has none.
//!
//! **The full members it keeps** are handed to it by a full member, with
//! their proofs: its anchors where the network names any; otherwise up to
//! [`FULLS_PER_MEMBER`] full members seen lately, ranked by the same score.
//!
//! **Anchors** are chosen by rendezvous hashing of the member's own device id
//! over the network's anchor list, the [`ANCHORS_PER_MEMBER`] highest scores.
//! Every member computes its own, nobody coordinates, and a list that grows by
//! one moves only the members that rank the newcomer among their highest —
//! each by exactly one anchor.
//!
//! Pure: everything is handed in.

use roster::id::DeviceId;

/// How many anchors a member keeps.
///
/// Three: one can be down and another busy, and the member still has one,
/// while a list that grows moves only a third of the members it would move
/// with nine.
pub const ANCHORS_PER_MEMBER: usize = 3;

/// How many full members a light member is handed where the network names no
/// anchors: as many as anchors, for the same reason.
pub const FULLS_PER_MEMBER: usize = ANCHORS_PER_MEMBER;

/// The tag the anchor score is hashed under.
const DOMAIN: &str = "peerfectly anchor v1";

/// The score `member` gives `anchor`.
fn score(member: &DeviceId, anchor: &DeviceId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DOMAIN);
    hasher.update(member.as_bytes());
    hasher.update(anchor.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The anchors `member` keeps from the network's list: all of them where there
/// are no more than [`ANCHORS_PER_MEMBER`], else the highest scored. Sorted.
#[must_use]
pub fn anchors_for(member: &DeviceId, list: &[DeviceId]) -> Vec<DeviceId> {
    let mut scored: Vec<([u8; 32], DeviceId)> = list
        .iter()
        .filter(|anchor| *anchor != member)
        .map(|anchor| (score(member, anchor), *anchor))
        .collect();
    scored.sort_unstable_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    scored.dedup_by(|a, b| a.1 == b.1);
    let mut chosen: Vec<DeviceId> =
        scored.into_iter().take(ANCHORS_PER_MEMBER).map(|(_, anchor)| anchor).collect();
    chosen.sort_unstable();
    chosen
}

/// The full members a full member hands `member`: its anchors, where the
/// network names any; otherwise up to [`FULLS_PER_MEMBER`] of `fulls`, those
/// `recent` says were seen lately first, each group in the order the anchor
/// score gives. Sorted.
///
/// Not a rule two devices must agree on: it is what the one handing them knows,
/// and every one is checked by its proof where it lands.
#[must_use]
pub fn handed(
    member: &DeviceId,
    anchors: &[DeviceId],
    fulls: &[DeviceId],
    recent: &dyn Fn(&DeviceId) -> bool,
) -> Vec<DeviceId> {
    if !anchors.is_empty() {
        return anchors_for(member, anchors);
    }
    let mut ranked: Vec<(bool, [u8; 32], DeviceId)> = fulls
        .iter()
        .filter(|full| *full != member)
        .map(|full| (recent(full), score(member, full), *full))
        .collect();
    ranked.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)).then(a.2.cmp(&b.2)));
    ranked.dedup_by(|a, b| a.2 == b.2);
    let mut chosen: Vec<DeviceId> =
        ranked.into_iter().take(FULLS_PER_MEMBER).map(|(_, _, full)| full).collect();
    chosen.sort_unstable();
    chosen
}

/// Somewhere a light member can learn of a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// What it already checked.
    Cache,
    /// A member heard announcing itself on the LAN.
    Lan(DeviceId),
    /// A full member it holds a session with.
    Session(DeviceId),
    /// One of its anchors.
    Anchor(DeviceId),
}

/// Where to look for a peer, in order: the cache, the LAN, full members in
/// session, then anchors. A member appearing twice is asked once, where it
/// comes first.
#[must_use]
pub fn lookup_order(
    lan: &[DeviceId],
    in_session: &[DeviceId],
    anchors: &[DeviceId],
) -> Vec<Source> {
    let mut asked: Vec<DeviceId> = Vec::new();
    let mut order = vec![Source::Cache];
    let mut push = |device: &DeviceId, source: Source, asked: &mut Vec<DeviceId>| {
        if !asked.contains(device) {
            asked.push(*device);
            order.push(source);
        }
    };
    for device in lan {
        push(device, Source::Lan(*device), &mut asked);
    }
    for device in in_session {
        push(device, Source::Session(*device), &mut asked);
    }
    for device in anchors {
        push(device, Source::Anchor(*device), &mut asked);
    }
    order
}

/// Whom to reach, on a member's start and when the one that admitted it is
/// off: its anchors, the full member that admitted it, the other full members
/// it keeps, full members in session, then the LAN. Each once.
#[must_use]
pub fn first_start_order(
    anchors: &[DeviceId],
    admitter: Option<DeviceId>,
    kept: &[DeviceId],
    in_session: &[DeviceId],
    lan: &[DeviceId],
) -> Vec<DeviceId> {
    let mut order: Vec<DeviceId> = Vec::new();
    for device in anchors
        .iter()
        .copied()
        .chain(admitter)
        .chain(kept.iter().copied())
        .chain(in_session.iter().copied())
        .chain(lan.iter().copied())
    {
        if !order.contains(&device) {
            order.push(device);
        }
    }
    order
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    fn device(n: u32) -> DeviceId {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&n.to_be_bytes());
        DeviceId::from_bytes(bytes)
    }

    #[test]
    fn a_home_network_with_no_anchors_reaches_whoever_admitted_it() {
        let me = device(1);
        assert!(anchors_for(&me, &[]).is_empty(), "an empty list is ordinary");
        let admitter = device(2);
        assert_eq!(first_start_order(&[], Some(admitter), &[], &[], &[]), vec![admitter]);
        assert_eq!(
            first_start_order(
                &[device(9)],
                Some(admitter),
                &[device(7), device(9)],
                &[device(3)],
                &[device(4), admitter]
            ),
            vec![device(9), admitter, device(7), device(3), device(4)],
            "anchors, the admitter, the full members kept, sessions, the LAN, each once"
        );
    }

    #[test]
    fn a_member_is_handed_its_anchors_or_full_members_seen_lately() {
        let me = device(1);
        let anchors: Vec<DeviceId> = (10..18).map(device).collect();
        let fulls: Vec<DeviceId> = (20..30).map(device).collect();
        assert_eq!(
            handed(&me, &anchors, &fulls, &|_| false),
            anchors_for(&me, &anchors),
            "its anchors, where there are any"
        );

        let lately = [device(21), device(25)];
        let given = handed(&me, &[], &fulls, &|full| lately.contains(full));
        assert_eq!(given.len(), FULLS_PER_MEMBER);
        assert!(lately.iter().all(|full| given.contains(full)), "those seen lately first");
        assert!(!handed(&me, &[], &[me, device(2)], &|_| true).contains(&me), "never itself");
        assert_eq!(handed(&me, &[], &[device(2)], &|_| false), vec![device(2)], "what there is");
    }

    #[test]
    fn a_short_list_is_kept_whole_and_a_long_one_to_three() {
        let me = device(1);
        assert_eq!(anchors_for(&me, &[device(5), device(6)]), vec![device(5), device(6)]);
        let list: Vec<DeviceId> = (10..18).map(device).collect();
        assert_eq!(anchors_for(&me, &list).len(), ANCHORS_PER_MEMBER);
        assert_eq!(anchors_for(&me, &list), anchors_for(&me, &list), "the same every time");
    }

    #[test]
    fn adding_one_anchor_of_nine_moves_about_a_third_each_by_one() {
        let eight: Vec<DeviceId> = (10_000..10_008).map(device).collect();
        let mut nine = eight.clone();
        nine.push(device(10_008));
        let members = 9_000_u32;
        let mut moved = 0_u32;
        for n in 0..members {
            let me = device(n);
            let before = anchors_for(&me, &eight);
            let after = anchors_for(&me, &nine);
            let kept = before.iter().filter(|anchor| after.contains(anchor)).count();
            assert!(kept >= ANCHORS_PER_MEMBER - 1, "nobody moves by more than one anchor");
            if kept < ANCHORS_PER_MEMBER {
                moved += 1;
                assert!(after.contains(&device(10_008)), "and the one it moves to is the newcomer");
            }
        }
        // Three in nine expected; well inside either side of it.
        assert!((2_400..3_600).contains(&moved), "{moved} of {members} moved");
    }

    #[test]
    fn the_lookup_order_asks_each_member_once_where_it_comes_first() {
        let order = lookup_order(&[device(1)], &[device(2), device(1)], &[device(3), device(2)]);
        assert_eq!(
            order,
            vec![
                Source::Cache,
                Source::Lan(device(1)),
                Source::Session(device(2)),
                Source::Anchor(device(3))
            ]
        );
    }
}

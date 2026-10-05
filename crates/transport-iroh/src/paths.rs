//! Which of a connection's paths carries the session, and which is not a path
//! at all.
//!
//! # Why this exists
//!
//! The connectivity layer finds candidate addresses by enumerating the machine's
//! interfaces. One of those interfaces is the tunnel this session is carrying,
//! so its address is offered to the peer like any other — and the peer can reach
//! it, because the tunnel works. The path validates, the layer's own policy puts
//! every direct path ahead of the relay and switches the moment one appears, and
//! from then on the connection that carries the tunnel is asked to run inside
//! the tunnel it carries. Nothing crosses.
//!
//! That was measured on a phone over mobile data: a path from this device's
//! overlay address to the peer's was selected every sixty seconds, on the dot,
//! and abandoned fifteen seconds later as timed out, every single time. Pings
//! through the tunnel averaged 1 600 ms against 27 ms outside it.
//!
//! # The rule
//!
//! A path with either end inside a range a tunnel of ours serves is not a path.
//! It is never chosen — not when something else is available, and not when
//! nothing else is, because choosing it is choosing a stall.
//!
//! Validation cannot tell the difference, which is why this is not a judgement
//! about quality: a packet did reach the far end, through the tunnel. The loop
//! is only visible to somebody who knows which addresses belong to a tunnel, and
//! the only one who knows that is the caller running it.

use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use iroh::endpoint::transports::{
    FourTuple, PathSelection, PathSelectionContext, PathSelectionData, PathSelector,
};
use transport::Range;

/// The ranges served by tunnels of ours, shared between the transport and the
/// selector the endpoint was built with.
///
/// The endpoint is built before anybody can say what the tunnels are, so the two
/// hold this instead of a value: the selector reads it at each decision, and
/// knowing nothing means refusing nothing.
#[derive(Debug, Clone, Default)]
pub struct Avoided(Arc<RwLock<Vec<Range>>>);

impl Avoided {
    /// Nothing to avoid yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces what is avoided.
    ///
    /// Replaced rather than added to: a tunnel going down takes its range with
    /// it, and a set that only grew would keep refusing paths through an adapter
    /// that no longer exists.
    pub fn set(&self, ranges: &[Range]) {
        // A poisoned lock means a panic in a critical section elsewhere. Keeping
        // the previous answer is the conservative reading and cannot make this
        // loop appear; the alternative is bringing the transport down over a
        // list of address ranges.
        if let Ok(mut held) = self.0.write() {
            held.clear();
            held.extend_from_slice(ranges);
        }
    }

    /// What is avoided now.
    #[must_use]
    pub fn ranges(&self) -> Vec<Range> {
        self.0.read().map(|held| held.clone()).unwrap_or_default()
    }

    /// Whether either end of a path lies in an avoided range.
    #[must_use]
    pub fn refuses(&self, ends: &Ends) -> bool {
        let Ok(held) = self.0.read() else { return false };
        held.iter().any(|range| ends.inside(range))
    }
}

/// Where a path runs, as far as addresses go.
///
/// Both ends are optional: a relayed path has no IP ends at all, and the local
/// end of a direct path is only known when the operating system reported which
/// interface it left by.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ends {
    /// This end, when the operating system named it.
    pub local: Option<IpAddr>,
    /// The far end.
    pub remote: Option<IpAddr>,
}

impl Ends {
    /// Whether either end is inside `range`.
    #[must_use]
    pub fn inside(&self, range: &Range) -> bool {
        [self.local, self.remote].iter().flatten().any(|end| range.contains(end))
    }
}

/// What kind of path a candidate is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// Straight to the peer.
    Direct,
    /// Through the relay.
    Relayed,
}

/// One candidate, as the policy needs to see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// Direct or relayed.
    pub kind: Kind,
    /// Where it runs.
    pub ends: Ends,
    /// Its round trip, when the connection has one for it.
    pub rtt: Option<Duration>,
    /// Whether it is the path carrying the session now.
    pub selected: bool,
}

/// Picks the candidate that should carry the session, or nothing.
///
/// `None` means "keep whatever is carrying it", which is what the connectivity
/// layer does with an empty answer. That is the right answer when every
/// candidate runs through a tunnel of ours, including when the path in use is
/// one of them: there is nowhere better to go, and saying so would only move the
/// session to another stall.
///
/// Otherwise: direct beats relayed, a shorter round trip beats a longer one, and
/// the path already carrying the session beats an equal alternative. That last
/// clause is what stops two direct paths from trading the session back and forth
/// over a millisecond of jitter.
#[must_use]
pub fn choose(candidates: &[Candidate], avoid: &[Range]) -> Option<usize> {
    let usable: Vec<(usize, &Candidate)> = candidates
        .iter()
        .enumerate()
        .filter(|(_, candidate)| !avoid.iter().any(|range| candidate.ends.inside(range)))
        .collect();

    let best = usable.iter().min_by_key(|(_, candidate)| rank(candidate))?;

    // An incumbent that is as good as the best answer keeps the session. Only a
    // better *kind* of path moves it, so a relay in use yields to a direct path
    // and a direct path in use does not yield to a relay.
    let incumbent = usable
        .iter()
        .find(|(_, candidate)| candidate.selected)
        .filter(|(_, candidate)| candidate.kind <= best.1.kind);

    Some(incumbent.unwrap_or(best).0)
}

/// The rule above, as the connectivity layer asks for it.
///
/// Nothing is decided here. This reads `iroh`'s view of the candidates into the
/// shape [`choose`] judges, and turns the answer back into `iroh`'s. The policy
/// stays testable without a connection, which is the only way the table of cases
/// above could be written at all: `iroh`'s own way of making a context for a test
/// is private to `iroh`.
#[derive(Debug, Clone)]
pub struct Selector {
    /// The ranges tunnels of ours serve, read afresh at every decision.
    avoided: Avoided,
}

impl Selector {
    /// A selector reading `avoided`.
    #[must_use]
    pub const fn new(avoided: Avoided) -> Self {
        Self { avoided }
    }
}

impl PathSelector for Selector {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let current = ctx.current();
        let paths: Vec<PathSelectionData<'_>> = ctx.paths().collect();
        let candidates: Vec<Candidate> =
            paths.iter().map(|path| candidate_of(path, current)).collect();

        let mut selection = PathSelection::none();
        if let Some(index) = choose(&candidates, &self.avoided.ranges())
            && let Some(chosen) = paths.get(index)
        {
            selection.set(chosen);
        }
        // An empty selection keeps whatever is carrying the session, which is
        // what `choose` means by refusing everything.
        selection
    }
}

/// One of `iroh`'s candidates, as the policy needs to see it.
fn candidate_of(path: &PathSelectionData<'_>, current: Option<&FourTuple>) -> Candidate {
    let network_path = path.network_path();
    let (kind, ends) = shape_of(network_path);
    Candidate {
        kind,
        ends,
        rtt: path.stats().map(|stats| stats.rtt),
        selected: current == Some(network_path),
    }
}

/// What kind of path `iroh`'s four-tuple is, and where it runs.
///
/// Separate from the rest of the translation because it is the only part with a
/// judgement in it, and the only part that can be tested: `iroh` keeps the way
/// to make a candidate for a test to itself.
fn shape_of(network_path: &FourTuple) -> (Kind, Ends) {
    match network_path {
        FourTuple::Ip { remote, local } => {
            (Kind::Direct, Ends { local: *local, remote: Some(remote.ip()) })
        }
        // A relayed path has no IP ends: no range of ours can name it, and none
        // should — losing the relay to a range would leave a device with nothing.
        FourTuple::Relay { .. } => (Kind::Relayed, Ends::default()),
        // A transport of somebody else's making. This binding adds none, so this
        // is unreachable today; treated as direct with no ends it is judged on
        // its round trip and never refused, which is the harmless reading.
        _ => (Kind::Direct, Ends::default()),
    }
}

/// How good a candidate is, lower being better.
fn rank(candidate: &Candidate) -> (Kind, Duration) {
    // No round trip yet ranks last among its kind rather than first: a path
    // nobody has timed is not a fast path.
    (candidate.kind, candidate.rtt.unwrap_or(Duration::MAX))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a test that cannot construct its own fixtures proves less than it costs"
)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn range(text: &str, prefix_len: u8) -> Range {
        Range::new(ip(text), prefix_len).unwrap()
    }

    /// The overlay ranges of a device with one network up.
    fn overlay() -> Vec<Range> {
        vec![range("100.64.0.0", 10), range("fd12:3456:789a:bcde::", 64)]
    }

    fn direct(local: &str, remote: &str, rtt: u64, selected: bool) -> Candidate {
        Candidate {
            kind: Kind::Direct,
            ends: Ends { local: Some(ip(local)), remote: Some(ip(remote)) },
            rtt: Some(Duration::from_millis(rtt)),
            selected,
        }
    }

    fn relayed(rtt: u64, selected: bool) -> Candidate {
        Candidate {
            kind: Kind::Relayed,
            ends: Ends::default(),
            rtt: Some(Duration::from_millis(rtt)),
            selected,
        }
    }

    #[test]
    fn with_nothing_selected_the_only_path_is_chosen() {
        let candidates = [relayed(20, false)];
        assert_eq!(choose(&candidates, &overlay()), Some(0));
    }

    #[test]
    fn a_direct_path_takes_the_session_from_the_relay() {
        let candidates = [relayed(20, true), direct("192.168.1.9", "192.168.1.7", 4, false)];
        assert_eq!(choose(&candidates, &overlay()), Some(1));
    }

    /// The measured failure: the candidate runs from our overlay address to the
    /// peer's, and the relay is carrying the session.
    #[test]
    fn a_path_through_our_own_tunnel_never_takes_the_session() {
        let candidates = [relayed(20, true), direct("100.117.31.3", "100.99.120.85", 2, false)];
        assert_eq!(choose(&candidates, &overlay()), Some(0), "the relay keeps carrying it");
    }

    /// Either end inside a range is enough, whichever end it is.
    #[test]
    fn one_end_inside_a_range_is_enough_to_refuse_a_path() {
        let ours = overlay();
        let from_us = [relayed(20, true), direct("100.117.31.3", "93.184.216.34", 2, false)];
        assert_eq!(choose(&from_us, &ours), Some(0));

        let to_them = [relayed(20, true), direct("192.168.1.9", "100.99.120.85", 2, false)];
        assert_eq!(choose(&to_them, &ours), Some(0));

        let over_the_ula = [
            relayed(20, true),
            direct("fd12:3456:789a:bcde::7", "fd12:3456:789a:bcde::9", 2, false),
        ];
        assert_eq!(choose(&over_the_ula, &ours), Some(0));
    }

    /// Refused even when it is the only candidate: choosing it is choosing the
    /// stall, and nothing is the answer that keeps the session where it is.
    #[test]
    fn a_path_through_our_own_tunnel_is_refused_even_when_it_is_alone() {
        let candidates = [direct("100.117.31.3", "100.99.120.85", 2, false)];
        assert_eq!(choose(&candidates, &overlay()), None);
    }

    /// The path in use is itself through our tunnel and there is nowhere better.
    #[test]
    fn a_selected_path_through_our_tunnel_with_nowhere_to_go_is_left_alone() {
        let candidates = [direct("100.117.31.3", "100.99.120.85", 2, true)];
        assert_eq!(choose(&candidates, &overlay()), None);
    }

    /// The same, with a relay available: the session moves to the relay.
    #[test]
    fn a_selected_path_through_our_tunnel_yields_to_the_relay() {
        let candidates = [direct("100.117.31.3", "100.99.120.85", 2, true), relayed(20, false)];
        assert_eq!(choose(&candidates, &overlay()), Some(1));
    }

    #[test]
    fn no_candidates_at_all_choose_nothing() {
        assert_eq!(choose(&[], &overlay()), None);
    }

    /// A transport nobody has told anything refuses nothing on this ground.
    #[test]
    fn with_no_ranges_known_a_path_is_judged_on_its_merits_alone() {
        let candidates = [relayed(20, true), direct("100.117.31.3", "100.99.120.85", 2, false)];
        assert_eq!(choose(&candidates, &[]), Some(1));
    }

    #[test]
    fn the_shorter_round_trip_wins_among_direct_paths() {
        let candidates = [
            direct("192.168.1.9", "192.168.1.7", 9, false),
            direct("192.168.1.9", "192.168.1.8", 3, false),
        ];
        assert_eq!(choose(&candidates, &overlay()), Some(1));
    }

    /// Stickiness: an equal alternative does not move a session.
    #[test]
    fn a_marginally_faster_path_does_not_take_the_session_from_an_equal_one() {
        let candidates = [
            direct("192.168.1.9", "192.168.1.7", 4, true),
            direct("192.168.1.9", "192.168.1.8", 3, false),
        ];
        assert_eq!(choose(&candidates, &overlay()), Some(0));
    }

    /// But a direct path does take it from the relay, which is not an equal.
    #[test]
    fn the_relay_in_use_yields_to_a_direct_path() {
        let candidates = [relayed(3, true), direct("192.168.1.9", "192.168.1.7", 40, false)];
        assert_eq!(choose(&candidates, &overlay()), Some(1));
    }

    #[test]
    fn a_path_with_no_round_trip_yet_ranks_behind_one_that_has_it() {
        let untimed = Candidate {
            kind: Kind::Direct,
            ends: Ends { local: Some(ip("192.168.1.9")), remote: Some(ip("192.168.1.8")) },
            rtt: None,
            selected: false,
        };
        let candidates = [untimed, direct("192.168.1.9", "192.168.1.7", 40, false)];
        assert_eq!(choose(&candidates, &overlay()), Some(1));
    }

    /// A path whose local end the operating system did not name is judged on the
    /// end that is known.
    #[test]
    fn a_path_with_an_unknown_local_end_is_judged_on_its_remote() {
        let ours = overlay();
        let through_the_tunnel = Candidate {
            kind: Kind::Direct,
            ends: Ends { local: None, remote: Some(ip("100.99.120.85")) },
            rtt: Some(Duration::from_millis(2)),
            selected: false,
        };
        let candidates = [relayed(20, true), through_the_tunnel];
        assert_eq!(choose(&candidates, &ours), Some(0));

        let elsewhere = Candidate {
            ends: Ends { local: None, remote: Some(ip("93.184.216.34")) },
            ..through_the_tunnel
        };
        let candidates = [relayed(20, true), elsewhere];
        assert_eq!(choose(&candidates, &ours), Some(1));
    }

    /// A relayed path has no IP ends, so no range can refuse it. Losing the
    /// relay to a range that happens to hold the relay's address would leave a
    /// device with no path at all.
    #[test]
    fn a_relayed_path_is_never_refused_by_a_range() {
        let candidates = [relayed(20, false)];
        let everything = vec![range("0.0.0.0", 0), range("::", 0)];
        assert_eq!(choose(&candidates, &everything), Some(0));
    }

    /// The translation from `iroh`'s four-tuple, which is the one part of the
    /// wiring with a judgement in it.
    #[test]
    fn a_direct_four_tuple_carries_both_its_ends() {
        let path = FourTuple::Ip {
            remote: "100.99.120.85:46921".parse().unwrap(),
            local: Some(ip("100.117.31.3")),
        };
        let (kind, ends) = shape_of(&path);
        assert_eq!(kind, Kind::Direct);
        assert_eq!(ends.local, Some(ip("100.117.31.3")));
        assert_eq!(ends.remote, Some(ip("100.99.120.85")));
        assert!(ends.inside(&range("100.64.0.0", 10)), "the measured loop is refused");
    }

    /// The operating system does not always say which interface a path left by.
    #[test]
    fn a_direct_four_tuple_without_a_local_end_keeps_its_remote() {
        let path = FourTuple::Ip { remote: "192.168.1.7:46921".parse().unwrap(), local: None };
        let (kind, ends) = shape_of(&path);
        assert_eq!(kind, Kind::Direct);
        assert_eq!(ends.local, None);
        assert_eq!(ends.remote, Some(ip("192.168.1.7")));
    }

    #[test]
    fn what_is_avoided_can_be_set_after_a_reader_took_it() {
        let avoided = Avoided::new();
        let reader = avoided.clone();
        assert!(reader.ranges().is_empty());

        avoided.set(&overlay());
        assert_eq!(reader.ranges().len(), 2);
        assert!(
            reader.refuses(&Ends { local: Some(ip("100.117.31.3")), remote: Some(ip("8.8.8.8")) })
        );
        assert!(
            !reader.refuses(&Ends { local: Some(ip("192.168.1.9")), remote: Some(ip("8.8.8.8")) })
        );

        // A tunnel going down takes its range with it.
        avoided.set(&[]);
        assert!(reader.ranges().is_empty());
        assert!(
            !reader.refuses(&Ends { local: Some(ip("100.117.31.3")), remote: Some(ip("8.8.8.8")) })
        );
    }
}

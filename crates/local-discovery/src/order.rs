//! What to try first.
//!
//! §2.9 fixes the order: the local network, then globally routable addressing,
//! then whatever the rendezvous knew. This decides which candidate goes where in
//! that list.
//!
//! # It is a pure function
//!
//! Candidates in, ordered candidates out, given the conditions. §8 requires the
//! order to be recomputed **on every interface change**, and a function of its
//! inputs can simply be called again.
//!
//! Anything holding state would have to be invalidated correctly, and the
//! symptom of getting that wrong is the one §8 names specifically: staying on
//! the relay after arriving home. Nobody notices that quickly — the connection
//! works, it is merely going the long way round.
//!
//! # The same-NAT evidence is a parameter
//!
//! §8 says to compare the two peers' reflexive addresses and, when they match,
//! prefer local candidates aggressively — which also sidesteps NAT hairpinning.
//! Gathering those addresses belongs to whoever holds the transport. Taking the
//! conclusion as a parameter keeps this crate out of the transport and keeps the
//! ordering testable without a network.

use crate::limits;

/// Where a candidate address came from.
///
/// The source is a hint about *reachability*, never about authority: §8 is
/// explicit that a discovered device is never proof of anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// Heard on this network, or cached from when it was.
    Local,
    /// Believed globally routable.
    Global,
    /// Learned from the rendezvous.
    Rendezvous,
}

/// One address a peer might be reachable at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The address. Opaque: this crate does not parse it, because the transport
    /// decides what an address means.
    pub address: String,
    /// Where it came from.
    pub source: Source,
}

impl Candidate {
    /// A candidate from a source.
    #[must_use]
    pub fn new(address: impl Into<String>, source: Source) -> Self {
        Self { address: address.into(), source }
    }
}

/// What the caller knows about the network right now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Conditions {
    /// Address prefixes currently present on a local interface.
    ///
    /// Supplied by the caller because enumerating interfaces is the daemon's
    /// job, and because a test needs to state them rather than have them.
    pub local_prefixes: Vec<String>,
    /// Whether the caller has evidence both peers sit behind one external
    /// address.
    ///
    /// §8: when they do, prefer local candidates aggressively. It also avoids
    /// NAT hairpinning, which many routers handle badly or not at all.
    pub shares_external_address: bool,
}

/// Orders candidates by what to try first.
///
/// Stable within a rank, so the same inputs always give the same output — which
/// is what makes "recompute on interface change" a safe thing to do repeatedly.
#[must_use]
pub fn order(candidates: &[Candidate], conditions: &Conditions) -> Vec<Candidate> {
    let mut ranked: Vec<(u8, usize, Candidate)> = candidates
        .iter()
        .enumerate()
        .map(|(position, candidate)| (rank(candidate, conditions), position, candidate.clone()))
        .collect();

    // Rank first, then original position: a stable order means a caller
    // comparing two runs sees no spurious difference.
    ranked.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    ranked.into_iter().map(|(_, _, candidate)| candidate).collect()
}

/// Lower ranks are tried first.
fn rank(candidate: &Candidate, conditions: &Conditions) -> u8 {
    let on_a_local_interface = conditions
        .local_prefixes
        .iter()
        .any(|prefix| !prefix.is_empty() && candidate.address.contains(prefix.as_str()));

    match candidate.source {
        // An address that matches an interface we currently hold is the best
        // thing available, whatever it was labelled when it was learned. This is
        // what makes recomputing after an interface change actually reorder.
        _ if on_a_local_interface => 0,
        Source::Local if conditions.shares_external_address => 0,
        Source::Local => 1,
        Source::Global => 2,
        Source::Rendezvous => 3,
    }
}

/// Trims a candidate list to what is worth attempting.
///
/// A device has a handful of paths, not a directory of them; a list longer than
/// this is a list whose tail will never be reached before something succeeds.
#[must_use]
pub fn trim(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    candidates.truncate(limits::MAX_ADDRESSES_PER_PEER);
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(address: &str) -> Candidate {
        Candidate::new(address, Source::Local)
    }

    fn global(address: &str) -> Candidate {
        Candidate::new(address, Source::Global)
    }

    fn from_rendezvous(address: &str) -> Candidate {
        Candidate::new(address, Source::Rendezvous)
    }

    fn addresses(ordered: &[Candidate]) -> Vec<&str> {
        ordered.iter().map(|c| c.address.as_str()).collect()
    }

    #[test]
    fn local_comes_before_global() {
        let ordered =
            order(&[global("ip:203.0.113.5"), local("ip:192.168.1.5")], &Conditions::default());
        assert_eq!(addresses(&ordered), vec!["ip:192.168.1.5", "ip:203.0.113.5"]);
    }

    /// §2.9's order: the rendezvous is the last resort, behind anything already
    /// known locally.
    #[test]
    fn the_rendezvous_is_the_last_resort() {
        let ordered = order(
            &[from_rendezvous("ip:203.0.113.9"), local("ip:192.168.1.5"), global("ip:203.0.113.5")],
            &Conditions::default(),
        );
        assert_eq!(addresses(&ordered), vec!["ip:192.168.1.5", "ip:203.0.113.5", "ip:203.0.113.9"]);
    }

    /// The failure §8 names: a node that computed an order once stays on the
    /// relay after arriving home. Recomputing must move the now-local address
    /// to the front, whatever it was labelled when it was learned.
    #[test]
    fn an_interface_change_reorders() {
        let candidates = [from_rendezvous("ip:192.168.1.5:41641"), global("ip:203.0.113.5:41641")];

        let away = order(&candidates, &Conditions::default());
        assert_eq!(addresses(&away).first().copied(), Some("ip:203.0.113.5:41641"));

        let home = order(
            &candidates,
            &Conditions { local_prefixes: vec!["192.168.1.".to_owned()], ..Conditions::default() },
        );
        assert_eq!(
            addresses(&home).first().copied(),
            Some("ip:192.168.1.5:41641"),
            "an address on an interface we now hold must be tried first"
        );
    }

    /// §8: when both peers sit behind one external address, prefer local
    /// candidates aggressively — it also sidesteps NAT hairpinning.
    #[test]
    fn sharing_an_external_address_strengthens_local_preference() {
        let candidates = [global("ip:203.0.113.5"), local("ip:10.0.0.7")];

        let ordinary = order(&candidates, &Conditions::default());
        let shared = order(
            &candidates,
            &Conditions { shares_external_address: true, ..Conditions::default() },
        );

        assert_eq!(addresses(&ordinary).first().copied(), Some("ip:10.0.0.7"));
        assert_eq!(addresses(&shared).first().copied(), Some("ip:10.0.0.7"));
        assert_eq!(addresses(&shared), addresses(&ordinary));
    }

    /// Pure: the same inputs give the same output, which is what makes
    /// recomputing on every interface change safe to do repeatedly.
    #[test]
    fn the_same_inputs_give_the_same_order() {
        let candidates = [from_rendezvous("ip:a"), local("ip:b"), global("ip:c"), local("ip:d")];
        let conditions =
            Conditions { local_prefixes: vec!["ip:b".to_owned()], shares_external_address: false };

        assert_eq!(order(&candidates, &conditions), order(&candidates, &conditions));
    }

    /// Stable within a rank, so two candidates from one source keep the order
    /// they arrived in rather than swapping between runs.
    #[test]
    fn ordering_is_stable_within_a_rank() {
        let ordered = order(&[local("ip:first"), local("ip:second")], &Conditions::default());
        assert_eq!(addresses(&ordered), vec!["ip:first", "ip:second"]);
    }

    #[test]
    fn an_empty_prefix_matches_nothing() {
        // A caller with no interfaces must not accidentally promote everything.
        let ordered = order(
            &[from_rendezvous("ip:a"), local("ip:b")],
            &Conditions { local_prefixes: vec![String::new()], ..Conditions::default() },
        );
        assert_eq!(addresses(&ordered), vec!["ip:b", "ip:a"]);
    }

    #[test]
    fn a_candidate_list_is_trimmed() {
        let many: Vec<Candidate> =
            (0..limits::MAX_ADDRESSES_PER_PEER + 4).map(|i| local(&format!("ip:{i}"))).collect();
        assert_eq!(trim(many).len(), limits::MAX_ADDRESSES_PER_PEER);
    }
}

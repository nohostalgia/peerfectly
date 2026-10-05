//! The name-resolution rule: what it should say, decided here.
//!
//! On Windows a rule directing one suffix to one resolver is a set of registry
//! values. Writing them is [`crate::platform`]'s job. Deciding what they contain
//! is this module's, so the part that could be wrong in a way that matters — the
//! suffix it claims, the resolver it points at, whether it is recognisable as
//! ours — is testable without Administrator.
//!
//! # Why it carries a tag
//!
//! Routes are scoped to an adapter and die with it. A rule is a registry value
//! and dies with nothing: it survives a crash, a kill, and a power loss. A stale
//! one sends every name under the suffix to a resolver that is not running, which
//! looks to a person like the network being broken rather than like a leftover.
//!
//! So the daemon has to be able to recognise its own leftovers on the next start.
//! Recognising them by suffix alone would mean deleting a rule somebody else
//! wrote for the same suffix; recognising them by a tag means deleting exactly
//! what this daemon wrote and nothing else.

use core::fmt;
use std::net::Ipv6Addr;

use roster::state::RosterState;

use crate::error::{Error, Result};
use crate::limits;

/// A rule directing one suffix to one resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The network it belongs to, as this device names it.
    network: String,
    /// The suffix it claims, from the signed parameters.
    suffix: String,
    /// The resolver it points at.
    nameserver: Ipv6Addr,
}

impl Rule {
    /// The rule for a network, resolving through this device's own address.
    ///
    /// The suffix comes from the roster. `DESIGN.md` §0 forbids a constant, and
    /// this is the only place the daemon could have put one.
    ///
    /// # Errors
    ///
    /// When the parameters carry no suffix. A rule claiming an empty suffix would
    /// direct **every** name on the machine to this resolver — the DNS equivalent
    /// of a default route, and the same kind of mistake.
    ///
    /// And when the suffix is not a private name. A rule for `azienda.it` sends
    /// that whole branch of the public DNS to this network's resolver: the names
    /// its devices carry resolve to the network's addresses, and every other name
    /// under it stops existing on this machine. The roster refuses such
    /// parameters at decoding; this is the second line, where the suffix would
    /// become configuration.
    pub fn for_network(network: &str, state: &RosterState, nameserver: Ipv6Addr) -> Result<Self> {
        let suffix = state.params.suffix.trim().trim_matches('.');
        if suffix.is_empty() {
            return Err(Error::Parameters {
                cause: "an empty suffix would send every name on the machine to this resolver"
                    .to_owned(),
            });
        }
        if let Some(cause) = unusable_suffix(suffix) {
            return Err(Error::Parameters { cause });
        }
        Ok(Self { network: network.to_owned(), suffix: suffix.to_owned(), nameserver })
    }

    /// The network this rule belongs to.
    #[must_use]
    pub fn network(&self) -> &str {
        &self.network
    }

    /// The subkey this rule lives under.
    ///
    /// Tagged, so the daemon finds its own leftovers and only those, and carrying
    /// the network, so that one network's rule is not the same key as another's.
    /// With a single key, bringing a second network up would overwrite the rule
    /// of a network that was carrying traffic.
    #[must_use]
    pub fn key_name(&self) -> String {
        limits::rule_key(&self.network)
    }

    /// The suffix, in the leading-dot form the rule format wants.
    ///
    /// The leading dot is what makes it a suffix rule rather than an exact-name
    /// rule: without it the rule matches one name and nothing under it.
    #[must_use]
    pub fn matched_name(&self) -> String {
        format!(".{}", self.suffix)
    }

    /// The resolver this rule points at.
    #[must_use]
    pub const fn nameserver(&self) -> Ipv6Addr {
        self.nameserver
    }

    /// The suffix, without the leading dot.
    #[must_use]
    pub fn suffix(&self) -> &str {
        &self.suffix
    }

    /// Whether this rule would capture names outside its suffix.
    ///
    /// Always false, and checked rather than asserted — the same treatment the
    /// default route gets, for the same reason.
    #[must_use]
    pub fn claims_everything(&self) -> bool {
        let matched = self.matched_name();
        matched == "." || matched.is_empty() || self.suffix.is_empty()
    }
}

/// Why a suffix cannot be used, when it cannot.
///
/// The roster's rule, called rather than restated, with the sentence a person
/// reads written once. A roster refusal carries the rule it broke and never the
/// value — a roster error has no room for one — so naming what was refused is
/// this layer's job, and every place the daemon refuses a suffix says it the
/// same way.
#[must_use]
pub fn unusable_suffix(suffix: &str) -> Option<String> {
    let reason = match roster::params::private_suffix(suffix) {
        Ok(()) => return None,
        Err(roster::Error::InvalidValue(reason) | roster::Error::LimitExceeded(reason)) => reason,
        Err(_) => "outside what a network may claim",
    };
    Some(format!(
        "`{suffix}` is not a private name: {reason}. A network's suffix is one or more lowercase \
         labels under `.{}` — `casa.internal`, say — and not `docker`, `google`, `ec2` or \
         `compute` directly beneath it.",
        roster::params::PRIVATE_PARENT
    ))
}

/// Whether two name suffixes would claim overlapping namespaces.
///
/// A resolution rule captures every name beneath its suffix, so two rules where
/// one suffix sits under the other mean one network's resolver answering for
/// names that belong to another. Nobody would see that as a conflict until a
/// name resolved to the wrong device, and no error anywhere would report it.
///
/// Equality is only the plainest case. `casa.internal` against
/// `ufficio.casa.internal` is the same fault, and so is `internal` against
/// anything beneath it. Compared on label boundaries, so `notcasa.internal` does
/// not count as beneath `casa.internal`.
#[must_use]
pub fn overlapping(one: &str, other: &str) -> bool {
    let tidy = |text: &str| text.trim().trim_matches('.').to_ascii_lowercase();
    let (one, other) = (tidy(one), tidy(other));

    if one.is_empty() || other.is_empty() {
        // An empty suffix claims every name on the machine, so it overlaps
        // anything at all. `claims_everything` refuses it in its own right; this
        // agrees rather than answering "no" to a question it cannot settle.
        return true;
    }
    one == other || one.ends_with(&format!(".{other}")) || other.ends_with(&format!(".{one}"))
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} via {}", self.matched_name(), self.nameserver)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use roster::id::NetworkId;
    use roster::types::NetworkParams;

    use super::*;

    /// A state carrying a chosen suffix.
    ///
    /// The suffix is written into the field rather than passed to the
    /// constructor: the roster refuses anything outside its grammar, and the
    /// check here is for a state that did not come through decoding — an older
    /// build's parameters, or one assembled in memory.
    fn state(suffix: &str) -> RosterState {
        let mut params = NetworkParams::new(
            vec![0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "example.internal",
            2_592_000,
        )
        .expect("valid");
        params.suffix = suffix.to_owned();
        RosterState {
            network: NetworkId::from_bytes([1; 32]),
            params,
            devices: BTreeMap::new(),
            revoked: BTreeSet::new(),
        }
    }

    fn resolver() -> Ipv6Addr {
        "fd00::1".parse().expect("valid")
    }

    #[test]
    fn the_rule_claims_the_suffix_and_points_at_the_resolver() {
        let rule =
            Rule::for_network("test", &state("example.internal"), resolver()).expect("usable");

        assert_eq!(rule.matched_name(), ".example.internal");
        assert_eq!(rule.nameserver(), resolver());
    }

    /// The leading dot is what makes it a suffix rule. Without it the rule
    /// matches one name and nothing under it, and every device name would go to
    /// the system resolver instead.
    #[test]
    fn the_matched_name_is_a_suffix_not_a_name() {
        let rule =
            Rule::for_network("test", &state("example.internal"), resolver()).expect("usable");
        assert!(rule.matched_name().starts_with('.'), "{}", rule.matched_name());
    }

    /// The DNS equivalent of a default route, and refused for the same reason.
    #[test]
    fn an_empty_suffix_is_refused() {
        match Rule::for_network("test", &state(""), resolver()) {
            Err(Error::Parameters { cause }) => {
                assert!(cause.contains("every name"), "the refusal says what it would do: {cause}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// A rule for `azienda.it` would send that whole branch of the public DNS
    /// to this network's resolver on every member's machine. The roster refuses
    /// it at decoding; this is the second line, and its message names the value
    /// — which the roster's refusal cannot carry.
    #[test]
    fn a_suffix_outside_the_private_namespace_gets_no_rule() {
        for suffix in ["azienda.it", "com", "banca.it", "internal", "docker.internal"] {
            match Rule::for_network("test", &state(suffix), resolver()) {
                Err(Error::Parameters { cause }) => {
                    assert!(cause.contains(suffix), "the refusal names the suffix: {cause}");
                    assert!(cause.contains(".internal"), "and the namespace allowed: {cause}");
                }
                other => panic!("`{suffix}` must get no rule, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_suffix_of_only_dots_is_refused() {
        for suffix in [".", "..", " . "] {
            assert!(Rule::for_network("test", &state(suffix), resolver()).is_err(), "{suffix:?}");
        }
    }

    #[test]
    fn no_rule_this_crate_builds_claims_everything() {
        for suffix in ["example.internal", "a.b.c.internal", "x.internal"] {
            let rule = Rule::for_network("test", &state(suffix), resolver()).expect("usable");
            assert!(!rule.claims_everything(), "{suffix}");
        }
    }

    /// The suffix follows the signed parameters, and there is nowhere else it
    /// could have come from.
    #[test]
    fn the_suffix_follows_the_signed_parameters() {
        let one =
            Rule::for_network("test", &state("example.internal"), resolver()).expect("usable");
        let two = Rule::for_network("test", &state("other.internal"), resolver()).expect("usable");

        assert_ne!(one.matched_name(), two.matched_name());
        assert_eq!(two.matched_name(), ".other.internal");
    }

    /// A trailing dot is the wire form, not part of the suffix. Left in, the rule
    /// would claim `.example.internal.` and match nothing a resolver ever asks
    /// about.
    #[test]
    fn a_trailing_dot_is_not_part_of_the_suffix() {
        let rule =
            Rule::for_network("test", &state("example.internal."), resolver()).expect("usable");
        assert_eq!(rule.matched_name(), ".example.internal");
    }

    /// Equality is only the plainest case, and the others are the ones that
    /// would go unnoticed: a name resolving to the wrong device, with no error
    /// anywhere reporting it.
    #[test]
    fn a_suffix_beneath_another_overlaps_it() {
        assert!(overlapping("casa.internal", "casa.internal"), "the same claim twice");
        assert!(overlapping("ufficio.casa.internal", "casa.internal"), "beneath");
        assert!(overlapping("casa.internal", "ufficio.casa.internal"), "and the other way");
        assert!(overlapping("internal", "casa.internal"), "a parent swallows everything");
    }

    #[test]
    fn unrelated_suffixes_do_not_overlap() {
        assert!(!overlapping("casa.internal", "lavoro.internal"));
        assert!(!overlapping("casa.internal", "notcasa.internal"), "compared on label boundaries");
        assert!(!overlapping("acasa.internal", "casa.internal"));
    }

    /// Written the way a person might, with stray dots and capitals.
    #[test]
    fn overlap_is_judged_on_what_the_suffix_means() {
        assert!(overlapping(" casa.internal. ", "CASA.internal"));
    }

    /// An empty suffix claims every name on the machine, so it overlaps
    /// anything. `claims_everything` refuses it in its own right; this must not
    /// disagree.
    #[test]
    fn an_empty_suffix_overlaps_everything() {
        assert!(overlapping("", "casa.internal"));
        assert!(overlapping("casa.internal", "."));
    }

    /// Two things at once, and they pull in opposite directions.
    ///
    /// A leftover has to be recognisable as this daemon's by a daemon that has
    /// not loaded a roster yet, so every key **contains the tag**. And one
    /// network's rule must not be the same key as another's, or bringing the
    /// second up would overwrite the first while it was carrying traffic — so
    /// every key also **carries the network**.
    ///
    /// The earlier version of this test asserted the key was the tag exactly,
    /// which satisfied the first and made the second impossible.
    #[test]
    fn a_key_is_recognisable_as_this_daemons_and_still_its_own() {
        let casa = Rule::for_network("casa", &state("casa.internal"), resolver()).expect("usable");
        let lavoro =
            Rule::for_network("lavoro", &state("lavoro.internal"), resolver()).expect("usable");

        for rule in [&casa, &lavoro] {
            assert!(
                rule.key_name().contains(limits::RULE_TAG),
                "a crash leaves this behind and a fresh daemon must know it is ours"
            );
        }
        assert_ne!(casa.key_name(), lavoro.key_name(), "and one must not overwrite the other");
    }

    /// The key follows the network, not the suffix: renaming a network's suffix
    /// must not orphan the rule that is already installed for it.
    #[test]
    fn the_key_follows_the_network_rather_than_the_suffix() {
        let one =
            Rule::for_network("casa", &state("example.internal"), resolver()).expect("usable");
        let two = Rule::for_network("casa", &state("other.internal"), resolver()).expect("usable");

        assert_eq!(one.key_name(), two.key_name());
    }
}

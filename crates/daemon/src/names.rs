//! What a name under the network's suffix resolves to.
//!
//! Two layers, and the split matters. [`answer`] is the decision: given the
//! roster's current state and a name, what is true? [`Resolver`] is the DNS wire
//! format around it. The first is where every rule lives and is testable with a
//! roster fixture and nothing else.
//!
//! # It reads the roster, and keeps nothing
//!
//! There is no name cache here, and that is deliberate rather than lazy. §2.5
//! makes the roster the authority on who is in the network; a cached name would
//! be a second authority that disagrees with it for exactly as long as its
//! lifetime, and the disagreement would be at its most dangerous right after a
//! revocation. Resolving from the current derived state means a removed device
//! stops resolving the moment the roster says so, with nothing to invalidate.
//!
//! # It forwards nothing, ever
//!
//! A name under the suffix that matches no device is answered as non-existent,
//! not passed to another resolver. On Windows the resolution rule scopes this to
//! the suffix, so a query outside it never arrives — unlike Android (§7.1), where
//! declaring a DNS server means receiving every query on the device. A forwarder
//! here would put the daemon in the path of resolution it was never asked about.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use roster::id::DeviceId;
use roster::state::RosterState;
use tunnel::{Ipv4Holdings, Prefix, address_of};

use crate::conflicts::Conflict;

/// Which IPv4 address each device of a network is answered with on this device.
///
/// The holdings the roster implies, less the peers withheld here. Read from the
/// node when a query arrives, like the roster itself: a device revoked, or a peer
/// withheld because this machine moved, stops being answered `A` at once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ipv4View {
    /// Which device holds which address in the network.
    pub holdings: Arc<Ipv4Holdings>,
    /// The peers withheld on this device, and why.
    pub withheld: Arc<BTreeMap<DeviceId, Conflict>>,
}

impl Ipv4View {
    /// The IPv4 address a device is answered with here, if any.
    #[must_use]
    pub fn answered(&self, device: &DeviceId) -> Option<Ipv4Addr> {
        self.holdings.of(device).filter(|_| !self.withheld.contains_key(device))
    }
}

/// What a name resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Answer {
    /// The device holding this name: its overlay IPv6 address, and its IPv4
    /// address when it holds one and is not withheld on this device.
    Device {
        /// Its IPv6 address, which every device has.
        v6: Ipv6Addr,
        /// Its IPv4 address, when it can be answered here.
        v4: Option<Ipv4Addr>,
    },

    /// A name under the suffix that no device holds.
    ///
    /// Answered as non-existent. Not forwarded, and not guessed at.
    NonExistent,

    /// More than one device holds this name.
    ///
    /// Answered as non-existent rather than by choosing one. The roster does not
    /// forbid two devices sharing a name, and picking either would send traffic
    /// to a machine on the strength of a coin toss.
    Ambiguous,

    /// A name outside the network's suffix.
    ///
    /// The resolution rule should mean this never arrives. It is a distinct
    /// answer rather than an error because if it ever does arrive, the useful
    /// response is to notice the rule is wrong.
    NotOurs,
}

impl Answer {
    /// The IPv6 address, when there is one.
    #[must_use]
    pub const fn address(&self) -> Option<Ipv6Addr> {
        match self {
            Self::Device { v6, .. } => Some(*v6),
            _ => None,
        }
    }

    /// The IPv4 address, when there is one to answer with.
    #[must_use]
    pub const fn ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Device { v4, .. } => *v4,
            _ => None,
        }
    }

    /// Whether this answer says the name does not exist.
    #[must_use]
    pub const fn is_non_existent(&self) -> bool {
        matches!(self, Self::NonExistent | Self::Ambiguous)
    }
}

/// Splits a queried name into its label and the suffix it claims.
///
/// Tolerates the trailing dot the wire format uses and differences of case,
/// because DNS does; tolerates nothing else.
fn under_suffix<'a>(query: &'a str, suffix: &str) -> Option<&'a str> {
    let trimmed = query.strip_suffix('.').unwrap_or(query);
    if trimmed.len() <= suffix.len() {
        return None;
    }
    let boundary = trimmed.len().checked_sub(suffix.len())?;
    let (head, tail) = trimmed.split_at_checked(boundary)?;
    if !tail.eq_ignore_ascii_case(suffix) {
        return None;
    }
    head.strip_suffix('.').filter(|label| !label.is_empty())
}

/// What the roster says a name resolves to, right now.
///
/// The suffix and the prefix both come from the signed network parameters. There
/// is no constant here for either, and `DESIGN.md` §0 forbids one for the suffix.
///
/// The IPv4 address comes from `ipv4`: the holdings the node enforced, less the
/// peers withheld on this device.
#[must_use]
pub fn answer(state: &RosterState, ipv4: &Ipv4View, query: &str) -> Answer {
    let Ok(prefix) = Prefix::from_parameter(&state.params.ula) else {
        // Unusable parameters mean the daemon should not be up at all. Refusing
        // to invent an address is the only safe reading.
        return Answer::NonExistent;
    };

    let Some(label) = under_suffix(query, &state.params.suffix) else {
        return Answer::NotOurs;
    };

    let mut found = None;
    for record in state.devices.values() {
        if record.name.eq_ignore_ascii_case(label) {
            if found.is_some() {
                return Answer::Ambiguous;
            }
            found = Some(record.id);
        }
    }

    found.map_or(Answer::NonExistent, |device| Answer::Device {
        v6: address_of(&device, &prefix),
        v4: ipv4.answered(&device),
    })
}

/// A suffix this device holds a network under, and whether that network is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held<K> {
    /// Whatever the caller uses to find the network again.
    pub key: K,
    /// The network's suffix, from its signed parameters.
    pub suffix: String,
    /// Whether the network is on.
    pub on: bool,
}

/// Where a query belongs, on a platform that sends every lookup to one resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Belongs<K> {
    /// Under the suffix of a network that is on: answered from its roster.
    Ours(K),
    /// Under the suffix of a network this device holds that is off.
    ///
    /// Answered as non-existent and never forwarded. Sending it upstream would
    /// hand a public resolver the name of a device in a private network.
    Private,
    /// Under no suffix this device holds: forwarded, unchanged.
    Elsewhere,
}

/// Decides where a query belongs.
///
/// Only a platform with no per-suffix resolution rule needs this; a desktop that
/// installs one never sees a query outside its suffix, and `windows-daemon` must
/// never call it. Kept here rather than in the edge because it is a decision:
/// which names are private is the roster's to say, not the socket's.
///
/// The longest matching suffix wins, so `lab.home.internal` held as its own
/// network is not answered by the `home.internal` network. Case and a trailing dot
/// are tolerated because DNS tolerates them. A query that is empty, or that is not
/// a sequence of non-empty labels, is `Elsewhere`: it names nothing of ours, and
/// judging it is not this resolver's business.
///
/// A held suffix outside the roster's grammar claims nothing. Every query on the
/// device arrives here, so a network whose suffix were `com` would have this
/// resolver answering for the public internet — and answering `NonExistent`,
/// since no device of that network holds those names. The roster refuses such
/// parameters at decoding; this is the second line, and it forwards the name
/// instead of answering it.
#[must_use]
pub fn route<K: Copy>(query: &str, held: &[Held<K>]) -> Belongs<K> {
    let name = query.strip_suffix('.').unwrap_or(query);
    if name.is_empty() || name.split('.').any(str::is_empty) {
        return Belongs::Elsewhere;
    }

    let mut best: Option<&Held<K>> = None;
    for network in held {
        let suffix = network.suffix.strip_suffix('.').unwrap_or(&network.suffix);
        if suffix.is_empty() || !is_within(name, suffix) {
            continue;
        }
        // Checked as held, not normalised: the grammar has one spelling, and a
        // suffix in another is one no roster under this rule could have carried.
        if roster::params::private_suffix(suffix).is_err() {
            continue;
        }
        if best.is_none_or(|current| suffix.len() > current.suffix.len()) {
            best = Some(network);
        }
    }

    match best {
        Some(network) if network.on => Belongs::Ours(network.key),
        Some(_) => Belongs::Private,
        None => Belongs::Elsewhere,
    }
}

/// Whether `name` is `suffix` or sits under it, label by label.
fn is_within(name: &str, suffix: &str) -> bool {
    if name.len() < suffix.len() {
        return false;
    }
    let Some(boundary) = name.len().checked_sub(suffix.len()) else { return false };
    let Some((head, tail)) = name.split_at_checked(boundary) else { return false };
    tail.eq_ignore_ascii_case(suffix) && (head.is_empty() || head.ends_with('.'))
}

/// The names this network currently serves, for display.
///
/// Not used to resolve anything — [`answer`] reads the roster each time — but a
/// person asking what exists deserves a list.
#[must_use]
/// **Only its own tests call this.** It was public while every module in this
/// crate was, so nothing said so; narrowing the surface is what made it visible.
/// Kept rather than removed because it is the readable form of what `answer`
/// does one name at a time, and the tests below are about that correspondence.
#[cfg(test)]
pub(crate) fn names(state: &RosterState) -> Vec<(String, Ipv6Addr)> {
    let Ok(prefix) = Prefix::from_parameter(&state.params.ula) else {
        return Vec::new();
    };
    state
        .devices
        .values()
        .map(|record| {
            (format!("{}.{}", record.name, state.params.suffix), address_of(&record.id, &prefix))
        })
        .collect()
}

#[cfg(test)]
mod routing {
    use super::{Belongs, Held, route};

    fn held() -> Vec<Held<&'static str>> {
        vec![
            Held { key: "casa", suffix: "home.internal".to_owned(), on: true },
            Held { key: "lab", suffix: "lab.home.internal".to_owned(), on: true },
            Held { key: "lavoro", suffix: "work.internal".to_owned(), on: false },
        ]
    }

    #[test]
    fn a_name_under_an_on_network_is_ours() {
        assert_eq!(route("nas.home.internal", &held()), Belongs::Ours("casa"));
        assert_eq!(route("home.internal", &held()), Belongs::Ours("casa"), "the suffix itself");
    }

    #[test]
    fn the_longer_suffix_wins() {
        assert_eq!(route("scope.lab.home.internal", &held()), Belongs::Ours("lab"));
    }

    #[test]
    fn an_off_network_is_private_and_never_elsewhere() {
        assert_eq!(route("laptop.work.internal", &held()), Belongs::Private);
    }

    #[test]
    fn case_and_a_trailing_dot_are_tolerated() {
        assert_eq!(route("NAS.Home.Internal.", &held()), Belongs::Ours("casa"));
    }

    #[test]
    fn a_lookalike_suffix_is_not_ours() {
        assert_eq!(route("nas.myhome.internal", &held()), Belongs::Elsewhere);
        assert_eq!(route("home.internal.example.com", &held()), Belongs::Elsewhere);
    }

    #[test]
    fn anything_else_goes_elsewhere() {
        for name in ["example.com", "", ".", "a..home.internal", "..", "internal"] {
            assert_eq!(route(name, &held()), Belongs::Elsewhere, "{name:?}");
        }
    }

    /// Every query on the device arrives here. A network holding a suffix
    /// outside the grammar claims nothing, so the name is forwarded rather than
    /// answered from a roster that cannot know it — otherwise a network whose
    /// suffix were `azienda.it` or `com` would take that branch of the public
    /// DNS away from the phone.
    #[test]
    fn a_held_suffix_outside_the_grammar_claims_nothing() {
        let claimed =
            |suffix: &str| vec![Held { key: "theirs", suffix: suffix.to_owned(), on: true }];

        assert_eq!(route("www.azienda.it", &claimed("azienda.it")), Belongs::Elsewhere);
        assert_eq!(route("www.google.com", &claimed("com")), Belongs::Elsewhere);
        assert_eq!(route("host.docker.internal", &claimed("docker.internal")), Belongs::Elsewhere);
        assert_eq!(route("anything.internal", &claimed("internal")), Belongs::Elsewhere);

        // And a network whose suffix is within the grammar still answers.
        assert_eq!(route("nas.casa.internal", &claimed("casa.internal")), Belongs::Ours("theirs"));
    }

    /// A network held with a suffix outside the grammar does not even shadow a
    /// well-formed one beneath it: the longest match is only among suffixes that
    /// claim anything at all.
    #[test]
    fn a_suffix_outside_the_grammar_does_not_shadow_one_within_it() {
        let held = vec![
            Held { key: "theirs", suffix: "internal".to_owned(), on: true },
            Held { key: "ours", suffix: "casa.internal".to_owned(), on: true },
        ];
        assert_eq!(route("nas.casa.internal", &held), Belongs::Ours("ours"));
        assert_eq!(route("nas.altro.internal", &held), Belongs::Elsewhere);
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use std::collections::BTreeSet;

    use roster::id::{DeviceId, NetworkId, OperationId};
    use roster::types::{DeviceRecord, NetworkParams, Role};

    use super::*;

    fn record(tag: u8, name: &str) -> DeviceRecord {
        DeviceRecord {
            id: DeviceId::from_bytes([tag; 32]),
            keys: Vec::new(),
            name: name.to_owned(),
            role: Role::Member,
            founder: false,
            added_by: OperationId::from_bytes([0; 32]),
            capabilities: Vec::new(),
        }
    }

    fn state(devices: Vec<DeviceRecord>) -> RosterState {
        state_with_suffix(devices, "example.internal")
    }

    fn state_with_suffix(devices: Vec<DeviceRecord>, suffix: &str) -> RosterState {
        RosterState {
            network: NetworkId::from_bytes([1; 32]),
            params: NetworkParams::new(
                vec![0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                suffix,
                2_592_000,
            )
            .expect("valid"),
            devices: devices.into_iter().map(|record| (record.id, record)).collect(),
            revoked: BTreeSet::new(),
        }
    }

    #[test]
    fn a_name_resolves_to_the_devices_overlay_address() {
        let state = state(vec![record(1, "nas")]);
        let prefix = Prefix::from_parameter(&state.params.ula).expect("valid");

        assert_eq!(
            answer(&state, &Ipv4View::default(), "nas.example.internal"),
            Answer::Device { v6: address_of(&DeviceId::from_bytes([1; 32]), &prefix), v4: None },
            "the address tunnel derives, not one this crate invents"
        );
    }

    #[test]
    fn resolution_tolerates_the_wire_forms_dot_and_case() {
        let state = state(vec![record(1, "nas")]);
        let expected = answer(&state, &Ipv4View::default(), "nas.example.internal");

        for query in ["nas.example.internal.", "NAS.Example.Internal", "Nas.EXAMPLE.internal."] {
            assert_eq!(answer(&state, &Ipv4View::default(), query), expected, "{query}");
        }
    }

    /// The scenario: a name under the suffix that no device holds is answered as
    /// non-existent, and does not escape to another resolver.
    #[test]
    fn an_unknown_name_under_the_suffix_does_not_exist() {
        let state = state(vec![record(1, "nas")]);
        assert_eq!(
            answer(&state, &Ipv4View::default(), "printer.example.internal"),
            Answer::NonExistent
        );
    }

    #[test]
    fn a_name_outside_the_suffix_is_not_ours() {
        let state = state(vec![record(1, "nas")]);
        for query in ["example.com", "nas.example.internal.evil.com", "internal", ""] {
            assert_eq!(answer(&state, &Ipv4View::default(), query), Answer::NotOurs, "{query}");
        }
    }

    /// A suffix on its own is not a name, and an empty label is not a name.
    #[test]
    fn the_bare_suffix_resolves_to_nothing() {
        let state = state(vec![record(1, "nas")]);
        assert_eq!(answer(&state, &Ipv4View::default(), "example.internal"), Answer::NotOurs);
        assert_eq!(answer(&state, &Ipv4View::default(), ".example.internal"), Answer::NotOurs);
    }

    /// A device removed from the roster stops resolving, with no cache to
    /// invalidate — the property that makes a revocation take effect.
    #[test]
    fn a_removed_device_stops_resolving() {
        let mut state = state(vec![record(1, "nas"), record(2, "printer")]);
        assert!(answer(&state, &Ipv4View::default(), "nas.example.internal").address().is_some());

        state.devices.remove(&DeviceId::from_bytes([1; 32]));
        state.revoked.insert(DeviceId::from_bytes([1; 32]));

        assert_eq!(
            answer(&state, &Ipv4View::default(), "nas.example.internal"),
            Answer::NonExistent
        );
        assert!(
            answer(&state, &Ipv4View::default(), "printer.example.internal").address().is_some(),
            "others unaffected"
        );
    }

    /// Two devices, one name. Choosing either would send traffic to a machine on
    /// the strength of a coin toss.
    #[test]
    fn a_name_two_devices_hold_resolves_to_neither() {
        let state = state(vec![record(1, "nas"), record(2, "nas")]);
        assert_eq!(answer(&state, &Ipv4View::default(), "nas.example.internal"), Answer::Ambiguous);
        assert!(answer(&state, &Ipv4View::default(), "nas.example.internal").is_non_existent());
    }

    /// The suffix comes from the signed parameters. `DESIGN.md` §0 forbids a
    /// constant, and this is what enforces it.
    #[test]
    fn the_suffix_follows_the_signed_parameters() {
        let ours = state_with_suffix(vec![record(1, "nas")], "example.internal");
        let theirs = state_with_suffix(vec![record(1, "nas")], "other.internal");

        assert!(answer(&ours, &Ipv4View::default(), "nas.example.internal").address().is_some());
        assert_eq!(answer(&ours, &Ipv4View::default(), "nas.other.internal"), Answer::NotOurs);

        assert!(answer(&theirs, &Ipv4View::default(), "nas.other.internal").address().is_some());
        assert_eq!(answer(&theirs, &Ipv4View::default(), "nas.example.internal"), Answer::NotOurs);
    }

    #[test]
    fn the_address_follows_the_signed_prefix() {
        let mut state = state(vec![record(1, "nas")]);
        let before = answer(&state, &Ipv4View::default(), "nas.example.internal");

        state.params = NetworkParams::new(
            vec![0xfd, 0x11, 0x22, 0x33, 0x00, 0x00, 0x00, 0x00],
            "example.internal",
            2_592_000,
        )
        .expect("valid");
        let after = answer(&state, &Ipv4View::default(), "nas.example.internal");

        assert_ne!(before, after, "a different prefix is a different address");
    }

    fn view(state: &RosterState, withheld: &[u8]) -> Ipv4View {
        Ipv4View {
            holdings: Arc::new(Ipv4Holdings::of_state(state)),
            withheld: Arc::new(
                withheld
                    .iter()
                    .map(|tag| (DeviceId::from_bytes([*tag; 32]), Conflict::LocalAddress))
                    .collect(),
            ),
        }
    }

    /// Both addresses for a device that holds IPv4 and is not withheld.
    #[test]
    fn a_name_resolves_to_both_addresses_of_a_device_holding_ipv4() {
        let state = state(vec![record(1, "nas")]);
        let view = view(&state, &[]);
        let expected = view.holdings.of(&DeviceId::from_bytes([1; 32]));
        assert!(expected.is_some());

        let answered = answer(&state, &view, "nas.example.internal");
        assert_eq!(answered.ipv4(), expected);
        assert!(answered.address().is_some(), "and IPv6 as ever");
    }

    /// A withheld peer is answered over IPv6 alone.
    #[test]
    fn a_withheld_device_resolves_over_ipv6_alone() {
        let state = state(vec![record(1, "nas")]);
        let answered = answer(&state, &view(&state, &[1]), "nas.example.internal");
        assert_eq!(answered.ipv4(), None);
        assert!(answered.address().is_some());
    }

    #[test]
    fn an_empty_network_resolves_nothing() {
        let state = state(Vec::new());
        assert_eq!(
            answer(&state, &Ipv4View::default(), "nas.example.internal"),
            Answer::NonExistent
        );
        assert!(names(&state).is_empty());
    }

    #[test]
    fn the_listing_agrees_with_resolution() {
        let state = state(vec![record(1, "nas"), record(2, "printer")]);
        for (name, address) in names(&state) {
            assert_eq!(
                answer(&state, &Ipv4View::default(), &name),
                Answer::Device { v6: address, v4: None },
                "{name}"
            );
        }
    }

    /// Nothing here forwards, under any condition. A forwarder would put the
    /// daemon in the path of resolution nobody asked it about.
    #[test]
    fn nothing_here_forwards() {
        let code = crate::code_of(include_str!("names.rs"));

        for forbidden in ["forward", "upstream", "fallback_resolver"] {
            assert!(!code.contains(forbidden), "`{forbidden}` would make this a forwarder");
        }
    }
}

//! Creating a network, as an operation a person performs.
//!
//! Founding used to live inside `peerfectly-seed`, a fixture that was never meant to
//! ship. §3.1 has a phone doing this, and one day it will; until then the
//! machine that runs the daemon is where a network begins, and beginning one is
//! not a thing to do with a test tool.
//!
//! # It refuses rather than replaces
//!
//! A machine that already holds a network is not founded again. There is no flag
//! to force it, because the two outcomes of getting that wrong are losing a
//! network and silently running two, and neither is worth the convenience of not
//! having to delete a file on purpose.

use identity::NodeIdentity;
use roster::id::NetworkId;
use roster::types::{NetworkParams, OperationBody, OperationCore, Role};

use crate::state::{Log, Paths};

/// Why a network could not be founded.
///
/// A message rather than a variant, for the reason [`crate::relay::Refusal`] is:
/// each ends the command, and the person needs the sentence.
pub type Refusal = String;

/// What a person supplies to create a network.
#[derive(Debug, Clone)]
pub struct Founding {
    /// The name this device takes in its own network.
    pub name: String,
    /// The DNS suffix every name in the network sits under.
    pub suffix: String,
    /// The relay, if the network has one, as it will be signed: `key@host:port`.
    pub relay: Option<String>,
    /// The IPv4 range the network's devices derive their addresses in, if one
    /// other than the default was chosen.
    pub ipv4_range: Option<roster::types::Ipv4Range>,
    /// The freshness window, in seconds, or `None` for none — the default.
    pub window: Option<u64>,
}

/// Reads the IPv4 range a person asked a founding for.
///
/// The default range, asked for by name, is read as no choice at all: the
/// parameters then encode exactly as a network founded without one, and software
/// predating the range can still read the network. Writing the default would
/// change nothing about any address and exclude those devices for nothing.
///
/// # Errors
///
/// When the text is not an allowed range, in the roster's words.
pub fn ipv4_range(text: Option<&str>) -> Result<Option<roster::types::Ipv4Range>, Refusal> {
    let Some(text) = text.map(str::trim).filter(|text| !text.is_empty()) else {
        return Ok(None);
    };
    let range: roster::types::Ipv4Range = text.parse().map_err(|cause: roster::Error| {
        format!(
            "`{text}` cannot be this network's IPv4 range ({cause}). A range is written \
             a.b.c.d/len, with a length from 10 to 28, inside 10.0.0.0/8, 172.16.0.0/12, \
             192.168.0.0/16, 100.64.0.0/10 or 198.18.0.0/15. Nothing was signed."
        )
    })?;
    Ok((range != roster::types::Ipv4Range::DEFAULT).then_some(range))
}

/// How many devices a network is founded for when its founder says nothing: a
/// `/16`, 65,534 hosts, four times that.
pub const DEFAULT_EXPECTED: u32 = 16_000;

/// How many times its expected size a proposed block holds, so a network that
/// grows past what its founder foresaw is not moved at once.
const ROOM_TO_GROW: u64 = 4;

/// The blocks a network's block is proposed from, in the order they are tried.
///
/// The shared address space first, which home and office networks rarely use;
/// then the private blocks; then the benchmarking block; `192.168.0.0/16`,
/// which nearly every home's router hands out from, only when nothing else is
/// free.
const POOLS: [([u8; 4], u8); 5] = [
    ([100, 64, 0, 0], 10),
    ([10, 0, 0, 0], 8),
    ([172, 16, 0, 0], 12),
    ([198, 18, 0, 0], 15),
    ([192, 168, 0, 0], 16),
];

/// A block of addresses a proposed block must not overlap: another network's
/// block, or a subnet this machine is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Taken {
    /// Any address inside it.
    pub address: std::net::Ipv4Addr,
    /// Its prefix length.
    pub prefix_len: u8,
}

impl Taken {
    /// Whether it and `block` share an address.
    #[must_use]
    pub fn overlaps_block(&self, block: &roster::types::Ipv4Range) -> bool {
        self.overlaps(u32::from_be_bytes(block.address()), block.prefix_len())
    }

    /// Whether it and the block at `base` of `prefix_len` share an address.
    fn overlaps(&self, base: u32, prefix_len: u8) -> bool {
        let shorter = self.prefix_len.min(prefix_len).min(32);
        let mask = u32::MAX.checked_shl(32_u32.saturating_sub(u32::from(shorter))).unwrap_or(0);
        u32::from(self.address) & mask == base & mask
    }
}

/// The prefix length of the smallest block that holds `expected` devices with
/// room to grow; the widest allowed, `/10`, for more than it holds that way.
#[must_use]
pub fn prefix_for(expected: u32) -> u8 {
    prefix_for_hosts(u64::from(expected.max(1)).saturating_mul(ROOM_TO_GROW))
}

/// The prefix length of the smallest block with at least `hosts` hosts; the
/// widest allowed, `/10`, where none is that wide.
#[must_use]
pub fn prefix_for_hosts(hosts: u64) -> u8 {
    (roster::types::Ipv4Range::MIN_PREFIX_LEN..=roster::types::Ipv4Range::MAX_PREFIX_LEN)
        .rev()
        .find(|prefix_len| span(32_u8.saturating_sub(*prefix_len)).saturating_sub(2) >= hosts)
        .unwrap_or(roster::types::Ipv4Range::MIN_PREFIX_LEN)
}

/// Two to the power `bits`, for the bit counts an IPv4 prefix leaves.
fn span(bits: u8) -> u64 {
    1_u64.checked_shl(u32::from(bits)).unwrap_or(u64::MAX)
}

/// A block for a network of `expected` devices that overlaps nothing `taken`
/// names, drawn at random among the free blocks of the first pool that has one
/// (`scalable-membership` 19.3).
///
/// At random, because two founders who never met would otherwise both take the
/// first free block, and a person in both networks would have them in conflict.
/// `draw(count)` answers an index below `count`.
///
/// # Errors
///
/// When no pool has a free block that size.
pub fn propose_block(
    expected: u32,
    taken: &[Taken],
    draw: &mut dyn FnMut(u64) -> u64,
) -> Result<roster::types::Ipv4Range, Refusal> {
    let prefix_len = prefix_for(expected);
    let step = span(32_u8.saturating_sub(prefix_len));
    for (pool, pool_len) in POOLS {
        if pool_len > prefix_len {
            continue;
        }
        let count = span(prefix_len.saturating_sub(pool_len));
        let first = u64::from(u32::from_be_bytes(pool));
        // From a random start, the first free one after it: as random as a
        // draw among the free ones wherever few are taken, and certain to end.
        let start = draw(count).checked_rem(count).unwrap_or(0);
        for index in (0..count).map(|at| start.saturating_add(at).checked_rem(count).unwrap_or(0)) {
            let Ok(base) = u32::try_from(first.saturating_add(index.saturating_mul(step))) else {
                continue;
            };
            if taken.iter().any(|taken| taken.overlaps(base, prefix_len)) {
                continue;
            }
            if let Ok(block) = roster::types::Ipv4Range::new(base.to_be_bytes(), prefix_len) {
                return Ok(block);
            }
        }
    }
    Err(format!(
        "no block of /{prefix_len} is free of this device's other networks and the subnets it is \
         on. Name one with --ipv4-range, or expect fewer devices. Nothing was signed."
    ))
}

/// The suffix a founding proposes when a person supplies none.
///
/// Composed from the network's own name, so that two networks founded on one
/// machine do not both land on a default and claim the same namespace. That was
/// not a risk while a device held one network and is the ordinary case now.
///
/// A **proposal**, never a rule. §2.5 makes the suffix a signed network
/// parameter and `DESIGN.md` §0 forbids it as a compile-time constant, so a suffix
/// a person supplies is taken exactly as given and checked as given. What is
/// constant here is only what to suggest when nobody said.
///
/// The label is normalised into the roster's grammar — lower case, underscores
/// to hyphens, leading and trailing hyphens trimmed — so that a label a person
/// already uses, `Casa_Mia`, still founds a network as `casa-mia.internal`.
///
/// `None` when what is left is not a name a network may claim: a label of
/// nothing but underscores, one carrying characters the grammar has no place
/// for, or one that lands on a reserved name. Founding then asks for an explicit
/// `--suffix` rather than inventing one.
#[must_use]
pub fn suffix_under(label: &str) -> Option<String> {
    let composed: String = label
        .to_ascii_lowercase()
        .chars()
        .map(|letter| if letter == '_' { '-' } else { letter })
        .collect();
    let suffix = format!("{}.{}", composed.trim_matches('-'), roster::params::PRIVATE_PARENT);
    roster::params::private_suffix(&suffix).is_ok().then_some(suffix)
}

/// Creates a network on this machine.
///
/// The founding device is an admin and a founder, because somebody has to be and
/// there is nobody else yet.
///
/// # Errors
///
/// When this machine already holds a network, when the parameters are outside
/// what the roster allows, or when the identity or the log cannot be written.
pub fn found(paths: &Paths, wanted: &Founding) -> Result<NetworkId, Refusal> {
    found_with(paths, wanted, &crate::keys::PlatformKeys)
}

/// Founds a network with keys from `keys`.
///
/// # Errors
///
/// As [`found`], and when the keys decline to sign.
pub fn found_with(
    paths: &Paths,
    wanted: &Founding,
    keys: &dyn crate::keys::Keys,
) -> Result<NetworkId, Refusal> {
    let (identity, genesis) = genesis(paths, wanted, keys)?;
    let bytes =
        identity.sign_operation(&genesis).map_err(|cause| crate::control::declined(&cause))?;
    // A key that can be used here signs the snapshot inside `adopt`, so nothing
    // comes back to be asked for.
    adopt(paths, &genesis, &bytes, &identity).map(|(network, _asked)| network)
}

/// Prepares a network's first operation, up to but not including its signature.
///
/// Everything that can refuse a founding happens here — the directory, a network
/// already held, the parameters, the name — so a device that has to ask somebody
/// for a signature asks only once it is certain there is something to sign.
///
/// # Errors
///
/// As [`found`], short of signing.
pub fn genesis(
    paths: &Paths,
    wanted: &Founding,
    keys: &dyn crate::keys::Keys,
) -> Result<(NodeIdentity, OperationCore), Refusal> {
    paths.create().map_err(|cause| cause.to_string())?;

    let log = Log::at(paths.roster());
    if !log.read().map_err(|cause| cause.to_string())?.is_empty() {
        return Err(format!(
            "this machine already holds a network. Founding again would abandon it, so it is \
             refused.\nTo start over deliberately, remove {} first.",
            paths.roster().display()
        ));
    }

    let identity = keys.identity(paths).map_err(|cause| cause.to_string())?;
    let params = parameters(&identity, wanted)?;

    let spec = identity
        .device_spec(&wanted.name, Role::Admin, true, vec![])
        .map_err(|cause| cause.to_string())?;

    let genesis = OperationCore::new(
        // The minute it was founded, on this device's clock. Shown, never used to
        // decide anything; see `clock`.
        crate::clock::signing_time(),
        identity.signing_key().algorithm(),
        OperationBody::CreateNetwork { device: spec, params },
        vec![],
        identity.signing_key().key_id(),
        // The founding operation names no network, because it is what creates
        // one: the network's identifier is this operation's own id.
        NetworkId::from_bytes([0; 32]),
    )
    .map_err(|cause| cause.to_string())?;

    Ok((identity, genesis))
}

/// Puts a signed genesis in the log, after which the network exists.
///
/// The signature may have been made here or somewhere this process cannot reach;
/// by the time these bytes exist that difference is over.
///
/// # Errors
///
/// When the log cannot be written.
pub fn adopt(
    paths: &Paths,
    genesis: &OperationCore,
    bytes: &[u8],
    identity: &NodeIdentity,
) -> Result<(NetworkId, Option<identity::detached::SigningRequest>), Refusal> {
    Log::at(paths.roster()).append(bytes).map_err(|cause| cause.to_string())?;

    let wanted = first_snapshot(paths, bytes, identity);

    Ok((NetworkId::from_bytes(*genesis.id().as_bytes()), wanted))
}

/// Signs the network's first snapshot and keeps it beside the log.
///
/// A network with no snapshot has nothing for freshness to be measured from, so
/// its founder would begin unable to confirm the roster it had just created —
/// and "no snapshot has ever been accepted" would be the ordinary state of a
/// healthy network rather than a sign that something is wrong.
///
/// **A failure here does not fail the founding.** The genesis is signed and in
/// the log by now: the network exists, and reporting that it did not would leave
/// a person with a network the daemon disowns. A person declining the second
/// lock prompt is the likely case, and an admin's daemon signs one again as a
/// matter of course. So this is attempted, and what it did is left in the log for
/// somebody reading it afterwards.
fn first_snapshot(
    paths: &Paths,
    genesis: &[u8],
    identity: &NodeIdentity,
) -> Option<identity::detached::SigningRequest> {
    let mut roster = roster::roster::Roster::with_clock(Box::new(crate::state::WallClock));
    if !roster.offer_bytes(genesis).is_accepted() {
        return None;
    }

    // The attestation first, and not because it matters more.
    //
    // It used to be second, after the snapshot, and each `return` on the way to
    // it took the attestation with it. That cost nothing while the only way to
    // fail was a person declining a lock prompt — they had just declined, and
    // were there to be told. It stops being free when a signing key can be
    // somewhere this process cannot reach: then the snapshot *always* stops
    // here, and an attestation that asks nobody would have been skipped every
    // single time, on every network founded on such a device.
    //
    // Without one, *"no attestation has ever been accepted"* would be the
    // ordinary state of a healthy network founded a minute ago, and it could not
    // mean anything. So it goes first, where nothing above it can take it away.
    if let Ok(dated) = crate::attesting::sign_over_heads(&roster, identity)
        && roster.offer_attestation(&dated).is_accepted()
    {
        let _dated = crate::state::write_attestation(paths, &dated, crate::state::wall_seconds());
    }

    // The first root is signed with the attestation key, which asks nobody, so
    // a founding never asks twice whatever holds the signing key.
    let bytes = crate::snapshots::sign_over_heads(&roster, identity).ok()?;
    // Offered to a roster of its own before it is kept, so that what is written
    // is a snapshot this build can verify rather than one it merely produced.
    if roster.offer_snapshot(&bytes).is_accepted() {
        let _kept = crate::state::write_snapshot(paths, &bytes, crate::state::wall_seconds());
    }
    None
}

/// The parameters a founding carries, checked by the roster's own rules.
fn parameters(identity: &NodeIdentity, wanted: &Founding) -> Result<NetworkParams, Refusal> {
    // The roster refuses a suffix outside its grammar a moment later, but its
    // refusal cannot carry the value. Checked here so that a person who typed
    // `--suffix azienda.it` is told what they typed and what is allowed, and
    // told it before anything is signed.
    if let Some(refusal) = crate::rule::unusable_suffix(wanted.suffix.trim().trim_matches('.')) {
        return Err(format!("{refusal} Nothing was signed."));
    }

    let params = NetworkParams::with_relay(
        derived_prefix(identity),
        wanted.relay.clone(),
        wanted.suffix.clone(),
        // None unless asked for: an island with an admin of its own keeps
        // working for as long as it is cut off. Zero is how none is written.
        wanted.window.unwrap_or(0),
    )
    .map_err(|cause| cause.to_string())?;

    Ok(match wanted.ipv4_range {
        Some(range) => params.in_ipv4_range(range),
        None => params,
    })
}

/// The network's ULA prefix, derived from the founding device.
///
/// Derived rather than chosen so two runs on one machine agree and two machines
/// do not collide. `fd00::/8` is the unique-local block, and the seven bytes
/// after it are the global id RFC 4193 says to pick at random — here, from this
/// device's own identity, which is random enough and reproducible.
fn derived_prefix(identity: &NodeIdentity) -> Vec<u8> {
    let derived = blake3::derive_key("peerfectly founding ula v1", identity.device_id().as_bytes());
    let mut prefix = vec![0xfd_u8];
    prefix.extend(derived.iter().take(7).copied());
    prefix
}

#[cfg(test)]
mod suffixes {
    #![allow(clippy::unwrap_used, reason = "a test reports failure by panicking")]

    use super::suffix_under;

    /// Two networks founded on one machine used to land on the same default and
    /// claim the same namespace. The network's own name is what separates them.
    #[test]
    fn two_networks_propose_different_suffixes() {
        assert_ne!(suffix_under("casa"), suffix_under("lavoro"));
        assert_eq!(suffix_under("casa"), Some("casa.internal".to_owned()));
    }

    /// The composed default sits under `.internal`, which is reserved for
    /// exactly this and belongs to nobody.
    #[test]
    fn the_default_sits_under_internal() {
        assert!(suffix_under("casa").expect("valid").ends_with(".internal"));
    }

    /// A label a person may already be using is brought into the grammar rather
    /// than refused: the network is theirs, and the shape is ours.
    #[test]
    fn a_label_is_normalised_into_the_grammar() {
        assert_eq!(suffix_under("Casa_Mia"), Some("casa-mia.internal".to_owned()));
        assert_eq!(suffix_under("LAVORO"), Some("lavoro.internal".to_owned()));
        assert_eq!(suffix_under("_casa_"), Some("casa.internal".to_owned()));
        assert_eq!(suffix_under("rete-2"), Some("rete-2.internal".to_owned()));
    }

    /// What normalising cannot fix, founding does not invent a name for: it asks
    /// for an explicit `--suffix` instead.
    #[test]
    fn a_label_that_cannot_be_normalised_proposes_nothing() {
        for label in ["___", "", "-", "città", "casa mia", "docker", "ec2"] {
            assert_eq!(suffix_under(label), None, "{label}");
        }
    }
}

#[cfg(test)]
mod blocks {
    #![allow(clippy::unwrap_used, reason = "a test reports failure by panicking")]

    use super::{DEFAULT_EXPECTED, Taken, prefix_for, propose_block};

    fn taken(text: &str) -> Taken {
        let (address, prefix_len) = text.split_once('/').unwrap();
        Taken { address: address.parse().unwrap(), prefix_len: prefix_len.parse().unwrap() }
    }

    /// Room for four times the devices expected, and never wider than `/10`.
    #[test]
    fn a_block_holds_four_times_what_is_expected() {
        assert_eq!(prefix_for(DEFAULT_EXPECTED), 16);
        assert_eq!(prefix_for(3), 28, "fourteen hosts hold twelve");
        assert_eq!(prefix_for(4), 27);
        assert_eq!(prefix_for(1_000_000), 10);
        assert_eq!(prefix_for(u32::MAX), 10, "the widest there is");
    }

    /// Drawn in the shared space, and where the draw falls.
    #[test]
    fn a_block_is_drawn_from_the_shared_space() {
        let block = propose_block(DEFAULT_EXPECTED, &[], &mut |_| 19).unwrap();
        assert_eq!(block.to_string(), "100.83.0.0/16");
        let other = propose_block(DEFAULT_EXPECTED, &[], &mut |_| 7).unwrap();
        assert_ne!(block, other, "two founders drawing differently land apart");
    }

    /// Another network's block and this machine's subnets are stepped over.
    #[test]
    fn a_block_overlaps_nothing_taken() {
        let block = propose_block(
            DEFAULT_EXPECTED,
            &[taken("100.83.0.0/16"), taken("100.84.7.9/24")],
            &mut |_| 19,
        )
        .unwrap();
        assert_eq!(block.to_string(), "100.85.0.0/16", "the first free one after the draw");
    }

    /// With the shared space taken whole — a phone on mobile data behind a
    /// carrier's NAT — the next pool is tried.
    #[test]
    fn a_taken_pool_moves_to_the_next() {
        let block = propose_block(DEFAULT_EXPECTED, &[taken("100.64.0.0/10")], &mut |_| 0).unwrap();
        assert_eq!(block.to_string(), "10.0.0.0/16");
    }

    /// Nothing free anywhere is said, with what to do about it.
    #[test]
    fn nothing_free_is_refused_in_words() {
        let everything = [taken("0.0.0.0/1"), taken("128.0.0.0/1")];
        let refused = propose_block(DEFAULT_EXPECTED, &everything, &mut |_| 0).unwrap_err();
        assert!(refused.contains("--ipv4-range"), "{refused}");
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use roster::roster::Roster;

    use super::*;

    fn wanted() -> Founding {
        Founding {
            name: "nas".to_owned(),
            suffix: "peerfectly.internal".to_owned(),
            relay: Some("https://relay.example:443".to_owned()),
            ipv4_range: None,
            window: None,
        }
    }

    fn state_at(paths: &Paths) -> roster::state::RosterState {
        let held = Log::at(paths.roster()).read().expect("reads");
        let mut roster = Roster::new();
        for operation in &held {
            assert!(roster.offer_bytes(operation).is_accepted(), "the log must load");
        }
        roster.state().expect("derives")
    }

    #[test]
    fn founding_produces_a_network_naming_this_device_as_an_admin() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());

        found(&paths, &wanted()).expect("founds");

        let state = state_at(&paths);
        assert_eq!(state.devices.len(), 1);
        let record = state.devices.values().next().expect("one device");
        assert_eq!(record.name, "nas");
        assert_eq!(record.role, Role::Admin);
        assert!(record.founder, "somebody has to be, and there is nobody else");
        assert_eq!(state.params.suffix, "peerfectly.internal");
        assert_eq!(state.params.relay.as_deref(), Some("https://relay.example:443"));
    }

    /// A founding that asks for nothing sets no window: an island with an admin
    /// of its own keeps working for as long as it is cut off.
    #[test]
    fn a_default_founding_sets_no_window() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());
        found(&paths, &wanted()).expect("founds");
        assert_eq!(state_at(&paths).params.snapshot_window, 0);
    }

    /// A network with no snapshot has nothing for freshness to measure from, so
    /// its own founder would begin unable to confirm the roster it just made.
    #[test]
    fn a_founded_network_has_a_snapshot_and_an_attestation_and_is_fresh() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());

        // A network that asked for a window: one with none is never stale.
        let windowed =
            Founding { window: Some(roster::limits::DEFAULT_SNAPSHOT_WINDOW), ..wanted() };
        found(&paths, &windowed).expect("founds");

        let (bytes, at) = crate::state::read_snapshot(&paths).expect("a snapshot was kept");
        assert!(at > 0, "dated on this device's wall clock, not left at the epoch");

        // What a restart would build: the log replayed, and what was kept restored.
        let mut roster = Roster::with_clock(Box::new(crate::state::WallClock));
        for operation in &Log::at(paths.roster()).read().expect("reads") {
            assert!(roster.offer_bytes(operation).is_accepted());
        }
        assert!(roster.restore_snapshot(&bytes, at).is_accepted(), "and it verifies");
        assert_eq!(
            roster::roster::Freshness::Unknown,
            roster.freshness(),
            "a snapshot dates nothing, whoever signed it and however recently"
        );

        // The attestation is what dates it, and the founding produces one for
        // the same reason it produces the snapshot: otherwise "never attested"
        // would be the ordinary state of a healthy network a minute old.
        let (dated, at) = crate::state::read_attestation(&paths).expect("an attestation was kept");
        assert!(at > 0, "dated on this device's wall clock, not left at the epoch");
        assert!(roster.restore_attestation(&dated, at).is_accepted(), "and it verifies");
        assert_eq!(
            roster::roster::Freshness::Fresh,
            roster.freshness(),
            "a network is not born unable to confirm itself"
        );
    }

    /// Nothing is signed when the founding is refused, snapshot included.
    #[test]
    fn a_refused_founding_leaves_no_snapshot() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());

        let refused = Founding { suffix: "azienda.it".to_owned(), ..wanted() };
        assert!(found(&paths, &refused).is_err(), "a public suffix is refused");

        assert!(crate::state::read_snapshot(&paths).is_none(), "and nothing was kept");
    }

    /// A suffix a person supplies is checked as given. `azienda.it` would send    /// A suffix a person supplies is checked as given. `azienda.it` would send
    /// that whole branch of the public DNS to this network's resolver on every
    /// machine that joins, so founding stops before anything is signed and says
    /// what was typed and what is allowed.
    #[test]
    fn founding_under_a_public_name_is_refused_before_anything_is_signed() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());

        for suffix in ["azienda.it", "com", "internal", "docker.internal", "Casa.internal"] {
            let refusal = found(&paths, &Founding { suffix: suffix.to_owned(), ..wanted() })
                .expect_err("a suffix outside the grammar founds nothing");

            assert!(refusal.contains(suffix), "the refusal names the suffix: {refusal}");
            assert!(refusal.contains(".internal"), "and the namespace allowed: {refusal}");
            assert!(refusal.contains("Nothing was signed"), "{refusal}");
            assert!(
                Log::at(paths.roster()).read().expect("readable").is_empty(),
                "`{suffix}` must leave no network behind"
            );
        }
    }

    /// A founding carries the minute it happened, not a counter that renders as
    /// January 1970.
    #[test]
    fn a_founding_carries_the_minute_it_was_signed() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());
        found(&paths, &wanted()).expect("founds");

        let log = Log::at(paths.roster()).read().expect("readable");
        let genesis = log.first().expect("the founding is written");
        let ts = roster::sign::RawOperation::decode(genesis).expect("decodes").core().ts;
        assert_eq!(ts % 60_000, 0, "the minute and nothing below it");
        assert!(crate::clock::signing_time().saturating_sub(ts) <= 60_000, "{ts} is now");
    }

    /// Losing a network by typing a command twice is not a thing this offers.
    #[test]
    fn founding_twice_is_refused_and_changes_nothing() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());

        let first = found(&paths, &wanted()).expect("founds");
        let before = Log::at(paths.roster()).read().expect("reads");

        let refusal = found(&paths, &wanted()).expect_err("a second founding is refused");
        assert!(refusal.contains("already holds a network"), "{refusal}");
        assert!(refusal.contains("remove"), "and it says how to start over on purpose: {refusal}");

        assert_eq!(Log::at(paths.roster()).read().expect("reads"), before, "untouched");
        assert_eq!(state_at(&paths).network, first, "and it is still the same network");
    }

    /// Two runs on one machine agree; two machines do not collide.
    #[test]
    fn the_prefix_is_derived_and_not_invented() {
        let one = NodeIdentity::generate().expect("generates");
        let other = NodeIdentity::generate().expect("generates");

        assert_eq!(derived_prefix(&one), derived_prefix(&one), "the same device, twice");
        assert_ne!(derived_prefix(&one), derived_prefix(&other), "two devices");

        let prefix = derived_prefix(&one);
        assert_eq!(prefix.len(), 8);
        assert_eq!(prefix.first(), Some(&0xfd), "unique-local, as RFC 4193 requires");
    }

    /// The relay a person supplies reaches the signed parameters, where every
    /// device will read it.
    #[test]
    fn what_a_person_supplies_ends_up_signed() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());

        found(&paths, &wanted()).expect("founds");

        let state = state_at(&paths);
        assert_eq!(state.params.relay.as_deref(), Some("https://relay.example:443"));
    }

    /// The roster's own rules decide what a parameter may be, and founding does
    /// not get its own opinion about them.
    #[test]
    fn parameters_the_roster_would_refuse_are_refused_here() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());

        let mut asked = wanted();
        asked.suffix = "s".repeat(roster::limits::MAX_SUFFIX_LEN.saturating_add(1));

        assert!(found(&paths, &asked).is_err());
        assert!(
            Log::at(paths.roster()).read().expect("reads").is_empty(),
            "a refused founding leaves no half-written network"
        );
    }
}

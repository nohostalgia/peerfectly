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
    /// The relay, if the network has one.
    pub relay: Option<String>,
    /// The rendezvous, if the network has one.
    pub rendezvous: Option<String>,
    /// The relay's certificate to pin, if one is being pinned.
    pub certificate: Option<Vec<u8>>,
    /// The IPv4 range the network's devices derive their addresses in, if one
    /// other than the default was chosen.
    pub ipv4_range: Option<roster::types::Ipv4Range>,
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
             a.b.c.d/len, with a length from 8 to 28, inside 10.0.0.0/8, 172.16.0.0/12, \
             192.168.0.0/16, 100.64.0.0/10 or 198.18.0.0/15. Nothing was signed."
        )
    })?;
    Ok((range != roster::types::Ipv4Range::DEFAULT).then_some(range))
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

    // The snapshot needs the signing key, which may be behind a person or out of
    // reach entirely. When it is out of reach the request goes back to the caller,
    // who asks: a network with no snapshot has nothing for freshness to be
    // measured from, so it is worth a second prompt rather than a gap.
    if !identity.signing_key().answers_here() {
        let body = crate::snapshots::body_over_heads(&roster, identity).ok()?;
        return Some(identity::detached::prepare_snapshot(
            &body,
            &identity.signing_key().public_key(),
        ));
    }

    let bytes = crate::snapshots::sign_over_heads(&roster, identity).ok()?;
    // Offered to a roster of its own before it is kept, so that what is written
    // is a snapshot this build can verify rather than one it merely produced.
    if roster.offer_snapshot(&bytes).is_accepted() {
        let _kept = crate::state::write_snapshot(paths, &bytes, crate::state::wall_seconds());
    }
    None
}

/// The body of a network's first snapshot, prepared **before** its genesis is
/// signed.
///
/// Where the signing key is somewhere this process cannot reach, founding is one
/// batch — the genesis and this — shown to a person together and signed at once.
/// The genesis has no signature yet, so the snapshot is built over a preview of
/// it; the body is exactly what [`first_snapshot`] would build over a roster
/// holding the signed genesis, and the roster that is later offered it checks
/// that by deriving it again.
///
/// `None` only where no body can be built, which leaves a founding with no
/// snapshot — the state a declined second prompt used to leave, and one an
/// admin's next act repairs.
#[must_use]
pub fn first_snapshot_body(
    genesis: &OperationCore,
    identity: &NodeIdentity,
) -> Option<roster::snapshot::Snapshot> {
    let nothing_yet = roster::roster::Roster::new();
    crate::snapshots::after(
        &nothing_yet,
        core::slice::from_ref(genesis),
        identity,
        crate::state::wall_seconds(),
    )
    .ok()
    .flatten()
}

/// Keeps a first snapshot that was signed somewhere this process could not sign.
///
/// Offered to a roster of its own before it is kept, exactly as one signed here
/// is: what is written must be a snapshot this build can verify rather than one
/// it merely received.
pub fn keep_first_snapshot(paths: &Paths, genesis: &[u8], snapshot: &[u8]) -> bool {
    let mut roster = roster::roster::Roster::with_clock(Box::new(crate::state::WallClock));
    if !roster.offer_bytes(genesis).is_accepted() {
        return false;
    }
    if !roster.offer_snapshot(snapshot).is_accepted() {
        return false;
    }
    crate::state::write_snapshot(paths, snapshot, crate::state::wall_seconds()).is_ok()
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
        // Seven days: the roster's own starting point for how long an
        // attestation stands. Not a founding decision worth asking a person
        // about yet, and named there rather than written here so the reason it
        // is no longer thirty sits with the number.
        roster::limits::DEFAULT_SNAPSHOT_WINDOW,
    )
    .map_err(|cause| cause.to_string())?;

    let params = match wanted.certificate.clone() {
        Some(certificate) => params.pinning(certificate).map_err(|cause| cause.to_string())?,
        None => params,
    };

    let params = match wanted.ipv4_range {
        Some(range) => params.in_ipv4_range(range),
        None => params,
    };

    match wanted.rendezvous.clone() {
        Some(address) => params.meeting_at(address).map_err(|cause| cause.to_string()),
        None => Ok(params),
    }
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
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use roster::roster::Roster;

    use super::*;

    fn wanted() -> Founding {
        Founding {
            name: "nas".to_owned(),
            suffix: "peerfectly.internal".to_owned(),
            relay: Some("https://relay.example:443".to_owned()),
            rendezvous: None,
            certificate: None,
            ipv4_range: None,
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

    /// A network with no snapshot has nothing for freshness to measure from, so
    /// its own founder would begin unable to confirm the roster it just made.
    #[test]
    fn a_founded_network_has_a_snapshot_and_an_attestation_and_is_fresh() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());

        found(&paths, &wanted()).expect("founds");

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

    /// A pinned certificate and a rendezvous both reach the signed parameters,
    /// where every device will read them.
    #[test]
    fn what_a_person_supplies_ends_up_signed() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());

        let mut asked = wanted();
        asked.certificate = Some(vec![0x30, 0x01, 0x02]);
        asked.rendezvous = Some("https://meet.example".to_owned());
        found(&paths, &asked).expect("founds");

        let state = state_at(&paths);
        assert_eq!(state.params.relay_cert.as_deref(), Some([0x30, 0x01, 0x02].as_slice()));
        assert_eq!(state.params.rendezvous.as_deref(), Some("https://meet.example"));
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

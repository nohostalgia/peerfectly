//! The relay address, carried as a signed network parameter.
//!
//! A relay is infrastructure a network depends on for reachability. Left to
//! local configuration, no two nodes would necessarily agree, and anyone able to
//! write a node's configuration could point it at a relay of their choosing —
//! which reveals who talks to whom and when, and can withhold service, even
//! though it can read nothing. Here it is one signed answer, changed only by the
//! people allowed to change everything else.
//!
//! The ways of *spelling* it wrongly — omitted, misordered, repeated, two
//! addresses, an empty one, the wrong CBOR type — are in the negative vector
//! corpus rather than here. That corpus is built from hand-written bytes, which
//! is the only honest way to prove a decoder rejects what an encoder would never
//! produce, and it is what a second implementation runs.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod support;

use roster::cbor::is_canonical_schema;
use roster::roster::Roster;
use roster::types::{NETWORK_PARAMS_SCHEMA, NetworkParams, OperationBody, Role};
use support::{History, device, device_id, params};

const RELAY: &str = "https://relay.example.com:4433";

/// Parameters carrying a relay.
fn params_with_relay(relay: &str) -> NetworkParams {
    NetworkParams::with_relay(
        vec![0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        Some(relay),
        "example.internal",
        2_592_000,
    )
    .expect("well-formed parameters")
}

/// A history founded with a relay, plus a member to watch across changes.
fn founded_with_relay() -> History {
    let mut history = History::new();
    history.genesis_with("g", 1, device(1, "founder", Role::Admin, true), params_with_relay(RELAY));
    history.op(
        "add2",
        1,
        &["g"],
        OperationBody::AddDevice(device(2, "phone", Role::Member, false)),
    );
    history
}

/// Loads every operation of a history into a roster.
fn loaded(history: &History) -> Roster {
    let mut roster = Roster::new();
    for entry in history.entries() {
        let admission = roster.offer_bytes(&entry.bytes);
        assert!(admission.is_accepted(), "{} refused: {admission:?}", entry.label);
    }
    roster
}

// ---------------------------------------------------------------------------
// Where the field sits
// ---------------------------------------------------------------------------

/// Length-first, not alphabetical. `relay` is five bytes and belongs between
/// `ula` and `suffix`; `leaving`, seven, between `suffix` and `relay_cert`;
/// `relay_cert`, ten, between `leaving` and `snapshot_window`. Anywhere else they produce bytes a conforming decoder
/// refuses. This is the single easiest rule to get wrong by habit — and the
/// reason to spell the whole order out rather than trust the eye.
#[test]
fn the_schema_is_in_canonical_key_order() {
    assert!(is_canonical_schema(NETWORK_PARAMS_SCHEMA), "{NETWORK_PARAMS_SCHEMA:?}");
    assert_eq!(
        NETWORK_PARAMS_SCHEMA,
        &[
            "ula",
            "ipv4",
            "relay",
            "suffix",
            "leaving",
            "relay_cert",
            "rendezvous",
            "snapshot_window"
        ]
    );
}

// ---------------------------------------------------------------------------
// Presence, absence, and bounds
// ---------------------------------------------------------------------------

#[test]
fn parameters_with_a_relay_round_trip_through_an_operation() {
    let state = loaded(&founded_with_relay()).state().expect("derives");
    assert_eq!(state.params.relay.as_deref(), Some(RELAY));
}

#[test]
fn parameters_without_a_relay_round_trip_through_an_operation() {
    let mut history = History::new();
    history.genesis_with("g", 1, device(1, "founder", Role::Admin, true), params());
    assert_eq!(loaded(&history).state().expect("derives").params.relay, None);
}

/// A network confined to a LAN, or one still being set up, has no relay and must
/// not be made to invent one.
#[test]
fn a_network_with_no_relay_is_well_formed() {
    assert_eq!(params().relay, None);
    assert!(
        loaded(&{
            let mut history = History::new();
            history.genesis_with("g", 1, device(1, "founder", Role::Admin, true), params());
            history
        })
        .state()
        .is_ok()
    );
}

/// Absence and an empty address are not two spellings of one thing. Absence has
/// its own encoding; an empty address is refused outright, so no byte string can
/// mean "a relay whose address is nothing".
#[test]
fn an_empty_relay_address_is_not_absence() {
    let absent =
        NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 1).expect("valid");
    assert_eq!(absent.relay, None);

    let empty =
        NetworkParams::with_relay(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], Some(""), "example.internal", 1);
    match empty {
        Err(roster::Error::InvalidValue(which)) => assert!(which.contains("relay"), "{which}"),
        other => panic!("an empty relay address must be refused, got {other:?}"),
    }
}

#[test]
fn an_over_long_relay_address_is_refused_when_the_parameters_are_built() {
    let too_long = "h".repeat(roster::limits::MAX_RELAY_LEN.saturating_add(1));
    match NetworkParams::with_relay(
        vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
        Some(too_long),
        "example.internal",
        1,
    ) {
        Err(roster::Error::LimitExceeded(which)) => assert!(which.contains("relay"), "{which}"),
        other => panic!("expected a bound refusal naming the relay, got {other:?}"),
    }
}

#[test]
fn a_relay_address_at_the_bound_is_accepted() {
    let exact = "h".repeat(roster::limits::MAX_RELAY_LEN);
    assert!(
        NetworkParams::with_relay(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            Some(exact),
            "example.internal",
            1
        )
        .is_ok(),
        "the bound is inclusive"
    );
}

// ---------------------------------------------------------------------------
// Changing it
// ---------------------------------------------------------------------------

#[test]
fn set_network_changes_the_relay() {
    let mut history = founded_with_relay();
    history.op(
        "move",
        1,
        &["add2"],
        OperationBody::SetNetwork(params_with_relay("https://relay2.example.com:4433")),
    );

    let state = loaded(&history).state().expect("derives");
    assert_eq!(state.params.relay.as_deref(), Some("https://relay2.example.com:4433"));
}

/// Changing where a network meets must not change who belongs to it.
#[test]
fn changing_the_relay_does_not_change_who_belongs() {
    let before = loaded(&founded_with_relay()).state().expect("derives");

    let mut history = founded_with_relay();
    history.op(
        "move",
        1,
        &["add2"],
        OperationBody::SetNetwork(params_with_relay("https://elsewhere.example")),
    );
    let after = loaded(&history).state().expect("derives");

    assert_eq!(before.devices, after.devices, "the device set is untouched");
    assert_eq!(before.revoked, after.revoked, "so are revocations");
    assert_eq!(after.params.suffix, before.params.suffix, "and every other parameter");
    assert_eq!(after.params.ula, before.params.ula);
    assert_eq!(after.params.snapshot_window, before.params.snapshot_window);
    assert_ne!(after.params.relay, before.params.relay, "only the relay moved");
}

#[test]
fn a_device_added_after_a_relay_change_is_still_a_member() {
    let mut history = founded_with_relay();
    history.op(
        "move",
        1,
        &["add2"],
        OperationBody::SetNetwork(params_with_relay("https://elsewhere.example")),
    );
    history.op(
        "add3",
        1,
        &["move"],
        OperationBody::AddDevice(device(3, "laptop", Role::Member, false)),
    );

    let state = loaded(&history).state().expect("derives");
    assert!(state.devices.contains_key(&device_id(3)), "membership is unaffected by the relay");
    assert_eq!(state.params.relay.as_deref(), Some("https://elsewhere.example"));
}

/// The rule already governing concurrent `set_network` settles this too: every
/// node derives the same parameters, and none holds a mixture of the two.
#[test]
fn two_concurrent_relay_changes_settle_deterministically() {
    let mut history = founded_with_relay();
    // Two admins. Concurrency between different authors is what this rule is
    // about; one admin signing both branches is a fork, judged before it.
    history.op(
        "add9",
        1,
        &["add2"],
        OperationBody::AddDevice(device(9, "other-admin", Role::Admin, false)),
    );
    history.op(
        "left",
        1,
        &["add9"],
        OperationBody::SetNetwork(params_with_relay("https://left.example")),
    );
    history.op(
        "right",
        9,
        &["add9"],
        OperationBody::SetNetwork(params_with_relay("https://right.example")),
    );

    let forward = loaded(&history).state().expect("derives");

    // The same operations, with the two concurrent branches offered the other
    // way round.
    let entries = history.entries();
    let mut reversed = Roster::new();
    for index in [0, 1, 2, 4, 3] {
        let entry = entries.get(index).expect("five operations");
        assert!(reversed.offer_bytes(&entry.bytes).is_accepted(), "{}", entry.label);
    }
    let backward = reversed.state().expect("derives");

    assert_eq!(forward.params.relay, backward.params.relay, "arrival order does not decide it");
    assert!(
        matches!(
            forward.params.relay.as_deref(),
            Some("https://left.example" | "https://right.example")
        ),
        "one of the two, never a mixture: {:?}",
        forward.params.relay
    );
    assert_eq!(forward.to_bytes(), backward.to_bytes(), "and the whole state agrees");
}

// ---------------------------------------------------------------------------
// The relay's certificate
// ---------------------------------------------------------------------------

/// A certificate that looks like DER without being one. The roster carries
/// bytes and asks no questions about them; whether they parse is the
/// transport's business, and the roster having an opinion would be a second
/// authority on what a certificate is.
const CERTIFICATE: &[u8] = &[0x30, 0x82, 0x01, 0x0a, 0xde, 0xad, 0xbe, 0xef];

/// A history founded with a relay whose certificate the network pins.
fn founded_with_pinned_relay() -> History {
    let params = params_with_relay(RELAY).pinning(CERTIFICATE.to_vec()).expect("usable");

    let mut history = History::new();
    history.genesis_with("g", 1, device(1, "founder", Role::Admin, true), params);
    history
}

/// The roster authenticates the relay, so the certificate has to survive a
/// signature and come back byte for byte.
#[test]
fn a_pinned_certificate_survives_a_signed_operation() {
    let state = loaded(&founded_with_pinned_relay()).state().expect("derives");

    assert_eq!(state.params.relay_cert.as_deref(), Some(CERTIFICATE));
    assert_eq!(state.params.relay.as_deref(), Some(RELAY), "the address is still there too");
}

/// A network with a relay and no pin is the ordinary case: a relay presenting a
/// publicly trusted certificate, or one still being set up.
#[test]
fn a_network_may_carry_a_relay_without_pinning_it() {
    let state = loaded(&founded_with_relay()).state().expect("derives");
    assert_eq!(state.params.relay_cert, None);
}

/// Empty is refused rather than treated as absence: absence already has an
/// encoding, and two spellings of one value is how two implementations come to
/// disagree about what was signed.
#[test]
fn an_empty_certificate_is_refused() {
    assert!(params_with_relay(RELAY).pinning(Vec::new()).is_err());
}

#[test]
fn an_oversized_certificate_is_refused() {
    let huge = vec![0u8; roster::limits::MAX_RELAY_CERT_LEN + 1];
    assert!(params_with_relay(RELAY).pinning(huge).is_err());
}

/// The bound is inclusive: a chain is allowed to be large.
///
/// And a certificate at the bound must still fit inside a signed operation. Two
/// limits meet here — the certificate's own and `MAX_OPERATION_SIZE` — and a
/// certificate the parameters accept but no genesis can carry would be a bound
/// that is not really the bound, discovered by whoever founds a network with a
/// large chain.
#[test]
fn a_certificate_at_the_bound_still_fits_in_a_signed_operation() {
    let exact = vec![0u8; roster::limits::MAX_RELAY_CERT_LEN];
    let params = params_with_relay(RELAY).pinning(exact).expect("at the bound");

    let mut history = History::new();
    history.genesis_with("g", 1, device(1, "founder", Role::Admin, true), params);

    let state = loaded(&history).state().expect("derives");
    assert_eq!(
        state.params.relay_cert.map(|certificate| certificate.len()),
        Some(roster::limits::MAX_RELAY_CERT_LEN)
    );
}

/// Pinning a certificate for a network with no relay is allowed but useless,
/// and the roster does not police it — the transport ignores a pin it has no
/// relay to check against, and a parameter set that refused would be one more
/// rule to keep in step with a layer that does not care.
#[test]
fn a_pin_without_a_relay_is_carried_rather_than_refused() {
    let params = params().pinning(CERTIFICATE.to_vec()).expect("carried");
    assert_eq!(params.relay, None);
    assert_eq!(params.relay_cert.as_deref(), Some(CERTIFICATE));
}

// ---------------------------------------------------------------------------
// The rendezvous
// ---------------------------------------------------------------------------

const MEETING: &str = "https://rendezvous.example.com";

/// The address has to survive a signature, like the relay's: a rendezvous each
/// node were told about separately is one anybody who can write a config file
/// can move.
#[test]
fn a_rendezvous_survives_a_signed_operation() {
    let params = params_with_relay(RELAY).meeting_at(MEETING).expect("usable");

    let mut history = History::new();
    history.genesis_with("g", 1, device(1, "founder", Role::Admin, true), params);

    let state = loaded(&history).state().expect("derives");
    assert_eq!(state.params.rendezvous.as_deref(), Some(MEETING));
    assert_eq!(state.params.relay.as_deref(), Some(RELAY), "the relay is untouched");
}

/// A network confined to a LAN needs none, and must not be made to invent one.
#[test]
fn a_network_may_have_no_rendezvous() {
    let state = loaded(&founded_with_relay()).state().expect("derives");
    assert_eq!(state.params.rendezvous, None);
}

#[test]
fn an_empty_rendezvous_address_is_refused() {
    assert!(params().meeting_at("").is_err());
}

#[test]
fn an_oversized_rendezvous_address_is_refused() {
    let long = "h".repeat(roster::limits::MAX_RENDEZVOUS_LEN + 1);
    assert!(params().meeting_at(long).is_err());
}

/// The three infrastructure answers are independent: a network may pin a relay
/// certificate and name no rendezvous, or the reverse.
#[test]
fn the_relay_the_pin_and_the_rendezvous_are_carried_independently() {
    let both = params_with_relay(RELAY)
        .pinning(CERTIFICATE.to_vec())
        .expect("pins")
        .meeting_at(MEETING)
        .expect("meets");

    let mut history = History::new();
    history.genesis_with("g", 1, device(1, "founder", Role::Admin, true), both);
    let state = loaded(&history).state().expect("derives");

    assert_eq!(state.params.relay.as_deref(), Some(RELAY));
    assert_eq!(state.params.relay_cert.as_deref(), Some(CERTIFICATE));
    assert_eq!(state.params.rendezvous.as_deref(), Some(MEETING));
}

// ---------------------------------------------------------------------------
// The IPv4 range
// ---------------------------------------------------------------------------

fn range(text: &str) -> roster::types::Ipv4Range {
    text.parse().expect("an allowed range")
}

/// A history with an admin, a member and a revoked device, so a range change
/// has roles and a revocation to leave alone.
fn founded_with_a_revocation() -> History {
    let mut history = founded_with_relay();
    history.op(
        "add3",
        1,
        &["add2"],
        OperationBody::AddDevice(device(3, "old-laptop", Role::Member, false)),
    );
    history.op(
        "revoke3",
        1,
        &["add3"],
        OperationBody::RevokeDevice { device: device_id(3), reason: "lost".to_owned() },
    );
    history
}

#[test]
fn a_network_without_a_range_uses_the_default() {
    let state = loaded(&founded_with_relay()).state().expect("derives");
    assert_eq!(state.params.ipv4, None);
    assert_eq!(state.params.ipv4_range().to_string(), "100.64.0.0/10");
}

#[test]
fn a_range_chosen_at_founding_survives_a_signed_operation() {
    let mut history = History::new();
    history.genesis_with(
        "g",
        1,
        device(1, "founder", Role::Admin, true),
        params_with_relay(RELAY).in_ipv4_range(range("10.42.0.0/16")),
    );
    let state = loaded(&history).state().expect("derives");
    assert_eq!(state.params.ipv4, Some(range("10.42.0.0/16")));
    assert_eq!(state.params.relay.as_deref(), Some(RELAY), "the relay is untouched");
}

/// Moving the range moves addresses and nothing else.
#[test]
fn changing_the_range_does_not_change_who_belongs() {
    let before = loaded(&founded_with_a_revocation()).state().expect("derives");

    let mut history = founded_with_a_revocation();
    history.op(
        "move",
        1,
        &["revoke3"],
        OperationBody::SetNetwork(params_with_relay(RELAY).in_ipv4_range(range("192.168.77.0/24"))),
    );
    let after = loaded(&history).state().expect("derives");

    assert_eq!(after.params.ipv4, Some(range("192.168.77.0/24")));
    assert_eq!(before.devices, after.devices, "devices and their roles are untouched");
    assert_eq!(before.revoked, after.revoked, "so are revocations");
    assert_eq!(
        NetworkParams { ipv4: None, ..after.params.clone() },
        before.params,
        "and every other parameter"
    );
}

/// The rule already governing concurrent `set_network` settles two ranges too.
#[test]
fn two_concurrent_range_changes_settle_deterministically() {
    let mut history = founded_with_relay();
    history.op(
        "add9",
        1,
        &["add2"],
        OperationBody::AddDevice(device(9, "other-admin", Role::Admin, false)),
    );
    history.op(
        "left",
        1,
        &["add9"],
        OperationBody::SetNetwork(params_with_relay(RELAY).in_ipv4_range(range("10.1.0.0/16"))),
    );
    history.op(
        "right",
        9,
        &["add9"],
        OperationBody::SetNetwork(params_with_relay(RELAY).in_ipv4_range(range("10.2.0.0/16"))),
    );

    let forward = loaded(&history).state().expect("derives");
    let entries = history.entries();
    let mut reversed = Roster::new();
    for index in [0, 1, 2, 4, 3] {
        let entry = entries.get(index).expect("five operations");
        assert!(reversed.offer_bytes(&entry.bytes).is_accepted(), "{}", entry.label);
    }
    let backward = reversed.state().expect("derives");

    assert_eq!(forward.params.ipv4, backward.params.ipv4, "arrival order does not decide it");
    assert!(
        [Some(range("10.1.0.0/16")), Some(range("10.2.0.0/16"))].contains(&forward.params.ipv4),
        "one of the two: {:?}",
        forward.params.ipv4
    );
    assert_eq!(forward.to_bytes(), backward.to_bytes(), "and the whole state agrees");
}

/// Dropping a chosen range returns the network to the default, and the
/// parameters to the six-entry encoding.
#[test]
fn a_range_can_be_removed_again() {
    let mut history = founded_with_relay();
    history.op(
        "set",
        1,
        &["add2"],
        OperationBody::SetNetwork(params_with_relay(RELAY).in_ipv4_range(range("10.1.0.0/16"))),
    );
    history.op("unset", 1, &["set"], OperationBody::SetNetwork(params_with_relay(RELAY)));
    let state = loaded(&history).state().expect("derives");
    assert_eq!(state.params.ipv4, None);
    assert_eq!(
        OperationBody::SetNetwork(params_with_relay(RELAY)).encode(),
        OperationBody::SetNetwork(state.params).encode()
    );
}

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
/// `ula` and `suffix`; `leaving`, seven, between `suffix` and `snapshot_window`.
/// Anywhere else they produce bytes a conforming decoder refuses. This is the single easiest rule to get wrong by habit — and the
/// reason to spell the whole order out rather than trust the eye.
#[test]
fn the_schema_is_in_canonical_key_order() {
    assert!(is_canonical_schema(NETWORK_PARAMS_SCHEMA), "{NETWORK_PARAMS_SCHEMA:?}");
    assert_eq!(
        NETWORK_PARAMS_SCHEMA,
        &["ula", "ipv4", "relay", "policy", "suffix", "anchors", "leaving", "snapshot_window"]
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

// ---------------------------------------------------------------------------
// One leaf at a time
// ---------------------------------------------------------------------------

/// Two admins each change a different parameter, neither having seen the other:
/// both changes stand, because a change sets only the leaves it differs in.
#[test]
fn concurrent_changes_to_different_parameters_both_stand() {
    use roster::leaf::Group;
    use roster::parameters::Rule;

    let mut history = History::new();
    history.genesis_with("g", 1, device(1, "phone", Role::Admin, true), params_with_relay(RELAY));
    history.op("admin2", 1, &["g"], OperationBody::AddDevice(device(2, "pc", Role::Admin, false)));

    let mut with_anchors = params_with_relay(RELAY);
    with_anchors.anchors = vec![device_id(2)];
    history.op("anchors", 1, &["admin2"], OperationBody::SetNetwork(with_anchors));

    let mut with_policy = params_with_relay(RELAY);
    with_policy.policy =
        vec![Rule { from: Group::new("sensori").unwrap(), to: Group::new("controller").unwrap() }];
    history.op("policy", 2, &["admin2"], OperationBody::SetNetwork(with_policy));

    let mut roster = Roster::new();
    for entry in history.entries() {
        assert!(roster.offer_bytes(&entry.bytes).is_accepted(), "{}", entry.label);
    }
    let state = roster.state().unwrap();
    assert_eq!(state.params.anchors, vec![device_id(2)], "the anchors stand");
    assert_eq!(state.params.policy.len(), 1, "and so does the policy");
    assert_eq!(state.params.relay.as_deref(), Some(RELAY), "and nothing else moved");

    // The same in the other order of arrival.
    let mut reversed = Roster::new();
    for entry in history.entries().iter().rev() {
        let _ = reversed.offer_bytes(&entry.bytes);
    }
    assert_eq!(reversed.state().unwrap().params, state.params);
}

/// A change that carries a parameter as it already was does not set it: a
/// concurrent change of that parameter is not undone by it.
#[test]
fn a_parameter_carried_unchanged_is_not_set() {
    let mut history = History::new();
    history.genesis_with("g", 1, device(1, "phone", Role::Admin, true), params_with_relay(RELAY));
    history.op("admin2", 1, &["g"], OperationBody::AddDevice(device(2, "pc", Role::Admin, false)));
    // Admin 1 moves the relay; admin 2, concurrently and deeper, changes only
    // the anchors and carries the old relay unchanged.
    history.op(
        "moved",
        1,
        &["admin2"],
        OperationBody::SetNetwork(params_with_relay("https://other.example.com:4433")),
    );
    let mut anchors = params_with_relay(RELAY);
    anchors.anchors = vec![device_id(1)];
    history.op("a1", 2, &["admin2"], OperationBody::SetNetwork(anchors.clone()));
    let mut more = anchors;
    more.anchors.push(device_id(2));
    more.anchors.sort();
    history.op("a2", 2, &["a1"], OperationBody::SetNetwork(more));

    let mut roster = Roster::new();
    for entry in history.entries() {
        assert!(roster.offer_bytes(&entry.bytes).is_accepted(), "{}", entry.label);
    }
    let state = roster.state().unwrap();
    assert_eq!(state.params.relay.as_deref(), Some("https://other.example.com:4433"));
    assert_eq!(state.params.anchors.len(), 2);
}

/// An anchor that is revoked drops out of the list on every node, with no
/// admin removing it.
#[test]
fn a_revoked_anchor_is_ignored() {
    let mut history = founded_with_relay();
    let mut with_anchor = params_with_relay(RELAY);
    let last = history.labels().last().cloned().unwrap();
    with_anchor.anchors = vec![device_id(2)];
    history.op("anchor", 1, &[last.as_str()], OperationBody::SetNetwork(with_anchor));
    history.op(
        "revoke",
        1,
        &["anchor"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "retired".into() },
    );

    let mut roster = Roster::new();
    for entry in history.entries() {
        let _ = roster.offer_bytes(&entry.bytes);
        if entry.label == "anchor" {
            assert_eq!(roster.state().unwrap().params.anchors, vec![device_id(2)]);
        }
    }
    let state = roster.state().unwrap();
    assert!(state.params.anchors.is_empty(), "the revoked anchor is gone");
    assert_eq!(roster::state::derive(&history.dag()).unwrap(), state, "derivation agrees");
}

/// An anchor naming a device that is not a member is ignored from the start.
#[test]
fn an_anchor_naming_no_member_is_ignored() {
    let mut history = founded_with_relay();
    let last = history.labels().last().cloned().unwrap();
    let mut with_stranger = params_with_relay(RELAY);
    with_stranger.anchors = vec![roster::id::DeviceId::from_bytes([0xee; 32])];
    history.op("stranger", 1, &[last.as_str()], OperationBody::SetNetwork(with_stranger));
    let state = roster::state::derive(&history.dag()).unwrap();
    assert!(state.params.anchors.is_empty());
}

/// A long run of parameter changes derives in time proportional to its length.
///
/// Each change is judged against what its ancestors imply. Computed afresh at
/// every level, that cost doubles with each change before it.
#[test]
fn a_chain_of_parameter_changes_derives_quickly() {
    let mut history = History::new();
    history.genesis("g", 1);
    let mut parent = "g".to_owned();
    for index in 0..200_u32 {
        let label = format!("set{index}");
        let relay = format!("https://relay{index}.example.com:4433");
        history.op(
            &label,
            1,
            &[parent.as_str()],
            OperationBody::SetNetwork(params_with_relay(&relay)),
        );
        parent = label;
    }
    let started = std::time::Instant::now();
    let mut roster = Roster::new();
    for entry in history.entries() {
        let _ = roster.offer_bytes(&entry.bytes);
    }
    let _ = roster::state::derive(roster.dag()).unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(10), "took {:?}", started.elapsed());
}

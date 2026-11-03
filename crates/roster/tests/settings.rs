//! A device's settings: what an admin may change after admitting it, one field
//! at a time, last writer wins.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod support;

use roster::leaf::{Group, Mode, SettingsChange};
use roster::roster::Roster;
use roster::types::{OperationBody, Role};
use support::{History, device, device_id};

/// A network with two admins and a member, device 3, to change.
fn founded() -> History {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("admin2", 1, &["g"], OperationBody::AddDevice(device(2, "pc", Role::Admin, false)));
    history.op(
        "member3",
        1,
        &["admin2"],
        OperationBody::AddDevice(device(3, "sensor", Role::Member, false)),
    );
    history
}

fn set(device: u8, change: SettingsChange) -> OperationBody {
    OperationBody::SetDevice { device: device_id(device), change }
}

fn loaded(history: &History) -> Roster {
    let mut roster = Roster::new();
    for entry in history.entries() {
        let _ = roster.offer_bytes(&entry.bytes);
    }
    roster
}

#[test]
fn two_admins_change_different_settings_and_both_stand() {
    let mut history = founded();
    history.op(
        "ipv4",
        1,
        &["member3"],
        set(3, SettingsChange { ipv4: Some(Some([100, 70, 0, 3])), ..SettingsChange::default() }),
    );
    history.op(
        "groups",
        2,
        &["member3"],
        set(
            3,
            SettingsChange {
                groups: Some(vec![Group::new("sensori").unwrap()]),
                ..SettingsChange::default()
            },
        ),
    );

    let state = loaded(&history).state().unwrap();
    let settings = state.settings_of(&device_id(3));
    assert_eq!(settings.ipv4, Some([100, 70, 0, 3]));
    assert_eq!(settings.groups, vec![Group::new("sensori").unwrap()]);

    let mut reversed = Roster::new();
    for entry in history.entries().iter().rev() {
        let _ = reversed.offer_bytes(&entry.bytes);
    }
    assert_eq!(reversed.state().unwrap().root(), state.root(), "in either order");
}

#[test]
fn of_two_writers_of_one_field_the_later_wins() {
    let mut history = founded();
    let light = SettingsChange { mode: Some(Mode::Light), ..SettingsChange::default() };
    let full = SettingsChange { mode: Some(Mode::Full), ..SettingsChange::default() };
    history.op("light", 1, &["member3"], set(3, light));
    history.op("full", 1, &["light"], set(3, full));
    let state = loaded(&history).state().unwrap();
    assert_eq!(state.settings_of(&device_id(3)).mode, Mode::Full);
    assert!(
        state.devices.changed_settings().all(|(device, _)| device != device_id(3)),
        "back at the default, nothing is recorded"
    );
}

#[test]
fn a_change_naming_no_member_is_refused() {
    let mut history = founded();
    history.op(
        "ghost",
        1,
        &["member3"],
        set(9, SettingsChange { mode: Some(Mode::Light), ..SettingsChange::default() }),
    );
    let mut roster = Roster::new();
    let mut refused = false;
    for entry in history.entries() {
        let admission = roster.offer_bytes(&entry.bytes);
        if entry.label == "ghost" {
            refused = admission.refusal().is_some();
        }
    }
    assert!(refused, "a settings change for a device not in the network is refused");
}

#[test]
fn a_settings_change_changes_the_root_and_the_leaf() {
    let history = founded();
    let before = loaded(&history).state().unwrap();
    let mut changed = history;
    changed.op(
        "light",
        1,
        &["member3"],
        set(3, SettingsChange { mode: Some(Mode::Light), ..SettingsChange::default() }),
    );
    let after = loaded(&changed).state().unwrap();
    assert_ne!(before.root(), after.root());
    assert_eq!(after.leaf(&device_id(3)).unwrap().settings.mode, Mode::Light);
}

#[test]
fn settings_survive_the_state_bytes() {
    let mut history = founded();
    history.op(
        "light",
        1,
        &["member3"],
        set(3, SettingsChange { mode: Some(Mode::Light), ..SettingsChange::default() }),
    );
    let state = loaded(&history).state().unwrap();
    let decoded = roster::state::RosterState::from_bytes(&state.to_bytes()).unwrap();
    assert_eq!(
        decoded.devices.changed_settings().collect::<Vec<_>>(),
        state.devices.changed_settings().collect::<Vec<_>>()
    );
    assert_eq!(decoded.root(), state.root());
}

#[test]
fn promoting_a_light_device_does_nothing() {
    let mut history = founded();
    history.op(
        "light",
        1,
        &["member3"],
        set(3, SettingsChange { mode: Some(Mode::Light), ..SettingsChange::default() }),
    );
    history.op(
        "promote",
        1,
        &["light"],
        OperationBody::Promote { device: device_id(3), founder: false },
    );
    let state = loaded(&history).state().unwrap();
    assert_eq!(state.devices.get(&device_id(3)).unwrap().role, Role::Member);
    assert_eq!(state.settings_of(&device_id(3)).mode, Mode::Light);
    assert_eq!(roster::state::derive(&history.dag()).unwrap(), state, "derivation agrees");
}

#[test]
fn an_admin_cannot_be_made_light() {
    let mut history = founded();
    history.op(
        "light",
        1,
        &["member3"],
        set(2, SettingsChange { mode: Some(Mode::Light), ..SettingsChange::default() }),
    );
    let state = loaded(&history).state().unwrap();
    assert_eq!(state.devices.get(&device_id(2)).unwrap().role, Role::Admin);
    assert_eq!(state.settings_of(&device_id(2)).mode, Mode::Full);
    assert_eq!(roster::state::derive(&history.dag()).unwrap(), state, "derivation agrees");
}

#[test]
fn a_race_between_promotion_and_light_is_decided_by_the_later() {
    let mut history = founded();
    // Admin 1 makes device 3 light while admin 2, concurrently, promotes it.
    // Whichever decision ranks later stands; either way the device is never an
    // admin and light at once, and every node reaches the same answer.
    history.op(
        "light",
        1,
        &["member3"],
        set(3, SettingsChange { mode: Some(Mode::Light), ..SettingsChange::default() }),
    );
    history.op(
        "rename",
        2,
        &["member3"],
        OperationBody::Rename { device: device_id(3), name: "s".into() },
    );
    history.op(
        "promote",
        2,
        &["rename"],
        OperationBody::Promote { device: device_id(3), founder: false },
    );
    let forward = roster::state::derive(&history.dag()).unwrap();
    let record = forward.devices.get(&device_id(3)).unwrap();
    let mode = forward.settings_of(&device_id(3)).mode;
    assert!(
        !(record.role == Role::Admin && mode == Mode::Light),
        "never an admin and light at once"
    );
    let mut reversed = Roster::new();
    for entry in history.entries().iter().rev() {
        let _ = reversed.offer_bytes(&entry.bytes);
    }
    assert_eq!(reversed.state().unwrap(), forward, "the same in either order");
}

// ---------------------------------------------------------------------------
// What a root's delta names
// ---------------------------------------------------------------------------

/// The delta between the state before an act and the state after it.
fn delta_of(mut history: History, act: &str, body: OperationBody) -> Vec<roster::id::DeviceId> {
    let before = roster::state::derive(&history.dag()).unwrap();
    let last = history.labels().last().cloned().unwrap();
    history.op(act, 1, &[last.as_str()], body);
    roster::state::derive(&history.dag()).unwrap().delta_from(&before)
}

#[test]
fn a_revocation_is_in_the_delta() {
    let delta = delta_of(
        founded(),
        "revoke",
        OperationBody::RevokeDevice { device: device_id(3), reason: "lost".into() },
    );
    assert_eq!(delta, vec![device_id(3)]);
}

#[test]
fn a_demotion_is_in_the_delta() {
    let delta = delta_of(founded(), "demote", OperationBody::Demote { device: device_id(2) });
    assert_eq!(delta, vec![device_id(2)]);
}

#[test]
fn a_removal_from_a_group_is_in_the_delta() {
    let mut history = founded();
    history.op(
        "join",
        1,
        &["member3"],
        set(
            3,
            SettingsChange {
                groups: Some(vec![Group::new("lab").unwrap()]),
                ..SettingsChange::default()
            },
        ),
    );
    let delta = delta_of(
        history,
        "leave",
        set(3, SettingsChange { groups: Some(vec![]), ..SettingsChange::default() }),
    );
    assert_eq!(delta, vec![device_id(3)]);
}

#[test]
fn a_settings_change_is_in_the_delta() {
    let delta = delta_of(
        founded(),
        "light",
        set(3, SettingsChange { mode: Some(Mode::Light), ..SettingsChange::default() }),
    );
    assert_eq!(delta, vec![device_id(3)]);
}

#[test]
fn an_admission_is_not_in_the_delta() {
    let delta = delta_of(
        founded(),
        "add4",
        OperationBody::AddDevice(device(4, "new", Role::Member, false)),
    );
    assert!(delta.is_empty(), "an admission invalidates no earlier proof: {delta:?}");
}

fn offset(value: u32) -> SettingsChange {
    SettingsChange { ipv4: Some(Some(value.to_be_bytes())), ..SettingsChange::default() }
}

/// Founding is the founder's admission: it holds the block's first host with
/// no operation saying so, and the next device admitted is given the second.
#[test]
fn the_founder_holds_the_first_host_and_the_next_is_the_second() {
    let history = founded();
    let state = loaded(&history).state().unwrap();
    assert_eq!(state.settings_of(&device_id(1)).ipv4, Some(roster::leaf::FIRST_HOST));
    assert_eq!(state.free_offsets(1), Some(2_u32.to_be_bytes()));
}

/// The lowest free offset is taken, a revoked device's included; a run takes
/// the lowest gap wide enough for it.
#[test]
fn the_lowest_free_offsets_are_given() {
    let mut history = founded();
    history.op("two", 1, &["member3"], set(2, offset(2)));
    history.op("three", 1, &["two"], set(3, offset(4)));
    let state = loaded(&history).state().unwrap();
    assert_eq!(state.free_offsets(1), Some(3_u32.to_be_bytes()), "the gap at 3");
    assert_eq!(state.free_offsets(2), Some(5_u32.to_be_bytes()), "3 alone is too narrow");

    history.op(
        "revoke",
        1,
        &["three"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "sold".into() },
    );
    let state = loaded(&history).state().unwrap();
    assert_eq!(state.free_offsets(2), Some(2_u32.to_be_bytes()), "2 is free again");
}

/// A block whose hosts are all held has none to give.
#[test]
fn a_full_block_gives_none() {
    let mut history = History::new();
    let params = support::params().in_ipv4_range("10.0.0.0/28".parse().unwrap());
    history.genesis_with("g", 1, device(1, "phone", Role::Admin, true), params);
    let mut previous = "g".to_owned();
    for seed in 2..=14_u8 {
        let label = format!("add{seed}");
        let given = format!("offset{seed}");
        history.op(
            &label,
            1,
            &[previous.as_str()],
            OperationBody::AddDevice(device(seed, &format!("d{seed}"), Role::Member, false)),
        );
        history.op(&given, 1, &[label.as_str()], set(seed, offset(u32::from(seed))));
        previous = given;
    }
    let state = loaded(&history).state().unwrap();
    assert_eq!(state.free_offsets(1), None, "fourteen hosts, fourteen held");
}

/// Two admins admitting at once both give the lowest free offset: the claim
/// that ranks later keeps it, the other device holds none, and the next
/// lowest free is what its admin gives it then.
#[test]
fn two_admins_admitting_at_once_settle_one_offset_and_the_loser_is_given_the_next() {
    let mut history = founded();
    history.op(
        "four",
        1,
        &["member3"],
        OperationBody::AddDevice(device(4, "a", Role::Member, false)),
    );
    history.op(
        "five",
        2,
        &["member3"],
        OperationBody::AddDevice(device(5, "b", Role::Member, false)),
    );
    history.op("give4", 1, &["four"], set(4, offset(2)));
    history.op("give5", 2, &["five"], set(5, offset(2)));
    let state = loaded(&history).state().unwrap();
    let held: Vec<_> = [4_u8, 5]
        .into_iter()
        .filter(|seed| state.settings_of(&device_id(*seed)).ipv4 == Some(2_u32.to_be_bytes()))
        .collect();
    assert_eq!(held.len(), 1, "one of the two keeps it: {held:?}");
    let loser = if held == [4] { 5 } else { 4 };
    assert_eq!(state.settings_of(&device_id(loser)).ipv4, None);

    let next = state.free_offsets(1).unwrap();
    assert_eq!(next, 3_u32.to_be_bytes());
    history.op("again", 1, &["give4", "give5"], set(loser, offset(3)));
    let state = loaded(&history).state().unwrap();
    assert_eq!(
        state.settings_of(&device_id(loser)).ipv4,
        Some(next),
        "a new claim, not the lost one"
    );
}

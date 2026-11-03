//! IPv4 holdings read only what a snapshot keeps.
//!
//! Admission order is gone once a roster is compacted, so a rule that read it
//! would give a node fed a snapshot different addresses from a node fed the
//! whole history. This builds both nodes from one history, with offsets
//! assigned, contended and freed by revocations on both sides of the snapshot,
//! and compares.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

#[path = "../../roster/tests/support/mod.rs"]
mod support;

use roster::roster::Roster;
use roster::types::{OperationBody, Role};
use support::{History, device, device_id, params};
use tunnel::Ipv4Holdings;

/// A network in a range of fourteen hosts, its devices given offsets as they
/// are admitted, some of them twice over; revocations before and after the
/// point a snapshot covers.
fn crowded() -> History {
    let mut history = History::new();
    history.genesis_with(
        "g",
        1,
        device(1, "phone", Role::Admin, true),
        params().in_ipv4_range("10.0.0.0/28".parse().expect("allowed")),
    );
    let mut previous = "g".to_owned();
    for seed in 2..=20u8 {
        let label = format!("add{seed}");
        history.op(
            &label,
            1,
            &[previous.as_str()],
            OperationBody::AddDevice(device(seed, &format!("d{seed}"), Role::Member, false)),
        );
        // Offsets 1 to 14, then round again: the later claim keeps each.
        let offset = u32::from(seed.saturating_sub(2)).rem_euclid(14).saturating_add(1);
        let given = format!("offset{seed}");
        history.op(&given, 1, &[label.as_str()], assign(seed, offset.to_be_bytes()));
        previous = given;
    }
    history.op(
        "rev3",
        1,
        &[previous.as_str()],
        OperationBody::RevokeDevice { device: device_id(3), reason: "sold".into() },
    );
    previous = "rev3".to_owned();
    for index in 0..12 {
        let label = format!("n{index}");
        history.op(
            &label,
            1,
            &[previous.as_str()],
            OperationBody::Rename { device: device_id(2), name: format!("name{index}") },
        );
        previous = label;
    }
    history.op(
        "rev4",
        1,
        &[previous.as_str()],
        OperationBody::RevokeDevice { device: device_id(4), reason: "lost".into() },
    );
    history
}

fn loaded(history: &History) -> Roster {
    let mut roster = Roster::with_staleness_depth(2);
    for entry in history.entries() {
        let outcome = roster.offer_bytes(&entry.bytes);
        assert!(outcome.is_accepted(), "{} should be admitted: {outcome:?}", entry.label);
    }
    roster
}

#[test]
fn history_and_snapshot_give_identical_holdings() {
    let history = crowded();

    let whole = loaded(&history);
    let mut compacted = loaded(&history);
    assert!(compacted.offer_snapshot(&history.snapshot_at(1, 1, &["n2"])).is_accepted());
    let discarded = compacted.compact().expect("compacts");
    assert!(discarded > 0, "the fixture actually compacts");
    assert!(!compacted.dag().contains(&history.id("add2")), "admission order is gone");

    let from_history = Ipv4Holdings::of_state(&whole.state().expect("derives"));
    let from_snapshot = Ipv4Holdings::of_state(&compacted.state().expect("derives"));

    assert_eq!(from_history, from_snapshot);
    for seed in 2..=20_u8 {
        assert_eq!(
            from_history.of(&device_id(seed)),
            from_snapshot.of(&device_id(seed)),
            "device {seed}"
        );
    }
    assert!(from_history.held().next().is_some(), "the fixture holds addresses");
    assert_eq!(from_history.of(&device_id(3)), None, "a revoked device holds nothing");
    // Offset 1 went to device 2, then again to device 16, which keeps it.
    assert_eq!(from_history.of(&device_id(2)), None, "an offset lost is lost");
    assert_eq!(from_history.holder([10, 0, 0, 1].into()), Some(device_id(16)));
}

/// A founded network in `range`, with a second admin and the members given.
fn founded_in(range: &str, members: &[u8]) -> History {
    let mut history = History::new();
    history.genesis_with(
        "g",
        1,
        device(1, "phone", Role::Admin, true),
        params().in_ipv4_range(range.parse().expect("allowed")),
    );
    history.op("admin2", 1, &["g"], OperationBody::AddDevice(device(2, "pc", Role::Admin, false)));
    let mut previous = "admin2".to_owned();
    for seed in members {
        let label = format!("add{seed}");
        history.op(
            &label,
            1,
            &[previous.as_str()],
            OperationBody::AddDevice(device(*seed, &format!("d{seed}"), Role::Member, false)),
        );
        previous = label;
    }
    history
}

/// An admin's act giving `device` the offset `offset` in the network's block.
fn assign(device: u8, offset: [u8; 4]) -> OperationBody {
    OperationBody::SetDevice {
        device: device_id(device),
        change: roster::leaf::SettingsChange {
            ipv4: Some(Some(offset)),
            ..roster::leaf::SettingsChange::default()
        },
    }
}

fn holdings_of(history: &History) -> Ipv4Holdings {
    let mut roster = Roster::new();
    for entry in history.entries() {
        let _ = roster.offer_bytes(&entry.bytes);
    }
    Ipv4Holdings::of_state(&roster.state().expect("derives"))
}

#[test]
fn of_two_concurrent_assignments_of_one_offset_the_later_keeps_it() {
    let mut history = founded_in("100.64.0.0/10", &[5, 6]);
    let offset = 0x0909_u32.to_be_bytes();
    let address = [100, 64, 9, 9];
    history.op("five", 1, &["add6"], assign(5, offset));
    history.op("six", 2, &["add6"], assign(6, offset));

    let holdings = holdings_of(&history);
    let holder = holdings.holder(address.into()).expect("one of them holds it");
    let loser = if holder == device_id(5) { device_id(6) } else { device_id(5) };
    assert_ne!(holdings.of(&loser), Some(address.into()));

    let mut reversed = Roster::new();
    for entry in history.entries().iter().rev() {
        let _ = reversed.offer_bytes(&entry.bytes);
    }
    assert_eq!(Ipv4Holdings::of_state(&reversed.state().unwrap()), holdings, "in either order");
}

#[test]
fn a_revoked_devices_offset_is_free_for_the_next() {
    let mut history = founded_in("10.0.0.0/28", &[5]);
    history.op("five", 1, &["add5"], assign(5, 4_u32.to_be_bytes()));
    history.op(
        "revoke",
        1,
        &["five"],
        OperationBody::RevokeDevice { device: device_id(5), reason: "sold".into() },
    );
    history.op(
        "next",
        1,
        &["revoke"],
        OperationBody::AddDevice(device(6, "next", Role::Member, false)),
    );
    history.op("six", 1, &["next"], assign(6, 4_u32.to_be_bytes()));
    assert_eq!(holdings_of(&history).of(&device_id(6)), Some([10, 0, 0, 4].into()));
}

/// Moving the block is one change of the parameters: every device keeps its
/// offset and holds the address it names in the new block.
#[test]
fn moving_the_block_moves_every_device_at_once() {
    let mut history = founded_in("10.0.0.0/28", &[5]);
    history.op("five", 1, &["add5"], assign(5, 3_u32.to_be_bytes()));
    let before = holdings_of(&history);
    let moved = params().in_ipv4_range("10.9.0.0/24".parse().unwrap());
    history.op("move", 1, &["five"], OperationBody::SetNetwork(moved));
    let after = holdings_of(&history);
    assert_eq!(before.of(&device_id(5)), Some([10, 0, 0, 3].into()));
    assert_eq!(after.of(&device_id(5)), Some([10, 9, 0, 3].into()));
}

// ---------------------------------------------------------------------------
// The view of a state is the holdings decided whole
// ---------------------------------------------------------------------------

/// A network in a range of fourteen addresses, with the members given, some
/// admitted alone and some by a batch, and some assigned an address: in or out
/// of the range, contended or not.
fn crowded_with(alone: &[u8], batch: &[u8], assigned: &[(u8, u8)]) -> roster::state::RosterState {
    let mut history = founded_in("10.0.0.0/28", alone);
    let mut previous = alone.last().map_or("admin2".to_owned(), |seed| format!("add{seed}"));
    let entries: Vec<roster::batch::BatchEntry> = batch
        .iter()
        .filter(|seed| !alone.contains(seed))
        .map(|seed| {
            let spec = device(*seed, &format!("b{seed}"), Role::Member, false);
            roster::batch::BatchEntry {
                keys: spec.keys,
                name: format!("b{seed}"),
                serial: vec![*seed],
                ipv4: None,
            }
        })
        .collect();
    if !entries.is_empty() {
        let header = roster::batch::BatchHeader::for_entries(
            &entries,
            roster::leaf::Mode::Light,
            Vec::new(),
            None,
            "lot",
        )
        .unwrap();
        history.op("batch", 1, &[previous.as_str()], OperationBody::AdmitBatch(header));
        previous = "batch".to_owned();
    }
    for (number, (seed, host)) in assigned.iter().enumerate() {
        let label = format!("assign{number}");
        // Offsets 1 to 14 are the block's hosts; 0, 15 and beyond are its
        // network, its broadcast and outside it, as good as none.
        history.op(&label, 1, &[previous.as_str()], assign(*seed, u32::from(*host).to_be_bytes()));
        previous = label;
    }
    let mut roster = Roster::new();
    for entry in history.entries() {
        let _ = roster.offer_bytes(&entry.bytes);
    }
    if !entries.is_empty() {
        for piece in roster::batch::pieces_of(&history.id("batch"), &entries).unwrap() {
            let _ = roster.offer_piece(&piece);
        }
    }
    roster.state().expect("derives")
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig { cases: 128, ..proptest::prelude::ProptestConfig::default() })]

    /// Every answer the view of a state gives is the one the holdings decided
    /// whole give: who holds each address, and what each device holds.
    #[test]
    fn the_view_of_a_state_is_the_holdings_decided_whole(
        alone in proptest::collection::btree_set(3u8..30, 0..12),
        batch in proptest::collection::btree_set(3u8..30, 0..12),
        assigned in proptest::collection::vec((1u8..30, 0u8..18), 0..6),
    ) {
        let alone: Vec<u8> = alone.into_iter().collect();
        let batch: Vec<u8> = batch.into_iter().collect();
        let state = crowded_with(&alone, &batch, &assigned);
        let view = Ipv4Holdings::of_state(&state);
        let whole = Ipv4Holdings::assigned(
            state.params.ipv4_range(),
            state.devices.iter().map(|(device, leaf)| (device, leaf.settings.ipv4)),
        );
        for device in state.devices.keys() {
            proptest::prop_assert_eq!(view.of(&device), whole.of(&device));
        }
        for host in 0..=16u8 {
            let address = std::net::Ipv4Addr::new(10, 0, 0, host);
            proptest::prop_assert_eq!(view.holder(address), whole.holder(address));
        }
        let mut held: Vec<_> = view.held().collect();
        held.sort();
        let mut decided: Vec<_> = whole.held().collect();
        decided.sort();
        proptest::prop_assert_eq!(held, decided);
    }
}

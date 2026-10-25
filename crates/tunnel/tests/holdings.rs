//! IPv4 holdings read only what a snapshot keeps.
//!
//! Admission order is gone once a roster is compacted, so a rule that read it
//! would give a node fed a snapshot different addresses from a node fed the
//! whole history. This builds both nodes from one history, with collisions and
//! revocations on both sides of the snapshot, and compares.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

#[path = "../../roster/tests/support/mod.rs"]
mod support;

use roster::roster::Roster;
use roster::types::{OperationBody, Role};
use support::{History, device, device_id, params};
use tunnel::Ipv4Holdings;

/// A network in a range of fourteen assignable addresses, with more devices
/// than that, so collisions are certain; revocations before and after the
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
        previous = label;
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
    assert!(from_history.colliding().next().is_some(), "the fixture exercises collisions");
    assert!(from_history.held().next().is_some(), "and holdings");
    assert_eq!(from_history.of(&device_id(3)), None, "a revoked device holds nothing");
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

fn assign(device: u8, address: [u8; 4]) -> OperationBody {
    OperationBody::SetDevice {
        device: device_id(device),
        change: roster::leaf::SettingsChange {
            ipv4: Some(Some(address)),
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
fn of_two_concurrent_assignments_of_one_address_the_later_keeps_it() {
    let mut history = founded_in("100.64.0.0/10", &[5, 6]);
    let address = [100, 64, 9, 9];
    history.op("five", 1, &["add6"], assign(5, address));
    history.op("six", 2, &["add6"], assign(6, address));

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
fn an_assigned_address_beats_another_devices_derived_candidate() {
    let history = founded_in("10.0.0.0/28", &[5]);
    let derived = holdings_of(&history).of(&device_id(5)).expect("device 5 holds its candidate");
    let mut history = history;
    history.op("assign", 1, &["add5"], assign(2, derived.octets()));

    let holdings = holdings_of(&history);
    assert_eq!(holdings.holder(derived), Some(device_id(2)));
    assert_eq!(holdings.of(&device_id(5)), None, "the derived candidate loses");
}

#[test]
fn a_revoked_devices_candidate_is_free_for_the_next() {
    // Two seeds deriving one candidate in a narrow range.
    let network = founded_in("10.0.0.0/28", &[]).network();
    let range: roster::types::Ipv4Range = "10.0.0.0/28".parse().unwrap();
    let mut seen: std::collections::BTreeMap<std::net::Ipv4Addr, u8> =
        std::collections::BTreeMap::new();
    let (first, second) = (3..=255_u8)
        .find_map(|seed| {
            let candidate = tunnel::ipv4_candidate(&network, &device_id(seed), &range);
            seen.insert(candidate, seed).map(|earlier| (earlier, seed))
        })
        .expect("sixteen addresses cannot keep 250 devices apart");

    let mut history = founded_in("10.0.0.0/28", &[first]);
    let added = format!("add{first}");
    history.op(
        "revoke",
        1,
        &[added.as_str()],
        OperationBody::RevokeDevice { device: device_id(first), reason: "sold".into() },
    );
    history.op(
        "next",
        1,
        &["revoke"],
        OperationBody::AddDevice(device(second, "next", Role::Member, false)),
    );
    let candidate = tunnel::ipv4_candidate(&network, &device_id(second), &range);
    assert_eq!(holdings_of(&history).of(&device_id(second)), Some(candidate));
}

#[test]
fn a_batch_assigns_from_its_block_and_nothing_collides() {
    let mut history = founded_in("100.70.0.0/16", &[]);
    let entries: Vec<roster::batch::BatchEntry> = (0..1000_u32)
        .map(|index| {
            let mut seed = [0_u8; 32];
            seed[..4].copy_from_slice(&index.to_be_bytes());
            seed[31] = 0xb0;
            let signing = roster::sign::Ed25519Signer::from_seed(seed);
            seed[30] = 1;
            let attesting = roster::sign::Ed25519Signer::from_seed(seed);
            use roster::sign::Signer as _;
            use roster::types::{Algorithm, KeyEntry, KeyPurpose};
            let mut keys = vec![
                KeyEntry::new(
                    Algorithm::Ed25519,
                    KeyPurpose::Signing,
                    signing.public_key().as_bytes().to_vec(),
                )
                .unwrap(),
                KeyEntry::new(
                    Algorithm::Ed25519,
                    KeyPurpose::Attestation,
                    attesting.public_key().as_bytes().to_vec(),
                )
                .unwrap(),
            ];
            keys.sort_by_key(KeyEntry::order_key);
            let [_, _, high, low] = (index + 10).to_be_bytes();
            roster::batch::BatchEntry {
                keys,
                name: format!("sensor-{index}"),
                serial: Vec::new(),
                ipv4: Some([100, 70, high, low]),
            }
        })
        .collect();
    let header = roster::batch::BatchHeader::for_entries(
        &entries,
        roster::leaf::Mode::Light,
        Vec::new(),
        Some("100.70.0.0/16".parse().unwrap()),
        "lot",
    )
    .unwrap();
    history.op("batch", 1, &["admin2"], OperationBody::AdmitBatch(header));

    let mut roster = Roster::new();
    for entry in history.entries() {
        let _ = roster.offer_bytes(&entry.bytes);
    }
    for piece in roster::batch::pieces_of(&history.id("batch"), &entries).unwrap() {
        let _ = roster.offer_piece(&piece);
    }
    let holdings = Ipv4Holdings::of_state(&roster.state().unwrap());
    for entry in &entries {
        let address = entry.ipv4.unwrap();
        assert_eq!(holdings.of(&entry.device_id().unwrap()), Some(address.into()));
    }
    assert!(
        entries.iter().all(|entry| holdings.collision(&entry.device_id().unwrap()).is_none()),
        "no entry collides"
    );
}

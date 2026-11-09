//! Derivation with batches as layers, held to the reference that resolves a
//! batch's every device one by one (`scalable-membership` 16.3).
//!
//! The layered derivation does less: it resolves only the devices something
//! besides their batch names, and reads the rest from the batch's layer. The
//! argument that this is the same answer is the kind that convinces and is
//! wrong, so it is not the acceptance criterion — this file is. Two admins act
//! side by side, often concurrently, over a small pool of boards that batches,
//! single admissions, revocations, renames and settings keep colliding on, and
//! after every operation and every piece taken the state derived, the state
//! kept and the reference are one. The founder signs roots along the way, and
//! a second roster taking the same compacts beneath them whenever it may, so
//! that its base is itself a state with layers and changes: it must agree with
//! the one that compacts nothing.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod support;

use proptest::prelude::*;
use roster::batch::{BatchEntry, BatchHeader, OffsetRun, pieces_of};
use roster::id::DeviceId;
use roster::leaf::{Mode, SettingsChange};
use roster::roster::Roster;
use roster::sign::Signer as _;
use roster::snapshot::{Covering, Snapshot, sign_snapshot};
use roster::state::{RosterState, derive, derive_reference};
use roster::types::{DeviceSpec, OperationBody, Role};
use support::{History, device};

/// How many boards the steps choose among: few, so that they collide.
const BOARDS: u8 = 8;

/// A board's keys, from its seed: seeds clear of the admins'.
fn board_spec(board: u8) -> DeviceSpec {
    let seed = board.wrapping_add(40);
    let keys = device(seed, "board", Role::Member, false).keys;
    DeviceSpec::new(keys, format!("board-{board}"), Role::Member, false, Vec::new()).unwrap()
}

fn board_id(board: u8) -> DeviceId {
    board_spec(board).device_id().unwrap()
}

/// One of a few offsets, the last outside every batch's run.
fn address(choice: u8) -> [u8; 4] {
    match choice % 4 {
        3 => 200_u32.to_be_bytes(),
        other => [0, 0, 0, other.saturating_add(1)],
    }
}

/// What a step does, and who signs it.
#[derive(Debug, Clone)]
enum Act {
    /// A batch of these boards, each with an address or not, in this mode.
    Batch(Vec<(u8, Option<u8>)>, bool),
    /// One board admitted alone.
    Add(u8),
    /// A board revoked.
    Revoke(u8),
    /// A board renamed.
    Rename(u8, u8),
    /// A board assigned an address, or its address taken away.
    Assign(u8, Option<u8>),
    /// A board switched to full or light.
    Mode(u8, bool),
    /// A board promoted to admin, or demoted.
    Role(u8, bool),
    /// The second admin revoked, by the founder.
    RevokeAdmin,
    /// The founder signs a root over the heads.
    Root,
}

#[derive(Debug, Clone)]
struct Step {
    /// The second admin signs it, rather than the founder.
    second: bool,
    /// It names both admins' last operations as parents, joining their lines,
    /// rather than its author's own last one.
    joins: bool,
    act: Act,
}

fn act_strategy() -> impl Strategy<Value = Act> {
    let board = 0..BOARDS;
    prop_oneof![
        3 => (prop::collection::vec((0..BOARDS, prop::option::of(0u8..4)), 1..6), any::<bool>())
            .prop_map(|(entries, light)| Act::Batch(entries, light)),
        1 => board.clone().prop_map(Act::Add),
        2 => board.clone().prop_map(Act::Revoke),
        1 => (board.clone(), any::<u8>()).prop_map(|(board, tag)| Act::Rename(board, tag)),
        2 => (board.clone(), prop::option::of(0u8..4)).prop_map(|(board, to)| Act::Assign(board, to)),
        1 => (board.clone(), any::<bool>()).prop_map(|(board, light)| Act::Mode(board, light)),
        1 => (board, any::<bool>()).prop_map(|(board, up)| Act::Role(board, up)),
        1 => Just(Act::RevokeAdmin),
        2 => Just(Act::Root),
    ]
}

fn step_strategy() -> impl Strategy<Value = Step> {
    (any::<bool>(), prop::bool::weighted(0.3), act_strategy())
        .prop_map(|(second, joins, act)| Step { second, joins, act })
}

/// What the layered derivation, the kept state and the reference say, side by
/// side: the bytes the root commits to, and the revoked set, which it does
/// not.
fn agree(roster: &Roster, after: &str) {
    let reference = derive_reference(roster.dag()).ok();
    let derived = derive(roster.dag()).ok();
    let kept = roster.state().ok();
    let bytes = |state: &Option<RosterState>| state.as_ref().map(RosterState::to_bytes);
    let revoked = |state: &Option<RosterState>| state.as_ref().map(|state| state.revoked.clone());
    assert_eq!(
        bytes(&derived),
        bytes(&reference),
        "after {after}, derivation is not the reference"
    );
    assert_eq!(revoked(&derived), revoked(&reference), "after {after}, the revoked set differs");
    assert_eq!(
        bytes(&kept),
        bytes(&reference),
        "after {after}, the kept state is not the reference"
    );
    assert_eq!(revoked(&kept), revoked(&reference), "after {after}, the kept revoked set differs");
    // The lowest offsets free, found in one pass over the indexes, are those
    // asking each offset finds: in the derived state, the kept one, and the
    // reference's, and for runs as well as one. A listing begins after any
    // member as the whole one goes on, over the batches' layers too, and the
    // admins asked of the indexes are those a pass finds.
    for state in [&derived, &kept, &reference].into_iter().flatten() {
        let ids: Vec<DeviceId> = state.devices.keys().collect();
        for (at, from) in core::iter::once(None).chain(ids.iter().copied().map(Some)).enumerate() {
            let rest: Vec<DeviceId> =
                state.devices.iter_after(from).map(|(device, _)| device).collect();
            assert_eq!(
                rest,
                ids.get(at..).unwrap_or_default(),
                "after {after}, a listing after {at}"
            );
        }
        let admins: Vec<DeviceId> =
            ids.iter().copied().filter(|device| state.is_admin(device)).collect();
        assert_eq!(state.devices.admins(), admins, "after {after}, the admins");
        for count in [1_u32, 2, 3, 6] {
            assert_eq!(
                state.free_offsets(count),
                state.free_offsets_by_lookup(count),
                "after {after}, the lowest {count} offsets free differ"
            );
        }
    }
}

/// How far behind the frontier an operation may be anchored, in both rosters:
/// shallow, so that compaction is often allowed.
const STALENESS: u64 = 2;

/// The founder's root over `roster`'s heads, signed with its attestation key,
/// following the root `roster` holds: what an admin's daemon signs after an
/// act. `None` where the founder is no admin in either.
fn root_over_heads(roster: &Roster) -> Option<Vec<u8>> {
    let state = roster.state().ok()?;
    let heads = roster.heads();
    let dag = roster.dag();
    let depths = heads
        .iter()
        .map(|head| dag.position(head).map(|index| dag.depth(index)))
        .collect::<Option<Vec<u64>>>()?;
    let previous = match roster.snapshot() {
        None => None,
        Some(held) => Some((held.body(), roster.snapshot_state()?)),
    };
    let attesting = support::signer(201);
    let body =
        Snapshot::over(&state, Covering { heads, depths }, attesting.key_id(), previous).ok()?;
    sign_snapshot(&body, &attesting).ok()
}

/// Both rosters agree with the reference, and with each other.
fn both_agree(whole: &Roster, compacted: &Roster, after: &str) {
    agree(whole, after);
    agree(compacted, &format!("{after}, compacted"));
    assert_eq!(
        whole.state().ok().map(|state| state.to_bytes()),
        compacted.state().ok().map(|state| state.to_bytes()),
        "after {after}, compacting changed the state"
    );
}

/// Plays `steps` into two rosters, one compacting whenever it may, checking
/// after every operation, piece and root.
fn play(steps: &[Step]) {
    play_in(steps, false);
    play_in(steps, true);
}

/// [`play`], with the batches' layers in memory or in a store.
fn play_in(steps: &[Step], stored: bool) {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("admin2", 1, &["g"], OperationBody::AddDevice(device(2, "pc", Role::Admin, false)));
    let mut roster = Roster::with_staleness_depth(STALENESS);
    let mut compacted = Roster::with_staleness_depth(STALENESS);
    let stores = [
        std::sync::Arc::new(support::MemoryLayers::default()),
        std::sync::Arc::new(support::MemoryLayers::default()),
    ];
    if stored {
        let [one, two] = &stores;
        roster.keep_layers_in(
            std::sync::Arc::clone(one) as std::sync::Arc<dyn roster::members::LayerStore>
        );
        compacted.keep_layers_in(
            std::sync::Arc::clone(two) as std::sync::Arc<dyn roster::members::LayerStore>
        );
    }
    for entry in history.entries() {
        assert!(roster.offer_bytes(&entry.bytes).is_accepted());
        assert!(compacted.offer_bytes(&entry.bytes).is_accepted());
    }
    // Each admin's last operation taken: its line.
    let mut tips = ["admin2".to_owned(), "admin2".to_owned()];
    for (index, step) in steps.iter().enumerate() {
        let label = format!("s{index}");
        if matches!(step.act, Act::Root) {
            if let Some(root) = root_over_heads(&roster) {
                let _ = roster.offer_snapshot(&root);
                let _ = compacted.offer_snapshot(&root);
                let _ = compacted.compact();
            }
            both_agree(&roster, &compacted, &format!("{label}, a root"));
            continue;
        }
        let author = if step.second { 2 } else { 1 };
        let line = usize::from(step.second);
        // A join names the heads, as a daemon's act does. Naming an old
        // operation beside a new one is what an honest author never signs, and
        // what a node that compacted cannot place while one that did not
        // takes it: a gap of its own, recorded in `scalable-membership` 16.3.
        let parents: Vec<String> = if step.joins {
            let heads = roster.heads();
            history
                .labels()
                .into_iter()
                .filter(|label| heads.contains(&history.id(label)))
                .collect()
        } else {
            vec![tips.get(line).cloned().unwrap()]
        };
        let parents: Vec<&str> = parents.iter().map(String::as_str).collect();
        let setting = |board: u8, change: SettingsChange| OperationBody::SetDevice {
            device: board_id(board),
            change,
        };
        let mut entries = Vec::new();
        let body = match &step.act {
            Act::Batch(chosen, light) => {
                let mut seen = Vec::new();
                entries = chosen
                    .iter()
                    // A header refuses a device twice in one batch.
                    .filter(|(board, _)| {
                        let fresh = !seen.contains(board);
                        seen.push(*board);
                        fresh
                    })
                    .map(|(board, at)| {
                        let spec = board_spec(*board);
                        BatchEntry {
                            keys: spec.keys,
                            name: spec.name,
                            serial: vec![*board],
                            ipv4: at.map(address),
                        }
                    })
                    .collect();
                let mode = if *light { Mode::Light } else { Mode::Full };
                // From the first host, as long as the batch: a short batch
                // leaves the higher offsets outside it.
                let count = u32::try_from(entries.len()).unwrap();
                let block = Some(OffsetRun::new(1_u32.to_be_bytes(), count).unwrap());
                OperationBody::AdmitBatch(
                    BatchHeader::for_entries(
                        &entries,
                        mode,
                        Vec::new(),
                        block,
                        format!("lot {index}"),
                    )
                    .unwrap(),
                )
            }
            Act::Add(board) => OperationBody::AddDevice(board_spec(*board)),
            Act::Revoke(board) => {
                OperationBody::RevokeDevice { device: board_id(*board), reason: "gone".to_owned() }
            }
            Act::Rename(board, tag) => {
                OperationBody::Rename { device: board_id(*board), name: format!("renamed-{tag}") }
            }
            Act::Assign(board, to) => setting(
                *board,
                SettingsChange { ipv4: Some(to.map(address)), ..SettingsChange::default() },
            ),
            Act::Mode(board, light) => setting(
                *board,
                SettingsChange {
                    mode: Some(if *light { Mode::Light } else { Mode::Full }),
                    ..SettingsChange::default()
                },
            ),
            Act::Role(board, up) => {
                if *up {
                    OperationBody::Promote { device: board_id(*board), founder: false }
                } else {
                    OperationBody::Demote { device: board_id(*board) }
                }
            }
            Act::RevokeAdmin => OperationBody::RevokeDevice {
                device: support::device_id(2),
                reason: "gone".to_owned(),
            },
            Act::Root => unreachable!("taken above"),
        };
        history.op(&label, author, &parents, body);
        let admission = roster.offer_bytes(&history.bytes(&label));
        let _ = compacted.offer_bytes(&history.bytes(&label));
        if admission.is_accepted()
            || matches!(admission, roster::roster::Admission::AwaitingPieces(_))
        {
            if let Some(tip) = tips.get_mut(line) {
                *tip = label.clone();
            }
            if step.joins {
                tips = [label.clone(), label.clone()];
            }
        }
        both_agree(&roster, &compacted, &label);
        if !entries.is_empty() {
            for (number, piece) in
                pieces_of(&history.id(&label), &entries).unwrap().iter().enumerate()
            {
                let _ = roster.offer_piece(piece);
                let _ = compacted.offer_piece(piece);
                both_agree(&roster, &compacted, &format!("{label}, piece {number}"));
            }
        }
    }
    for store in &stores {
        assert_eq!(store.told(), 0, "an honest store is never told it lied");
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn layered_derivation_is_the_reference(steps in prop::collection::vec(step_strategy(), 1..24)) {
        play(&steps);
    }
}

/// The cases that matter most, fixed, so a change that breaks one names it.
#[test]
fn a_board_a_batch_admits_and_another_operation_names() {
    let at = |board: u8, address: Option<u8>| (board, address);
    play(&[
        Step {
            second: false,
            joins: false,
            act: Act::Batch(vec![at(0, Some(0)), at(1, None), at(2, Some(1))], true),
        },
        Step {
            second: true,
            joins: false,
            act: Act::Batch(vec![at(1, None), at(3, Some(0))], false),
        },
        Step { second: false, joins: false, act: Act::Rename(0, 7) },
        Step { second: true, joins: false, act: Act::Revoke(2) },
        Step { second: false, joins: true, act: Act::Assign(1, Some(1)) },
        Step { second: true, joins: false, act: Act::Role(3, true) },
        Step { second: false, joins: false, act: Act::RevokeAdmin },
        Step {
            second: false,
            joins: true,
            act: Act::Batch(vec![at(2, Some(2)), at(4, None)], true),
        },
    ]);
}

/// A base that is itself a state with a layer and changes: compacted beneath a
/// root over a batch and a rename, then a batch admitting a board that base
/// removed.
#[test]
fn a_batch_over_a_base_that_holds_a_layer_and_changes() {
    let at = |board: u8, address: Option<u8>| (board, address);
    let mut steps = vec![
        Step {
            second: false,
            joins: false,
            act: Act::Batch(vec![at(0, Some(0)), at(1, None), at(2, None)], true),
        },
        Step { second: false, joins: false, act: Act::Rename(1, 3) },
        Step { second: false, joins: false, act: Act::Revoke(2) },
        Step { second: false, joins: false, act: Act::Root },
    ];
    for tag in 0..4 {
        steps.push(Step { second: false, joins: false, act: Act::Rename(0, tag) });
        steps.push(Step { second: false, joins: false, act: Act::Root });
    }
    steps.push(Step {
        second: false,
        joins: false,
        act: Act::Batch(vec![at(2, Some(1)), at(1, None), at(5, None)], false),
    });
    steps.push(Step { second: true, joins: false, act: Act::Assign(5, Some(0)) });
    steps.push(Step { second: false, joins: true, act: Act::Root });
    play(&steps);
}

/// A store changed behind the daemon's back can hide a board, never add one
/// or change what one holds, and is told that it lied.
#[test]
fn an_altered_layer_store_hides_and_is_told() {
    let store = std::sync::Arc::new(support::MemoryLayers::default());
    let mut roster = Roster::new();
    roster.keep_layers_in(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn roster::members::LayerStore>
    );
    let mut history = History::new();
    history.genesis("g", 1);
    let entries: Vec<BatchEntry> = (0..3)
        .map(|board| {
            let spec = board_spec(board);
            BatchEntry { keys: spec.keys, name: spec.name, serial: vec![board], ipv4: None }
        })
        .collect();
    let header = BatchHeader::for_entries(&entries, Mode::Light, Vec::new(), None, "lot").unwrap();
    history.op("batch", 1, &["g"], OperationBody::AdmitBatch(header));
    for entry in history.entries() {
        let _ = roster.offer_bytes(&entry.bytes);
    }
    for piece in pieces_of(&history.id("batch"), &entries).unwrap() {
        let _ = roster.offer_piece(&piece);
    }
    let before = roster.state().unwrap();
    assert!(before.devices.get(&board_id(0)).is_some());
    assert_eq!(store.told(), 0);

    // Board 0's entry given another name, and a stranger's entry slipped in.
    let mut renamed = entries.first().unwrap().clone();
    renamed.name = "someone-else".to_owned();
    store.alter(&history.id("batch"), &board_id(0), renamed);
    let stranger = board_spec(7);
    store.alter(
        &history.id("batch"),
        &board_id(7),
        BatchEntry { keys: stranger.keys, name: stranger.name, serial: vec![7], ipv4: None },
    );

    let state = roster.state().unwrap();
    assert!(state.devices.get(&board_id(0)).is_none(), "the altered board is hidden");
    assert!(state.devices.named("someone-else").is_empty(), "under no name");
    assert!(state.devices.get(&board_id(7)).is_none(), "the stranger is not added");
    assert!(!state.devices.keys().any(|device| device == board_id(7)), "nor walked");
    assert!(state.devices.get(&board_id(1)).is_some(), "the others stand");
    assert_eq!(state.root(), before.root(), "and the root is the batch's");
    assert!(store.told() > 0, "the store is told it lied");
}

/// A whole pass over a stored layer checks the batch at once against its
/// signed root, and gives what a pass checking each entry gives: everything,
/// where the store is honest; and, where it is not, the altered board hidden,
/// the stranger left out, and the store told.
#[test]
fn a_whole_pass_over_a_stored_layer_is_checked_as_each_entry_is() {
    let store = std::sync::Arc::new(support::MemoryLayers::default());
    let mut roster = Roster::new();
    roster.keep_layers_in(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn roster::members::LayerStore>
    );
    let mut history = History::new();
    history.genesis("g", 1);
    let entries: Vec<BatchEntry> = (0..5)
        .map(|board| {
            let spec = board_spec(board);
            BatchEntry { keys: spec.keys, name: spec.name, serial: vec![board], ipv4: None }
        })
        .collect();
    let header = BatchHeader::for_entries(&entries, Mode::Light, Vec::new(), None, "lot").unwrap();
    history.op("batch", 1, &["g"], OperationBody::AdmitBatch(header));
    for entry in history.entries() {
        let _ = roster.offer_bytes(&entry.bytes);
    }
    for piece in pieces_of(&history.id("batch"), &entries).unwrap() {
        let _ = roster.offer_piece(&piece);
    }
    let state = roster.state().unwrap();
    let (layer, _) = state.devices.layers().next().expect("the batch's layer");
    let each: Vec<DeviceId> = layer.devices().map(|(device, _)| device).collect();
    let whole: Vec<DeviceId> = layer.all_devices().into_iter().map(|(device, _)| device).collect();
    assert_eq!(whole, each, "the same devices, in the same order");
    assert_eq!(whole.len(), 5);
    assert_eq!(store.told(), 0, "an honest store is never told");

    let mut renamed = entries.get(2).unwrap().clone();
    renamed.name = "someone-else".to_owned();
    store.alter(&history.id("batch"), &board_id(2), renamed);
    let stranger = board_spec(7);
    store.alter(
        &history.id("batch"),
        &board_id(7),
        BatchEntry { keys: stranger.keys, name: stranger.name, serial: vec![7], ipv4: None },
    );
    let whole: Vec<DeviceId> = layer.all_devices().into_iter().map(|(device, _)| device).collect();
    assert!(!whole.contains(&board_id(2)), "the altered board is hidden");
    assert!(!whole.contains(&board_id(7)), "the stranger is not added");
    assert_eq!(whole.len(), 4, "the others stand");
    assert!(store.told() > 0, "and the store is told it lied");
}

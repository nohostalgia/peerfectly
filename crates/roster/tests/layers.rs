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
use roster::batch::{BatchEntry, BatchHeader, pieces_of};
use roster::id::DeviceId;
use roster::leaf::{Mode, SettingsChange};
use roster::roster::Roster;
use roster::sign::Signer as _;
use roster::snapshot::{Covering, Snapshot, sign_snapshot};
use roster::state::{RosterState, derive, derive_reference};
use roster::types::{DeviceSpec, Ipv4Range, OperationBody, Role};
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

/// One of a few addresses, the last outside the batches' block.
fn address(choice: u8) -> [u8; 4] {
    match choice % 4 {
        3 => [10, 9, 9, 9],
        other => [100, 70, 0, other.saturating_add(1)],
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
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("admin2", 1, &["g"], OperationBody::AddDevice(device(2, "pc", Role::Admin, false)));
    let mut roster = Roster::with_staleness_depth(STALENESS);
    let mut compacted = Roster::with_staleness_depth(STALENESS);
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
                let block = Some(Ipv4Range::new([100, 70, 0, 0], 16).unwrap());
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

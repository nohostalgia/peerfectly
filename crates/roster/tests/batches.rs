//! Admitting many devices with one signature: the header, its entries, and the
//! pieces they travel in.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod support;

use roster::batch::{BatchEntry, BatchHeader, BatchPiece, Skip, entries_tree, pieces_of, skipped};
use roster::cbor::is_canonical_schema;
use roster::id::OperationId;
use roster::leaf::{Group, Mode};
use roster::limits::MAX_OPERATION_SIZE;
use roster::roster::{
    Admission, MAX_INCOMPLETE_BATCHES, PieceAdmission, Roster, URGENT_BATCH_AGE_MS,
};
use roster::sign::{Ed25519Signer, Signer as _};
use roster::types::{Algorithm, KeyEntry, KeyPurpose};
use roster::types::{OperationBody, Role};
use support::{History, device};

/// The entry a board numbered `index` would give the production station.
fn entry(index: u32) -> BatchEntry {
    let mut seed = [0_u8; 32];
    seed[..4].copy_from_slice(&index.to_be_bytes());
    let signing = Ed25519Signer::from_seed(seed);
    seed[4] = 1;
    let attesting = Ed25519Signer::from_seed(seed);
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
    BatchEntry {
        keys,
        name: format!("sensor-{index}"),
        serial: format!("SN{index:06}").into_bytes(),
        ipv4: Some([
            100,
            70,
            u8::try_from(index / 256).unwrap(),
            u8::try_from(index % 256).unwrap(),
        ]),
    }
}

fn lot(count: u32) -> (Vec<BatchEntry>, BatchHeader) {
    let entries: Vec<BatchEntry> = (0..count).map(entry).collect();
    let header = BatchHeader::for_entries(
        &entries,
        Mode::Light,
        vec![Group::new("sensori").unwrap()],
        Some(roster::types::Ipv4Range::new([100, 70, 0, 0], 16).unwrap()),
        "lot A",
    )
    .unwrap();
    (entries, header)
}

#[test]
fn the_schemas_are_canonical() {
    assert!(is_canonical_schema(roster::batch::BATCH_ENTRY_SCHEMA));
    assert!(is_canonical_schema(roster::batch::BATCH_PIECE_SCHEMA));
}

#[test]
fn five_hundred_entries_travel_in_pieces_each_within_an_operation() {
    let (entries, header) = lot(500);
    let batch = OperationId::from_bytes([9; 32]);
    let pieces = pieces_of(&batch, &entries).unwrap();
    assert!(pieces.len() > 1);
    let mut received = Vec::new();
    for piece in &pieces {
        assert!(piece.len() <= MAX_OPERATION_SIZE, "a piece of {} bytes", piece.len());
        assert_eq!(BatchPiece::batch_of(piece).unwrap(), batch);
        received.extend(BatchPiece::verified(piece, &batch, &header).unwrap().entries);
    }
    let mut sent = entries.clone();
    received.sort_by(|a, b| a.name.cmp(&b.name));
    sent.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(received, sent, "every entry arrives, once, as it was");
}

#[test]
fn a_forged_piece_is_refused_on_arrival() {
    let (entries, header) = lot(40);
    let batch = OperationId::from_bytes([9; 32]);
    // A piece built over different entries: its proofs lead to another root.
    let mut forged_entries = entries.clone();
    if let Some(first) = forged_entries.first_mut() {
        first.name = "intruder".to_owned();
    }
    let forged = pieces_of(&batch, &forged_entries).unwrap();
    let refused = forged.iter().any(|piece| BatchPiece::verified(piece, &batch, &header).is_err());
    assert!(refused, "an entry not in the signed root is refused");
}

#[test]
fn a_piece_of_another_batch_is_refused() {
    let (entries, header) = lot(10);
    let pieces = pieces_of(&OperationId::from_bytes([9; 32]), &entries).unwrap();
    let piece = pieces.first().unwrap();
    assert!(BatchPiece::verified(piece, &OperationId::from_bytes([8; 32]), &header).is_err());
}

#[test]
fn a_device_twice_in_one_batch_is_refused() {
    let entries = vec![entry(1), entry(1)];
    assert!(entries_tree(&entries).is_err());
}

/// A founded network, `g`, with a second admin, `admin2`.
fn founded() -> History {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("admin2", 1, &["g"], OperationBody::AddDevice(device(2, "pc", Role::Admin, false)));
    history
}

fn loaded(history: &History) -> Roster {
    let mut roster = Roster::new();
    for entry in history.entries() {
        let _ = roster.offer_bytes(&entry.bytes);
    }
    roster
}

/// A founded network with a 60-entry lot's header signed under `batch`.
fn with_header() -> (History, Vec<BatchEntry>) {
    let (entries, header) = lot(60);
    let mut history = founded();
    history.op("batch", 1, &["admin2"], OperationBody::AdmitBatch(header));
    (history, entries)
}

#[test]
fn a_header_without_its_pieces_admits_nobody() {
    let (history, entries) = with_header();
    let roster = loaded(&history);
    assert_eq!(roster.awaiting_pieces(), vec![history.id("batch")]);
    let state = roster.state().unwrap();
    assert!(!state.devices.contains_key(&entries.first().unwrap().device_id().unwrap()));
    assert_eq!(state.devices.len(), 2, "the founder and the second admin only");
}

#[test]
fn once_every_piece_is_in_the_batch_admits_every_entry_in_any_order() {
    let (history, entries) = with_header();
    let batch = history.id("batch");
    let pieces = pieces_of(&batch, &entries).unwrap();
    assert!(pieces.len() > 1, "enough pieces for the order to matter");

    let mut forward = loaded(&history);
    let before = forward.state().unwrap().root();
    let (last, rest) = pieces.split_last().unwrap();
    for piece in rest {
        assert_eq!(forward.offer_piece(piece), PieceAdmission::Taken { batch, complete: false });
        assert_eq!(forward.state().unwrap().root(), before, "partial pieces change nothing");
    }
    assert_eq!(forward.offer_piece(last), PieceAdmission::Taken { batch, complete: true });
    assert!(forward.awaiting_pieces().is_empty());
    assert_eq!(forward.offer_piece(last), PieceAdmission::AlreadyHeld { batch });

    let state = forward.state().unwrap();
    assert_eq!(state.devices.len(), 62);
    let first = entries.first().unwrap().device_id().unwrap();
    let settings = state.settings_of(&first);
    assert_eq!(settings.mode, Mode::Light, "the header's mode");
    assert_eq!(settings.groups, vec![Group::new("sensori").unwrap()], "the header's groups");
    assert_eq!(settings.ipv4, entries.first().unwrap().ipv4, "the entry's address");
    assert_eq!(state.devices.get(&first).unwrap().role, Role::Member);

    let mut backward = loaded(&history);
    for piece in pieces.iter().rev() {
        let _ = backward.offer_piece(piece);
    }
    assert_eq!(backward.state().unwrap().root(), state.root(), "in either order");
    // The cut is canonical, so what it hands on are the bytes its author sent.
    let handed: Vec<Vec<u8>> =
        forward.pieces_held(&batch).into_iter().map(|(_, piece)| piece).collect();
    assert_eq!(handed, pieces, "and it can hand them on");
}

#[test]
fn a_piece_before_its_header_is_refused() {
    let (history, entries) = with_header();
    let pieces = pieces_of(&history.id("batch"), &entries).unwrap();
    let mut roster = Roster::new();
    for entry in history.entries().iter().filter(|entry| entry.label != "batch") {
        let _ = roster.offer_bytes(&entry.bytes);
    }
    assert!(matches!(roster.offer_piece(pieces.first().unwrap()), PieceAdmission::Refused { .. }));
}

#[test]
fn a_header_whose_count_understates_its_tree_never_completes() {
    let (entries, honest) = lot(60);
    let understated = BatchHeader::new(
        roster::batch::Commitment { count: 59, ..honest.commitment() },
        honest.mode,
        honest.groups.clone(),
        honest.block,
        honest.label.clone(),
    )
    .unwrap();
    let mut history = founded();
    history.op("batch", 1, &["admin2"], OperationBody::AdmitBatch(understated));
    let mut roster = loaded(&history);
    let mut refused = false;
    for piece in pieces_of(&history.id("batch"), &entries).unwrap() {
        refused |= matches!(roster.offer_piece(&piece), PieceAdmission::Refused { .. });
    }
    assert!(refused);
    assert_eq!(roster.state().unwrap().devices.len(), 2, "nobody admitted");
}

#[test]
fn an_operation_after_an_incomplete_batch_waits_with_it() {
    let (mut history, entries) = with_header();
    history.op(
        "after",
        1,
        &["batch"],
        OperationBody::AddDevice(device(3, "phone", Role::Member, false)),
    );
    let mut roster = loaded(&history);
    assert_eq!(roster.state().unwrap().devices.len(), 2);
    for piece in pieces_of(&history.id("batch"), &entries).unwrap() {
        let _ = roster.offer_piece(&piece);
    }
    assert_eq!(roster.heads(), vec![history.id("after")]);
    assert_eq!(roster.state().unwrap().devices.len(), 63);
}

#[test]
fn only_a_bounded_number_of_batches_wait_at_once() {
    // One header more than the bound, each from a different admin and all
    // concurrent: a header waiting on another would wait as an ordinary
    // operation does, for its parent.
    let mut history = History::new();
    history.genesis("g", 1);
    let mut parent = "g".to_owned();
    let authors: Vec<u8> = (1..=u8::try_from(MAX_INCOMPLETE_BATCHES + 1).unwrap()).collect();
    for author in authors.iter().skip(1) {
        let label = format!("admin{author}");
        let body = OperationBody::AddDevice(device(*author, "pc", Role::Admin, false));
        history.op(&label, 1, &[parent.as_str()], body);
        parent = label;
    }
    for author in &authors {
        let (_, header) = lot(u32::from(*author) + 1);
        history.op(
            &format!("batch{author}"),
            *author,
            &[parent.as_str()],
            OperationBody::AdmitBatch(header),
        );
    }
    let mut roster = Roster::new();
    let mut outcomes = Vec::new();
    for entry in history.entries() {
        outcomes.push(roster.offer_bytes(&entry.bytes));
    }
    assert_eq!(roster.awaiting_pieces().len(), MAX_INCOMPLETE_BATCHES);
    assert!(matches!(outcomes.last(), Some(Admission::Refused { .. })), "{outcomes:?}");
}

#[test]
fn one_duplicate_in_five_hundred_is_skipped_and_reported_and_the_rest_stand() {
    let (entries, header) = lot(500);
    let duplicate = entries.get(7).unwrap().clone();
    let duplicate_id = duplicate.device_id().unwrap();
    let mut history = founded();
    // Already a member, admitted on its own before the batch was signed.
    history.op("single", 1, &["admin2"], OperationBody::AddDevice(duplicate.spec().unwrap()));
    // And another device already holds the address entry 9 was assigned.
    let holder = roster::leaf::SettingsChange {
        ipv4: Some(entries.get(9).unwrap().ipv4),
        ..roster::leaf::SettingsChange::default()
    };
    history.op(
        "address",
        1,
        &["single"],
        OperationBody::SetDevice { device: support::device_id(2), change: holder },
    );

    // What the admin's device shows before signing.
    let before = loaded(&history).state().unwrap();
    let preview = skipped(&before, &header, &entries);
    let taken_id = entries.get(9).unwrap().device_id().unwrap();
    assert_eq!(preview.len(), 2, "{preview:?}");
    assert_eq!(preview.get(&duplicate_id), Some(&Skip::AlreadyMember));
    assert_eq!(preview.get(&taken_id), Some(&Skip::AddressTaken));

    history.op("batch", 1, &["address"], OperationBody::AdmitBatch(header));
    let mut roster = loaded(&history);
    for piece in pieces_of(&history.id("batch"), &entries).unwrap() {
        let _ = roster.offer_piece(&piece);
    }
    let state = roster.state().unwrap();
    assert_eq!(state.devices.len(), 2 + 1 + 498, "the founder, admin2, the single and 498");
    assert_eq!(
        state.devices.get(&duplicate_id).unwrap().added_by,
        history.id("single"),
        "the member keeps the record it had"
    );
    assert!(!state.devices.contains_key(&taken_id), "the address stays with its holder");
    let reversed = roster::state::derive(roster.dag()).unwrap();
    assert_eq!(reversed.root(), state.root(), "a full derivation agrees");
}

#[test]
fn an_address_outside_the_block_is_skipped() {
    let (mut entries, _) = lot(3);
    if let Some(first) = entries.first_mut() {
        first.ipv4 = Some([10, 0, 0, 1]);
    }
    let header = BatchHeader::for_entries(
        &entries,
        Mode::Light,
        Vec::new(),
        Some(roster::types::Ipv4Range::new([100, 70, 0, 0], 16).unwrap()),
        "lot B",
    )
    .unwrap();
    let state = loaded(&founded()).state().unwrap();
    let skips = skipped(&state, &header, &entries);
    assert_eq!(
        skips.get(&entries.first().unwrap().device_id().unwrap()),
        Some(&Skip::AddressOutsideBlock)
    );
    assert_eq!(skips.len(), 1);
}

/// The time an operation was signed at, read back from its bytes.
fn signed_at(history: &History, label: &str) -> u64 {
    roster::sign::RawOperation::decode(&history.bytes(label)).unwrap().core().ts
}

#[test]
fn an_urgent_act_is_anchored_off_a_recent_batch() {
    let (history, entries) = with_header();
    let mut roster = loaded(&history);
    for piece in pieces_of(&history.id("batch"), &entries).unwrap() {
        let _ = roster.offer_piece(&piece);
    }
    let member = entries.first().unwrap().device_id().unwrap();
    let at = signed_at(&history, "batch");

    let soon = roster.urgent_anchor(&member, at.saturating_add(1_000));
    assert_eq!(soon.heads, vec![history.id("admin2")], "the batch is left out");
    assert!(soon.voided.is_empty(), "a member's revocation voids nothing of its own");

    let later = roster.urgent_anchor(&member, at.saturating_add(URGENT_BATCH_AGE_MS + 1));
    assert_eq!(later.heads, vec![history.id("batch")], "an old batch is an ancestor like any");
}

#[test]
fn revoking_an_admin_keeps_its_whole_batches_and_reports_what_it_voids() {
    let mut history = founded();
    // In one line of its own acts, admin 2 signs a batch this node holds
    // whole, a rename resting on the founder's recent batch, and a batch this
    // node holds only the header of.
    let (whole_entries, whole) = lot(5);
    history.op("whole", 2, &["admin2"], OperationBody::AdmitBatch(whole));
    let (founders_entries, founders) = lot(7);
    history.op("founders", 1, &["admin2"], OperationBody::AdmitBatch(founders));
    history.op(
        "on-top",
        2,
        &["founders", "whole"],
        OperationBody::Rename { device: support::device_id(2), name: "laptop".to_owned() },
    );
    let (_, partial) = lot(6);
    history.op("partial", 2, &["on-top"], OperationBody::AdmitBatch(partial));
    let mut roster = loaded(&history);
    for piece in pieces_of(&history.id("whole"), &whole_entries).unwrap() {
        let _ = roster.offer_piece(&piece);
    }
    for piece in pieces_of(&history.id("founders"), &founders_entries).unwrap() {
        let _ = roster.offer_piece(&piece);
    }
    assert_eq!(roster.awaiting_pieces(), vec![history.id("partial")]);

    let at = signed_at(&history, "on-top");
    let anchor = roster.urgent_anchor(&support::device_id(2), at.saturating_add(1_000));
    assert_eq!(anchor.heads, vec![history.id("whole")], "its whole batch is kept");
    let voided: Vec<OperationId> = anchor.voided.iter().map(|(id, _)| *id).collect();
    let mut expected = vec![history.id("on-top"), history.id("partial")];
    expected.sort_unstable();
    let mut sorted = voided.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, expected, "what rests on another's recent batch, and what is incomplete");
}

#[test]
fn a_piece_is_checked_on_its_own_and_its_index_cannot_be_forged() {
    let (entries, header) = lot(120);
    let batch = OperationId::from_bytes([9; 32]);
    let pieces = pieces_of(&batch, &entries).unwrap();
    assert_eq!(pieces.len() as u64, header.pieces, "the header counts the canonical cut");
    for (index, piece) in (0_u64..).zip(&pieces) {
        assert_eq!(BatchPiece::verified(piece, &batch, &header).unwrap().index, index);
    }

    // The second piece relabelled as the first: its entries are genuine, but it
    // does not prove as piece 0.
    let second = pieces.get(1).unwrap();
    let relabelled = relabel(second, 0);
    assert!(BatchPiece::verified(&relabelled, &batch, &header).is_err());
}

#[test]
fn the_cut_is_the_same_whatever_order_the_entries_come_in() {
    let (entries, _) = lot(90);
    let mut reversed = entries.clone();
    reversed.reverse();
    let batch = OperationId::from_bytes([9; 32]);
    assert_eq!(pieces_of(&batch, &entries).unwrap(), pieces_of(&batch, &reversed).unwrap());
    assert_eq!(roster::batch::commit(&entries).unwrap(), roster::batch::commit(&reversed).unwrap());
}

/// A piece with its index rewritten, everything else as it was.
fn relabel(piece: &[u8], index: u64) -> Vec<u8> {
    // Map header, "batch" and its 32-byte id, then "index" and a small integer.
    let at =
        piece.windows(5).position(|window| window == b"index").unwrap().checked_add(5).unwrap();
    let mut out = piece.get(..at).unwrap().to_vec();
    out.push(u8::try_from(index).unwrap());
    out.extend_from_slice(piece.get(at.checked_add(1).unwrap()..).unwrap());
    out
}

#[test]
fn the_incomplete_batches_declare_a_bounded_number_of_entries_between_them() {
    // Three headers of the largest batch, from three admins at once: two fill
    // the bound, and the third is refused before anything is stored.
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("admin2", 1, &["g"], OperationBody::AddDevice(device(2, "pc", Role::Admin, false)));
    history.op(
        "admin3",
        1,
        &["admin2"],
        OperationBody::AddDevice(device(3, "pc", Role::Admin, false)),
    );
    for author in 1..=3_u8 {
        history.op(
            &format!("batch{author}"),
            author,
            &["admin3"],
            OperationBody::AdmitBatch(largest(author)),
        );
    }
    let mut roster = Roster::new();
    let outcomes: Vec<Admission> =
        history.entries().iter().map(|entry| roster.offer_bytes(&entry.bytes)).collect();
    assert_eq!(roster.awaiting_pieces().len(), 2);
    assert!(
        matches!(
            outcomes.last(),
            Some(Admission::Refused { reason: roster::error::Error::LimitExceeded(_), .. })
        ),
        "{outcomes:?}"
    );
}

/// A header declaring the largest batch there may be, told apart by `tag`.
fn largest(tag: u8) -> BatchHeader {
    BatchHeader::new(
        roster::batch::Commitment {
            count: 65_536,
            entries: [tag; 32],
            pieces: 1,
            layout: [tag; 32],
        },
        Mode::Light,
        Vec::new(),
        None,
        "lot",
    )
    .unwrap()
}

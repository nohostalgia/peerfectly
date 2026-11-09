//! What a full member's roster holds in memory, part by part, for a fleet
//! admitted in batches (`scalable-membership` 16.2).
//!
//! Run by hand, never in CI:
//! `cargo test -p roster --test memory -- --ignored --nocapture`, at the size
//! `PEERFECTLY_MEMORY_DEVICES` gives (a hundred thousand by default). An
//! allocator counting live bytes and their peak stands under the whole test
//! binary, which holds this test alone.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
#![allow(unsafe_code, reason = "a global allocator is an unsafe trait; this one only counts")]

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use roster::batch::{BatchEntry, BatchHeader, pieces_of};
use roster::leaf::Mode;
use roster::roster::Roster;
use roster::sign::{Ed25519Signer, Signer as _};
use roster::types::{Algorithm, KeyEntry, KeyPurpose, OperationBody, Role};
use support::{History, device};

/// The system allocator, counting what is live and the most that was.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call is passed to the system allocator unchanged; the counters
// only observe it.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as the system allocator's own contract.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let live =
                LIVE.fetch_add(layout.size(), Ordering::Relaxed).saturating_add(layout.size());
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: as the system allocator's own contract.
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// Starts a new peak from what is live now.
fn reset_peak() {
    PEAK.store(live(), Ordering::Relaxed);
}

fn peak() -> usize {
    PEAK.load(Ordering::Relaxed)
}

/// A board's entry, as the production station writes it: three keys, a name
/// and a serial, no address.
fn entry(index: u32) -> BatchEntry {
    let mut seed = [0_u8; 32];
    seed[..4].copy_from_slice(&index.to_be_bytes());
    let mut key = |purpose: KeyPurpose, tag: u8| {
        seed[4] = tag;
        let signer = Ed25519Signer::from_seed(seed);
        KeyEntry::new(Algorithm::Ed25519, purpose, signer.public_key().as_bytes().to_vec()).unwrap()
    };
    let mut keys = vec![
        key(KeyPurpose::Signing, 0),
        key(KeyPurpose::Transport, 1),
        key(KeyPurpose::Attestation, 2),
    ];
    keys.sort_by_key(KeyEntry::order_key);
    BatchEntry {
        keys,
        name: format!("board-{index}"),
        serial: format!("SN{index:07}").into_bytes(),
        ipv4: None,
    }
}

/// Per device, in bytes.
fn per(bytes: usize, devices: usize) -> usize {
    bytes.checked_div(devices).unwrap_or(0)
}

#[test]
#[ignore = "a measurement, run by hand: cargo test -p roster --test memory -- --ignored --nocapture"]
fn what_a_full_member_holds_per_device() {
    let devices: usize = std::env::var("PEERFECTLY_MEMORY_DEVICES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100_000);
    let report = |what: &str, bytes: usize| {
        println!("{what}: {} MB, {} B per device", bytes / 1_000_000, per(bytes, devices));
    };

    let start = live();
    let entries: Vec<BatchEntry> = (0..u32::try_from(devices).unwrap()).map(entry).collect();
    report("the entries, as the station hands them", live() - start);

    let mut history = History::new();
    history.genesis("g", 1);
    history.op("admin2", 1, &["g"], OperationBody::AddDevice(device(2, "pc", Role::Admin, false)));
    let most = usize::try_from(roster::limits::MAX_BATCH_ENTRIES).unwrap();
    let mut lots = Vec::new();
    let mut parent = "admin2".to_owned();
    for (number, lot) in entries.chunks(most).enumerate() {
        let header = BatchHeader::for_entries(lot, Mode::Light, Vec::new(), None, "fleet").unwrap();
        let label = format!("batch{number}");
        history.op(&label, 1, &[parent.as_str()], OperationBody::AdmitBatch(header));
        lots.push((label.clone(), lot));
        parent = label;
    }

    let before = live();
    let mut roster = Roster::new();
    for operation in history.entries() {
        let _ = roster.offer_bytes(&operation.bytes);
    }
    report("the roster, headers parked", live() - before);

    let before = live();
    reset_peak();
    for (label, lot) in &lots {
        for piece in pieces_of(&history.id(label), lot).unwrap() {
            let _ = roster.offer_piece(&piece);
        }
    }
    assert_eq!(roster.state().unwrap().devices.len(), devices + 2, "every board admitted");
    let whole = live() - before;
    report("taking every piece: the graph's entries and the kept state", whole);
    report("  at its peak, over what was live before", peak() - before);

    let before = live();
    let dag = roster.dag().clone();
    report("  of which the graph, copied (its entries included)", live() - before);
    drop(dag);

    let before = live();
    reset_peak();
    let derived = roster::state::derive(roster.dag()).unwrap();
    report("  a state derived afresh, shared with nothing", live() - before);
    report("    deriving it, at its peak", peak() - before);
    let before = live();
    let tree = derived.devices.clone();
    report("    its members copied (shares the tree and the base)", live() - before);
    drop(tree);
    drop(derived);

    let before = live();
    reset_peak();
    let root = {
        let state = roster.state().unwrap();
        let head = history.id(&parent);
        let depth = roster.dag().depth(roster.dag().position(&head).unwrap());
        let author = support::signer(1).key_id();
        let signer = state.device_holding(&author).unwrap();
        let body = roster::snapshot::Snapshot::new(
            1,
            Vec::new(),
            state.root(),
            roster::snapshot::Covering { heads: vec![head], depths: vec![depth] },
            Vec::new(),
            state.leaf(&signer).unwrap(),
            roster::membership::MembershipProof::of(&state, &signer).unwrap(),
            author,
            history.network(),
        )
        .unwrap();
        roster::snapshot::sign_snapshot(&body, &support::signer(1)).unwrap()
    };
    let taken = roster.offer_snapshot(&root);
    assert!(taken.is_accepted(), "the root over it: {taken:?}");
    report("taking a root over it (the state it commits to)", live() - before);
    report("  at its peak", peak() - before);

    drop(entries);
    report("the roster in all, the entries handed back", live() - start);
}

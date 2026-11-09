//! What a full member's roster holds in memory with its batches' layers kept
//! on disk (`scalable-membership` 16.5).
//!
//! Run by hand, never in CI:
//! `cargo test -p member-store --test layers_memory -- --ignored --nocapture`,
//! at the size `PEERFECTLY_MEMORY_DEVICES` gives (a million by default). An
//! allocator counting live bytes and their peak stands under the whole test
//! binary, which holds this test alone.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
#![allow(unsafe_code, reason = "a global allocator is an unsafe trait; this one only counts")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use member_store::Layers;
use roster::batch::{BatchEntry, BatchHeader, pieces_of};
use roster::id::NetworkId;
use roster::leaf::Mode;
use roster::members::LayerStore;
use roster::roster::Roster;
use roster::sign::{Ed25519Signer, Signer as _, sign_operation};
use roster::types::{
    Algorithm, DeviceSpec, KeyEntry, KeyPurpose, NetworkParams, OperationBody, OperationCore, Role,
};

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

fn reset_peak() {
    PEAK.store(live(), Ordering::Relaxed);
}

fn peak() -> usize {
    PEAK.load(Ordering::Relaxed)
}

/// A board's entry from a number, its keys made of hashes.
fn entry(n: u32) -> BatchEntry {
    let hash = |tag: &str| blake3::hash(format!("board-{tag}{n}").as_bytes()).as_bytes().to_vec();
    let mut keys: Vec<KeyEntry> = [
        ("signing", KeyPurpose::Signing),
        ("transport", KeyPurpose::Transport),
        ("attestation", KeyPurpose::Attestation),
    ]
    .into_iter()
    .map(|(tag, purpose)| KeyEntry::new(Algorithm::Ed25519, purpose, hash(tag)).unwrap())
    .collect();
    keys.sort_by_key(KeyEntry::order_key);
    // Each its offset in the network's block, after the founder's: a fleet's
    // boards hold consecutive addresses.
    let ipv4 = Some(n.saturating_add(2).to_be_bytes());
    BatchEntry { keys, name: format!("board-{n}"), serial: n.to_be_bytes().to_vec(), ipv4 }
}

/// The founder's device, from its signer.
fn founder_spec(signer: &Ed25519Signer) -> DeviceSpec {
    let key = |purpose, tag: &str| {
        let value = if purpose == KeyPurpose::Signing {
            signer.public_key().as_bytes().to_vec()
        } else {
            blake3::hash(tag.as_bytes()).as_bytes().to_vec()
        };
        KeyEntry::new(Algorithm::Ed25519, purpose, value).unwrap()
    };
    let mut keys = vec![
        key(KeyPurpose::Signing, "s"),
        key(KeyPurpose::Transport, "t"),
        key(KeyPurpose::Attestation, "a"),
    ];
    keys.sort_by_key(KeyEntry::order_key);
    DeviceSpec::new(keys, "founder", Role::Admin, true, Vec::new()).unwrap()
}

fn per(bytes: usize, devices: usize) -> usize {
    bytes.checked_div(devices).unwrap_or(0)
}

#[test]
#[ignore = "a measurement, run by hand: cargo test -p member-store --test layers_memory -- --ignored --nocapture"]
fn a_full_member_holds_nothing_per_board_with_its_layers_on_disk() {
    let devices: usize = std::env::var("PEERFECTLY_MEMORY_DEVICES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000_000);
    let started = std::time::Instant::now();
    let report = |what: &str, bytes: usize| {
        println!(
            "{what}: {} MB, {} B per device  ({:?})",
            bytes / 1_000_000,
            per(bytes, devices),
            started.elapsed()
        );
    };
    let scratch = tempfile::tempdir().unwrap();
    // redb's cache is counted with the rest: what the store may hold of its
    // pages, bounded, and the same at any size.
    let cache: usize = std::env::var("PEERFECTLY_MEMORY_CACHE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(16 << 20);
    let layers = Layers::open(&scratch.path().join("layers.redb"), cache).unwrap();

    let start = live();
    let founder = Ed25519Signer::from_seed([1; 32]);
    let params = NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "fleet.internal", 0).unwrap();
    let mut roster = Roster::new();
    roster.keep_layers_in(Arc::clone(&layers) as Arc<dyn LayerStore>);
    let mut ts = 1_760_000_000_000_u64;
    let mut sign = |roster: &Roster, body: OperationBody, network: NetworkId| {
        ts = ts.saturating_add(60_000);
        let core = OperationCore::new(
            ts,
            Algorithm::Ed25519,
            body,
            roster.heads(),
            founder.key_id(),
            network,
        )
        .unwrap();
        (core.id(), sign_operation(&core, &founder).unwrap())
    };
    let (genesis, bytes) = sign(
        &roster,
        OperationBody::CreateNetwork { device: founder_spec(&founder), params },
        NetworkId::from_bytes([0; 32]),
    );
    assert!(roster.offer_bytes(&bytes).is_accepted());
    let network = NetworkId::from_bytes(*genesis.as_bytes());

    // The fleet, a batch at a time, as an admin admits one larger than the
    // limit on a batch: each batch's entries made, admitted and let go.
    let most = usize::try_from(roster::limits::MAX_BATCH_ENTRIES).unwrap();
    reset_peak();
    let mut admitted = 0_usize;
    while admitted < devices {
        let count = most.min(devices.saturating_sub(admitted));
        let lot: Vec<BatchEntry> = (admitted..admitted.saturating_add(count))
            .map(|n| entry(u32::try_from(n).unwrap()))
            .collect();
        let first = u32::try_from(admitted).unwrap().saturating_add(2).to_be_bytes();
        let run = roster::batch::OffsetRun::new(first, u32::try_from(count).unwrap()).unwrap();
        let header =
            BatchHeader::for_entries(&lot, Mode::Light, Vec::new(), Some(run), "fleet").unwrap();
        let (batch, bytes) = sign(&roster, OperationBody::AdmitBatch(header), network);
        let _ = roster.offer_bytes(&bytes);
        for piece in pieces_of(&batch, &lot).unwrap() {
            let _ = roster.offer_piece(&piece);
        }
        admitted = admitted.saturating_add(count);
    }
    let held = roster.state().unwrap();
    assert_eq!(held.devices.len(), devices.saturating_add(1), "every board admitted");
    // The next device admitted is given the lowest offset free: past every
    // board's, which an admission asks the index for one at a time.
    let asked = std::time::Instant::now();
    let next = held.free_offsets(1).map(u32::from_be_bytes);
    println!(
        "the lowest offset free, past {devices} boards: {next:?}, found in {:?}",
        asked.elapsed()
    );
    assert_eq!(next, u32::try_from(devices).ok().map(|boards| boards.saturating_add(2)));
    drop(held);
    report("the roster, every board admitted, layers on disk", live().saturating_sub(start));
    report("  at its peak while admitting", peak().saturating_sub(start));

    let before = live();
    reset_peak();
    let derived = roster::state::derive(roster.dag()).unwrap();
    report("  a state derived afresh", live().saturating_sub(before));
    report("    deriving it, at its peak", peak().saturating_sub(before));
    let board = entry(u32::try_from(devices / 2).unwrap()).device_id().unwrap();
    assert_eq!(derived.devices.get(&board).unwrap().record.name, format!("board-{}", devices / 2));
    drop(derived);
    assert!(!layers.tampered(), "nothing was told it lied");
}

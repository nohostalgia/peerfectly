//! A million devices on disk, opened and asked within 64 MB of memory.
//!
//! Run on purpose, in release, since writing the store takes a while:
//! `cargo test -p member-store --release --test million -- --ignored --nocapture`.
//!
//! Memory is counted by this binary's own allocator: every byte the heap holds,
//! redb's cache included, at its highest while the store is opened and asked.

#![allow(
    unsafe_code,
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a counting allocator, and a test that reports failure by panicking"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use member_store::Store;
use roster::id::{DeviceId, NetworkId, OperationId};
use roster::leaf::{DeviceLeaf, DeviceSettings, Mode};
use roster::state::RosterState;
use roster::types::{Algorithm, DeviceRecord, KeyEntry, KeyPurpose, NetworkParams, Role};

struct Counting;

static HELD: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call is passed to the system allocator unchanged; the counters
// are only added to and read.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as the caller's contract with `alloc`.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let held = HELD.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(held, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: as the caller's contract with `dealloc`.
        unsafe { System.dealloc(pointer, layout) };
        HELD.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: as the caller's contract with `realloc`.
        let moved = unsafe { System.realloc(pointer, layout, size) };
        if !moved.is_null() {
            HELD.fetch_sub(layout.size(), Ordering::Relaxed);
            let held = HELD.fetch_add(size, Ordering::Relaxed) + size;
            PEAK.fetch_max(held, Ordering::Relaxed);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const DEVICES: u32 = 1_000_000;
const BOUND: usize = 64 << 20;
const CACHE: usize = 16 << 20;

/// Device `n`, as a real one is: three keys, a name, an address on a third.
fn leaf(n: u32) -> DeviceLeaf {
    let hash = |tag: &[u8]| {
        let mut hasher = blake3::Hasher::new();
        hasher.update(tag);
        hasher.update(&n.to_le_bytes());
        hasher.finalize().as_bytes().to_vec()
    };
    let mut keys: Vec<KeyEntry> = [
        (&b"signing"[..], KeyPurpose::Signing),
        (&b"transport"[..], KeyPurpose::Transport),
        (&b"attestation"[..], KeyPurpose::Attestation),
    ]
    .into_iter()
    .map(|(tag, purpose)| KeyEntry::new(Algorithm::Ed25519, purpose, hash(tag)).unwrap())
    .collect();
    keys.sort_by_key(KeyEntry::order_key);
    let record = DeviceRecord {
        id: DeviceId::of_signing_key(&hash(b"signing")),
        keys,
        name: format!("sensor-{n}"),
        role: Role::Member,
        founder: false,
        added_by: OperationId::from_bytes([1; 32]),
        capabilities: Vec::new(),
    };
    let address = n.is_multiple_of(3).then(|| {
        let [_, high, middle, low] = n.to_be_bytes();
        [10, high, middle, low]
    });
    let settings = DeviceSettings::new(Mode::Light, Vec::new(), address, None).unwrap();
    DeviceLeaf { record, settings }
}

fn transport_key(leaf: &DeviceLeaf) -> roster::id::KeyId {
    leaf.record.keys.iter().find(|entry| entry.purpose == KeyPurpose::Transport).unwrap().key_id()
}

#[test]
#[ignore = "writes a million devices; run on purpose, in release"]
fn a_million_devices_load_and_answer_within_64_mb() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.redb");
    let params = NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "fleet.internal", 0).unwrap();
    let skeleton = RosterState::empty(NetworkId::from_bytes([7; 32]), params);

    let started = Instant::now();
    let root = {
        let store = Store::open(&path, CACHE).unwrap();
        store.write_leaves(&skeleton, (0..DEVICES).map(leaf), None).unwrap()
    };
    let size = std::fs::metadata(&path).unwrap().len();
    println!(
        "written: {DEVICES} devices in {:.1?}, {} MB on disk, {} MB at most in memory while writing",
        started.elapsed(),
        size >> 20,
        PEAK.load(Ordering::SeqCst) >> 20
    );

    // From here on, what loading and asking costs.
    let before = HELD.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);
    let started = Instant::now();
    let store = Store::open(&path, CACHE).unwrap();
    let state = store.state().unwrap().unwrap();
    assert_eq!(state.devices.root(), root, "the root the caller trusts");
    assert_eq!(state.devices.len(), DEVICES as usize);
    println!("opened in {:.1?}", started.elapsed());

    let started = Instant::now();
    let asked = 2_000_u32;
    for i in 0..asked {
        let n = i.wrapping_mul(2_654_435_761) % DEVICES;
        let expected = leaf(n);
        let device = expected.record.id;
        assert_eq!(state.devices.get(&device).as_deref(), Some(&expected));
        let holder =
            state.device_for_key_of_purpose(&transport_key(&expected), KeyPurpose::Transport);
        assert_eq!(holder.map(|held| held.record.id), Some(device));
        if let Some(address) = expected.settings.ipv4 {
            assert_eq!(state.devices.holding_address(address), vec![device]);
        }
    }
    let per_device = started.elapsed() / asked;
    println!("asked {asked} devices by id, key and address: {per_device:.1?} each");

    // A window's worth of changes on top, and the root over them.
    let started = Instant::now();
    let mut next = state.clone();
    for n in DEVICES..DEVICES + 1_000 {
        next.devices.insert_leaf(leaf(n));
    }
    for n in 0..1_000 {
        next.devices.remove(&leaf(n).record.id);
    }
    assert_ne!(next.devices.root(), root);
    println!("a thousand admissions and a thousand removals on top: {:.1?}", started.elapsed());

    let peak = PEAK.load(Ordering::SeqCst).saturating_sub(before);
    println!("at most {} MB in memory loading and asking", peak >> 20);
    assert!(!store.tampered(), "nothing failed a check");
    assert!(peak < BOUND, "{peak} bytes is over the bound");

    drop(next);
    let started = Instant::now();
    store.verify(&root).unwrap();
    println!("checked whole in {:.1?}", started.elapsed());
}

//! What a full member's daemon holds in memory beside its roster, part by
//! part, for a network of many devices (`scalable-membership` 16.6).
//!
//! Run by hand, never in CI:
//! `cargo test -p daemon --test memory -- --ignored --nocapture`, at the size
//! `PEERFECTLY_MEMORY_DEVICES` gives (a million by default). An allocator
//! counting live bytes and their peak stands under the whole test binary,
//! which holds this test alone.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
#![allow(unsafe_code, reason = "a global allocator is an unsafe trait; this one only counts")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use roster::id::{DeviceId, NetworkId, OperationId};
use roster::leaf::{DeviceLeaf, DeviceSettings, Mode};
use roster::state::RosterState;
use roster::types::{Algorithm, DeviceRecord, KeyEntry, KeyPurpose, NetworkParams, Role};

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

/// A light board from a number, with real-looking keys (the transport key a
/// valid curve point, as convesso reads it), and no address.
fn leaf(n: u32) -> DeviceLeaf {
    let hash = |tag: &str| blake3::hash(format!("{tag}{n}").as_bytes()).as_bytes().to_vec();
    let transport = {
        use roster::sign::Signer as _;
        roster::sign::Ed25519Signer::from_seed(*blake3::hash(&n.to_be_bytes()).as_bytes())
            .public_key()
            .as_bytes()
            .to_vec()
    };
    let mut keys = vec![
        KeyEntry::new(Algorithm::Ed25519, KeyPurpose::Signing, hash("signing")).unwrap(),
        KeyEntry::new(Algorithm::Ed25519, KeyPurpose::Transport, transport).unwrap(),
        KeyEntry::new(Algorithm::Ed25519, KeyPurpose::Attestation, hash("attestation")).unwrap(),
    ];
    keys.sort_by_key(KeyEntry::order_key);
    let id = DeviceId::of_signing_key(&hash("signing"));
    DeviceLeaf {
        record: DeviceRecord {
            id,
            keys,
            name: format!("board-{n}"),
            role: Role::Member,
            founder: false,
            added_by: OperationId::from_bytes([1; 32]),
            capabilities: Vec::new(),
        },
        settings: DeviceSettings::new(Mode::Light, Vec::new(), None, None).unwrap(),
    }
}

#[test]
#[ignore = "a measurement, run by hand: cargo test -p daemon --test memory -- --ignored --nocapture"]
fn what_a_full_members_daemon_holds_beside_its_roster() {
    let devices: u32 = std::env::var("PEERFECTLY_MEMORY_DEVICES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1_000_000);
    let per = |bytes: usize| bytes.checked_div(devices as usize).unwrap_or(0);
    let report = |what: &str, bytes: usize| {
        println!("{what}: {} MB, {} B per device", bytes / 1_000_000, per(bytes));
    };

    let params = NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "fleet.internal", 0).unwrap();
    let mut state = RosterState::empty(NetworkId::from_bytes([7; 32]), params);
    state.devices = (0..devices).map(leaf).collect();
    let me = state.devices.keys().next().unwrap();

    let before = live();
    let holdings = tunnel::Ipv4Holdings::of_state(&state);
    report("the IPv4 holdings", live().saturating_sub(before));

    let before = live();
    let mut router =
        daemon::router::Router::new(tunnel::Prefix::from_parameter(&state.params.ula).unwrap());
    router.follow_state(&state, &me);
    report("the router's members", live().saturating_sub(before));

    let before = live();
    let members = transport_convesso::members::Members::from_state(&state);
    report("the transport's members", live().saturating_sub(before));

    // What the report reads: a page of the devices, not every one, and the
    // admins asked when this device is revoked.
    let before = live();
    let page: Vec<_> = state.devices.iter_after(None).take(daemon::control::PEERS_PAGE).collect();
    report("a page of the report's devices", live().saturating_sub(before));
    let before = live();
    let admins = state.devices.admins();
    report("the admins found", live().saturating_sub(before));

    drop((holdings, router, members, page, admins));
}

//! What admitting a roster's worth of operations costs.
//!
//! The security review's finding F-02 measured the build of the time: 400
//! operations from a member took 1.65 s, 800 took 11.3 s and 1600 took 87.0 s,
//! all admitted. The cost grew with about the cube, because resolving an
//! operation's author derived the whole state for **every operation offered** —
//! extrapolating to roughly twenty-four minutes of CPU for a full roster, on
//! every node that received it. That is the denial of service, and a check that
//! refused at the same price would not have fixed it.
//!
//! This is the same shape of measurement, kept as a test so the cost cannot
//! quietly come back. It asserts a bound generous enough not to be flaky on a
//! loaded machine or in a debug build, and prints what it actually took, which is
//! the number worth reading.
//!
//! Run it on its own to see the figures:
//! `cargo test -p roster --test cost -- --nocapture`

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod support;

use std::time::{Duration, Instant};

use roster::roster::Roster;
use roster::types::{OperationBody, Role};
use support::{History, device, device_id};

/// How many operations an honest admin writes here.
///
/// Not the roster's full 4096: this runs in a debug build in the ordinary suite,
/// and the property being checked is that the cost per operation stays flat, not
/// the ceiling itself. The two batches below are what show the shape.
const BATCH: usize = 200;

/// Admits `count` renames authored by the founder, each on the current head, and
/// says how long it took.
fn admit_a_chain(count: usize) -> Duration {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("add2", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Member, false)));

    let mut parent = "add2".to_owned();
    for step in 0..count {
        let label = format!("s{step}");
        history.op(
            &label,
            1,
            &[parent.as_str()],
            OperationBody::Rename { device: device_id(2), name: format!("n{step}") },
        );
        parent = label;
    }

    let entries = history.entries();
    let started = Instant::now();
    let mut roster = Roster::new();
    for entry in entries {
        let admission = roster.offer_bytes(&entry.bytes);
        assert!(admission.is_accepted(), "{} refused: {admission:?}", entry.label);
    }
    let taken = started.elapsed();
    assert_eq!(roster.dag().len(), count.saturating_add(2));
    taken
}

/// The cost per operation does not grow with the graph.
///
/// Doubling the history must not quadruple or cube the time. The bound is loose
/// — a debug build on a busy machine is noisy — but it is nowhere near what the
/// old behaviour would produce: deriving per offer made the second batch cost
/// about eight times the first, not about twice.
#[test]
fn admitting_an_honest_history_stays_linear() {
    let small = admit_a_chain(BATCH);
    let large = admit_a_chain(BATCH.saturating_mul(2));

    println!("admitting {BATCH} operations took {small:?}");
    println!("admitting {} operations took {large:?}", BATCH * 2);

    let ratio = large.as_secs_f64() / small.as_secs_f64().max(f64::MIN_POSITIVE);
    println!("twice the history cost {ratio:.2} times as much");

    assert!(
        large < Duration::from_secs(20),
        "admitting {} operations took {large:?}; it used to be minutes",
        BATCH * 2
    );
    assert!(
        ratio < 4.0,
        "doubling the history multiplied the cost by {ratio:.2}, which is the growth this \
         change exists to remove"
    );
}

/// The attack of F-02, timed: a member's flood costs the node a lookup apiece,
/// not a derivation apiece, and leaves the graph where it was.
#[test]
fn refusing_a_flood_is_cheap() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("addB", 1, &["g"], OperationBody::AddDevice(device(2, "b", Role::Member, false)));

    let mut roster = Roster::new();
    for entry in history.entries() {
        assert!(roster.offer_bytes(&entry.bytes).is_accepted());
    }
    let held = roster.dag().len();

    let mut parent = "addB".to_owned();
    for attempt in 0..BATCH {
        let label = format!("flood{attempt}");
        history.op(
            &label,
            2,
            &[parent.as_str()],
            OperationBody::Rename { device: device_id(2), name: format!("n{attempt}") },
        );
        parent = label;
    }

    let started = Instant::now();
    for attempt in 0..BATCH {
        let bytes = history.bytes(&format!("flood{attempt}"));
        assert!(!roster.offer_bytes(&bytes).is_accepted());
    }
    let taken = started.elapsed();
    println!("refusing {BATCH} operations from a member took {taken:?}");

    assert_eq!(roster.dag().len(), held, "and the graph did not grow");
    assert!(taken < Duration::from_secs(10), "refusing {BATCH} operations took {taken:?}");
}

/// A full roster, in release, for the record.
///
/// Ignored by default: it is a minute of work in a release build and much longer
/// in a debug one, and the two tests above already hold the property. Run it when
/// the figure above needs remeasuring:
///
/// `cargo test -p roster --release --test cost -- --ignored --nocapture`
#[test]
#[ignore = "a release-build measurement, run deliberately"]
fn admitting_a_full_roster() {
    // Within the share the ceiling leaves for operations that are not
    // revocations, so this measures admission and not the reserve.
    const OPERATIONS: usize = 3_500;

    let taken = admit_a_chain(OPERATIONS);
    println!("admitting {OPERATIONS} operations took {taken:?}");
}

//! Previewing a roster before its operations are signed.
//!
//! The weight is on equivalence: whatever `preview` says a set of operations
//! would make of a roster must be exactly what that roster says once the same
//! operations arrive signed. A snapshot built from a preview is only ever
//! accepted by re-deriving it from verified operations, so a wrong preview
//! costs a refused snapshot rather than a trusted one — but a preview that is
//! wrong in ordinary use would make every batched act lose its snapshot.

#![allow(clippy::panic, clippy::expect_used, reason = "a test reports failure by panicking")]

mod support;

use roster::id::OperationId;
use roster::roster::{Preview, Roster};
use roster::sign::RawOperation;
use roster::types::{OperationBody, OperationCore, Role};
use support::{History, device, device_id, params_with};

/// The core a signed operation carries.
fn core_of(bytes: &[u8]) -> OperationCore {
    RawOperation::decode(bytes).expect("decodes").core().clone()
}

/// A roster holding the labelled operations, offered signed.
fn holding(history: &History, labels: &[&str]) -> Roster {
    let mut roster = Roster::new();
    for label in labels {
        assert!(roster.offer_bytes(&history.bytes(label)).is_accepted(), "{label} is accepted");
    }
    roster
}

/// What a roster that really holds these operations says, in a preview's terms.
fn as_preview(roster: &Roster) -> Preview {
    let heads = roster.heads();
    let dag = roster.dag();
    let depths = heads
        .iter()
        .map(|head| dag.depth(dag.position(head).expect("a head is in its graph")))
        .collect();
    Preview { state: roster.state().expect("derives"), heads, depths }
}

/// Previews `later` over a roster holding `before`, and compares that with a
/// roster that was then given `later` signed.
fn previews_what_signing_makes(history: &History, before: &[&str], later: &[&str]) {
    let base = holding(history, before);
    let cores: Vec<OperationCore> =
        later.iter().map(|label| core_of(&history.bytes(label))).collect();
    let previewed = base.preview(&cores).expect("previews");

    let everything: Vec<&str> = before.iter().chain(later).copied().collect();
    let signed = holding(history, &everything);

    assert_eq!(as_preview(&signed), previewed, "the preview is what signing makes");
}

/// The founding: a genesis previewed over nothing at all.
#[test]
fn a_genesis_previews_over_an_empty_roster() {
    let mut history = History::new();
    history.genesis("g", 1);
    previews_what_signing_makes(&history, &[], &["g"]);
}

/// A replacement: a revocation, and an admission built on top of it.
#[test]
fn a_revocation_then_an_admission_previews_as_signed() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("a", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    history.op(
        "r",
        1,
        &["a"],
        OperationBody::RevokeDevice { device: device_id(2), reason: "replaced".to_owned() },
    );
    history.op("n", 1, &["r"], OperationBody::AddDevice(device(3, "laptop", Role::Member, false)));
    previews_what_signing_makes(&history, &["g", "a"], &["r", "n"]);

    let base = holding(&history, &["g", "a"]);
    let previewed = base
        .preview(&[core_of(&history.bytes("r")), core_of(&history.bytes("n"))])
        .expect("previews");
    assert_eq!(previewed.heads, vec![history.id("n")], "the admission is the only head");
    assert!(previewed.state.revoked.contains(&device_id(2)), "and the revocation is in");
}

/// A change of the network's parameters.
#[test]
fn a_settings_change_previews_as_signed() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("s", 1, &["g"], OperationBody::SetNetwork(params_with("elsewhere.internal")));
    previews_what_signing_makes(&history, &["g"], &["s"]);
}

/// Concurrent heads survive a preview: an operation hung off one of two heads
/// leaves the other standing.
#[test]
fn a_preview_keeps_the_heads_it_does_not_touch() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("a", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    history.op("b", 1, &["g"], OperationBody::AddDevice(device(3, "tablet", Role::Member, false)));
    history.op(
        "c",
        1,
        &["a"],
        OperationBody::Rename { device: device_id(2), name: "desk".to_owned() },
    );
    previews_what_signing_makes(&history, &["g", "a", "b"], &["c"]);
}

/// An operation whose parent is nowhere is refused rather than previewed.
#[test]
fn a_preview_refuses_an_operation_without_its_parents() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("a", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));
    history.op(
        "b",
        1,
        &["a"],
        OperationBody::Rename { device: device_id(2), name: "desk".to_owned() },
    );

    let base = holding(&history, &["g"]);
    assert!(base.preview(&[core_of(&history.bytes("b"))]).is_err(), "`a` is not there");
}

/// Previewing changes nothing about the roster it was asked of.
#[test]
fn a_preview_leaves_the_roster_as_it_was() {
    let mut history = History::new();
    history.genesis("g", 1);
    history.op("a", 1, &["g"], OperationBody::AddDevice(device(2, "laptop", Role::Member, false)));

    let base = holding(&history, &["g"]);
    let heads: Vec<OperationId> = base.heads();
    let state = base.state().expect("derives");
    let pending = base.pending_count();
    let operations = base.dag().len();

    let _previewed = base.preview(&[core_of(&history.bytes("a"))]).expect("previews");

    assert_eq!(heads, base.heads());
    assert_eq!(state, base.state().expect("derives"));
    assert_eq!(pending, base.pending_count());
    assert_eq!(operations, base.dag().len(), "nothing was admitted");
}

/// **No public path yields an unsigned operation.** `VerifiedOperation` is proof
/// that a signature was checked; the one constructor that makes an exception is
/// crate-private and called from `preview` alone, whose copy is dropped.
#[test]
fn only_the_preview_can_make_an_unsigned_operation() {
    let sign = include_str!("../src/sign.rs");
    assert!(
        sign.contains("pub(crate) fn unsigned_for_preview("),
        "the placeholder constructor stays crate-private"
    );

    let sources = [
        ("sign.rs", sign),
        ("roster.rs", include_str!("../src/roster.rs")),
        ("dag.rs", include_str!("../src/dag.rs")),
        ("state.rs", include_str!("../src/state.rs")),
        ("snapshot.rs", include_str!("../src/snapshot.rs")),
        ("lib.rs", include_str!("../src/lib.rs")),
    ];
    let callers: Vec<&str> = sources
        .iter()
        .filter(|(_, text)| text.contains("unsigned_for_preview(core)"))
        .map(|(name, _)| *name)
        .collect();
    assert_eq!(callers, vec!["roster.rs"], "only the preview calls it");
}

//! Claims this crate makes about itself that only reading it can hold to.
//!
//! Each of these is a property no behavioural test can catch, because the code
//! would still pass its tests while quietly becoming something else: a second
//! authority, a second encoder, a dependency pointing the wrong way.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use roster::id::OperationId;

/// The dependency runs one way. `roster` must not know about the transport, and
/// nothing below this crate may know about this crate.
#[test]
fn the_dependency_direction_holds() {
    let roster = include_str!("../../roster/Cargo.toml");
    let identity = include_str!("../../identity/Cargo.toml");
    let transport = include_str!("../../transport/Cargo.toml");

    for forbidden in ["transport", "roster-sync"] {
        assert!(
            !roster.contains(forbidden),
            "`roster` must not depend on `{forbidden}`; it is the layer everything else \
             is defined against"
        );
    }
    assert!(!identity.contains("roster-sync"), "`identity` must not depend on this crate");
    assert!(
        !transport.contains("roster-sync"),
        "`transport` must not depend on this crate — its ignorance of what an operation \
         is is what makes it replaceable"
    );

    let own = include_str!("../Cargo.toml");
    assert!(own.contains("roster"), "this crate depends on roster");
    assert!(own.contains("transport"), "and on transport");
}

/// The iroh binding is still deferred. This crate runs over the in-memory
/// transports precisely so it needs no network.
#[test]
fn no_network_dependency_creeps_in() {
    let own = include_str!("../Cargo.toml");
    for forbidden in ["iroh", "quinn", "reqwest", "hyper"] {
        assert!(
            !own.contains(forbidden),
            "`{forbidden}` would make this network code, which `DESIGN.md` §0 forbids \
             merging without a real-world NAT test"
        );
    }
}

/// Sync keeps no membership list of its own. One that disagreed with the signed
/// log would be the thing actually deciding who is in the network — and it would
/// be consulted far more often than the log.
#[test]
fn sync_keeps_no_independent_membership_list() {
    let syncer = include_str!("../src/syncer.rs");
    let quota = include_str!("../src/quota.rs");

    for forbidden in ["allowed_devices", "known_members", "is_member", "trusted"] {
        assert!(
            !syncer.contains(forbidden),
            "`{forbidden}` in the syncer would be a second answer to who belongs"
        );
    }
    // The only identity it holds is what a session authenticated, used as a key
    // for accounting — never as a decision about membership.
    assert!(quota.contains("DeviceId"), "the quota is keyed on the authenticated device");
    assert!(
        !quota.contains("Role") && !quota.contains("admin"),
        "the quota must not know or care what a peer is allowed to do"
    );
}

/// Everything received reaches derived state through the roster, and by no other
/// path. A single call that bypassed it would make this crate an authority.
#[test]
fn everything_received_goes_through_the_roster() {
    let syncer = include_str!("../src/syncer.rs");

    assert!(syncer.contains("offer_bytes"), "operations go through the roster");
    assert!(syncer.contains("offer_snapshot"), "and so do snapshots");

    // No path into the graph that skips admission.
    for bypass in ["dag_mut", "insert(", "force_", "unchecked"] {
        assert!(
            !syncer.contains(bypass),
            "`{bypass}` would be a way into derived state that skips verification"
        );
    }
}

/// The wire format reuses roster's encoder rather than growing a second set of
/// canonicity rules. Two sets in one workspace drift apart exactly where it is
/// hardest to test — the length-first key ordering has already been written
/// wrong once here.
#[test]
fn the_wire_format_reuses_the_one_canonical_encoder() {
    let message = include_str!("../src/message.rs");

    assert!(message.contains("roster::cbor"), "encoding must come from roster's canonical encoder");
    assert!(
        !message.contains("minicbor") && !message.contains("serde"),
        "a private encoder here would be a second set of canonicity rules"
    );
}

/// Sync messages are unsigned, and the reason is recorded. Left unstated, the
/// absence reads like an oversight rather than a decision.
#[test]
fn the_absence_of_a_signature_is_explained() {
    let message = include_str!("../src/message.rs");
    assert!(
        message.contains("not signed") || message.contains("unsigned"),
        "the message module must say that these are not signed"
    );
    assert!(
        message.contains("domain separation"),
        "and why: a second signing context is a second place to get it wrong"
    );
}

/// Sync closes no sessions. Membership is the only ground for ending one, and
/// that decision belongs to the transport.
#[test]
fn sync_closes_no_sessions() {
    let syncer = include_str!("../src/syncer.rs");
    assert!(
        !syncer.contains(".close("),
        "sync must not close a session; content-based disconnection can be aimed \
         by an attacker who forges one operation and has honest nodes drop each other"
    );
}

/// The deferrals name where each piece went. "Later" is not a destination.
#[test]
fn every_deferral_names_its_destination() {
    let lib = include_str!("../src/lib.rs");
    for destination in
        ["rendezvous-service", "local-discovery", "equivocation-detection", "windows-daemon"]
    {
        assert!(lib.contains(destination), "a deferral must name `{destination}`");
    }
}

/// The format document covers every requirement the specification adds. A second
/// implementation is written from it, and a requirement missing there is one
/// that implementation is never told it has to satisfy.
#[test]
fn the_format_covers_every_requirement() {
    let format = include_str!("../FORMAT.md");
    for (requirement, marker) in [
        ("Reconciliation when a session is established", "## 8. The exchange"),
        ("The exchange is bounded", "### Size"),
        ("Local admissions propagate to open sessions", "## 10. Push"),
        ("A compacted node reconciles through its snapshot", "## 7. Snapshot"),
        ("A fair share of the pending set per peer", "## 11. The per-peer quota"),
        ("Only verified operations are relayed", "## 9. Relay only from the verified set"),
        ("A refusal throttles its sender and nothing more", "## 13. Misbehaviour"),
        ("Sync carries no authority over validity", "## 2. The trust model"),
        ("Reconciled nodes converge", "Terminating by structure"),
    ] {
        assert!(
            format.contains(marker),
            "FORMAT.md must cover `{requirement}`; nothing matching `{marker}`"
        );
    }
}

/// Roster's §19 no longer reads as an outstanding obligation, now that it is
/// discharged here. A requirement left looking open is one someone implements
/// twice, or not at all.
#[test]
fn rosters_deferred_obligation_points_here() {
    let roster_format = include_str!("../../roster/FORMAT.md");
    assert!(
        roster_format.contains("roster-sync"),
        "roster's pending-set section must name where its per-peer quota is discharged"
    );
}

/// The README records the reasoning behind the two policies. Without the
/// transitive punishment argument, throttle-never-disconnect reads as laxness
/// rather than as the answer to a specific attack.
#[test]
fn the_readme_records_why_the_policies_are_what_they_are() {
    let readme = include_str!("../README.md");
    assert!(readme.contains("never evict"), "the eviction policy and its reason");
    assert!(readme.contains("honest nodes drop each other"), "the transitive punishment attack");
    assert!(readme.contains("reconnecting"), "why the quota is keyed on the device");
}

/// The wire is not what changed.
///
/// Per-device propagation evidence is read out of an offer a peer was already
/// sending; nothing was added to it. A pinned encoding is what makes that
/// claim checkable rather than asserted, and it is pinned for the frame as a
/// whole — kind tag, ids and snapshot sequence — so a reordering of fields
/// fails here too.
#[test]
fn an_offer_encodes_to_the_same_bytes_it_always_did() {
    let offer = roster_sync::message::Offer {
        ids: vec![OperationId::from_bytes([0x11; 32]), OperationId::from_bytes([0x22; 32])],
        snapshot: Some(7),
    };
    let encoded = roster_sync::message::Message::Offer(offer).encode();
    let hex: String = encoded.iter().map(|byte| format!("{byte:02x}")).collect();

    // Split at the structure's own seams so a diff here reads as what moved.
    let expected = concat!(
        "a264626f64795859a363696473825820",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "5820",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "64736e6170f567736e617073657107646b696e6401",
    );
    assert_eq!(hex, expected, "the offer format is unchanged by this work");
}

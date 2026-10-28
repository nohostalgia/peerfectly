//! What reaches the log, and what heals when a push is lost.
//!
//! A revocation is in force on a device once that device holds it, and it holds
//! it only if it was written down and carried again where a send failed. Every
//! test here is a way that used not to hold: an operation learned from a peer
//! and never written, a restart that forgot it, a push lost on a session that
//! stayed open.
//!
//! They drive `Node` over the in-memory transport, because the defects live in
//! the component that owns the roster and the sessions — not in any layer below,
//! each of which was already tested and already correct.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod common;

use std::sync::Arc;

use common::{a_network, node_off, node_on, within};
use daemon::channel::{Channel, frame};
use daemon::node::Node;
use roster::id::OperationId;
use roster::sign::RawOperation;
use roster_sync::message::{Message, Offer};
use transport::memory::MemoryFabric;

/// The ids of a set of signed operations.
fn ids_of(operations: &[Vec<u8>]) -> Vec<OperationId> {
    operations.iter().map(|bytes| RawOperation::decode(bytes).expect("decodes").id()).collect()
}

// ---------------------------------------------------------------------------
// Reconciliation repeats while a session is open
// ---------------------------------------------------------------------------

/// An operation learned from a peer must survive a restart.
///
/// It is admitted to the roster in memory and never written to the log, so a
/// device that receives a revocation and is then restarted no longer holds it.
/// See the note in `received_roster`: the append loop walks `replies` — what
/// this node is about to *send* — rather than what it just took in.
#[tokio::test]
async fn an_operation_learned_from_a_peer_reaches_the_log() {
    let network = a_network();
    let scratch = tempfile::tempdir().unwrap();

    // This node holds only the founding operation.
    let node = node_off(&network.joiner, core::slice::from_ref(&network.genesis), &scratch);
    let before = daemon::state::Log::at(scratch.path().join("roster.log")).read().unwrap().len();

    // A peer sends it the admission it lacks.
    let transfer = Message::Transfer(vec![network.admit_joiner.clone()]);
    node.received(network.founder.device_id(), &frame(Channel::Roster, &transfer.encode())).await;

    let after = daemon::state::Log::at(scratch.path().join("roster.log")).read().unwrap();
    let devices = node.state().await.map(|s| s.devices.len()).unwrap_or(0);
    println!("PROBE log_before={before} log_after={} devices_in_roster={devices}", after.len());
    assert_eq!(after.len(), before + 1, "an operation learned from a peer must reach the log");
}

/// Reconciling with a peer that is behind sends it operations this node already
/// holds. Appending those again grows the log with nothing, and once
/// reconciliation repeats on a tick it grows without bound.
#[tokio::test]
async fn reconciling_does_not_grow_the_log_with_what_is_already_held() {
    let network = a_network();
    let scratch = tempfile::tempdir().unwrap();

    let node = node_off(&network.founder, &network.everything(), &scratch);
    let log = daemon::state::Log::at(scratch.path().join("roster.log"));
    let before = log.read().unwrap().len();

    // A peer that holds only the founding operation offers twice. Each time this
    // node answers with the two operations that peer lacks.
    let behind = Message::Offer(Offer {
        ids: ids_of(core::slice::from_ref(&network.genesis)),
        snapshot: None,
        root: None,
        partial: Vec::new(),
    });
    for _ in 0..2 {
        node.received(network.joiner.device_id(), &frame(Channel::Roster, &behind.encode())).await;
    }

    assert_eq!(
        log.read().unwrap().len(),
        before,
        "what is sent to a peer is what this node already had; the log must not repeat it"
    );
}

/// The receiving end of a revocation. The device applies it, and a restart does
/// not put the expelled device back.
#[tokio::test]
async fn a_revocation_received_from_a_peer_survives_a_restart() {
    let network = a_network();
    let scratch = tempfile::tempdir().unwrap();
    let everything = network.everything();

    // `c` holds the network and is told, by a peer, that `b` has been expelled.
    let signing = node_off(&network.founder, &everything, &tempfile::tempdir().unwrap());
    let state = signing.state().await.expect("a network");
    let expulsion = daemon::revoking::resolve(
        &state,
        &network.founder,
        &daemon::control::Target::Name("b".to_owned()),
        "lost",
    )
    .expect("the roster names it");
    let revocation =
        daemon::revoking::sign(&expulsion, &network.founder, &state, signing.heads().await)
            .expect("signs");

    let receiver = node_off(&network.third, &everything, &scratch);
    let transfer = Message::Transfer(vec![revocation]);
    receiver
        .received(network.founder.device_id(), &frame(Channel::Roster, &transfer.encode()))
        .await;

    let expelled = network.joiner.device_id();
    assert!(
        !receiver.state().await.expect("a network").devices.contains_key(&expelled),
        "the revocation took effect on the device that received it"
    );
    drop(receiver);

    // The restart. Nothing is handed to this node a second time.
    let restarted = node_off(&network.third, &[], &scratch);
    assert!(
        !restarted.state().await.expect("a network").devices.contains_key(&expelled),
        "and it is still in force after a restart, rather than the expelled device \
         being admitted again"
    );
}

// ---------------------------------------------------------------------------
// Reconciliation repeats while a session is open
// ---------------------------------------------------------------------------

/// A push whose send failed used to be a permanent divergence: full
/// reconciliation happened only when a session opened, and nothing re-offered
/// afterwards. This is that failure, healed on the session that was already
/// there.
///
/// The recurring offer runs on both daemons, which is what makes it converge:
/// an offer tells a peer what this node *has*, so it is the peer's own offer
/// that pulls across what the peer lacks.
#[tokio::test]
async fn a_failed_push_heals_without_reconnecting() {
    let network = a_network();
    let fabric = MemoryFabric::new();
    let founder_scratch = tempfile::tempdir().unwrap();
    let joiner_scratch = tempfile::tempdir().unwrap();

    let two = network.two_devices();
    let founder = node_on(&network.founder, &two, &fabric, &founder_scratch).await;
    let joiner = node_on(&network.joiner, &two, &fabric, &joiner_scratch).await;

    tokio::spawn(Arc::clone(&joiner).accept_forever());
    founder.connect(&network.joiner.transport_key().public_key()).await.expect("a member");

    let joiner_device = network.joiner.device_id();
    within("a session is open", async || founder.has_session(&joiner_device).await).await;
    let third = network.third.device_id();
    let holds_third = async |node: &Arc<Node>| {
        node.state().await.is_ok_and(|state| state.devices.contains_key(&third))
    };

    // An operation that reaches the founder's roster without being pushed to the
    // joiner: handed over as though the joiner itself had sent it, so the
    // forward goes to every session *except* that one — of which there are none.
    // This is the state a failed send leaves behind: held here, absent there,
    // and the session still open.
    let transfer = Message::Transfer(vec![network.admit_third.clone()]);
    founder.received(joiner_device, &frame(Channel::Roster, &transfer.encode())).await;
    assert!(holds_third(&founder).await, "held here");
    assert!(!holds_third(&joiner).await, "the peer has not got it");
    assert!(founder.has_session(&joiner_device).await, "on a session that never dropped");

    // No reconnection, no new push. Only the tick both daemons run.
    within("the recurring reconciliation carries what the push did not", async || {
        joiner.offer_to_everyone().await;
        founder.offer_to_everyone().await;
        holds_third(&joiner).await
    })
    .await;

    assert!(founder.has_session(&joiner_device).await, "on the same session throughout");
}

// ---------------------------------------------------------------------------
// Last contact comes only from an authenticated session and decides nothing
// ---------------------------------------------------------------------------

/// Whole minutes since the epoch, now.
fn minute_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 60
}

/// The minute a contact records, if one is recorded.
fn minute_of(contact: daemon::control::Contact) -> Option<u64> {
    match contact {
        daemon::control::Contact::Recorded { at } => {
            Some(at.duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_secs() / 60)
        }
        daemon::control::Contact::NoneRecorded => None,
    }
}

/// A session that speaks leaves its minute behind, and a restart keeps it.
#[tokio::test]
async fn a_session_records_contact_and_a_restart_keeps_it() {
    let network = a_network();
    let fabric = MemoryFabric::new();
    let founder_scratch = tempfile::tempdir().unwrap();
    let joiner_scratch = tempfile::tempdir().unwrap();

    let both = network.two_devices();
    let founder = node_on(&network.founder, &both, &fabric, &founder_scratch).await;
    let joiner = node_on(&network.joiner, &both, &fabric, &joiner_scratch).await;
    let joiner_device = network.joiner.device_id();

    assert_eq!(
        founder.last_contact(&joiner_device).await,
        daemon::control::Contact::NoneRecorded,
        "nothing before a session"
    );

    let before = minute_now();
    tokio::spawn(Arc::clone(&joiner).accept_forever());
    founder
        .connect(&network.joiner.transport_key().public_key())
        .await
        .expect("members reach each other");
    within("the founder records contact with the joiner", async || {
        minute_of(founder.last_contact(&joiner_device).await).is_some()
    })
    .await;
    let after = minute_now();

    let recorded = minute_of(founder.last_contact(&joiner_device).await).unwrap();
    assert!((before..=after).contains(&recorded), "{recorded} is within the session");

    founder.stopped().await;
    drop(founder);
    let restarted = node_off(&network.founder, &both, &founder_scratch);
    assert_eq!(
        minute_of(restarted.last_contact(&joiner_device).await),
        Some(recorded),
        "a restart keeps what was recorded"
    );
}

/// Kept for a revoked device, and unchanged once it is revoked: it can no longer
/// hold a session here to change it.
#[tokio::test]
async fn a_revoked_devices_last_contact_is_kept_and_stops_changing() {
    let network = a_network();
    let fabric = MemoryFabric::new();
    let founder_scratch = tempfile::tempdir().unwrap();
    let joiner_scratch = tempfile::tempdir().unwrap();
    let both = network.two_devices();
    let joiner_device = network.joiner.device_id();

    // A contact from long ago, as a previous run would have left it.
    drop(node_off(&network.founder, &both, &founder_scratch));
    let seeded = format!("{{\"{}\": 5}}", joiner_device.to_hex());
    std::fs::write(founder_scratch.path().join("contacts.json"), seeded).unwrap();

    let founder = node_on(&network.founder, &both, &fabric, &founder_scratch).await;
    assert_eq!(minute_of(founder.last_contact(&joiner_device).await), Some(5));

    let state = founder.state().await.unwrap();
    let expulsion = daemon::revoking::resolve(
        &state,
        &network.founder,
        &daemon::control::Target::Name("b".to_owned()),
        "lost",
    )
    .unwrap();
    let revocation =
        daemon::revoking::sign(&expulsion, &network.founder, &state, founder.heads().await)
            .unwrap();
    founder.admit_without_activating(&revocation).await.unwrap();

    // The revoked device still holds the old roster and tries to reach in.
    let joiner = node_on(&network.joiner, &both, &fabric, &joiner_scratch).await;
    tokio::spawn(Arc::clone(&founder).accept_forever());
    let refused = joiner.connect(&network.founder.transport_key().public_key()).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    assert!(
        refused.is_err() || !founder.has_session(&joiner_device).await,
        "the revoked device holds no session"
    );
    assert_eq!(
        minute_of(founder.last_contact(&joiner_device).await),
        Some(5),
        "kept for the revoked device, and unchanged by its attempt"
    );
}

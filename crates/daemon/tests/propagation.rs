//! What the daemon believes about operations it signed, and who has them.
//!
//! The count of unpropagated operations is the one number a person reads before
//! deciding a stolen laptop has been dealt with. Every test here is a way that
//! number used to lie: a tunnel taken down, a restart, a send that failed, one
//! member's word taken for the whole network.
//!
//! They drive `Node` over the in-memory transport, because the defects live in
//! the component that owns the roster and the sessions — not in any layer below,
//! each of which was already tested and already correct.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod common;

use std::sync::Arc;

use common::{a_network, node_off, node_on, within};
use daemon::channel::{Channel, frame};
use daemon::confirmations::{Confirmations, Confirmed};
use daemon::node::Node;
use roster::id::OperationId;
use roster::sign::RawOperation;
use roster_sync::message::{Message, Offer};
use transport::memory::MemoryFabric;

/// The ids of a set of signed operations.
fn ids_of(operations: &[Vec<u8>]) -> Vec<OperationId> {
    operations.iter().map(|bytes| RawOperation::decode(bytes).expect("decodes").id()).collect()
}

/// How many operations a named device has not confirmed.
async fn outstanding_toward(node: &Arc<Node>, name: &str) -> usize {
    node.outstanding()
        .await
        .iter()
        .find(|device| device.name == name)
        .map_or(0, |device| device.operations)
}

/// The record this node keeps beside its log.
fn record_in(scratch: &tempfile::TempDir) -> Confirmations {
    Confirmations::beside(&scratch.path().join("roster.log"))
}

// ---------------------------------------------------------------------------
// An operation has propagated when a device says it holds it
// ---------------------------------------------------------------------------

/// One member's word settles the question for that member and no other.
///
/// An aggregate count would go to zero here — something has propagated, so
/// nothing is waiting — and the device that never heard the operation would
/// vanish from the report along with it.
#[tokio::test]
async fn one_device_confirming_leaves_it_outstanding_toward_another() {
    let network = a_network();
    let fabric = MemoryFabric::new();
    let founder_scratch = tempfile::tempdir().unwrap();
    let joiner_scratch = tempfile::tempdir().unwrap();

    let everything = network.everything();
    let founder = node_on(&network.founder, &everything, &fabric, &founder_scratch).await;
    let joiner = node_on(&network.joiner, &everything, &fabric, &joiner_scratch).await;

    // Before anybody has said anything, both members lack everything the
    // founder signed — which is every operation in this network.
    assert_eq!(outstanding_toward(&founder, "b").await, everything.len());
    assert_eq!(outstanding_toward(&founder, "c").await, everything.len());

    tokio::spawn(Arc::clone(&joiner).accept_forever());
    founder.connect(&network.joiner.transport_key().public_key()).await.expect("a member");

    within("the device that reconciled stops being outstanding", async || {
        outstanding_toward(&founder, "b").await == 0
    })
    .await;

    assert_eq!(
        outstanding_toward(&founder, "c").await,
        everything.len(),
        "the device that said nothing is still owed all of it"
    );
}

/// The revoked device is the one party with a motive to say the revocation is
/// delivered. Its word is refused by a rule, not by the accident that its
/// session has usually been closed by the time it could speak.
#[tokio::test]
async fn a_device_cannot_confirm_the_operation_that_revokes_it() {
    let network = a_network();
    let scratch = tempfile::tempdir().unwrap();

    let founder = node_off(&network.founder, &network.everything(), &scratch);

    let state = founder.state().await.expect("a network");
    let expulsion = daemon::revoking::resolve(
        &state,
        &network.founder,
        &daemon::control::Target::Name("b".to_owned()),
        "lost",
    )
    .expect("the roster names it");
    let revocation =
        daemon::revoking::sign(&expulsion, &network.founder, &state, founder.heads().await)
            .expect("signs");
    founder.admit_without_activating(&revocation).await.expect("the roster accepts it");

    let revocation_id = RawOperation::decode(&revocation).expect("decodes").id();
    let before = outstanding_toward(&founder, "b").await;

    // `b` offers, naming the very operation that expels it. Delivered straight
    // to the node, so that nothing about session lifetime is doing the work.
    let claim = Message::Offer(Offer {
        ids: ids_of(&network.everything()).into_iter().chain([revocation_id]).collect(),
        snapshot: None,
    });
    founder.received(network.joiner.device_id(), &frame(Channel::Roster, &claim.encode())).await;

    assert_eq!(
        outstanding_toward(&founder, "b").await,
        before,
        "a device's claim to hold its own revocation counts for nothing"
    );
}

/// A peer that compacts stops naming what it discarded. Recomputing from the
/// most recent offer would make a delivered operation outstanding again.
#[tokio::test]
async fn a_confirmation_survives_the_peer_compacting() {
    let network = a_network();
    let scratch = tempfile::tempdir().unwrap();

    let founder = node_off(&network.founder, &network.everything(), &scratch);
    let peer = network.joiner.device_id();
    let everything = ids_of(&network.everything());

    let full = Message::Offer(Offer { ids: everything.clone(), snapshot: None });
    founder.received(peer, &frame(Channel::Roster, &full.encode())).await;
    assert_eq!(outstanding_toward(&founder, "b").await, 0, "the peer named all of it");

    // The same peer, after compaction: it holds only its most recent operation
    // and no longer names the rest.
    let compacted = Message::Offer(Offer {
        ids: everything.last().copied().into_iter().collect(),
        snapshot: Some(1),
    });
    founder.received(peer, &frame(Channel::Roster, &compacted.encode())).await;

    assert_eq!(
        outstanding_toward(&founder, "b").await,
        0,
        "what was once observed stays observed; a peer tidying its history is not a regression"
    );
}

// ---------------------------------------------------------------------------
// What has not propagated survives being switched off
// ---------------------------------------------------------------------------

/// Taking the tunnel down ends sessions. It delivers nothing, and must not read
/// as though it had.
#[tokio::test]
async fn taking_the_tunnel_down_changes_nothing_about_propagation() {
    let network = a_network();
    let fabric = MemoryFabric::new();
    let scratch = tempfile::tempdir().unwrap();

    let founder = node_on(&network.founder, &network.two_devices(), &fabric, &scratch).await;
    founder.admit_without_activating(&network.admit_third).await.expect("the roster accepts it");

    let before = outstanding_toward(&founder, "b").await;
    assert!(before > 0, "nobody has confirmed anything yet");

    founder.stopped().await;

    assert_eq!(
        outstanding_toward(&founder, "b").await,
        before,
        "switching the network off is not a delivery"
    );
}

/// The defect as a person meets it: revoke, `down`, reboot, and be told the
/// revocation went out.
#[tokio::test]
async fn a_restart_does_not_deliver_anything() {
    let network = a_network();
    let scratch = tempfile::tempdir().unwrap();

    let founder = node_off(&network.founder, &network.everything(), &scratch);
    let before = outstanding_toward(&founder, "b").await;
    assert!(before > 0);

    founder.stopped().await;
    drop(founder);

    // A second daemon over the same directory. This is the restart.
    let restarted = node_off(&network.founder, &network.everything(), &scratch);
    assert_eq!(
        outstanding_toward(&restarted, "b").await,
        before,
        "a reboot carries nothing to anybody"
    );
}

/// Confirmed is confirmed, and that survives the restart too — otherwise the
/// honest count would simply be a permanently alarming one.
#[tokio::test]
async fn a_confirmed_operation_stays_confirmed_across_a_restart() {
    let network = a_network();
    let scratch = tempfile::tempdir().unwrap();

    let founder = node_off(&network.founder, &network.everything(), &scratch);
    let offer = Message::Offer(Offer { ids: ids_of(&network.everything()), snapshot: None });
    founder.received(network.joiner.device_id(), &frame(Channel::Roster, &offer.encode())).await;
    assert_eq!(outstanding_toward(&founder, "b").await, 0);
    drop(founder);

    let restarted = node_off(&network.founder, &network.everything(), &scratch);
    assert_eq!(
        outstanding_toward(&restarted, "b").await,
        0,
        "what a peer said it held is remembered across a restart"
    );
}

/// The direction of the failure is the decision. A record that cannot be read
/// must report everything as outstanding, never nothing.
#[tokio::test]
async fn a_lost_record_over_reports_rather_than_under_reports() {
    let network = a_network();
    let scratch = tempfile::tempdir().unwrap();
    let everything = network.everything();

    // Assembled once so the log exists, then given a record that confirms the
    // lot: with it, nothing is outstanding.
    drop(node_off(&network.founder, &everything, &scratch));

    let mut confirmed = Confirmed::default();
    confirmed.confirm(network.joiner.device_id(), ids_of(&everything));
    confirmed.confirm(network.third.device_id(), ids_of(&everything));
    let store = record_in(&scratch);
    store.save(&confirmed).unwrap();

    let settled = node_off(&network.founder, &everything, &scratch);
    assert!(settled.outstanding().await.is_empty(), "with the record, nothing is outstanding");
    drop(settled);

    std::fs::write(store.path(), b"not a record any more").unwrap();

    let confused = node_off(&network.founder, &everything, &scratch);
    let outstanding = confused.outstanding().await;
    assert_eq!(outstanding.len(), 2, "both members are reported as owed everything");
    for device in &outstanding {
        assert_eq!(device.operations, everything.len());
    }
    assert!(
        confused.fault().await.is_some_and(|fault| fault.subsystem == "state"),
        "and the over-reporting has a stated reason beside it"
    );
}

/// An operation cannot be outstanding toward somebody who is no longer a member.
#[tokio::test]
async fn a_revoked_device_is_dropped_from_the_record() {
    let network = a_network();
    let scratch = tempfile::tempdir().unwrap();

    let founder = node_off(&network.founder, &network.everything(), &scratch);
    let offer = Message::Offer(Offer { ids: ids_of(&network.everything()), snapshot: None });
    for peer in [network.joiner.device_id(), network.third.device_id()] {
        founder.received(peer, &frame(Channel::Roster, &offer.encode())).await;
    }

    let state = founder.state().await.expect("a network");
    let expulsion = daemon::revoking::resolve(
        &state,
        &network.founder,
        &daemon::control::Target::Name("b".to_owned()),
        "lost",
    )
    .expect("the roster names it");
    let revocation =
        daemon::revoking::sign(&expulsion, &network.founder, &state, founder.heads().await)
            .expect("signs");
    founder.admit_without_activating(&revocation).await.expect("the roster accepts it");

    let kept = record_in(&scratch).load().unwrap();
    assert!(
        !kept.devices().any(|device| *device == network.joiner.device_id()),
        "the expelled device is forgotten"
    );
    assert!(
        kept.devices().any(|device| *device == network.third.device_id()),
        "and nothing else is"
    );
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

/// A write to a session the far end never reads looks, from this side, exactly
/// like one it did. The queue used to empty on the send, so it looked like a
/// delivery; now nothing is recorded until the peer says so itself.
#[tokio::test]
async fn a_send_nobody_reads_is_not_a_delivery() {
    let network = a_network();
    let fabric = MemoryFabric::new();
    let founder_scratch = tempfile::tempdir().unwrap();
    let joiner_scratch = tempfile::tempdir().unwrap();

    let two = network.two_devices();
    let founder = node_on(&network.founder, &two, &fabric, &founder_scratch).await;

    // The peer accepts the connection and then does nothing with it: it never
    // reads what is sent and never offers anything back. This is what a failed
    // delivery looks like from the sending side — identical, at the socket, to
    // one that worked.
    let silent = node_on(&network.joiner, &two, &fabric, &joiner_scratch).await;
    let silent_transport = silent.transport().await.expect("the peer is up");
    tokio::spawn(async move {
        let _held = silent_transport.accept().await;
        core::future::pending::<()>().await;
    });

    founder.connect(&network.joiner.transport_key().public_key()).await.expect("a member");
    let joiner_device = network.joiner.device_id();
    within("a session is open", async || founder.has_session(&joiner_device).await).await;

    // Authored with the session open, so it is written to the socket.
    founder.admit_without_activating(&network.admit_third).await.expect("the roster accepts it");

    assert_eq!(
        outstanding_toward(&founder, "b").await,
        two.len().saturating_add(1),
        "the send happened and settles nothing; only the peer's own offer would"
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
/// that pulls across what the peer lacks — and its next one that supplies the
/// evidence it now holds it.
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
    within("the first reconciliation has run", async || {
        outstanding_toward(&founder, "b").await == 0
    })
    .await;

    // An operation that reaches the founder's roster without being pushed to the
    // joiner: handed over as though the joiner itself had sent it, so the
    // forward goes to every session *except* that one — of which there are none.
    // This is the state a failed send leaves behind: held here, absent there,
    // and the session still open.
    let transfer = Message::Transfer(vec![network.admit_third.clone()]);
    founder.received(joiner_device, &frame(Channel::Roster, &transfer.encode())).await;
    assert_eq!(outstanding_toward(&founder, "b").await, 1, "the peer has not got it");
    assert!(founder.has_session(&joiner_device).await, "on a session that never dropped");

    // No reconnection, no new push. Only the tick both daemons run.
    within("the recurring reconciliation carries what the push did not", async || {
        joiner.offer_to_everyone().await;
        founder.offer_to_everyone().await;
        outstanding_toward(&founder, "b").await == 0
    })
    .await;

    assert!(founder.has_session(&joiner_device).await, "on the same session throughout");
}

/// Pressing is scoped to what is actually being waited for.
#[tokio::test]
async fn only_the_members_that_have_not_confirmed_are_pressed() {
    let network = a_network();
    let scratch = tempfile::tempdir().unwrap();

    let founder = node_off(&network.founder, &network.everything(), &scratch);
    let offer = Message::Offer(Offer { ids: ids_of(&network.everything()), snapshot: None });
    founder.received(network.joiner.device_id(), &frame(Channel::Roster, &offer.encode())).await;

    let pressed = founder.pressed().await;
    assert_eq!(pressed, vec![network.third.device_id()], "only the member that is owed anything");
    assert!(founder.owed().await > 0, "and there is something to press for");
}

/// With nothing outstanding there is nothing to press, so the pacing falls back
/// to the ordinary tick rather than dialling anybody.
#[tokio::test]
async fn a_network_with_nothing_outstanding_presses_nobody() {
    let network = a_network();
    let scratch = tempfile::tempdir().unwrap();

    let founder = node_off(&network.founder, &network.everything(), &scratch);
    let offer = Message::Offer(Offer { ids: ids_of(&network.everything()), snapshot: None });
    for peer in [network.joiner.device_id(), network.third.device_id()] {
        founder.received(peer, &frame(Channel::Roster, &offer.encode())).await;
    }

    assert!(founder.pressed().await.is_empty());
    assert_eq!(founder.owed().await, 0);
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

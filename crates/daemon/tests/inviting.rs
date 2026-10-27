//! A device joining from an admin's invite, end to end.
//!
//! The admin issues an invite; the device waits at the rendezvous key the
//! invite's secret derives; the admin's side dials it there and takes its
//! request; later, a delivery brings it the network as the invite's record
//! says. A relay in this process, and everything below the person real.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::time::Duration;

use daemon::admitting::{self, Applicant, Delivery, Destination};
use daemon::founding::{Founding, found};
use daemon::invites::{Invited, Record};
use daemon::joining::{Joined, Progress, Underway};
use daemon::keys::Keys as _;
use daemon::state::{Log, Paths};
use roster::leaf::{Group, Mode};
use roster::types::Role;
use transport_convesso::fixture::TestRelay;

/// Longer than any step an enrolment bounds itself.
const A_STEP: Duration = Duration::from_secs(180);

/// A network founded at `relay`, its founder's identity, and its state.
fn founded(paths: &Paths, relay: &str) -> (identity::NodeIdentity, roster::state::RosterState) {
    found(
        paths,
        &Founding {
            name: "nas".to_owned(),
            suffix: "peerfectly.internal".to_owned(),
            relay: Some(relay.to_owned()),
            ipv4_range: None,
            window: None,
        },
    )
    .expect("founds");
    let mut roster = roster::roster::Roster::new();
    for operation in &Log::at(paths.roster()).read().expect("reads") {
        assert!(roster.offer_bytes(operation).is_accepted());
    }
    (
        identity::store::load(&paths.identity()).expect("the founder"),
        roster.state().expect("derives"),
    )
}

/// The heads and the log of the roster at `paths`.
fn held(paths: &Paths) -> (Vec<roster::id::OperationId>, Vec<Vec<u8>>) {
    let log = Log::at(paths.roster()).read().expect("reads");
    let mut roster = roster::roster::Roster::new();
    for operation in &log {
        roster.offer_bytes(operation);
    }
    (roster.heads(), log)
}

/// A device joining from `invite` in a directory of its own: its fresh keys,
/// where the join has got to, and the join itself.
fn joining(
    paths: &Paths,
    invite: &str,
) -> (identity::NodeIdentity, Underway, tokio::task::JoinHandle<Result<Joined, String>>) {
    paths.create().unwrap();
    let identity = daemon::keys::PlatformKeys.identity(paths).unwrap();
    let read = enrollment::Invite::from_text(invite).unwrap();
    let proof = daemon::joining::prove_here(&read, &identity).unwrap();
    let join = daemon::joins::Join {
        invite: invite.to_owned(),
        name: "board".to_owned(),
        proof: roster::hex::encode(proof.as_bytes()),
        started_at: 1,
        requested_at: None,
    };
    let (underway, reporting) = Underway::new(Progress::Registering);
    let paths = paths.clone();
    let task = tokio::spawn(async move {
        let identity = daemon::keys::PlatformKeys.identity(&paths).unwrap();
        daemon::joining::run(&paths, &join, &identity, &reporting, |_| {}).await
    });
    (identity, underway, task)
}

/// Dials an invite's rendezvous until the device there makes its request, as
/// the daemon's dial loop does.
async fn requested(record: &Record) -> Applicant {
    tokio::time::timeout(A_STEP, async {
        loop {
            if let Ok(applicant) = admitting::collect(&record.invite).await {
                return applicant;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("the invited device makes its request")
}

/// Waits until the join says its request was received.
async fn told_received(underway: &Underway) {
    tokio::time::timeout(A_STEP, async {
        while !matches!(underway.progress(), Progress::Requested { .. }) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the device is told its request was received");
}

/// The admission of `applicant` as `invited` says, with its settings, signed
/// by `admin` on `heads`.
fn admission(
    admin: &identity::NodeIdentity,
    state: &roster::state::RosterState,
    heads: Vec<roster::id::OperationId>,
    applicant: &Applicant,
    invited: &Invited,
) -> Vec<Vec<u8>> {
    let (core, _name) =
        admitting::admission_core(applicant, invited, admin, state, heads, false).unwrap();
    let settings = admitting::settings_core(invited, admin, state, &core).unwrap();
    core::iter::once(&core)
        .chain(settings.as_ref())
        .map(|each| admin.sign_operation(each).unwrap())
        .collect()
}

/// Delivers at the rendezvous of `record` to the device `applicant` is.
async fn delivered(
    relay: &str,
    record: &Record,
    applicant: &Applicant,
    delivery: &Delivery,
) -> bool {
    let rendezvous =
        transport_convesso::enrolment::rendezvous_key(&record.invite.rendezvous_seed()).unwrap();
    let destination = Destination {
        dialled: rendezvous,
        relay,
        signing: &applicant.signing,
        transport: &applicant.transport,
    };
    tokio::time::timeout(A_STEP, async {
        loop {
            if let Ok(taken) = admitting::deliver(&destination, delivery).await {
                return taken;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("the device is reached")
}

fn invited() -> Invited {
    Invited {
        name: "sensor".to_owned(),
        role: Role::Member,
        mode: Mode::Light,
        groups: vec![Group::new("sensori").unwrap()],
        ipv4: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invited_device_joins_as_its_invite_says() {
    let relay = TestRelay::start().await;
    let url = relay.written();
    let admin_home = tempfile::tempdir().unwrap();
    let admin_paths = Paths::under(admin_home.path());
    let (admin, state) = founded(&admin_paths, &url);
    let record = Record::issue(&url, state.network, invited(), 1, 1_000_000).unwrap();

    let joiner_home = tempfile::tempdir().unwrap();
    let joiner_paths = Paths::under(joiner_home.path());
    let (fresh, underway, task) = joining(&joiner_paths, &record.invite.to_text());

    // The request first, and the device told it was received.
    let applicant = requested(&record).await;
    assert_eq!(applicant.signing, fresh.signing_key().public_key(), "its own keys");
    assert_eq!(applicant.name, "board", "and the name it proposes");
    told_received(&underway).await;

    // Approved later: the roster, as the invite's record says.
    let (heads, mut log) = held(&admin_paths);
    log.extend(admission(&admin, &state, heads, &applicant, &record.invited));
    let delivery = Delivery { operations: log, pieces: Vec::new(), snapshot: None, base: None };
    assert!(delivered(&url, &record, &applicant, &delivery).await, "it adopted the network");
    let joined = tokio::time::timeout(A_STEP, task).await.unwrap().unwrap().expect("joins");
    assert_eq!(joined.devices, 2);

    let mut roster = roster::roster::Roster::new();
    for operation in &Log::at(joiner_paths.roster()).read().unwrap() {
        roster.offer_bytes(operation);
    }
    let state = roster.state().unwrap();
    let record = state.devices.get(&fresh.device_id()).expect("admitted under its keys");
    assert_eq!(record.name, "sensor", "the name the invite's record gave");
    let settings = state.settings_of(&fresh.device_id());
    assert_eq!(settings.mode, Mode::Light);
    assert_eq!(settings.groups, vec![Group::new("sensori").unwrap()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leaked_secret_cannot_pull_the_device_into_another_network() {
    let relay = TestRelay::start().await;
    let url = relay.written();
    let admin_home = tempfile::tempdir().unwrap();
    let (_admin, state) = founded(&Paths::under(admin_home.path()), &url);
    let record = Record::issue(&url, state.network, invited(), 1, 1_000_000).unwrap();

    // Somebody who learned the secret, with a network of their own, takes the
    // request and admits the device into it.
    let thief_home = tempfile::tempdir().unwrap();
    let thief_paths = Paths::under(thief_home.path());
    let (thief, thief_state) = founded(&thief_paths, &url);

    let joiner_home = tempfile::tempdir().unwrap();
    let joiner_paths = Paths::under(joiner_home.path());
    let (_fresh, underway, task) = joining(&joiner_paths, &record.invite.to_text());
    let applicant = requested(&record).await;
    let (heads, mut log) = held(&thief_paths);
    log.extend(admission(&thief, &thief_state, heads, &applicant, &record.invited));
    let delivery = Delivery { operations: log, pieces: Vec::new(), snapshot: None, base: None };

    assert!(!delivered(&url, &record, &applicant, &delivery).await, "the device does not take it");
    assert!(
        Log::at(joiner_paths.roster()).read().unwrap().is_empty(),
        "and nothing of the other network was written"
    );
    tokio::time::timeout(A_STEP, async {
        while underway.last_refusal().is_none() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("it says why");
    assert!(!task.is_finished(), "and goes on waiting");
    task.abort();
}

/// An admin whose roster was compacted: a root over its first operations and
/// the state beneath it as the base, and the operations after it as the window.
fn compacted(
    admin: &identity::NodeIdentity,
    paths: &Paths,
) -> (roster::roster::Roster, enrollment::adopt::Base) {
    let (founding, _at) = daemon::state::read_snapshot(paths).expect("the founding root");
    let mut roster = roster::roster::Roster::with_staleness_depth(2);
    for operation in &Log::at(paths.roster()).read().unwrap() {
        assert!(roster.offer_bytes(operation).is_accepted());
    }
    assert!(roster.offer_snapshot(&founding).is_accepted());
    let network = roster.state().unwrap().network;
    let mut root = Vec::new();
    for index in 0_u64..6 {
        // A root over the first two, which the rest leave far enough behind.
        if index == 2 {
            root = daemon::snapshots::sign_over_heads(&roster, admin).expect("signs a root");
            assert!(roster.offer_snapshot(&root).is_accepted());
        }
        let core = roster::types::OperationCore::new(
            index.saturating_add(2),
            admin.signing_key().algorithm(),
            roster::types::OperationBody::Rename {
                device: admin.device_id(),
                name: format!("nas-{index}"),
            },
            roster.heads(),
            admin.signing_key().key_id(),
            network,
        )
        .unwrap();
        let bytes = admin.sign_operation(&core).unwrap();
        assert!(roster.offer_bytes(&bytes).is_accepted());
    }
    assert!(roster.compact().unwrap() > 0, "the history beneath the root is gone");
    let state = roster.dag().base_state().cloned().expect("a base");
    (roster, enrollment::adopt::Base { root, state })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_invited_into_a_compacted_network_rests_on_the_state_beneath_it() {
    let relay = TestRelay::start().await;
    let url = relay.written();
    let admin_home = tempfile::tempdir().unwrap();
    let admin_paths = Paths::under(admin_home.path());
    let (admin, _state) = founded(&admin_paths, &url);
    let (roster, base) = compacted(&admin, &admin_paths);
    let mut window = roster.retained_operations();
    let state = roster.state().unwrap();
    let record = Record::issue(&url, state.network, invited(), 1, 1_000_000).unwrap();

    let joiner_home = tempfile::tempdir().unwrap();
    let joiner_paths = Paths::under(joiner_home.path());
    let (_fresh, _underway, task) = joining(&joiner_paths, &record.invite.to_text());
    let applicant = requested(&record).await;

    let admitted = admission(&admin, &state, roster.heads(), &applicant, &record.invited);
    let sent = window.len() + admitted.len();
    window.extend(admitted);
    let delivery =
        Delivery { operations: window, pieces: Vec::new(), snapshot: None, base: Some(base) };
    assert!(delivered(&url, &record, &applicant, &delivery).await, "it adopted the network");
    let joined = tokio::time::timeout(A_STEP, task).await.unwrap().unwrap().expect("joins");
    assert_eq!(joined.devices, 2);

    // It keeps the base, and its log reaches no further back than the window.
    let store = daemon::state::open_base_store(&joiner_paths).unwrap();
    assert!(daemon::state::read_base(&joiner_paths, &store).is_some(), "the base is kept");
    drop(store);
    let log = Log::at(joiner_paths.roster()).read().unwrap();
    let genesis = Log::at(admin_paths.roster()).read().unwrap().remove(0);
    assert!(!log.contains(&genesis), "the genesis is beneath the base, and was not sent");
    assert_eq!(log.len(), sent, "the window and its own admission");
}

/// A sender that lies about the state beneath the root is refused: the state
/// must make the root.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_base_that_does_not_make_its_root_is_refused() {
    let relay = TestRelay::start().await;
    let url = relay.written();
    let admin_home = tempfile::tempdir().unwrap();
    let admin_paths = Paths::under(admin_home.path());
    let (admin, _state) = founded(&admin_paths, &url);
    let (roster, mut base) = compacted(&admin, &admin_paths);
    let mut window = roster.retained_operations();
    let state = roster.state().unwrap();
    // A state that is not the one the root commits to.
    base.state = state.clone();
    let record = Record::issue(&url, state.network, invited(), 1, 1_000_000).unwrap();

    let joiner_home = tempfile::tempdir().unwrap();
    let joiner_paths = Paths::under(joiner_home.path());
    let (_fresh, _underway, task) = joining(&joiner_paths, &record.invite.to_text());
    let applicant = requested(&record).await;
    window.extend(admission(&admin, &state, roster.heads(), &applicant, &record.invited));
    let delivery =
        Delivery { operations: window, pieces: Vec::new(), snapshot: None, base: Some(base) };

    assert!(!delivered(&url, &record, &applicant, &delivery).await, "the device does not take it");
    assert!(Log::at(joiner_paths.roster()).read().unwrap().is_empty(), "nothing of it was written");
    task.abort();
}

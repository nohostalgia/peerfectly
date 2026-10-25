//! A device joining from an admin's invite, end to end.
//!
//! The admin issues an invite; the device waits at the rendezvous key the
//! invite's secret derives; the admin dials it there, a person compares the
//! code, and the admin signs what the invite's record says the device will be.
//! A relay in this process, and everything below the person real.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::sync::Arc;
use std::time::Duration;

use daemon::admitting;
use daemon::founding::{Founding, found};
use daemon::invites::{Invited, Record};
use daemon::joining::{Person, join};
use daemon::state::{Log, Paths};
use enrollment::code::Confirmation;
use roster::leaf::{Group, Mode};
use roster::types::Role;
use transport_convesso::fixture::TestRelay;

/// Longer than any step an enrolment bounds itself.
const A_STEP: Duration = Duration::from_secs(180);

/// How long the scripted person stands there.
const PATIENCE: Duration = Duration::from_secs(20);

/// A person at the joining device, typing what the admin's screen shows.
struct Scripted {
    from_the_admin: std::sync::Mutex<std::sync::mpsc::Receiver<String>>,
}

impl Person for Scripted {
    fn code_shown_by_the_admin(&self, _ours: &Confirmation) -> Option<String> {
        self.from_the_admin.lock().ok()?.recv_timeout(PATIENCE).ok()
    }

    fn signs_the_proof(&self, _request: &identity::detached::SigningRequest) -> Option<Vec<u8>> {
        None
    }

    fn note(&self, _message: &str) {}
}

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

/// A device joining from `invite`, and the sender its person types with.
fn joining(
    paths: &Paths,
    invite: String,
) -> (
    std::sync::mpsc::Sender<String>,
    tokio::task::JoinHandle<Result<daemon::joining::Joined, String>>,
) {
    let (types, from_the_admin) = std::sync::mpsc::channel();
    let person = Arc::new(Scripted { from_the_admin: std::sync::Mutex::new(from_the_admin) });
    let paths = paths.clone();
    let task = tokio::spawn(async move {
        join(&paths, &invite, "board", person, &daemon::keys::PlatformKeys).await
    });
    (types, task)
}

/// Dials an invited device until it is there, as the daemon's dial loop does.
async fn reached(
    identity: &identity::NodeIdentity,
    state: &roster::state::RosterState,
    record: &Record,
) -> admitting::Pending {
    tokio::time::timeout(A_STEP, async {
        loop {
            if let Ok(pending) = admitting::open_invited(identity, state, record).await {
                return pending;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("the invited device is reached")
}

async fn until_accepted(pending: &admitting::Pending) {
    let started = std::time::Instant::now();
    while !pending.accepted() {
        assert!(started.elapsed() < PATIENCE, "the device never said the code matched");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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
async fn an_invited_device_joins_as_its_invite_says_and_with_keys_it_never_had() {
    let relay = TestRelay::start().await;
    let url = relay.written();
    let admin_home = tempfile::tempdir().unwrap();
    let admin_paths = Paths::under(admin_home.path());
    let (admin, state) = founded(&admin_paths, &url);
    let record = Record::issue(&url, state.network, invited(), 1, 1_000_000).unwrap();

    // The device held an identity before — an earlier membership of this
    // network. A join makes fresh keys whatever it held.
    let joiner_home = tempfile::tempdir().unwrap();
    let joiner_paths = Paths::under(joiner_home.path());
    joiner_paths.create().unwrap();
    let old = identity::NodeIdentity::generate().unwrap();
    identity::store::save(&old, &joiner_paths.identity()).unwrap();

    let (types, task) = joining(&joiner_paths, record.invite.to_text());
    let pending = reached(&admin, &state, &record).await;
    types.send(pending.code().to_string()).unwrap();
    until_accepted(&pending).await;

    let (heads, log) = held(&admin_paths);
    let (_signed, said) = tokio::time::timeout(
        A_STEP,
        admitting::confirm(pending, &admin, &state, heads, &log, None, false),
    )
    .await
    .expect("delivers")
    .expect("admits");
    assert!(said.contains("adopted"), "{said}");
    let joined = tokio::time::timeout(A_STEP, task).await.unwrap().unwrap().expect("joins");
    assert_eq!(joined.devices, 2);

    let fresh = identity::store::load(&joiner_paths.identity()).unwrap();
    assert_ne!(fresh.device_id(), old.device_id(), "keys it never presented before");
    let mut roster = roster::roster::Roster::new();
    for operation in &Log::at(joiner_paths.roster()).read().unwrap() {
        roster.offer_bytes(operation);
    }
    let state = roster.state().unwrap();
    let record = state.devices.get(&fresh.device_id()).expect("admitted under its new keys");
    assert_eq!(record.name, "sensor", "the name the invite's record gave");
    let settings = state.settings_of(&fresh.device_id());
    assert_eq!(settings.mode, Mode::Light);
    assert_eq!(settings.groups, vec![Group::new("sensori").unwrap()]);
    assert!(!state.devices.contains_key(&old.device_id()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_leaked_secret_cannot_pull_the_device_into_another_network() {
    let relay = TestRelay::start().await;
    let url = relay.written();
    let admin_home = tempfile::tempdir().unwrap();
    let (_admin, state) = founded(&Paths::under(admin_home.path()), &url);
    let record = Record::issue(&url, state.network, invited(), 1, 1_000_000).unwrap();

    // Somebody who learned the secret, with a network of their own, dials first.
    let thief_home = tempfile::tempdir().unwrap();
    let thief_paths = Paths::under(thief_home.path());
    let (thief, thief_state) = founded(&thief_paths, &url);

    let joiner_home = tempfile::tempdir().unwrap();
    let joiner_paths = Paths::under(joiner_home.path());
    let (types, task) = joining(&joiner_paths, record.invite.to_text());
    let pending = reached(&thief, &thief_state, &record).await;
    types.send(pending.code().to_string()).unwrap();
    until_accepted(&pending).await;
    let (heads, log) = held(&thief_paths);
    let (_signed, said) = tokio::time::timeout(
        A_STEP,
        admitting::confirm(pending, &thief, &thief_state, heads, &log, None, false),
    )
    .await
    .expect("delivers")
    .expect("signs");

    assert!(said.contains("refused"), "the device says it did not take it: {said}");
    assert!(
        Log::at(joiner_paths.roster()).read().unwrap().is_empty(),
        "and nothing of the other network was written"
    );
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
    let window = roster.retained_operations();
    let state = roster.state().unwrap();
    let record = Record::issue(&url, state.network, invited(), 1, 1_000_000).unwrap();

    let joiner_home = tempfile::tempdir().unwrap();
    let joiner_paths = Paths::under(joiner_home.path());
    let (types, task) = joining(&joiner_paths, record.invite.to_text());
    let mut pending = reached(&admin, &state, &record).await;
    types.send(pending.code().to_string()).unwrap();
    until_accepted(&pending).await;

    let (admission, spec_name) =
        admitting::core(&mut pending, &admin, &state, roster.heads(), false)
            .await
            .expect("prepares");
    let signed = vec![admin.sign_operation(&admission).unwrap()];
    let (_signed, said) = tokio::time::timeout(
        A_STEP,
        admitting::finish_with_all(pending, signed, spec_name, &window, None, Some(base)),
    )
    .await
    .expect("delivers")
    .expect("admits");
    assert!(said.contains("adopted"), "{said}");
    let joined = tokio::time::timeout(A_STEP, task).await.unwrap().unwrap().expect("joins");
    assert_eq!(joined.devices, 2);

    // It keeps the base, and its log reaches no further back than the window.
    assert!(daemon::state::read_base(&joiner_paths).is_some(), "the base is kept");
    let log = Log::at(joiner_paths.roster()).read().unwrap();
    let genesis = Log::at(admin_paths.roster()).read().unwrap().remove(0);
    assert!(!log.contains(&genesis), "the genesis is beneath the base, and was not sent");
    assert_eq!(log.len(), window.len() + 1, "the window and its own admission");
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
    let window = roster.retained_operations();
    let state = roster.state().unwrap();
    // A state that is not the one the root commits to.
    base.state = state.clone();
    let record = Record::issue(&url, state.network, invited(), 1, 1_000_000).unwrap();

    let joiner_home = tempfile::tempdir().unwrap();
    let joiner_paths = Paths::under(joiner_home.path());
    let (types, task) = joining(&joiner_paths, record.invite.to_text());
    let mut pending = reached(&admin, &state, &record).await;
    types.send(pending.code().to_string()).unwrap();
    until_accepted(&pending).await;

    let (admission, spec_name) =
        admitting::core(&mut pending, &admin, &state, roster.heads(), false)
            .await
            .expect("prepares");
    let signed = vec![admin.sign_operation(&admission).unwrap()];
    let (_signed, said) = tokio::time::timeout(
        A_STEP,
        admitting::finish_with_all(pending, signed, spec_name, &window, None, Some(base)),
    )
    .await
    .expect("delivers")
    .expect("signs");
    assert!(said.contains("refused"), "the device says it did not take it: {said}");
    assert!(Log::at(joiner_paths.roster()).read().unwrap().is_empty(), "nothing of it was written");
    task.abort();
}

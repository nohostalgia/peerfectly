//! Membership reaching the transport, driven through the daemon.
//!
//! Every layer below already had tests for this, and every one of them passed
//! while two real machines refused each other for twenty minutes. They passed
//! because each supplied the new roster state itself — which is precisely the
//! thing the daemon could not do, and precisely what nothing checked.
//!
//! So these drive it through `Node`, the component that owns the roster. Over
//! the in-memory transport, so they run in CI, on the interface the real one
//! also satisfies.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod common;

use std::sync::Arc;

use common::{a_network, node_on, within};
use daemon::revoking;
use transport::memory::MemoryFabric;

/// A device admitted while the transport is already running becomes reachable,
/// with nothing taken down and nothing restarted.
///
/// **This is the test whose absence is the reason the defect shipped.** Before
/// the fix, the founder's transport went on authorising against the roster it
/// was bound with — a network of one — so the device it had just admitted read
/// as a stranger, in both directions, until somebody cycled the tunnel on both
/// machines.
#[tokio::test]
async fn a_device_admitted_while_running_becomes_reachable() {
    let network = a_network();
    let fabric = MemoryFabric::new();
    let founder_scratch = tempfile::tempdir().expect("a scratch directory");
    let joiner_scratch = tempfile::tempdir().expect("a scratch directory");

    // The founder knows only itself, which is the state its transport is bound
    // to. The joiner already holds the admission, as it would after adopting.
    let founder = node_on(
        &network.founder,
        core::slice::from_ref(&network.genesis),
        &fabric,
        &founder_scratch,
    )
    .await;
    let joiner = node_on(
        &network.joiner,
        &[network.genesis.clone(), network.admit_joiner.clone()],
        &fabric,
        &joiner_scratch,
    )
    .await;

    tokio::spawn(Arc::clone(&joiner).accept_forever());

    // Nothing has admitted the joiner here yet, so it is a stranger.
    assert!(
        founder.connect(&network.joiner.transport_key().public_key()).await.is_err(),
        "before the admission the joiner is not a member, and must be refused"
    );

    // The admission, signed on this device while everything is running.
    founder.admit_without_activating(&network.admit_joiner).await.expect("the roster accepts it");

    founder
        .connect(&network.joiner.transport_key().public_key())
        .await
        .expect("a device admitted while running must be reachable without a restart");

    let joiner_device = network.joiner.device_id();
    let founder_device = network.founder.device_id();
    within("the founder holds a session with the device it admitted", async || {
        founder.has_session(&joiner_device).await
    })
    .await;
    within("and the joiner holds one with the founder", async || {
        joiner.has_session(&founder_device).await
    })
    .await;
}

/// Revoking a device closes the session it already holds, without a restart.
///
/// The same staleness read the other way, and the half that matters: a stale
/// transport does not merely fail to admit somebody, it goes on admitting
/// somebody the roster has expelled.
#[tokio::test]
async fn revoking_a_device_closes_its_session_without_a_restart() {
    let network = a_network();
    let fabric = MemoryFabric::new();
    let founder_scratch = tempfile::tempdir().expect("a scratch directory");
    let joiner_scratch = tempfile::tempdir().expect("a scratch directory");

    let both = [network.genesis.clone(), network.admit_joiner.clone()];
    let founder = node_on(&network.founder, &both, &fabric, &founder_scratch).await;
    let joiner = node_on(&network.joiner, &both, &fabric, &joiner_scratch).await;

    tokio::spawn(Arc::clone(&joiner).accept_forever());

    founder
        .connect(&network.joiner.transport_key().public_key())
        .await
        .expect("two members reach each other");

    let joiner_device = network.joiner.device_id();
    within("a session is open before the revocation", async || {
        founder.has_session(&joiner_device).await
    })
    .await;

    // Signed here, while the session is carrying — and through the same code the
    // `revoke` command uses, so this exercises the path a person takes rather
    // than a hand-built operation that only resembles it.
    let state = founder.state().await.expect("a network");
    let expulsion = revoking::resolve(
        &state,
        &network.founder,
        &daemon::control::Target::Name("b".to_owned()),
        "the machine was lost",
    )
    .expect("the roster names it");
    assert_eq!(expulsion.device, joiner_device);

    let revoke_bytes =
        revoking::sign(&expulsion, &network.founder, &state, founder.heads().await).expect("signs");

    founder
        .admit_without_activating(&revoke_bytes)
        .await
        .expect("the roster accepts the revocation");

    within("the revoked device's session closes with no restart", async || {
        !founder.has_session(&joiner_device).await
    })
    .await;

    assert!(
        founder.connect(&network.joiner.transport_key().public_key()).await.is_err(),
        "and it cannot reconnect"
    );
}

/// Nothing changes the roster except through the one point that speaks.
///
/// The fix is a single call in `enforce_roster`, which is only correct while
/// every path that changes the roster ends there. A fourth path added later that
/// forgot to would reintroduce exactly this defect, and would look just as
/// innocent as the three that already existed.
#[test]
fn the_roster_is_owned_by_one_module_and_one_choke_point() {
    let node = include_str!("../src/node.rs");

    // The `Syncer` is private to `Node`: no accessor hands it out, so nothing
    // outside this module can change the roster without going through it.
    for escape in ["pub fn syncer", "pub async fn syncer", "pub(crate) fn syncer"] {
        assert!(
            !node.contains(escape),
            "`{escape}` would let something outside change the roster without telling the layers that decide from it"
        );
    }

    // Both mutating paths end at the choke point.
    for path in ["async fn received_roster", "pub async fn admit_without_activating"] {
        let body = node
            .split_once(path)
            .map(|(_, rest)| {
                rest.split(
                    "
    /// ",
                )
                .next()
                .unwrap_or(rest)
            })
            .unwrap_or_else(|| panic!("{path} is where the roster changes"));
        assert!(
            body.contains("enforce_roster"),
            "{path} changes the roster, so it must end at `enforce_roster`"
        );
    }

    // And the choke point is what tells the transport.
    let enforce = node
        .split_once("pub async fn enforce_roster")
        .map(|(_, rest)| rest)
        .expect("the choke point exists");
    assert!(
        enforce.contains("update_state"),
        "`enforce_roster` must hand the transport the new state; without it the transport goes on deciding from whatever it held at bring-up"
    );
}

/// Two admins, apart, each admit a `phone`. When the rosters meet, the name
/// answers to two devices — and `revoke phone` used to expel whichever sorted
/// first.
#[tokio::test]
async fn a_name_two_admins_gave_away_is_never_revoked_by_guessing() {
    use roster::sign::sign_operation;
    use roster::types::{OperationBody, OperationCore, Role};

    let network = a_network();
    let fabric = MemoryFabric::new();
    let desk = Arc::new(identity::NodeIdentity::generate().unwrap());
    let kept_phone = Arc::new(identity::NodeIdentity::generate().unwrap());
    let stolen_phone = Arc::new(identity::NodeIdentity::generate().unwrap());

    let genesis = roster::sign::RawOperation::decode(&network.genesis).unwrap();
    let net = roster::id::NetworkId::from_bytes(*genesis.id().as_bytes());
    let sign = |author: &Arc<identity::NodeIdentity>,
                parents: Vec<roster::id::OperationId>,
                body: OperationBody| {
        let core = OperationCore::new(
            1_757_000_040_000,
            author.signing_key().algorithm(),
            body,
            parents,
            author.signing_key().key_id(),
            net,
        )
        .unwrap();
        (core.id(), sign_operation(&core, author.signer()).unwrap())
    };

    let (desk_id, admit_desk) = sign(
        &network.founder,
        vec![genesis.id()],
        OperationBody::AddDevice(desk.device_spec("desk", Role::Admin, false, vec![]).unwrap()),
    );
    // Concurrent: each admin, from the same point, admits a device it calls `phone`.
    let (_, by_founder) = sign(
        &network.founder,
        vec![desk_id],
        OperationBody::AddDevice(
            kept_phone.device_spec("phone", Role::Member, false, vec![]).unwrap(),
        ),
    );
    let (_, by_desk) = sign(
        &desk,
        vec![desk_id],
        OperationBody::AddDevice(
            stolen_phone.device_spec("phone", Role::Member, false, vec![]).unwrap(),
        ),
    );
    let everything = vec![network.genesis.clone(), admit_desk, by_founder, by_desk];

    let scratch =
        [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let founder = node_on(&network.founder, &everything, &fabric, &scratch[0]).await;
    let kept = node_on(&kept_phone, &everything, &fabric, &scratch[1]).await;
    let stolen = node_on(&stolen_phone, &everything, &fabric, &scratch[2]).await;
    tokio::spawn(Arc::clone(&kept).accept_forever());
    tokio::spawn(Arc::clone(&stolen).accept_forever());
    founder.connect(&kept_phone.transport_key().public_key()).await.unwrap();
    founder.connect(&stolen_phone.transport_key().public_key()).await.unwrap();

    let state = founder.state().await.unwrap();
    let phones = state.devices.values().filter(|record| record.name == "phone").count();
    assert_eq!(phones, 2, "the merge really did produce two devices with one name");

    let refusal = revoking::resolve(
        &state,
        &network.founder,
        &daemon::control::Target::Name("phone".to_owned()),
        "stolen",
    )
    .expect_err("a name two devices share is not revoked");
    assert!(refusal.contains("nothing was signed"), "{refusal}");

    let stolen_id = daemon::control::short_id(&stolen_phone.device_id());
    let expulsion = revoking::resolve(
        &state,
        &network.founder,
        &daemon::control::Target::Id(stolen_id),
        "stolen",
    )
    .expect("an id names exactly one");
    assert_eq!(expulsion.device, stolen_phone.device_id());

    let revocation =
        revoking::sign(&expulsion, &network.founder, &state, founder.heads().await).unwrap();
    founder.admit_without_activating(&revocation).await.unwrap();

    let (kept_device, stolen_device) = (kept_phone.device_id(), stolen_phone.device_id());
    within("the stolen phone's session closes", async || {
        !founder.has_session(&stolen_device).await
    })
    .await;
    assert!(
        founder.has_session(&kept_device).await,
        "and the phone a person still has keeps its session"
    );
}

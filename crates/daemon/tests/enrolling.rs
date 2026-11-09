//! One device joining another's network from an invite, end to end, at the
//! level of the modules the daemon calls.
//!
//! Two machines and a relay in this process. Everything is real: real
//! endpoints, a real relay, real signed operations. The service-level runs —
//! the pending list, approval, restarts — are in the daemon's own tests.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::sync::Arc;
use std::time::Duration;

/// How long a step of an enrolment may take before a test calls it stuck.
///
/// **Above the exchange's own deadline, not equal to it.** These wrap a step the
/// enrolment itself already bounds at sixty seconds; a test bounded at the same
/// number is racing the thing it is watching, and under a full parallel run it
/// loses that race often enough to fail for reasons that have nothing to do with
/// what it asserts.
const A_STEP: Duration = Duration::from_secs(180);

use daemon::admitting::{self, Applicant, Delivery, Destination};
use daemon::founding::{Founding, found};
use daemon::invites::{Invited, Record};
use daemon::joining::{Joined, Progress, Underway};
use daemon::keys::Keys;
use daemon::state::{Log, Paths};
use transport_convesso::fixture::TestRelay;

/// A convesso relay in this process, and how a network writes it.
async fn relay() -> (TestRelay, String) {
    let relay = TestRelay::start().await;
    let written = relay.written();
    (relay, written)
}

/// An invite into the network `state` describes, at `url`, for a member called
/// `laptop`.
fn invite_into(state: &roster::state::RosterState, url: &str) -> Record {
    let invited = Invited {
        name: "laptop".to_owned(),
        role: roster::types::Role::Member,
        mode: roster::leaf::Mode::Full,
        groups: Vec::new(),
        ipv4: None,
    };
    Record::issue(url, state.network, state.params.ipv4_range(), invited, 1, 1_000_000)
        .expect("issues")
}

/// A signing key this process cannot reach, as a machine key store is.
struct OutOfReach {
    /// The key, which only the thing that can reach it may use.
    key: roster::sign::P256Signer,
}

impl identity::detached::KeyCustodian for OutOfReach {
    fn public_key(&self) -> roster::sign::PublicKey {
        roster::sign::Signer::public_key(&self.key)
    }

    fn sign_request(
        &self,
        _request: &identity::detached::SigningRequest,
    ) -> identity::Result<Vec<u8>> {
        panic!("nothing may reach this: the join must prepare and ask instead")
    }

    fn answers_here(&self) -> bool {
        false
    }
}

/// Keys whose signing half is in a store this process cannot reach.
struct Elsewhere {
    custodian: Arc<OutOfReach>,
}

impl identity::store::Custodians for Elsewhere {
    fn find(
        &self,
        _reference: &str,
    ) -> identity::Result<Option<Arc<dyn identity::detached::KeyCustodian + Send + Sync>>> {
        Ok(Some(
            Arc::clone(&self.custodian) as Arc<dyn identity::detached::KeyCustodian + Send + Sync>
        ))
    }
}

impl daemon::keys::Keys for Elsewhere {
    fn identity(&self, paths: &Paths) -> daemon::error::Result<identity::NodeIdentity> {
        let path = paths.identity();
        let failed = |cause: identity::Error| daemon::error::Error::State {
            path: path.clone(),
            cause: cause.to_string(),
        };
        if path.exists() {
            return identity::store::load_with(&path, &identity::store::PlatformSealer, self)
                .map_err(failed);
        }
        paths.create()?;
        let transport =
            identity::PrivateKey::generate(roster::types::Algorithm::Ed25519).map_err(failed)?;
        let attestation =
            identity::PrivateKey::generate(roster::types::Algorithm::Ed25519).map_err(failed)?;
        let custodian =
            Arc::clone(&self.custodian) as Arc<dyn identity::detached::KeyCustodian + Send + Sync>;
        let made = identity::NodeIdentity::with_custodian(
            "peerfectly.test.signing",
            custodian,
            transport,
            attestation,
        )
        .map_err(failed)?;
        identity::store::save_with(&made, &path, &identity::store::PlatformSealer)
            .map_err(failed)?;
        Ok(made)
    }
}

/// A device joining from `record`'s invite with `proof` made by its signing
/// key, however that was reached: where it has got to, and the join itself.
fn waiting(
    paths: &Paths,
    record: &Record,
    proof: &enrollment::exchange::Possession,
    keys: Arc<dyn Keys>,
) -> (Underway, tokio::task::JoinHandle<Result<Joined, String>>) {
    let join = daemon::joins::Join {
        invite: record.invite.to_text(),
        name: "laptop".to_owned(),
        proof: roster::hex::encode(proof.as_bytes()),
        started_at: 1,
        requested_at: None,
        conflicts: Vec::new(),
    };
    let (underway, reporting) = Underway::new(Progress::Registering);
    let paths = paths.clone();
    let task = tokio::spawn(async move {
        let identity = keys.identity(&paths).unwrap();
        daemon::joining::run(&paths, &join, &identity, &reporting, |_| {}).await
    });
    (underway, task)
}

/// Dials an invite's rendezvous until the device there makes its request.
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

/// Delivers at the rendezvous of `record` to the device `applicant` is.
async fn delivered(url: &str, record: &Record, applicant: &Applicant, delivery: &Delivery) -> bool {
    let rendezvous =
        transport_convesso::enrolment::rendezvous_key(&record.invite.rendezvous_seed()).unwrap();
    let destination = Destination {
        dialled: rendezvous,
        relay: url,
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

/// A founder, and the state it holds.
fn founded(paths: &Paths, relay: &str) -> roster::state::RosterState {
    found(
        paths,
        &Founding {
            name: "nas".to_owned(),
            suffix: "peerfectly.internal".to_owned(),
            relay: Some(relay.to_owned()),
            ipv4_range: None,
            window: Some(roster::limits::DEFAULT_SNAPSHOT_WINDOW),
        },
    )
    .expect("founds");

    let mut roster = roster::roster::Roster::new();
    for operation in &Log::at(paths.roster()).read().expect("reads") {
        assert!(roster.offer_bytes(operation).is_accepted());
    }
    roster.state().expect("derives")
}

/// Taking a request gives the device nothing, and changes nothing on the
/// admin's side: a device becomes a member because a signed operation says so,
/// and until a person approves there is no such operation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taking_a_request_changes_nothing_until_a_person_approves() {
    let (_server, url) = relay().await;
    let admin_home = tempfile::tempdir().expect("a scratch directory");
    let admin_paths = Paths::under(admin_home.path());
    let state = founded(&admin_paths, &url);
    let before = Log::at(admin_paths.roster()).read().expect("reads");

    let joiner_home = tempfile::tempdir().expect("a scratch directory");
    let joiner_paths = Paths::under(joiner_home.path());
    joiner_paths.create().unwrap();
    let record = invite_into(&state, &url);
    let identity = daemon::keys::PlatformKeys.identity(&joiner_paths).unwrap();
    let proof = daemon::joining::prove_here(&record.invite, &identity).unwrap();
    let (underway, task) =
        waiting(&joiner_paths, &record, &proof, Arc::new(daemon::keys::PlatformKeys));

    let applicant = requested(&record).await;
    assert_eq!(
        daemon::joining::fingerprint(&applicant.signing),
        daemon::joining::fingerprint(&identity.signing_key().public_key()),
        "the fingerprint the admin reviews is the one the device shows"
    );
    assert_eq!(before, Log::at(admin_paths.roster()).read().expect("reads"), "nothing signed");
    assert!(Log::at(joiner_paths.roster()).read().expect("reads").is_empty(), "nothing given");
    tokio::time::timeout(A_STEP, async {
        while !matches!(underway.progress(), Progress::Requested { .. }) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("and the device is told its request is kept");
    assert!(!task.is_finished(), "it goes on waiting for the approval");
    task.abort();
}

/// Enrolment adds no list of permitted devices and caches no decision.
///
/// The daemon's boundary requirement says membership comes from the roster and
/// nowhere else. Enrolment is where a second answer would be most tempting to
/// write, so this reads the modules that do it.
#[test]
fn enrolment_keeps_no_membership_of_its_own() {
    for (what, source) in [
        ("joining", include_str!("../src/joining.rs")),
        ("admitting", include_str!("../src/admitting.rs")),
    ] {
        // The comments explain the very thing being looked for, so only the
        // code is read — the same cut the crate's own scan tests make.
        let code = source
            .split("#[cfg(test)]")
            .next()
            .unwrap_or(source)
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && !trimmed.starts_with("///")
            })
            .collect::<String>();
        for smell in ["allowed", "permitted", "trusted_keys", "known_devices", "authorised"] {
            assert!(
                !code.contains(smell),
                "`{smell}` in {what} would be a second answer to who belongs"
            );
        }
    }
}

/// A device joins with its signing key in a store this process cannot reach.
///
/// The proof of its signing key is made once, before the join waits: prepared
/// here, signed by whatever reaches the key, and checked against the key being
/// presented before the join is started with it. The admin's side checks it
/// again when it takes the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_whose_key_is_out_of_reach_still_proves_it_holds_it() {
    let (_server, url) = relay().await;

    let admin_home = tempfile::tempdir().expect("a scratch directory");
    let admin_paths = Paths::under(admin_home.path());
    let state = founded(&admin_paths, &url);
    let admin = identity::store::load(&admin_paths.identity()).expect("the founder's identity");
    let record = invite_into(&state, &url);

    let joiner_home = tempfile::tempdir().expect("a scratch directory");
    let joiner_paths = Paths::under(joiner_home.path());
    let key = roster::sign::P256Signer::from_scalar([0x44; 32]).expect("inside the order");
    let reachable = roster::sign::P256Signer::from_scalar([0x44; 32]).expect("inside the order");
    let keys = Arc::new(Elsewhere { custodian: Arc::new(OutOfReach { key }) });
    let identity = keys.identity(&joiner_paths).expect("an identity");
    assert!(!identity.signing_key().answers_here());

    // Prepared here; signed by what reaches the key; checked before it is used.
    let request = daemon::joining::proof_request(&record.invite, &identity).expect("prepares");
    let signature = roster::sign::Signer::sign(&reachable, request.message()).expect("signs");
    let proof =
        daemon::joining::proof_from(&record.invite, &identity, signature).expect("it verifies");
    let wrong = roster::sign::Signer::sign(&reachable, b"something else").expect("signs");
    assert!(daemon::joining::proof_from(&record.invite, &identity, wrong).is_err());

    let (_underway, task) = waiting(&joiner_paths, &record, &proof, keys);
    let applicant = requested(&record).await;
    assert_eq!(applicant.signing, identity.signing_key().public_key(), "the key it proved");

    let (heads, mut log) = {
        let log = Log::at(admin_paths.roster()).read().expect("reads");
        let mut roster = roster::roster::Roster::new();
        for operation in &log {
            roster.offer_bytes(operation);
        }
        (roster.heads(), log)
    };
    let (core, _name) =
        admitting::admission_core(&applicant, &record.invited, &admin, &state, heads, false)
            .expect("prepares");
    let admission = admin.sign_operation(&core).expect("signs");
    log.push(admission.clone());
    let delivery = Delivery { operations: log, pieces: Vec::new(), snapshot: None, base: None };
    assert!(delivered(&url, &record, &applicant, &delivery).await, "it adopted the network");

    let joined = tokio::time::timeout(A_STEP, task)
        .await
        .expect("the joining device finishes")
        .expect("the task did not panic")
        .expect("it joined");
    assert_eq!(joined.devices, 2, "it is in the network it proved itself to");
    let held = Log::at(joiner_paths.roster()).read().expect("reads");
    assert!(held.contains(&admission), "and holds the admission it was given");
}

/// **A replacement is one batch, and the admission is built on the revocation.**
///
/// Where the admin's key is out of reach, the daemon prepares the whole act at
/// once: the revocation of the device holding the name, the admission of the
/// device taking it over, and the snapshot the network is then owed — none of
/// them signed. The admission is decided against a *preview* of the roster with
/// the revocation in, and names the revocation as its parent, so the two are
/// never concurrent. This drives exactly that preparation through the same
/// modules the daemon calls, signs the batch once, applies it in order, and
/// checks that the joining device got the network.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replacement_is_one_batch_built_on_its_revocation() {
    use roster::types::{OperationBody, OperationCore, Role};

    let (_server, url) = relay().await;

    let admin_home = tempfile::tempdir().expect("a scratch directory");
    let admin_paths = Paths::under(admin_home.path());
    founded(&admin_paths, &url);
    let admin = identity::store::load(&admin_paths.identity()).expect("the founder's identity");

    // A device already answering to `laptop`, which the joining device will
    // take the name over from.
    let mut roster = roster::roster::Roster::new();
    for operation in &Log::at(admin_paths.roster()).read().expect("reads") {
        assert!(roster.offer_bytes(operation).is_accepted());
    }
    let old = identity::NodeIdentity::generate().expect("generates");
    let added = OperationCore::new(
        2,
        admin.signing_key().algorithm(),
        OperationBody::AddDevice(
            old.device_spec("laptop", Role::Member, false, vec![]).expect("spec"),
        ),
        roster.heads(),
        admin.signing_key().key_id(),
        roster.state().expect("derives").network,
    )
    .expect("well-formed");
    let added = admin.sign_operation(&added).expect("signs");
    Log::at(admin_paths.roster()).append(&added).expect("appends");
    assert!(roster.offer_bytes(&added).is_accepted());
    let state = roster.state().expect("derives");

    let joiner_home = tempfile::tempdir().expect("a scratch directory");
    let joiner_paths = Paths::under(joiner_home.path());
    joiner_paths.create().unwrap();
    let record = invite_into(&state, &url);
    let identity = daemon::keys::PlatformKeys.identity(&joiner_paths).unwrap();
    let proof = daemon::joining::prove_here(&record.invite, &identity).unwrap();
    let (_underway, task) =
        waiting(&joiner_paths, &record, &proof, Arc::new(daemon::keys::PlatformKeys));
    let applicant = requested(&record).await;
    let taken = admitting::holder_of(&admitting::admitted_name(&record.invited.name), &state)
        .expect("the name is held by the old laptop");

    // The batch, as the daemon prepares it: nothing signed yet.
    let expulsion = daemon::revoking::Expulsion {
        device: taken.device,
        name: taken.name.clone(),
        reason: "replaced by a device admitted under the name `laptop`".to_owned(),
    };
    let revocation =
        daemon::revoking::core(&expulsion, &admin, &state, roster.heads()).expect("a revocation");
    let after = roster.preview(core::slice::from_ref(&revocation)).expect("previews");
    let (admission, spec_name) = admitting::admission_core(
        &applicant,
        &record.invited,
        &admin,
        &after.state,
        after.heads.clone(),
        true,
    )
    .expect("there is something to sign");
    assert_eq!(spec_name, "laptop", "the name carries over");
    assert_eq!(
        vec![revocation.id()],
        admission.parents,
        "built on the revocation, never beside it"
    );

    // Signed once, as one batch, by whatever reaches the key.
    let key = admin.signing_key().public_key();
    let requests = vec![
        identity::detached::prepare_operation(&revocation, &key),
        identity::detached::prepare_operation(&admission, &key),
    ];
    let signatures: Vec<Vec<u8>> = requests
        .iter()
        .map(|request| {
            roster::sign::Signer::sign(admin.signing_key().signer(), request.message())
                .expect("signs")
        })
        .collect();
    let artifacts =
        identity::detached::finish_all(&requests, &key, &signatures).expect("the batch verifies");

    // Applied in order: the revocation, then the admission, then delivered.
    for artifact in &artifacts {
        Log::at(admin_paths.roster()).append(artifact).expect("appends");
        assert!(roster.offer_bytes(artifact).is_accepted(), "taken in order");
    }
    let delivery = Delivery {
        operations: Log::at(admin_paths.roster()).read().expect("reads"),
        pieces: Vec::new(),
        snapshot: None,
        base: None,
    };
    assert!(delivered(&url, &record, &applicant, &delivery).await, "it adopted the network");
    let root = daemon::snapshots::sign_over_heads(&roster, &admin).expect("the root follows");
    assert!(roster.offer_snapshot(&root).is_accepted(), "and so is the root over both");

    let joined = tokio::time::timeout(A_STEP, task)
        .await
        .expect("the joining device finishes")
        .expect("the task did not panic")
        .expect("it joined");
    assert_eq!(joined.devices, 2, "the founder and the new laptop; the old one is gone");
    assert!(roster.state().expect("derives").revoked.contains(&taken.device));
}

//! One device joining another's network, end to end.
//!
//! Two machines, a relay in this process, and a person in the middle who
//! compares two screens. Everything below the person is real: real endpoints,
//! a real relay, real signed operations, and the same modules the commands call.
//!
//! This is the test the whole change exists to make pass.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::sync::Arc;
use std::time::Duration;

/// How long a step of an enrolment may take before a test calls it stuck.
///
/// **Above the exchange's own deadline, not equal to it.** These wrap a step the
/// enrolment itself already bounds at sixty seconds; a test bounded at the same
/// number is racing the thing it is watching, and under a full parallel run it
/// loses that race often enough to fail for reasons that have nothing to do with
/// what it asserts. Three minutes is long enough that reaching it means something
/// is genuinely stuck.
const A_STEP: Duration = Duration::from_secs(180);

use daemon::founding::{Founding, found};
use daemon::joining::{Person, join};
use daemon::state::{Log, Paths};
use daemon::{admitting, relay as relay_module};
use enrollment::code::Confirmation;
use tokio::sync::{Mutex, oneshot};

/// A relay in this process, and the certificate it presents.
async fn relay() -> (iroh_relay::server::Server, String, Vec<u8>) {
    use std::net::Ipv4Addr;

    use iroh_relay::server::{CertConfig, QuicConfig, RelayConfig, ServerConfig, TlsConfig};

    let (certs, server_config) = iroh_relay::server::testing::self_signed_tls_certs_and_config();
    let mut relay = RelayConfig::new((Ipv4Addr::LOCALHOST, 0));
    relay.tls =
        Some(TlsConfig::new((Ipv4Addr::LOCALHOST, 0), CertConfig::Manual { server_config }));

    let mut config = ServerConfig::default();
    config.relay = Some(relay);
    config.quic = Some(QuicConfig::new((Ipv4Addr::LOCALHOST, 0)));
    let server = iroh_relay::server::Server::spawn(config).await.expect("a relay in this process");

    let url = format!("https://{}", server.https_addr().expect("configured"));
    let certificate = certs.first().expect("one certificate").to_vec();
    (server, url, certificate)
}

/// How long a scripted person will stand there before giving up.
///
/// Every wait in a test is bounded. A person who waited for ever would take the
/// whole run down with them, on a blocking thread the runtime cannot reclaim —
/// which is exactly what an unbounded one did before this was written.
const PATIENCE: Duration = Duration::from_secs(20);

/// A person who carries the payload to the admin and types back what they read.
///
/// Deliberately holds no way to type into itself. A sender kept here would keep
/// the channel open for ever, and the blocking read waiting on it would never
/// end — so a test that meant to abandon an enrolment would hang instead.
struct Scripted {
    /// Where the payload goes, for the admitting side to read.
    payload: Mutex<Option<oneshot::Sender<String>>>,
    /// What the admin's screen says, once there is an admin.
    from_the_admin: std::sync::Mutex<std::sync::mpsc::Receiver<String>>,
    /// What this side computed, recorded so a test can compare the two.
    ours: Mutex<Option<String>>,
    /// Whatever can reach this device's signing key, when this process cannot.
    ///
    /// `None` on a device that signs its own proof, which is every device until
    /// one keeps its key in a store that answers only to a person.
    reaches_the_key: Option<Arc<dyn roster::sign::Signer + Send + Sync>>,
}

impl Person for Scripted {
    fn show_payload(&self, text: &str, _scannable: &str) {
        if let Ok(mut held) = self.payload.try_lock()
            && let Some(sender) = held.take()
        {
            let _ = sender.send(text.to_owned());
        }
    }

    fn code_shown_by_the_admin(&self, ours: &Confirmation) -> Option<String> {
        if let Ok(mut held) = self.ours.try_lock() {
            *held = Some(ours.to_string());
        }
        // What the person reads off the other machine and types in here. Bounded,
        // so a test that never types walks away instead of standing there.
        self.from_the_admin.lock().ok()?.recv_timeout(PATIENCE).ok()
    }

    fn signs_the_proof(&self, request: &identity::detached::SigningRequest) -> Option<Vec<u8>> {
        // The component that can reach the key. In the product it is the command
        // line running as the person, with the key store asking them first; here
        // it is the key itself, reached the same way — through the request and
        // nothing else.
        let signer = self.reaches_the_key.as_ref()?;
        Some(roster::sign::Signer::sign(signer.as_ref(), request.message()).expect("signs"))
    }

    fn note(&self, _message: &str) {}
}

/// Starts a device waiting to join, and hands back what a person would carry.
///
/// Returns the payload it shows, the person standing at it, and the task doing
/// the waiting.
fn start_waiting(paths: &Paths, url: &str) -> Waiting {
    let (payload_out, payload_in) = oneshot::channel();
    let (types, from_the_admin) = std::sync::mpsc::channel();
    let person = Arc::new(Scripted {
        payload: Mutex::new(Some(payload_out)),
        from_the_admin: std::sync::Mutex::new(from_the_admin),
        ours: Mutex::new(None),
        reaches_the_key: None,
    });

    let task = {
        let person = Arc::clone(&person);
        let paths = paths.clone();
        let url = url.to_owned();
        tokio::spawn(async move { join(&paths, &url, "laptop", person).await })
    };
    Waiting { payload: payload_in, person, types, task }
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

/// Starts a device whose signing key this process cannot reach.
fn start_waiting_out_of_reach(paths: &Paths, url: &str) -> Waiting {
    let (payload_out, payload_in) = oneshot::channel();
    let (types, from_the_admin) = std::sync::mpsc::channel();

    let key = roster::sign::P256Signer::from_scalar([0x44; 32]).expect("inside the order");
    let reachable =
        Arc::new(roster::sign::P256Signer::from_scalar([0x44; 32]).expect("inside the order"));
    let keys = Elsewhere { custodian: Arc::new(OutOfReach { key }) };

    let person = Arc::new(Scripted {
        payload: Mutex::new(Some(payload_out)),
        from_the_admin: std::sync::Mutex::new(from_the_admin),
        ours: Mutex::new(None),
        reaches_the_key: Some(reachable),
    });

    let task = {
        let person = Arc::clone(&person);
        let paths = paths.clone();
        let url = url.to_owned();
        tokio::spawn(async move {
            daemon::joining::join_with(&paths, &url, "laptop", person, &keys).await
        })
    };
    Waiting { payload: payload_in, person, types, task }
}

/// A device that is waiting to join, and the person standing at it.
struct Waiting {
    /// The payload it showed.
    payload: oneshot::Receiver<String>,
    /// The person, for reading back what the machine displayed.
    person: Arc<Scripted>,
    /// What the person types into it. Dropping this is walking away.
    types: std::sync::mpsc::Sender<String>,
    /// The wait itself.
    task: tokio::task::JoinHandle<Result<daemon::joining::Joined, String>>,
}

impl Waiting {
    /// The payload this device showed, once it has shown one.
    async fn payload(&mut self) -> String {
        tokio::time::timeout(A_STEP, &mut self.payload)
            .await
            .expect("the joining device shows a payload")
            .expect("the channel stays open")
    }

    /// What this machine displayed as its own code, if it has.
    async fn showed(&self) -> Option<String> {
        self.person.ours.lock().await.clone()
    }
}

/// Waits until the device being enrolled has said the code matched.
///
/// The admin's side refuses to sign before that — nothing may be signed while
/// the other machine has not confirmed — and the *person* driving it waits by
/// looking at the screen, which is what `Outcome::Admitting { accepted }` is
/// for. A test that skipped the wait was relying on the other task getting there
/// first, which it did until this file grew a relay or two more and it did not.
async fn until_accepted(pending: &admitting::Pending) {
    let started = std::time::Instant::now();
    while !pending.accepted() {
        assert!(
            started.elapsed() < PATIENCE,
            "the device being enrolled never said the code matched"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// A founder, and the state it holds.
fn founded(paths: &Paths, relay: &str, certificate: Vec<u8>) -> roster::state::RosterState {
    found(
        paths,
        &Founding {
            name: "nas".to_owned(),
            suffix: "peerfectly.internal".to_owned(),
            relay: Some(relay.to_owned()),
            rendezvous: None,
            certificate: Some(certificate),
            ipv4_range: None,
        },
    )
    .expect("founds");

    let mut roster = roster::roster::Roster::new();
    for operation in &Log::at(paths.roster()).read().expect("reads") {
        assert!(roster.offer_bytes(operation).is_accepted());
    }
    roster.state().expect("derives")
}

/// The whole ceremony: a device with nothing ends up holding the network.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_with_nothing_is_admitted_and_holds_the_whole_network() {
    let (_server, url, certificate) = relay().await;

    let admin_home = tempfile::tempdir().expect("a scratch directory");
    let admin_paths = Paths::under(admin_home.path());
    let state = founded(&admin_paths, &url, certificate);
    let admin_identity =
        identity::store::load(&admin_paths.identity()).expect("the founder's identity");

    let joiner_home = tempfile::tempdir().expect("a scratch directory");
    let joiner_paths = Paths::under(joiner_home.path());

    // The device that is joining: it shows what it is and waits.
    let mut joiner = start_waiting(&joiner_paths, &url);
    let payload = joiner.payload().await;

    // The admin reads it, reaches the device, and stops before signing.
    let pending = tokio::time::timeout(A_STEP, admitting::open(&admin_identity, &state, &payload))
        .await
        .expect("the admin reaches it")
        .expect("the exchange opens");

    assert_eq!(pending.proposed_name(), "laptop");
    assert!(!pending.fingerprint().is_empty());

    // A person reads the admin's screen and types it into the other machine.
    let admin_code = pending.code().to_string();
    joiner.types.send(admin_code.clone()).expect("the person types it");
    until_accepted(&pending).await;

    let heads = {
        let mut roster = roster::roster::Roster::new();
        for operation in &Log::at(admin_paths.roster()).read().expect("reads") {
            roster.offer_bytes(operation);
        }
        roster.heads()
    };
    let log = Log::at(admin_paths.roster()).read().expect("reads");

    let (operation, said) = tokio::time::timeout(
        A_STEP,
        admitting::confirm(
            pending,
            &admin_identity,
            &state,
            heads,
            &log,
            daemon::state::read_snapshot(&admin_paths).map(|(bytes, _at)| bytes),
            false,
        ),
    )
    .await
    .expect("the admission completes")
    .expect("it is signed and delivered");

    let joined = tokio::time::timeout(A_STEP, joiner.task)
        .await
        .expect("the joining device finishes")
        .expect("the task did not panic")
        .expect("it joined");

    // Both computed the same six digits, each from its own inputs.
    let ours = joiner.person.ours.lock().await.clone().expect("the joining device showed a code");
    assert_eq!(ours, admin_code, "both machines must show one code");
    assert_eq!(ours.len(), 6);

    assert_eq!(joined.devices, 2, "every device appears together, not only the admin");
    assert_eq!(joined.suffix, "peerfectly.internal");
    assert!(joined.relay_confirmed, "the network pins the certificate that was accepted");
    assert!(said.contains("adopted"), "{said}");

    // The joining device wrote the network, and it is the same network.
    let held = Log::at(joiner_paths.roster()).read().expect("reads");
    assert!(held.contains(&operation), "the admission it was given is in its own log");

    let mut roster = roster::roster::Roster::new();
    for entry in &held {
        assert!(roster.offer_bytes(entry).is_accepted(), "everything delivered must load");
    }
    let joined_state = roster.state().expect("derives");
    assert_eq!(joined_state.network, state.network, "the same network, not a lookalike");
    assert_eq!(joined_state.devices.len(), 2);

    // And it arrived with the snapshot, which is what a device with no roster
    // needs and what the admission is for.
    let (kept, at) =
        daemon::state::read_snapshot(&joiner_paths).expect("the network's snapshot came with it");
    let mut dated = roster::roster::Roster::with_clock(Box::new(daemon::state::WallClock));
    for entry in &held {
        assert!(dated.offer_bytes(entry).is_accepted());
    }
    assert!(dated.restore_snapshot(&kept, at).is_accepted(), "and it checks against what arrived");

    // It is **not** dated yet, and that is honest rather than a gap. Freshness
    // comes from an attestation, which an admin sends over a session — and a
    // device that has just joined has none yet, because §2.6b leaves its network
    // off until a person turns it on.
    //
    // The obligation this used to assert — that a device which has just joined
    // must not look like one out of touch too long — is met elsewhere now, and
    // better: the two read differently. A device that was away reads `Stale`,
    // having had an attestation that aged. This one reads `NeverAttested`, which
    // is exactly what it is. The moment it meets an admin it is dated, which is
    // `a_session_opening_dates_the_peer` in `assembled.rs`.
    assert_eq!(
        roster::roster::Freshness::Unknown,
        dated.freshness(),
        "a device that has just joined has never been attested, and says so"
    );
    assert!(
        daemon::state::read_attestation(&joiner_paths).is_none(),
        "the admission delivers no attestation, and is not the place for one"
    );

    // The admission carries the minute it was signed, not a counter that renders
    // as January 1970.
    let ts = roster::sign::RawOperation::decode(&operation).expect("decodes").core().ts;
    assert_eq!(ts % 60_000, 0, "the minute and nothing below it");
    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_millis(),
    )
    .expect("fits");
    assert!(now_ms.saturating_sub(ts) <= 5 * 60_000, "{ts} is when it was signed");

    // An enrolment exchange is not a session with a member, and it recorded no
    // contact: the admin's node, assembled from the directory the admission was
    // written to, holds none for the device that joined.
    let joined_device = *joined_state
        .devices
        .keys()
        .find(|device| **device != admin_identity.device_id())
        .expect("the joined device");
    let admin_node = daemon::node::Node::from_log(
        std::sync::Arc::new(admin_identity),
        Log::at(admin_paths.roster()),
        daemon::state::read_snapshot(&admin_paths),
        daemon::state::read_attestation(&admin_paths),
    )
    .expect("loads")
    .expect("holds a network");
    assert_eq!(
        admin_node.last_contact(&joined_device).await,
        daemon::control::Contact::NoneRecorded,
        "an enrolment is not contact"
    );
    assert!(!admin_home.path().join("contacts.json").exists(), "and nothing was written for it");
}

/// Declining signs nothing and writes nothing, on either machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abandoning_leaves_both_machines_as_they_were() {
    let (_server, url, certificate) = relay().await;

    let admin_home = tempfile::tempdir().expect("a scratch directory");
    let admin_paths = Paths::under(admin_home.path());
    let state = founded(&admin_paths, &url, certificate);
    let admin_identity =
        identity::store::load(&admin_paths.identity()).expect("the founder's identity");
    let before = Log::at(admin_paths.roster()).read().expect("reads");

    let joiner_home = tempfile::tempdir().expect("a scratch directory");
    let joiner_paths = Paths::under(joiner_home.path());

    let mut joiner = start_waiting(&joiner_paths, &url);
    let payload = joiner.payload().await;

    let pending = tokio::time::timeout(A_STEP, admitting::open(&admin_identity, &state, &payload))
        .await
        .expect("the admin reaches it")
        .expect("the exchange opens");

    // The codes did not match, or the person did not like what they saw.
    admitting::abandon(pending).await;
    // Nobody types anything: abandoning is what the person does instead.
    drop(joiner.types);

    // The joining device keeps waiting — a refused exchange does not end a wait,
    // so a person can try again — and that is why this checks the machines
    // rather than waiting the full ten minutes for it to give up.
    tokio::time::sleep(Duration::from_secs(2)).await;

    assert_eq!(
        Log::at(admin_paths.roster()).read().expect("reads"),
        before,
        "the admin signed nothing"
    );
    assert!(
        Log::at(joiner_paths.roster()).read().expect("reads").is_empty(),
        "the joining device holds no network"
    );
    assert!(!joiner.task.is_finished(), "and it is still waiting, ready for another attempt");

    // Closing the terminal is what ends a wait early.
    joiner.task.abort();
}

/// The fingerprint the admin shows is the joining device's signing key, in the
/// same shape a person compares everything else in.
#[test]
fn the_fingerprint_shown_is_the_signing_key() {
    let device = identity::NodeIdentity::generate().expect("generates");
    let printed = relay_module::fingerprint(device.signing_key().public_key().as_bytes());

    assert_eq!(printed.matches(':').count(), 31, "colon-separated, like openssl prints");
    assert!(printed.chars().all(|c| c.is_ascii_hexdigit() || c == ':'), "{printed}");
}

// ---------------------------------------------------------------------------
// The boundary
// ---------------------------------------------------------------------------

/// Reading a payload gives its sender nothing.
///
/// The exchange opens, the code is worked out, and the admin's roster is
/// untouched. A device becomes a member because a signed operation says so, and
/// until a person confirms there is no such operation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn opening_an_exchange_changes_nothing_until_a_person_confirms() {
    let (_server, url, certificate) = relay().await;

    let admin_home = tempfile::tempdir().expect("a scratch directory");
    let admin_paths = Paths::under(admin_home.path());
    let state = founded(&admin_paths, &url, certificate);
    let admin_identity =
        identity::store::load(&admin_paths.identity()).expect("the founder's identity");
    let before = Log::at(admin_paths.roster()).read().expect("reads");

    let joiner_home = tempfile::tempdir().expect("a scratch directory");
    let joiner_paths = Paths::under(joiner_home.path());
    let mut joiner = start_waiting(&joiner_paths, &url);
    let payload = joiner.payload().await;

    let pending =
        admitting::open(&admin_identity, &state, &payload).await.expect("the exchange opens");

    assert_eq!(
        Log::at(admin_paths.roster()).read().expect("reads"),
        before,
        "nothing is signed by reading a payload and reaching a device"
    );
    assert!(
        Log::at(joiner_paths.roster()).read().expect("reads").is_empty(),
        "and the device waiting is a member of nothing"
    );

    admitting::abandon(pending).await;
    joiner.task.abort();
}

/// A payload naming one device's signing key beside another's transport key is
/// refused, and refused at the proof rather than believed.
///
/// This is the attack the proof of possession exists for. Without it, an admin
/// would sign an operation binding a victim's identity — and its overlay address
/// — to somebody else's transport key, and because a roster keeps the *first*
/// admission of a device id, that binding could never be corrected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_payload_wearing_another_devices_identity_is_refused() {
    let (_server, url, certificate) = relay().await;

    let admin_home = tempfile::tempdir().expect("a scratch directory");
    let admin_paths = Paths::under(admin_home.path());
    let state = founded(&admin_paths, &url, certificate);
    let admin_identity =
        identity::store::load(&admin_paths.identity()).expect("the founder's identity");

    let joiner_home = tempfile::tempdir().expect("a scratch directory");
    let joiner_paths = Paths::under(joiner_home.path());
    let mut joiner = start_waiting(&joiner_paths, &url);
    let honest = enrollment::payload::Joining::from_text(&joiner.payload().await).expect("reads");

    // The victim's identity, pasted over the waiting device's own.
    let victim = identity::NodeIdentity::generate().expect("generates");
    let forged = enrollment::payload::Joining::new(
        victim.signing_key().public_key(),
        honest.transport.clone(),
        honest.attestation.clone(),
        honest.name.clone(),
        honest.relay.clone(),
    )
    .expect("well-formed, and that is the problem");

    let refusal = admitting::open(&admin_identity, &state, &forged.to_text())
        .await
        .expect_err("a device that cannot prove that identity must not be admitted");
    assert!(
        refusal.contains("did not prove"),
        "the refusal must say the proof failed, not something vaguer: {refusal}"
    );

    assert!(
        Log::at(admin_paths.roster()).read().expect("reads").len() == 1,
        "and nothing was signed"
    );
    joiner.task.abort();
}

/// A payload substituted on its way to the admin produces a different code, so
/// the person comparing two screens sees a mismatch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_substituted_payload_shows_a_different_code() {
    let (_server, url, certificate) = relay().await;

    let admin_home = tempfile::tempdir().expect("a scratch directory");
    let admin_paths = Paths::under(admin_home.path());
    let state = founded(&admin_paths, &url, certificate);
    let admin_identity =
        identity::store::load(&admin_paths.identity()).expect("the founder's identity");

    // The device the person is standing at.
    let watched_home = tempfile::tempdir().expect("a scratch directory");
    let watched_paths = Paths::under(watched_home.path());
    let mut watched = start_waiting(&watched_paths, &url);

    // The device whose payload reached the admin instead.
    let other_home = tempfile::tempdir().expect("a scratch directory");
    let other_paths = Paths::under(other_home.path());
    let mut other = start_waiting(&other_paths, &url);

    let _watched_text = watched.payload().await;
    let substituted = other.payload().await;

    // The admin admits what reached it, which is not the machine being watched.
    let pending =
        admitting::open(&admin_identity, &state, &substituted).await.expect("the exchange opens");
    let on_the_admin = pending.code().to_string();

    // The machine the person is looking at shows its own code, from its own
    // exchange — and there is no exchange, so it shows nothing yet. What matters
    // is that when it does, it is a different one.
    let on_the_other_machine = other.showed().await.unwrap_or_else(|| on_the_admin.clone());
    assert_eq!(
        on_the_admin, on_the_other_machine,
        "the admin is talking to the substituted device, so those two agree"
    );

    let watched_code = watched.showed().await;
    assert!(
        watched_code.is_none_or(|shown| shown != on_the_admin),
        "the machine the person is standing at must not show the admin's code"
    );

    admitting::abandon(pending).await;
    watched.task.abort();
    other.task.abort();
}

/// A stranger who reaches the waiting device cannot get past the code.
///
/// The payload is public, so anyone who has seen it can open an exchange. They
/// get as far as offering a network of their own — and the person, typing the
/// digits the real admin is showing, refuses it. Nothing is written and the wait
/// stays open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranger_offering_its_own_network_is_refused_at_the_code() {
    let (_server, url, certificate) = relay().await;

    // The stranger has a perfectly good network of its own.
    let stranger_home = tempfile::tempdir().expect("a scratch directory");
    let stranger_paths = Paths::under(stranger_home.path());
    let stranger_state = founded(&stranger_paths, &url, certificate);
    let stranger =
        identity::store::load(&stranger_paths.identity()).expect("the stranger's identity");

    let joiner_home = tempfile::tempdir().expect("a scratch directory");
    let joiner_paths = Paths::under(joiner_home.path());
    let mut joiner = start_waiting(&joiner_paths, &url);
    let payload = joiner.payload().await;

    let pending = admitting::open(&stranger, &stranger_state, &payload)
        .await
        .expect("anyone who has seen the payload can open an exchange");

    // The person is reading the real admin's screen, which shows something else.
    let typed = "000000".to_owned();
    assert_ne!(
        typed,
        pending.code().to_string(),
        "the stranger's code is not what is on the \
                                                   other screen"
    );
    joiner.types.send(typed).expect("the person types it");

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        Log::at(joiner_paths.roster()).read().expect("reads").is_empty(),
        "a stranger's network must not be adopted"
    );
    assert!(!joiner.task.is_finished(), "and the wait stays open for the real admin");

    admitting::abandon(pending).await;
    joiner.task.abort();
}

/// The admitting side signs nothing until the device being enrolled says the
/// code matched.
///
/// Its own person answering is not enough, and this is what makes that true
/// rather than merely intended: the joining side is left with nobody typing into
/// it, so it never sends its acceptance, and the admission ends with nothing
/// signed and nothing delivered.
#[tokio::test]
async fn nothing_is_signed_while_the_other_side_has_not_confirmed() {
    let (_server, url, certificate) = relay().await;

    let admin_home = tempfile::tempdir().expect("a scratch directory");
    let admin_paths = Paths::under(admin_home.path());
    let state = founded(&admin_paths, &url, certificate);
    let admin = identity::store::load(&admin_paths.identity()).expect("the admin's identity");
    let before = Log::at(admin_paths.roster()).read().expect("reads").len();

    let joiner_home = tempfile::tempdir().expect("a scratch directory");
    let joiner_paths = Paths::under(joiner_home.path());
    let mut joiner = start_waiting(&joiner_paths, &url);
    let payload = joiner.payload().await;

    let pending = admitting::open(&admin, &state, &payload).await.expect("an exchange opens");
    let heads = Vec::new();
    let log = Log::at(admin_paths.roster()).read().expect("reads");

    // Nobody types into the joining device, so it sends no acceptance. The
    // admitting side's own person has said yes — which is what `confirm` means —
    // and that must not be enough on its own.
    let outcome = admitting::confirm(pending, &admin, &state, heads, &log, None, false).await;
    let refusal = outcome.expect_err("nothing may be signed without the other side");
    // And it says what was missing, rather than surfacing as whatever the
    // channel did afterwards: a person reading this has to know to go and type
    // the digits into the other machine.
    assert!(
        refusal.contains("has not said the code was accepted"),
        "the refusal should name what was missing: {refusal}"
    );

    assert_eq!(
        Log::at(admin_paths.roster()).read().expect("reads").len(),
        before,
        "no admission was written"
    );
    assert!(
        Log::at(joiner_paths.roster()).read().expect("reads").is_empty(),
        "and nothing was delivered"
    );
    joiner.task.abort();
}

/// A wrong code is answered **at once**, and the wait stays open.
///
/// Both halves matter, and they pull in opposite directions. The exchange is
/// refused, but a refused exchange does not end the wait — a person who mistyped
/// tries again — so there is no failure for the daemon to report. Without
/// somewhere to put that refusal, a person who has just typed six digits waits
/// out a minute of polling and is told the join "did not finish", which is how
/// this was found: on a phone, where it read as the device freezing.
#[tokio::test]
async fn a_wrong_code_is_answered_at_once_and_the_wait_stays_open() {
    use daemon::joining::{AcrossTheChannel, join_with};

    let (_server, url, certificate) = relay().await;

    let admin_home = tempfile::tempdir().expect("a scratch directory");
    let admin_paths = Paths::under(admin_home.path());
    let state = founded(&admin_paths, &url, certificate);
    let admin = identity::store::load(&admin_paths.identity()).expect("the admin's identity");

    // The daemon's own person, not the scripted one: what is under test is the
    // bridge between a waiting join and whoever is standing at the device.
    let joiner_home = tempfile::tempdir().expect("a scratch directory");
    let joiner_paths = Paths::under(joiner_home.path());
    let (person, underway) = AcrossTheChannel::new();
    let task = {
        let paths = joiner_paths.clone();
        let url = url.clone();
        let person = person.clone();
        tokio::spawn(async move {
            join_with(&paths, &url, "laptop", person, &daemon::keys::PlatformKeys).await
        })
    };

    // Wait for it to show a payload, then let an admin reach it.
    let mut payload = String::new();
    for _ in 0..600_u32 {
        if let daemon::joining::Progress::Waiting { payload: shown, .. } = underway.progress() {
            payload = shown;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!payload.is_empty(), "the joining device shows a payload");

    let pending = admitting::open(&admin, &state, &payload).await.expect("an exchange opens");
    assert_ne!("000000", pending.code().to_string(), "the wrong code is wrong");

    // Wait until the join is asking for a code, then type the wrong one.
    for _ in 0..600_u32 {
        if matches!(underway.progress(), daemon::joining::Progress::Confirming { .. }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let started = std::time::Instant::now();
    assert!(underway.confirm("000000"), "the digits reach the join");

    // The answer must arrive in the time a person would call immediate.
    let mut refusal = None;
    for _ in 0..50_u32 {
        if let Some(said) = underway.refusal() {
            refusal = Some(said);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let took = started.elapsed();

    let refusal = refusal.unwrap_or_else(|| panic!("no answer after {took:?}"));
    assert!(refusal.contains("not the code"), "and it says which of the two it was: {refusal}");
    assert!(took < Duration::from_secs(3), "it took {took:?} to say so");

    // And the wait is still open, because a person who mistyped tries again.
    assert!(!task.is_finished(), "a refused exchange does not end the wait");
    assert!(
        Log::at(joiner_paths.roster()).read().expect("reads").is_empty(),
        "nothing was written"
    );

    admitting::abandon(pending).await;
    underway.abandon();
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

/// The same ceremony, with the admin's signing key somewhere its own process
/// cannot reach.
///
/// The admission is decided, stops at its signature, is signed by somebody else,
/// and is then delivered. What matters here is what a unit test cannot show: the
/// **exchange survives the pause**. A joining device is still on the other end of
/// an open channel while a person answers a prompt, and it has to still be there
/// afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_admission_signed_out_of_reach_still_reaches_the_joining_device() {
    let (_server, url, certificate) = relay().await;

    let admin_home = tempfile::tempdir().expect("a scratch directory");
    let admin_paths = Paths::under(admin_home.path());
    let state = founded(&admin_paths, &url, certificate);
    let admin_identity =
        identity::store::load(&admin_paths.identity()).expect("the founder's identity");

    let joiner_home = tempfile::tempdir().expect("a scratch directory");
    let joiner_paths = Paths::under(joiner_home.path());

    let mut joiner = start_waiting(&joiner_paths, &url);
    let payload = joiner.payload().await;

    let mut pending =
        tokio::time::timeout(A_STEP, admitting::open(&admin_identity, &state, &payload))
            .await
            .expect("the admin reaches it")
            .expect("the exchange opens");

    joiner.types.send(pending.code().to_string()).expect("the person types it");
    until_accepted(&pending).await;

    let heads = {
        let mut roster = roster::roster::Roster::new();
        for operation in &Log::at(admin_paths.roster()).read().expect("reads") {
            roster.offer_bytes(operation);
        }
        roster.heads()
    };
    let log = Log::at(admin_paths.roster()).read().expect("reads");

    // Decided, and stopped at the signature. Nothing has been signed.
    let (operation, spec_name) = tokio::time::timeout(
        A_STEP,
        admitting::core(&mut pending, &admin_identity, &state, heads, false),
    )
    .await
    .expect("the admission is decided")
    .expect("there is something to sign");

    // Somebody else signs the exact bytes that were prepared — here, the same key
    // reached by the path a component holding it would take.
    let key = admin_identity.signing_key().public_key();
    let request = identity::detached::prepare_operation(&operation, &key);
    let signature =
        roster::sign::Signer::sign(admin_identity.signing_key().signer(), request.message())
            .expect("signs");
    let signed = identity::detached::finish(&request, &key, &signature).expect("assembles");

    let (delivered, said) = tokio::time::timeout(
        A_STEP,
        admitting::finish_with(pending, signed, spec_name, &log, None),
    )
    .await
    .expect("the admission is delivered")
    .expect("it reached the other device");

    let joined = tokio::time::timeout(A_STEP, joiner.task)
        .await
        .expect("the joining device finishes")
        .expect("the task did not panic")
        .expect("it joined");

    assert_eq!(joined.devices, 2, "every device appears together");
    assert!(said.contains("adopted"), "{said}");

    let held = Log::at(joiner_paths.roster()).read().expect("reads");
    assert!(
        held.contains(&delivered),
        "the admission it was given is the one that was signed out of reach"
    );
}

/// A device joins with its signing key in a store this process cannot reach.
///
/// The proof of possession is what a device does to show the identity it is
/// presenting is its own, and it happens **inside** the live exchange, before a
/// code is shown. So on such a device the join stops there, asks, and goes on
/// with what comes back — and what comes back is checked against the key being
/// presented before a single byte of it is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_whose_key_is_out_of_reach_still_proves_it_holds_it() {
    let (_server, url, certificate) = relay().await;

    let admin_home = tempfile::tempdir().expect("a scratch directory");
    let admin_paths = Paths::under(admin_home.path());
    let state = founded(&admin_paths, &url, certificate);
    let admin_identity =
        identity::store::load(&admin_paths.identity()).expect("the founder's identity");

    let joiner_home = tempfile::tempdir().expect("a scratch directory");
    let joiner_paths = Paths::under(joiner_home.path());

    let mut joiner = start_waiting_out_of_reach(&joiner_paths, &url);
    let payload = joiner.payload().await;

    let pending = tokio::time::timeout(A_STEP, admitting::open(&admin_identity, &state, &payload))
        .await
        .expect("the admin reaches it")
        .expect("the exchange opens — which it only does if the proof verified");

    joiner.types.send(pending.code().to_string()).expect("the person types it");
    until_accepted(&pending).await;

    let heads = {
        let mut roster = roster::roster::Roster::new();
        for operation in &Log::at(admin_paths.roster()).read().expect("reads") {
            roster.offer_bytes(operation);
        }
        roster.heads()
    };
    let log = Log::at(admin_paths.roster()).read().expect("reads");

    let (operation, _said) = tokio::time::timeout(
        A_STEP,
        admitting::confirm(
            pending,
            &admin_identity,
            &state,
            heads,
            &log,
            daemon::state::read_snapshot(&admin_paths).map(|(bytes, _at)| bytes),
            false,
        ),
    )
    .await
    .expect("the admission completes")
    .expect("it is signed and delivered");

    let joined = tokio::time::timeout(A_STEP, joiner.task)
        .await
        .expect("the joining device finishes")
        .expect("the task did not panic")
        .expect("it joined");

    assert_eq!(joined.devices, 2, "it is in the network it proved itself to");

    let held = Log::at(joiner_paths.roster()).read().expect("reads");
    assert!(held.contains(&operation), "and holds the admission it was given");

    // The identity it kept names a custodian and carries no private signing
    // material, which is the point of keeping the key out of reach.
    let stored = std::fs::read(joiner_paths.identity()).expect("reads its identity");
    assert!(!stored.is_empty());
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
/// checks that the joining device got the network and the admin's roster took
/// every item — the snapshot over both included.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replacement_is_one_batch_built_on_its_revocation() {
    use roster::types::{OperationBody, OperationCore, Role};

    let (_server, url, certificate) = relay().await;

    let admin_home = tempfile::tempdir().expect("a scratch directory");
    let admin_paths = Paths::under(admin_home.path());
    founded(&admin_paths, &url, certificate);
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
    let mut joiner = start_waiting(&joiner_paths, &url);
    let payload = joiner.payload().await;

    let mut pending = tokio::time::timeout(A_STEP, admitting::open(&admin, &state, &payload))
        .await
        .expect("the admin reaches it")
        .expect("the exchange opens");
    let taken = pending.taken().cloned().expect("the name is held by the old laptop");
    joiner.types.send(pending.code().to_string()).expect("the person types it");
    until_accepted(&pending).await;

    // The batch, as the daemon prepares it: nothing signed yet.
    let expulsion = daemon::revoking::Expulsion {
        device: taken.device,
        name: taken.name.clone(),
        reason: "replaced by a device admitted under the name `laptop`".to_owned(),
    };
    let revocation =
        daemon::revoking::core(&expulsion, &admin, &state, roster.heads()).expect("a revocation");
    let after = roster.preview(core::slice::from_ref(&revocation)).expect("previews");
    let (admission, spec_name) = tokio::time::timeout(
        A_STEP,
        admitting::core(&mut pending, &admin, &after.state, after.heads.clone(), true),
    )
    .await
    .expect("the admission is decided")
    .expect("there is something to sign");
    assert_eq!(
        vec![revocation.id()],
        admission.parents,
        "built on the revocation, never beside it"
    );

    let snapshot =
        daemon::snapshots::after(&roster, &[revocation.clone(), admission.clone()], &admin, 0)
            .expect("previews")
            .expect("this roster holds no snapshot, so one is owed");
    assert!(snapshot.heads.contains(&admission.id()), "covering the admission");

    // Signed once, as one batch, by whatever reaches the key.
    let key = admin.signing_key().public_key();
    let requests = vec![
        identity::detached::prepare_operation(&revocation, &key),
        identity::detached::prepare_operation(&admission, &key),
        identity::detached::prepare_snapshot(&snapshot, &key),
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

    // Applied in order: the revocation, then the admission delivered, then the
    // snapshot over both.
    let revoked = artifacts.first().expect("the revocation").clone();
    Log::at(admin_paths.roster()).append(&revoked).expect("appends");
    assert!(roster.offer_bytes(&revoked).is_accepted(), "the revocation is taken");
    let log = Log::at(admin_paths.roster()).read().expect("reads");

    let (delivered, _said) = tokio::time::timeout(
        A_STEP,
        admitting::finish_with(
            pending,
            artifacts.get(1).expect("the admission").clone(),
            spec_name,
            &log,
            None,
        ),
    )
    .await
    .expect("the admission is delivered")
    .expect("it reached the other device");
    assert!(roster.offer_bytes(&delivered).is_accepted(), "the admission is taken");
    assert!(
        roster.offer_snapshot(artifacts.get(2).expect("the snapshot")).is_accepted(),
        "and so is the snapshot that was signed before either was in"
    );

    let joined = tokio::time::timeout(A_STEP, joiner.task)
        .await
        .expect("the joining device finishes")
        .expect("the task did not panic")
        .expect("it joined");
    assert_eq!(joined.devices, 2, "the founder and the new laptop; the old one is gone");
    assert!(roster.state().expect("derives").revoked.contains(&taken.device));
}

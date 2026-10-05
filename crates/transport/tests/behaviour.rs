//! The behavioural suite, run against every implementation.
//!
//! The test bodies never name a concrete transport: they take a harness and
//! drive the trait. That is what proves the suite describes the interface rather
//! than one implementation's habits — and it is what `transport-iroh` will run
//! unchanged, so its remaining job is connectivity rather than semantics.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

use std::sync::Arc;

use identity::NodeIdentity;
use roster::id::{DeviceId, NetworkId};
use roster::roster::Roster;
use roster::sign::{PublicKey, sign_operation};
use roster::state::RosterState;
use roster::types::{NetworkParams, OperationBody, OperationCore, Role};
use transport::error::Error;
use transport::session::Transport;
use transport::suite::{self, Harness};
use transport::{DirectFabric, DirectTransport, MemoryFabric, MemoryTransport};

/// Builds a two-device roster: a founder and a joiner, both real identities.
fn two_device_state(founder: &NodeIdentity, joiner: &NodeIdentity) -> RosterState {
    let params = NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 2_592_000)
        .expect("valid");

    let genesis = OperationCore::new(
        1,
        founder.signing_key().algorithm(),
        OperationBody::CreateNetwork {
            device: founder.device_spec("founder", Role::Admin, true, vec![]).expect("spec"),
            params,
        },
        vec![],
        founder.signing_key().key_id(),
        NetworkId::from_bytes([0; 32]),
    )
    .expect("well-formed");
    let genesis_bytes = sign_operation(&genesis, founder.signer()).expect("signs");
    let network = NetworkId::from_bytes(*genesis.id().as_bytes());

    let add = OperationCore::new(
        2,
        founder.signing_key().algorithm(),
        OperationBody::AddDevice(
            joiner.device_spec("joiner", Role::Member, false, vec![]).expect("spec"),
        ),
        vec![genesis.id()],
        founder.signing_key().key_id(),
        network,
    )
    .expect("well-formed");
    let add_bytes = sign_operation(&add, founder.signer()).expect("signs");

    let mut node = Roster::new();
    assert!(node.offer_bytes(&genesis_bytes).is_accepted());
    assert!(node.offer_bytes(&add_bytes).is_accepted());
    node.state().expect("derives")
}

// ---------------------------------------------------------------------------
// Harness for the in-memory transport
// ---------------------------------------------------------------------------

struct MemoryHarness {
    dialler: MemoryTransport,
    acceptor: MemoryTransport,
    acceptor_key: PublicKey,
    stranger_key: PublicKey,
    dialler_device: DeviceId,
    acceptor_device: DeviceId,
}

impl MemoryHarness {
    async fn build() -> Arc<Self> {
        let (founder, joiner) = suite::two_identities();
        let stranger = NodeIdentity::generate().expect("generates");
        let state = two_device_state(&founder, &joiner);
        let fabric = MemoryFabric::new();

        let dialler = MemoryTransport::join(&fabric, Arc::clone(&founder), state.clone()).await;
        let acceptor = MemoryTransport::join(&fabric, Arc::clone(&joiner), state).await;

        Arc::new(Self {
            acceptor_key: joiner.transport_key().public_key(),
            stranger_key: stranger.transport_key().public_key(),
            dialler_device: founder.device_id(),
            acceptor_device: joiner.device_id(),
            dialler,
            acceptor,
        })
    }
}

#[async_trait::async_trait]
impl Harness for MemoryHarness {
    fn dialler(&self) -> &dyn Transport {
        &self.dialler
    }
    fn acceptor(&self) -> &dyn Transport {
        &self.acceptor
    }
    fn acceptor_key(&self) -> PublicKey {
        self.acceptor_key.clone()
    }
    fn unreachable_key(&self) -> PublicKey {
        self.stranger_key.clone()
    }
    fn dialler_device(&self) -> DeviceId {
        self.dialler_device
    }
    fn acceptor_device(&self) -> DeviceId {
        self.acceptor_device
    }
    async fn set_state(&self, state: RosterState) {
        // Through `&dyn Transport`, deliberately. A node holds the transport
        // behind a trait object and nothing else, so a membership change driven
        // on the concrete type proves the implementation and says nothing about
        // whether the assembled system can drive one at all. It could not.
        self.dialler().update_state(state.clone()).await;
        self.acceptor().update_state(state).await;
    }
    async fn state(&self) -> RosterState {
        self.dialler.state().await
    }
}

// ---------------------------------------------------------------------------
// Harness for the direct transport
// ---------------------------------------------------------------------------

struct DirectHarness {
    dialler: DirectTransport,
    acceptor: DirectTransport,
    acceptor_key: PublicKey,
    stranger_key: PublicKey,
    dialler_device: DeviceId,
    acceptor_device: DeviceId,
}

impl DirectHarness {
    async fn build() -> Arc<Self> {
        let (founder, joiner) = suite::two_identities();
        let stranger = NodeIdentity::generate().expect("generates");
        let state = two_device_state(&founder, &joiner);
        let fabric = DirectFabric::new();

        let dialler = DirectTransport::join(&fabric, Arc::clone(&founder), state.clone()).await;
        let acceptor = DirectTransport::join(&fabric, Arc::clone(&joiner), state).await;

        Arc::new(Self {
            acceptor_key: joiner.transport_key().public_key(),
            stranger_key: stranger.transport_key().public_key(),
            dialler_device: founder.device_id(),
            acceptor_device: joiner.device_id(),
            dialler,
            acceptor,
        })
    }
}

#[async_trait::async_trait]
impl Harness for DirectHarness {
    fn dialler(&self) -> &dyn Transport {
        &self.dialler
    }
    fn acceptor(&self) -> &dyn Transport {
        &self.acceptor
    }
    fn acceptor_key(&self) -> PublicKey {
        self.acceptor_key.clone()
    }
    fn unreachable_key(&self) -> PublicKey {
        self.stranger_key.clone()
    }
    fn dialler_device(&self) -> DeviceId {
        self.dialler_device
    }
    fn acceptor_device(&self) -> DeviceId {
        self.acceptor_device
    }
    async fn set_state(&self, state: RosterState) {
        // Through `&dyn Transport`, deliberately. A node holds the transport
        // behind a trait object and nothing else, so a membership change driven
        // on the concrete type proves the implementation and says nothing about
        // whether the assembled system can drive one at all. It could not.
        self.dialler().update_state(state.clone()).await;
        self.acceptor().update_state(state).await;
    }
    async fn state(&self) -> RosterState {
        self.dialler.state().await
    }
}

// ---------------------------------------------------------------------------
// The suite, over each implementation
// ---------------------------------------------------------------------------

/// Runs every behaviour the specification requires, against both.
///
/// A behaviour only one implementation has fails here, which is what stops the
/// interface becoming a description of whichever was written first.
#[tokio::test]
async fn the_suite_passes_against_every_implementation() {
    suite::run_all(MemoryHarness::build().await).await;
    suite::run_all(DirectHarness::build().await).await;
}

/// Each behaviour also runs on its own, so a failure names itself rather than
/// arriving as "the suite failed".
macro_rules! both {
    ($name:ident, $behaviour:path) => {
        #[tokio::test]
        async fn $name() {
            $behaviour(MemoryHarness::build().await.as_ref()).await;
            $behaviour(DirectHarness::build().await.as_ref()).await;
        }
    };
}

both!(a_member_establishes_a_session, suite::a_member_establishes_a_session);
both!(a_session_reports_a_stable_peer, suite::a_session_reports_a_stable_peer);
both!(payloads_arrive_unchanged, suite::payloads_arrive_unchanged);
both!(payload_boundaries_are_preserved, suite::payload_boundaries_are_preserved);
both!(
    an_oversized_payload_is_refused_at_the_sender,
    suite::an_oversized_payload_is_refused_at_the_sender
);
both!(sending_on_a_closed_session_fails, suite::sending_on_a_closed_session_fails);
both!(
    receiving_on_a_closed_session_reports_the_close,
    suite::receiving_on_a_closed_session_reports_the_close
);
both!(
    an_unreachable_peer_is_reported_as_unreachable,
    suite::an_unreachable_peer_is_reported_as_unreachable
);
both!(revoking_a_peer_closes_its_session, suite::revoking_a_peer_closes_its_session);
both!(a_revoked_peer_cannot_reconnect, suite::a_revoked_peer_cannot_reconnect);
both!(packets_arrive_whole, suite::packets_arrive_whole);
both!(packets_and_payloads_are_received_apart, suite::packets_and_payloads_are_received_apart);
both!(
    an_oversized_packet_is_refused_at_the_sender,
    suite::an_oversized_packet_is_refused_at_the_sender
);
both!(
    sending_a_packet_on_a_closed_session_fails,
    suite::sending_a_packet_on_a_closed_session_fails
);
both!(
    receiving_a_packet_on_a_closed_session_reports_the_close,
    suite::receiving_a_packet_on_a_closed_session_reports_the_close
);

/// A path is something only a transport with paths can report. The in-memory
/// implementations have none, and say so rather than claiming one.
#[tokio::test]
async fn an_implementation_without_paths_says_it_cannot_tell() {
    for harness in [
        MemoryHarness::build().await as Arc<dyn Harness>,
        DirectHarness::build().await as Arc<dyn Harness>,
    ] {
        let key = harness.acceptor_key();
        let (dialled, _accepted) =
            tokio::join!(harness.dialler().connect(&key), harness.acceptor().accept());
        let _session = dialled.expect("establishes");
        assert_eq!(harness.dialler().path_to(&harness.acceptor_device()).await, None);
    }
}

/// A packet queue that nobody reads drops what does not fit rather than making
/// the sender wait: a best-effort channel that blocked would stall the tunnel
/// behind a slow reader, which is the stall packets exist to avoid.
#[tokio::test]
async fn a_full_packet_queue_drops_rather_than_blocks() {
    for harness in [
        MemoryHarness::build().await as Arc<dyn Harness>,
        DirectHarness::build().await as Arc<dyn Harness>,
    ] {
        let key = harness.acceptor_key();
        let (dialled, accepted) =
            tokio::join!(harness.dialler().connect(&key), harness.acceptor().accept());
        let (dialled, accepted) = (dialled.expect("establishes"), accepted.expect("establishes"));

        let extra = 10_usize;
        let sending = async {
            for index in 0..transport::limits::PACKET_QUEUE.saturating_add(extra) {
                dialled.send_packet(&index.to_be_bytes()).await.expect("sends a packet");
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), sending)
            .await
            .expect("sending never waits for the reader");

        let mut received = 0_usize;
        while tokio::time::timeout(std::time::Duration::from_millis(100), accepted.recv_packet())
            .await
            .is_ok()
        {
            received = received.saturating_add(1);
        }
        assert_eq!(received, transport::limits::PACKET_QUEUE, "what did not fit was dropped");
    }
}

// ---------------------------------------------------------------------------
// Behaviours that need to reach past the harness
// ---------------------------------------------------------------------------

/// A peer that is reachable but that the roster does not name gets no session.
#[tokio::test]
async fn a_stranger_is_refused_as_a_non_member() {
    let (founder, joiner) = suite::two_identities();
    let stranger = Arc::new(NodeIdentity::generate().expect("generates"));
    let state = two_device_state(&founder, &joiner);
    let fabric = MemoryFabric::new();

    let member = MemoryTransport::join(&fabric, Arc::clone(&founder), state.clone()).await;
    // Reachable on the same fabric, but absent from the roster.
    let outsider = MemoryTransport::join(&fabric, Arc::clone(&stranger), state).await;

    let key = member.transport_key();
    let (dialled, accepted) = tokio::join!(outsider.connect(&key), member.accept());

    assert_eq!(accepted.err(), Some(Error::NotAMember), "the acceptor refuses a stranger");
    match dialled {
        Err(error) => assert!(
            error.is_membership_refusal(),
            "and the dialler learns why rather than timing out: {error:?}"
        ),
        Ok(_) => panic!("a stranger must not establish a session"),
    }
    let _ = joiner;
}

/// A signing key naming a real device does not open a session. This is the case
/// that looks like it should work, and must not.
#[tokio::test]
async fn a_signing_key_does_not_authenticate_a_session() {
    let (founder, joiner) = suite::two_identities();
    let state = two_device_state(&founder, &joiner);

    // The joiner's *signing* key names a real device in this state.
    let signing = joiner.signing_key().public_key();
    assert!(
        state.device_for_key(&signing.key_id()).is_some(),
        "the signing key really does name a member"
    );

    // But it resolves to nobody for the transport purpose.
    assert!(
        state
            .device_for_key_of_purpose(&signing.key_id(), roster::types::KeyPurpose::Transport)
            .is_none(),
        "and must not be usable to authenticate a transport session"
    );

    // A handshake presenting it is refused even with a valid signature.
    let nonce = [9u8; transport::auth::CHALLENGE_LEN];
    let challenge = transport::auth::challenge_bytes(&nonce);
    let signature = joiner.signer().sign(&challenge).expect("signs");
    let handshake = transport::auth::Handshake { key: signing, signature };

    assert_eq!(
        transport::auth::authenticate(&state, &handshake, &nonce).map(|_| ()),
        Err(Error::NotAMember)
    );
}

/// A peer that cannot prove possession is refused, and the refusal says so
/// rather than blaming the roster.
#[tokio::test]
async fn a_peer_that_cannot_prove_possession_is_refused() {
    let (founder, joiner) = suite::two_identities();
    let state = two_device_state(&founder, &joiner);

    let nonce = [3u8; transport::auth::CHALLENGE_LEN];
    // A signature over the wrong challenge: valid bytes, wrong message.
    let wrong = transport::auth::challenge_bytes(&[4u8; transport::auth::CHALLENGE_LEN]);
    let signature = joiner.transport_key().signer().sign(&wrong).expect("signs");
    let handshake =
        transport::auth::Handshake { key: joiner.transport_key().public_key(), signature };

    assert_eq!(
        transport::auth::authenticate(&state, &handshake, &nonce).map(|_| ()),
        Err(Error::PossessionNotProven),
        "possession is checked before membership, so an unproven key is never looked up"
    );
}

/// Two sessions with different peers stay separate.
#[tokio::test]
async fn sessions_with_different_peers_stay_distinct() {
    let (founder, joiner) = suite::two_identities();
    let state = two_device_state(&founder, &joiner);
    let fabric = MemoryFabric::new();

    let hub = MemoryTransport::join(&fabric, Arc::clone(&founder), state.clone()).await;
    let spoke = MemoryTransport::join(&fabric, Arc::clone(&joiner), state).await;

    let key = spoke.transport_key();
    let (first_dialled, first_accepted) = tokio::join!(hub.connect(&key), spoke.accept());
    let first_dialled = first_dialled.expect("establishes");
    let first_accepted = first_accepted.expect("establishes");

    let (second_dialled, second_accepted) = tokio::join!(hub.connect(&key), spoke.accept());
    let second_dialled = second_dialled.expect("establishes");
    let second_accepted = second_accepted.expect("establishes");

    first_dialled.send(b"first session").await.expect("sends");
    second_dialled.send(b"second session").await.expect("sends");

    assert_eq!(first_accepted.recv().await.expect("receives"), b"first session".to_vec());
    assert_eq!(
        second_accepted.recv().await.expect("receives"),
        b"second session".to_vec(),
        "bytes sent on one session never arrive on another"
    );
    assert_eq!(first_dialled.peer(), second_dialled.peer());
}

/// Revoking one peer leaves sessions with others alone.
#[tokio::test]
async fn revoking_one_peer_leaves_others_untouched() {
    let founder = Arc::new(NodeIdentity::generate().expect("generates"));
    let first = Arc::new(NodeIdentity::generate().expect("generates"));
    let state = two_device_state(&founder, &first);
    let fabric = MemoryFabric::new();

    let hub = MemoryTransport::join(&fabric, Arc::clone(&founder), state.clone()).await;
    let peer = MemoryTransport::join(&fabric, Arc::clone(&first), state.clone()).await;

    let key = peer.transport_key();
    let (dialled, _accepted) = tokio::join!(hub.connect(&key), peer.accept());
    let dialled = dialled.expect("establishes");

    // Revoke a device that is *not* this session's peer.
    let mut updated = state;
    let bystander = DeviceId::from_bytes([0x77; 32]);
    updated.revoked.insert(bystander);
    hub.update_state(updated).await;

    dialled.send(b"still fine").await.expect("an unrelated revocation changes nothing");
}

/// The transport follows the state it is given rather than caching a verdict.
#[tokio::test]
async fn membership_follows_the_supplied_state() {
    let (founder, joiner) = suite::two_identities();
    let state = two_device_state(&founder, &joiner);
    let fabric = MemoryFabric::new();

    let dialler = MemoryTransport::join(&fabric, Arc::clone(&founder), state.clone()).await;
    let acceptor = MemoryTransport::join(&fabric, Arc::clone(&joiner), state.clone()).await;

    // It works while the joiner is a member.
    let key = acceptor.transport_key();
    let (ok, _) = tokio::join!(dialler.connect(&key), acceptor.accept());
    assert!(ok.is_ok());

    // Hand it state in which the joiner is gone. No reconfiguration.
    let mut narrowed = state;
    narrowed.devices.remove(&joiner.device_id());
    dialler.update_state(narrowed).await;

    let (refused, _) = tokio::join!(dialler.connect(&key), acceptor.accept());
    match refused {
        Err(error) => assert!(error.is_membership_refusal(), "got {error:?}"),
        Ok(_) => panic!("the transport must follow the state it was given"),
    }
}

// ---------------------------------------------------------------------------
// Membership without a challenge
// ---------------------------------------------------------------------------
//
// A real transport's own handshake proves possession, and proves it bound to
// the channel. `authorize` is the half of authentication that remains: does the
// roster name this key, for the transport purpose, and is that device still a
// member. These pin it, because a binding that gets this wrong admits strangers.

#[test]
fn authorize_accepts_a_transport_key_the_roster_names() {
    let founder = NodeIdentity::generate().expect("generates");
    let joiner = NodeIdentity::generate().expect("generates");
    let state = two_device_state(&founder, &joiner);

    assert_eq!(
        transport::auth::authorize(&state, &joiner.transport_key().key_id()),
        Ok(joiner.device_id())
    );
}

/// The case that looks like it should work. A device's two keys are distinct by
/// construction precisely so one cannot stand in for the other.
#[test]
fn authorize_refuses_a_signing_key_that_names_a_real_device() {
    let founder = NodeIdentity::generate().expect("generates");
    let joiner = NodeIdentity::generate().expect("generates");
    let state = two_device_state(&founder, &joiner);

    assert_eq!(
        transport::auth::authorize(&state, &joiner.signing_key().key_id()),
        Err(transport::Error::NotAMember),
        "a signing key must never open a session"
    );
}

#[test]
fn authorize_refuses_a_key_the_roster_does_not_name() {
    let founder = NodeIdentity::generate().expect("generates");
    let joiner = NodeIdentity::generate().expect("generates");
    let stranger = NodeIdentity::generate().expect("generates");
    let state = two_device_state(&founder, &joiner);

    assert_eq!(
        transport::auth::authorize(&state, &stranger.transport_key().key_id()),
        Err(transport::Error::NotAMember)
    );
}

#[test]
fn authorize_distinguishes_revocation_from_being_unknown() {
    let founder = NodeIdentity::generate().expect("generates");
    let joiner = NodeIdentity::generate().expect("generates");
    let mut state = two_device_state(&founder, &joiner);
    state.revoked.insert(joiner.device_id());

    assert_eq!(
        transport::auth::authorize(&state, &joiner.transport_key().key_id()),
        Err(transport::Error::Revoked),
        "revoked is not the same as never known"
    );
}

/// `authenticate` and `authorize` must agree about membership, or a binding
/// choosing one would admit peers the other refuses.
#[test]
fn authenticate_and_authorize_agree_about_membership() {
    let founder = NodeIdentity::generate().expect("generates");
    let joiner = NodeIdentity::generate().expect("generates");
    let stranger = NodeIdentity::generate().expect("generates");
    let state = two_device_state(&founder, &joiner);
    let nonce = [0x2a; transport::auth::CHALLENGE_LEN];
    let challenge = transport::auth::challenge_bytes(&nonce);

    for (identity, expected) in
        [(&joiner, Ok(joiner.device_id())), (&stranger, Err(transport::Error::NotAMember))]
    {
        let signature = identity.transport_key().signer().sign(&challenge).expect("signs");
        let handshake =
            transport::auth::Handshake { key: identity.transport_key().public_key(), signature };
        let full = transport::auth::authenticate(&state, &handshake, &nonce);
        let membership_only =
            transport::auth::authorize(&state, &identity.transport_key().key_id());
        assert_eq!(full, expected);
        assert_eq!(full, membership_only, "the two entry points must not disagree");
    }
}

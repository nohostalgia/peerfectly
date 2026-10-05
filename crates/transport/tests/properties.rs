//! Property-based tests, and the scans that keep the interface honest.
//!
//! The fixed suite in `behaviour.rs` checks the cases the specification names.
//! These check the ones it does not: arbitrary traffic, arbitrary rosters, and
//! the two claims the interface makes about itself that only a scan can hold to.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

use std::sync::Arc;

use identity::NodeIdentity;
use proptest::prelude::*;
use roster::id::NetworkId;
use roster::roster::Roster;
use roster::sign::sign_operation;
use roster::state::RosterState;
use roster::types::{NetworkParams, OperationBody, OperationCore, Role};
use transport::session::{Session, Transport};
use transport::{MemoryFabric, MemoryTransport};

/// A two-device roster, as in the behavioural suite.
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

/// A connected pair on the in-memory fabric.
async fn connected() -> (Box<dyn Session>, Box<dyn Session>, RosterState) {
    let founder = Arc::new(NodeIdentity::generate().expect("generates"));
    let joiner = Arc::new(NodeIdentity::generate().expect("generates"));
    let state = two_device_state(&founder, &joiner);
    let fabric = MemoryFabric::new();

    let dialler = MemoryTransport::join(&fabric, Arc::clone(&founder), state.clone()).await;
    let acceptor = MemoryTransport::join(&fabric, Arc::clone(&joiner), state.clone()).await;

    let key = acceptor.transport_key();
    let (dialled, accepted) = tokio::join!(dialler.connect(&key), acceptor.accept());
    (dialled.expect("establishes"), accepted.expect("establishes"), state)
}

/// A runtime for a property body, since proptest is synchronous.
fn block_on<F: core::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(future)
}

proptest! {
    /// Any sequence of payloads arrives with contents and boundaries intact.
    #[test]
    fn payloads_survive_intact(
        payloads in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..512),
            1..8,
        ),
    ) {
        block_on(async {
            let (dialled, accepted, _state) = connected().await;
            for payload in &payloads {
                dialled.send(payload).await.expect("sends");
            }
            for expected in &payloads {
                let received = accepted.recv().await.expect("receives");
                assert_eq!(&received, expected, "a payload changed in flight");
            }
        });
    }

    /// A session's peer never changes, whatever is done to it.
    #[test]
    fn the_peer_never_changes(
        sends in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 0..8),
    ) {
        block_on(async {
            let (dialled, accepted, _state) = connected().await;
            let first = dialled.peer();
            for payload in &sends {
                dialled.send(payload).await.expect("sends");
                assert_eq!(dialled.peer(), first);
            }
            for _ in &sends {
                let _ = accepted.recv().await;
                assert_eq!(dialled.peer(), first);
            }
            assert_eq!(dialled.peer(), first, "the peer is settled at establishment");
        });
    }

    /// No session is established with a device the supplied state omits.
    #[test]
    fn a_device_absent_from_state_never_gets_a_session(revoke in any::<bool>()) {
        block_on(async {
            let founder = Arc::new(NodeIdentity::generate().expect("generates"));
            let joiner = Arc::new(NodeIdentity::generate().expect("generates"));
            let mut state = two_device_state(&founder, &joiner);

            // Remove the joiner, either as revoked or simply absent.
            state.devices.remove(&joiner.device_id());
            if revoke {
                state.revoked.insert(joiner.device_id());
            }

            let fabric = MemoryFabric::new();
            let dialler =
                MemoryTransport::join(&fabric, Arc::clone(&founder), state.clone()).await;
            let acceptor = MemoryTransport::join(&fabric, Arc::clone(&joiner), state).await;

            let key = acceptor.transport_key();
            let (dialled, _accepted) =
                tokio::join!(dialler.connect(&key), acceptor.accept());
            assert!(dialled.is_err(), "an absent device must never get a session");
        });
    }

    /// Operations on a closed session always report the close.
    #[test]
    fn a_closed_session_always_reports_the_close(
        payload in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        block_on(async {
            let (dialled, _accepted, _state) = connected().await;
            dialled.close().await.expect("closes");

            let sent = dialled.send(&payload).await;
            assert!(
                sent.as_ref().err().is_some_and(transport::Error::is_closed),
                "a send on a closed session reports the close: {sent:?}"
            );

            let received = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                dialled.recv(),
            )
            .await;
            match received {
                Ok(Err(error)) => assert!(error.is_closed()),
                Ok(Ok(_)) => panic!("a closed session must not yield a payload"),
                Err(_) => panic!("a closed session must not block a receiver"),
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Scans: claims the interface makes that only reading it can hold to
// ---------------------------------------------------------------------------

/// The interface states it promises no confidentiality. Left implicit, "it goes
/// through the transport" is exactly what a later reader takes to mean "it is
/// encrypted".
#[test]
fn the_interface_says_it_promises_no_confidentiality() {
    let source = include_str!("../src/session.rs");
    assert!(
        source.contains("Confidentiality") || source.contains("confidentiality"),
        "the interface must state what it does not promise"
    );
    assert!(
        source.contains("TLS") || source.contains("QUIC"),
        "and say where a real transport gets it instead"
    );
}

/// No connectivity-layer type appears in the interface. The whole value of
/// §2.1's abstraction is that replacing the layer touches nothing above it, and
/// one leaked type undoes that.
#[test]
fn no_connectivity_layer_type_appears_in_the_interface() {
    let source = include_str!("../src/session.rs");
    let signatures: String = source
        .lines()
        .map(str::trim)
        .filter(|line| {
            (line.starts_with("async fn ") || line.starts_with("fn ") || line.starts_with("pub "))
                && !line.starts_with("///")
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(signatures.contains("async fn connect"), "the scan found the real signatures");
    for leaked in ["iroh", "NodeAddr", "Endpoint", "QuicConn", "SocketAddr", "TcpStream"] {
        assert!(
            !signatures.contains(leaked),
            "`{leaked}` must not appear in the interface; a leaked connectivity type \
             undoes the abstraction. Signatures were:\n{signatures}"
        );
    }
}

/// Every operation that decides membership is on the interface, not only on a
/// concrete type.
///
/// This is the shape of the defect two machines found. `update_state` existed,
/// was correct, and was called by three test files and nothing else — because the
/// trait did not declare it, so the daemon holding an `Arc<dyn Transport>` had no
/// way to call it. Both halves looked innocent on their own. The interface is
/// where the two meet, so it is where this is asserted.
#[test]
fn every_membership_operation_is_declared_on_the_interface() {
    let interface = include_str!("../src/session.rs");
    assert!(
        interface.contains("async fn update_state"),
        "the interface must carry the operation that supplies newer roster state"
    );

    for (name, source) in
        [("memory", include_str!("../src/memory.rs")), ("direct", include_str!("../src/direct.rs"))]
    {
        assert!(
            !source.contains("pub async fn update_state"),
            "{name} must not offer the operation as an inherent method as well: a caller \
             holding the concrete type and one holding `dyn Transport` would reach different \
             code, and the one nobody called is the one the daemon needed"
        );
    }
}

/// Both implementations override the default rather than inheriting it.
///
/// The default does nothing, which is right for a transport holding no state of
/// its own and wrong for both that exist here. A no-op inherited by accident
/// would leave every membership decision frozen at construction, which is
/// exactly the bug this change closes, reintroduced without a line changing.
#[test]
fn both_implementations_override_the_state_update() {
    for (name, source) in
        [("memory", include_str!("../src/memory.rs")), ("direct", include_str!("../src/direct.rs"))]
    {
        let after_impl = source
            .split_once("impl Transport for")
            .map(|(_, rest)| rest)
            .unwrap_or_else(|| panic!("{name} implements the transport interface"));
        assert!(
            after_impl.contains("async fn update_state"),
            "{name} must override the state update rather than inherit the no-op default"
        );
        assert!(
            after_impl.contains("ClosedOnMembershipLoss"),
            "{name} must close sessions whose peer stopped being a member, which is the \
             duty the call exists for"
        );
    }
}

/// The transport holds no membership list of its own. One that disagreed with
/// the signed log would be the thing actually deciding who is in the network.
#[test]
fn the_transport_keeps_no_independent_membership_list() {
    for source in [include_str!("../src/memory.rs"), include_str!("../src/direct.rs")] {
        // The only membership state either holds is the `RosterState` it was
        // given; there is no separate set of allowed devices or keys.
        assert!(
            !source.contains("allowed_devices") && !source.contains("permitted"),
            "a transport must not keep its own list of who is allowed"
        );
        assert!(source.contains("RosterState"), "membership comes from supplied roster state");
        assert!(
            source.contains("auth::is_member") || source.contains("auth::authenticate"),
            "and is asked each time rather than remembered"
        );
    }
}

/// `iroh` really is absent, so the deferral is enforced rather than intended.
#[test]
fn iroh_is_not_a_dependency_of_this_crate() {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        !manifest.contains("iroh"),
        "the iroh binding is `transport-iroh`, deferred because DESIGN.md §0 forbids \
         merging network code without a real-world NAT test"
    );
}

/// The README covers every requirement the specification adds. `transport-iroh`
/// is written from it, and a requirement missing here is one the binding is not
/// told it has to satisfy.
#[test]
fn the_readme_covers_every_requirement() {
    let readme = include_str!("../README.md");
    for (requirement, marker) in [
        ("A small, replaceable transport interface", "## The interface"),
        ("A peer is authenticated against the roster", "## Authentication, in two steps"),
        ("A session is bound to one device", "## One session, one device"),
        ("A session ends when its peer stops being a member", "## A session ends when its peer"),
        ("Distinguishable failure states", "## Failure states, kept apart"),
        ("Sending and receiving on a session", "## Payload boundaries are part of the contract"),
        ("The transport holds no authority of its own", "## The transport holds no authority"),
    ] {
        assert!(
            readme.contains(marker),
            "the README must cover `{requirement}`; no section matching `{marker}`"
        );
    }
}

/// The deferrals name where each piece went. "Later" is not a destination, and a
/// deferral without one is how a requirement gets lost between changes.
#[test]
fn every_deferral_names_its_destination() {
    let readme = include_str!("../README.md");
    for destination in ["transport-iroh", "roster-sync", "tunnel"] {
        assert!(readme.contains(destination), "a deferral must name `{destination}`");
    }
    for deferred in ["NAT", "gossip", "quota", "source validation", "Path selection"] {
        assert!(
            readme.to_lowercase().contains(&deferred.to_lowercase()),
            "the deferrals must account for `{deferred}`"
        );
    }
}

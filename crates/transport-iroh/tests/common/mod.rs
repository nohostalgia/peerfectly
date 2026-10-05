//! A network with two devices and a relay, built from real signed operations.

#![allow(dead_code, reason = "each test file uses a different part of the fixture")]
#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::sync::Arc;

use identity::NodeIdentity;
use roster::id::NetworkId;
use roster::roster::Roster;
use roster::sign::sign_operation;
use roster::state::RosterState;
use roster::types::{NetworkParams, OperationBody, OperationCore, Role};

/// A founded network whose parameters name `relay`.
pub struct Fixture {
    /// The founding admin.
    pub founder: Arc<NodeIdentity>,
    /// A member device.
    pub joiner: Arc<NodeIdentity>,
    /// Derived state, carrying the relay in its parameters.
    pub state: RosterState,
}

impl Fixture {
    /// Founds a network with two devices, naming a relay if one is given.
    pub fn found(relay: Option<&str>) -> Self {
        Self::found_pinning(relay, None)
    }

    /// Founds the same network, pinning the relay's certificate.
    pub fn found_pinning(relay: Option<&str>, certificate: Option<Vec<u8>>) -> Self {
        let founder = Arc::new(NodeIdentity::generate().expect("generates"));
        let joiner = Arc::new(NodeIdentity::generate().expect("generates"));
        let params = NetworkParams::with_relay(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            relay,
            "example.internal",
            2_592_000,
        )
        .expect("valid parameters");
        let params = match certificate {
            Some(certificate) => params.pinning(certificate).expect("a usable certificate"),
            None => params,
        };

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

        Self { founder, joiner, state: node.state().expect("derives") }
    }
}

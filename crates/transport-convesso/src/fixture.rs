//! A network of three devices and a convesso relay in this process, for tests.
//!
//! Behind the `fixture` feature, which only this crate's own tests turn on. The
//! relay's key is made here, before the network is founded, so the network's
//! parameters pin it exactly as a real network would: the nodes under test are
//! built by the ordinary constructor and trust nothing the roster does not name.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "a fixture fails a test by panicking")]

use std::sync::Arc;

use convesso_core::identity::Identity;
use convesso_relay::{Config as RelayConfig, Open, Relay};
use convesso_tokio::entropy::OsEntropy;
use identity::NodeIdentity;
use roster::id::NetworkId;
use roster::roster::Roster;
use roster::sign::sign_operation;
use roster::state::RosterState;
use roster::types::{NetworkParams, OperationBody, OperationCore, Role};
use tokio::net::{TcpListener, UdpSocket};

/// A relay running in this process.
pub struct TestRelay {
    /// `host:port`.
    pub host: String,
    /// Its key.
    pub key: [u8; 32],
    /// Whether its link is wrapped in TLS.
    pub tls: bool,
}

impl TestRelay {
    /// The relay as the roster writes it: `key@host:port`.
    #[must_use]
    pub fn written(&self) -> String {
        crate::relay::written(&self.key, &self.host, self.tls)
    }

    /// Starts a relay on localhost, UDP and TCP on one port.
    pub async fn start() -> Self {
        Self::serving(false).await
    }

    /// Starts a relay that serves TLS-wrapped links too, with a self-signed
    /// certificate nobody checks: the relay's key is what is trusted.
    pub async fn start_tls() -> Self {
        Self::serving(true).await
    }

    async fn serving(tls: bool) -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("the generator works");
        let identity = Identity::from_ed25519_seed(&seed).expect("a seed is an identity");
        let key = *identity.address().as_bytes();
        let (udp, listener, port) = loop {
            let udp = UdpSocket::bind("127.0.0.1:0").await.expect("binds UDP");
            let port = udp.local_addr().expect("has an address").port();
            if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)).await {
                break (udp, listener, port);
            }
        };
        let relay = Relay::new(
            identity,
            Open,
            OsEntropy,
            RelayConfig::default(),
            convesso_core::time::Instant::from_millis(0),
        )
        .expect("a relay starts");
        let acceptor = tls.then(|| {
            let issued = rcgen::generate_simple_self_signed(vec!["relay.example".to_owned()])
                .expect("a certificate");
            convesso_tokio::tls::TlsAcceptor::from_pem(
                issued.cert.pem().as_bytes(),
                issued.signing_key.serialize_pem().as_bytes(),
            )
            .expect("an acceptor")
        });
        tokio::spawn(convesso_tokio::relay_server::serve_with(relay, udp, listener, acceptor));
        Self { host: format!("127.0.0.1:{port}"), key, tls }
    }
}

/// A founded network of three devices.
pub struct Network {
    /// The founding admin.
    pub founder: Arc<NodeIdentity>,
    /// A member.
    pub joiner: Arc<NodeIdentity>,
    /// Another member.
    pub third: Arc<NodeIdentity>,
    /// Derived state.
    pub state: RosterState,
}

impl Network {
    /// Founds a network whose parameters name `relay`.
    pub fn found(relay: Option<&str>) -> Self {
        let founder = Arc::new(NodeIdentity::generate().expect("generates"));
        let joiner = Arc::new(NodeIdentity::generate().expect("generates"));
        let third = Arc::new(NodeIdentity::generate().expect("generates"));
        let params = NetworkParams::with_relay(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            relay,
            "example.internal",
            2_592_000,
        )
        .expect("valid parameters");

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

        let add_third = OperationCore::new(
            3,
            founder.signing_key().algorithm(),
            OperationBody::AddDevice(
                third.device_spec("third", Role::Member, false, vec![]).expect("spec"),
            ),
            vec![add.id()],
            founder.signing_key().key_id(),
            network,
        )
        .expect("well-formed");
        let third_bytes = sign_operation(&add_third, founder.signer()).expect("signs");

        let mut node = Roster::new();
        assert!(node.offer_bytes(&genesis_bytes).is_accepted());
        assert!(node.offer_bytes(&add_bytes).is_accepted());
        assert!(node.offer_bytes(&third_bytes).is_accepted());
        Self { founder, joiner, third, state: node.state().expect("derives") }
    }

    /// Founds a network on `relay`.
    pub fn on(relay: &TestRelay) -> Self {
        Self::found(Some(&relay.written()))
    }
}

//! The shared behavioural suite, run against the convesso binding.
//!
//! The suite is not modified for this implementation and must not be. If a
//! behaviour here could not be satisfied without editing the suite, that would
//! be a finding against the interface or against convesso, not a reason for a
//! smaller suite.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::sync::Arc;

use identity::NodeIdentity;
use roster::id::DeviceId;
use roster::sign::PublicKey;
use roster::state::RosterState;
use transport::session::Transport;
use transport::suite::{self, Harness};
use transport_convesso::ConvessoTransport;
use transport_convesso::fixture::{Network, TestRelay};

/// Two nodes on a relay running in this process.
struct ConvessoHarness {
    dialler: ConvessoTransport,
    acceptor: ConvessoTransport,
    acceptor_key: PublicKey,
    unreachable_key: PublicKey,
    dialler_device: DeviceId,
    acceptor_device: DeviceId,
}

#[async_trait::async_trait]
impl Harness for ConvessoHarness {
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
        self.unreachable_key.clone()
    }

    fn dialler_device(&self) -> DeviceId {
        self.dialler_device
    }

    fn acceptor_device(&self) -> DeviceId {
        self.acceptor_device
    }

    async fn set_state(&self, state: RosterState) {
        // Through `&dyn Transport`, as a node holding a trait object would.
        self.dialler().update_state(state.clone()).await;
        self.acceptor().update_state(state).await;
    }

    async fn state(&self) -> RosterState {
        self.dialler.state().await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_shared_suite_passes_against_the_convesso_binding() {
    let relay = TestRelay::start().await;
    let network = Network::on(&relay);

    let dialler = ConvessoTransport::bind(&network.founder, network.state.clone()).await.unwrap();
    let acceptor = ConvessoTransport::bind(&network.joiner, network.state.clone()).await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::join!(dialler.online(), acceptor.online())
    })
    .await
    .expect("both nodes reach the relay");

    // A key belonging to nobody: a real ed25519 key no operation ever named,
    // so dialling it is unreachability rather than refusal.
    let nobody = NodeIdentity::generate().unwrap();

    let harness = Arc::new(ConvessoHarness {
        acceptor_key: acceptor.transport_key(),
        unreachable_key: nobody.transport_key().public_key(),
        dialler_device: network.founder.device_id(),
        acceptor_device: network.joiner.device_id(),
        dialler,
        acceptor,
    });

    tokio::time::timeout(std::time::Duration::from_secs(180), suite::run_all(harness))
        .await
        .expect("the suite finishes");
}

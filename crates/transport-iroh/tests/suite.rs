//! The shared behavioural suite, run against the iroh binding.
//!
//! The suite is not modified for this implementation and must not be. It is the
//! reason `transport-session` shipped two implementations rather than one: an
//! interface with a single implementation is an untested claim about
//! replaceability. If a behaviour here could not be satisfied without editing
//! the suite, the abstraction would be wrong, and that would be the finding
//! worth having — not a smaller suite.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

mod common;

use std::sync::Arc;

use common::Fixture;
use identity::NodeIdentity;
use roster::id::DeviceId;
use roster::sign::PublicKey;
use roster::state::RosterState;
use transport::session::Transport;
use transport::suite::{self, Harness};
use transport_iroh::IrohTransport;

/// Two nodes on a relay running in this process.
struct IrohHarness {
    dialler: IrohTransport,
    acceptor: IrohTransport,
    acceptor_key: PublicKey,
    unreachable_key: PublicKey,
    dialler_device: DeviceId,
    acceptor_device: DeviceId,
}

#[async_trait::async_trait]
impl Harness for IrohHarness {
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

#[tokio::test]
async fn the_shared_suite_passes_against_the_iroh_binding() {
    let (_map, url, server) =
        iroh::test_utils::run_relay_server().await.expect("a relay in this process");
    let fixture = Fixture::found(Some(url.as_str()));

    let dialler =
        IrohTransport::bind_trusting_any_relay_certificate(&fixture.founder, fixture.state.clone())
            .await
            .expect("binds");
    let acceptor =
        IrohTransport::bind_trusting_any_relay_certificate(&fixture.joiner, fixture.state.clone())
            .await
            .expect("binds");

    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tokio::join!(dialler.endpoint().online(), acceptor.endpoint().online())
    })
    .await
    .expect("both endpoints reach the relay");

    // A key belonging to nobody: a real ed25519 key that no operation ever
    // named, so dialling it is unreachability rather than refusal.
    let nobody = NodeIdentity::generate().expect("generates");

    let harness = Arc::new(IrohHarness {
        acceptor_key: acceptor.transport_key(),
        unreachable_key: nobody.transport_key().public_key(),
        dialler_device: fixture.founder.device_id(),
        acceptor_device: fixture.joiner.device_id(),
        dialler,
        acceptor,
    });

    suite::run_all(harness).await;

    // The relay outlives the run; dropping it earlier would stop the thing the
    // sessions are reaching each other through.
    drop(server);
}

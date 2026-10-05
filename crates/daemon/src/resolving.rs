//! Who answers names, and when.
//!
//! A seam of the same shape as [`crate::connectivity::Connectivity`], and for the
//! same reason: the resolver listens on a socket bound to an address that only
//! exists while the tunnel is up, so it is *started* by bring-up rather than held
//! for the life of the process.
//!
//! Behind a trait so the whole lifecycle — started on up, stopped on down, gone
//! while down — is testable without an adapter. The socket itself lives in
//! [`sockets`]; every rule about what a name means is in
//! [`crate::names`], and neither this nor the socket decides anything.

use std::net::Ipv6Addr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::error::Result;
use crate::node::Node;

pub mod sockets;

/// Something answering names, until it is dropped.
pub trait Answering: Send + Sync {
    /// Stops answering.
    ///
    /// Also what dropping it does, so a resolver cannot outlive the tunnel by
    /// being forgotten.
    fn stop(&self);
}

/// Starts a resolver when the tunnel comes up.
#[async_trait]
pub trait Resolving: Send + Sync {
    /// Begins answering names at this address, reading the roster from `node`.
    ///
    /// The node is passed rather than a snapshot of its state because a name must
    /// be answered from the roster **as it is when the query arrives**. A resolver
    /// holding a copy would keep answering for a device that had just been
    /// revoked, for as long as it held it.
    async fn start(&self, address: Ipv6Addr, node: Arc<Node>) -> Result<Box<dyn Answering>>;
}

#[cfg(test)]
pub(crate) mod testing {
    //! A resolver that records that it was asked to run.

    use std::net::Ipv6Addr;
    use std::sync::{Arc, Mutex};

    use super::{Answering, Node, Resolving, Result};

    /// What a test wants to know: whether one is running, and where.
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    pub(crate) struct Serving {
        pub started: usize,
        pub running: bool,
        pub at: Option<Ipv6Addr>,
    }

    /// Records starts and stops instead of binding a socket.
    #[derive(Default)]
    pub(crate) struct Recording {
        serving: Arc<Mutex<Serving>>,
    }

    impl Recording {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        pub(crate) fn serving(&self) -> Serving {
            self.serving.lock().expect("not poisoned").clone()
        }
    }

    /// Marks the recorder as no longer serving when it goes.
    struct Handle(Arc<Mutex<Serving>>);

    impl Answering for Handle {
        fn stop(&self) {
            self.0.lock().expect("not poisoned").running = false;
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            self.stop();
        }
    }

    #[async_trait::async_trait]
    impl Resolving for Recording {
        async fn start(&self, address: Ipv6Addr, _node: Arc<Node>) -> Result<Box<dyn Answering>> {
            {
                let mut serving = self.serving.lock().expect("not poisoned");
                serving.started = serving.started.saturating_add(1);
                serving.running = true;
                serving.at = Some(address);
            }
            Ok(Box::new(Handle(Arc::clone(&self.serving))))
        }
    }
}

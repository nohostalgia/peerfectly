//! The real packet device.
//!
//! An implementation of [`tunnel::Packets`] over the platform adapter, and
//! nothing else. Every rule about which packets may pass is in
//! [`daemon::gateway`] and [`tunnel`], where an in-memory device exercises them
//! without privileges; this module moves bytes.
//!
//! No `unsafe` appears here. Loading the driver is the one unsafe call, and it
//! lives in [`super::driver`] because what needs justifying is which file gets
//! loaded, not the moving of bytes afterwards.
//!
//! # What is not tested here
//!
//! Creating an adapter needs Administrator and the driver, so nothing below runs
//! in CI. The expectations it must satisfy are written against the interface in
//! `daemon::gateway` and in `tunnel`, and they hold for this implementation only
//! if the platform behaves as assumed — which is what `VERIFICATION.md` is for.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tunnel::Packets;

use crate::platform::driver;
use daemon::error::{Error, Result, Step};
use daemon::limits;
use daemon::routes::Interface;

/// How many bytes the adapter's rings hold.
///
/// The library's own minimum is small and its maximum is large; this is a
/// middle value. Too small drops packets under burst, too large pins memory that
/// is never used. A starting value, like the schedule — see `daemon::schedule`.
const RING_CAPACITY: u32 = 0x40_0000;

/// A real adapter, and a session on it.
pub struct Adapter {
    /// The adapter itself. Dropping it removes it, and its routes with it.
    adapter: Arc<wintun::Adapter>,
    /// The session packets move over.
    session: Arc<wintun::Session>,
}

impl Adapter {
    /// Creates the adapter and starts a session on it.
    ///
    /// # Errors
    ///
    /// When the driver will not load, the adapter cannot be created — most often
    /// for want of Administrator — or the MTU will not take.
    ///
    /// `guid` is the adapter's identity. Given, it is the same every time for the
    /// same network, so Windows keeps the network's profile and any firewall rule
    /// bound to it; the bytes are read in order, as the GUID's text shows them.
    ///
    /// No orphan to clear first: since Wintun 0.14 an adapter belongs to the
    /// process that made it and goes when that process does, crash included.
    pub fn create(name: &str, guid: Option<[u8; 16]>) -> Result<Self> {
        let wintun = driver::load()?;

        let requested = guid.map(u128::from_be_bytes);
        let adapter = wintun::Adapter::create(&wintun, name, limits::PRODUCT, requested)
            .map_err(|cause| Self::failed("the adapter could not be created", &cause))?;

        // Set explicitly rather than left to a default. A link that carries more
        // than the transport does fails on large packets in a way that looks
        // like packet loss, and gets diagnosed as the wrong thing entirely.
        adapter
            .set_mtu(limits::MTU)
            .map_err(|cause| Self::failed("the MTU would not take", &cause))?;

        let session = adapter
            .start_session(RING_CAPACITY)
            .map_err(|cause| Self::failed("the session would not start", &cause))?;

        Ok(Self { adapter, session: Arc::new(session) })
    }

    /// The interface routes should point at.
    ///
    /// # Errors
    ///
    /// When the platform will not say which interface this is.
    pub fn interface(&self) -> Result<Interface> {
        self.adapter
            .get_adapter_index()
            .map(Interface::new)
            .map_err(|cause| Self::failed("the adapter has no interface index", &cause))
    }

    /// Ends the session and removes the adapter.
    ///
    /// Also what dropping it does. Routes are scoped to the interface, so this is
    /// what takes them with it — including when the process dies without
    /// unwinding, which is the case ordinary cleanup cannot cover.
    pub fn close(&self) {
        let _ = self.session.shutdown();
    }

    /// Wraps an adapter failure.
    fn failed(what: &str, cause: &wintun::Error) -> Error {
        Error::BringUp {
            step: Step::CreatingAdapter,
            cause: format!("{what}: {cause}"),
            left: Vec::new(),
        }
    }
}

#[async_trait]
impl Packets for Adapter {
    async fn deliver(&self, packet: &[u8]) -> io::Result<()> {
        // The gateway refuses anything past the link's bound before it gets
        // here. This is the second of two, and it is here because the conversion
        // below cannot be allowed to wrap.
        let size = u16::try_from(packet.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} bytes is past what the adapter takes", packet.len()),
            )
        })?;

        let mut allocated = self
            .session
            .allocate_send_packet(size)
            .map_err(|cause| io::Error::other(cause.to_string()))?;

        allocated.bytes_mut().copy_from_slice(packet);
        self.session.send_packet(allocated);
        Ok(())
    }

    async fn take(&self) -> io::Result<Vec<u8>> {
        let session = Arc::clone(&self.session);

        // `receive_blocking` waits on an event, so it cannot run on the async
        // runtime's threads without stalling every other task on that thread.
        tokio::task::spawn_blocking(move || {
            session
                .receive_blocking()
                .map(|packet| packet.bytes().to_vec())
                .map_err(|cause| io::Error::other(cause.to_string()))
        })
        .await
        .map_err(|cause| io::Error::other(cause.to_string()))?
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// The MTU is set from the crate's own bound rather than left to a default.
    #[test]
    fn the_mtu_is_set_explicitly() {
        let code = crate::code_of(include_str!("adapter.rs"));
        assert!(code.contains("set_mtu(limits::MTU)"), "an unset MTU fails like packet loss");
    }

    /// The unsafe is in `driver`, not here. This module moves bytes.
    #[test]
    fn no_unsafe_appears_in_this_module() {
        let code = crate::code_of(include_str!("adapter.rs"));
        assert!(!code.contains("unsafe"), "loading is `driver`'s business, and only loading");
    }

    /// No rule about what a packet may claim lives here. `tunnel` decides, and
    /// `gateway` is the only thing that asks it.
    #[test]
    fn the_adapter_judges_nothing() {
        let code = crate::code_of(include_str!("adapter.rs"));
        for forbidden in ["SOURCE_OFFSET", "address_of", "is_accepted", "RosterState"] {
            assert!(!code.contains(forbidden), "`{forbidden}` is a decision, and belongs in core");
        }
    }

    /// Creating one needs Administrator and a pinned driver, so this is the
    /// honest outcome in CI: it fails, and it fails saying why.
    #[test]
    fn creating_an_adapter_without_a_pinned_driver_is_refused() {
        match Adapter::create("peerfectly test", None) {
            Err(Error::BringUp { step, cause, .. }) => {
                assert_eq!(step, Step::CreatingAdapter);
                assert!(!cause.is_empty(), "the refusal says what went wrong: {cause}");
            }
            Err(other) => panic!("expected an adapter failure, got {other:?}"),
            Ok(_) => panic!(
                "an adapter was created in a test — the driver is pinned and this machine has \
                 Administrator, which means this test is no longer measuring what it claims"
            ),
        }
    }
}

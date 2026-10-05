//! The real connectivity layer, started when the person turns the network on.
//!
//! Binding an endpoint is not a passive act: it contacts the relay named in the
//! signed parameters and begins learning this device's observed addresses. That
//! is traffic to infrastructure, so §2.6c says it may only happen once a person
//! has asked for the network — never at startup, and never while the tunnel is
//! down.
//!
//! Which is the whole reason this is behind a trait: a transport that exists is
//! one that has already spoken.

/// The connectivity this edge uses, which is the portable one.
pub use daemon::connectivity::Iroh;

#[cfg(test)]
mod tests {
    /// Nothing here runs at startup. A transport built before the person asked
    /// would have contacted the relay before they asked.
    #[test]
    fn connectivity_is_only_ever_started_on_request() {
        let daemon = crate::code_of(include_str!("../programs/daemon.rs"));
        assert!(
            !daemon.contains("IrohTransport::bind"),
            "the daemon must not bind a transport itself; that is the service's, at bring-up"
        );
        assert!(
            !daemon.contains("Adapter::create()"),
            "nor create an adapter; that is the machine's, at bring-up"
        );
    }
}

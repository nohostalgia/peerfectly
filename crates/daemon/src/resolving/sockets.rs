//! The resolver's socket, the same on every desktop.
//!
//! It lived in `windows-daemon` until Linux needed the same one: nothing in it
//! is about Windows, and two copies would be two places for the rules below to
//! drift apart.
//!
//! Binds inside the tunnel and answers what [`crate::wire`] says to answer. No
//! rule about names lives here.
//!
//! # Bound on the overlay address, not on loopback
//!
//! Two reasons, and the second is the one that matters.
//!
//! Port 53 on loopback is contested on a desktop — a local development DNS
//! server, a container runtime, a corporate agent. Binding there is a fight the
//! daemon would sometimes lose, and lose in a way that looks like name
//! resolution being broken.
//!
//! More importantly, binding inside the tunnel means the resolver **does not
//! exist while the tunnel is down**. There is no socket, so there is nothing to
//! reach and nothing to answer with a stale roster. That is the same property
//! §2.6c asks for everywhere else in this daemon, obtained here for free rather
//! than by remembering to stop something.

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;

use super::{Answering, Resolving};
use crate::error::{Error, Result, Step};
use crate::limits;
use crate::node::Node;
use crate::wire;

/// How long to keep trying the bind while the address settles.
///
/// Long enough for an interface change to land, short enough that a person
/// waiting on `peerfectly up` does not think it has hung.
const SETTLE: core::time::Duration = core::time::Duration::from_secs(3);

/// How long between attempts.
const STEP: core::time::Duration = core::time::Duration::from_millis(100);

/// A resolver listening inside the tunnel.
pub struct Resolver {
    /// The socket it answers on.
    socket: UdpSocket,
}

impl Resolver {
    /// Binds on this device's own overlay address.
    ///
    /// # Errors
    ///
    /// When the address is not yet on the adapter, or the port is taken.
    pub async fn bind(address: Ipv6Addr) -> Result<Self> {
        let at = SocketAddr::new(address.into(), limits::RESOLVER_PORT);

        // The address was given to the adapter a moment ago, and Windows applies
        // that asynchronously: for a short window the stack does not yet consider
        // it local, and the bind fails with WSAEADDRNOTAVAIL — which reads as
        // though the address had never been assigned at all.
        //
        // Bounded, so a real failure still surfaces rather than hanging. A port
        // already taken, or an address that genuinely is not there, will not
        // become available by being waited for.
        let mut waited = core::time::Duration::ZERO;
        loop {
            let outcome = UdpSocket::bind(at).await;
            match outcome {
                Ok(socket) => return Ok(Self { socket }),
                Err(_) if waited < SETTLE => {
                    tokio::time::sleep(STEP).await;
                    waited = waited.saturating_add(STEP);
                }
                Err(cause) => {
                    return Err(Error::BringUp {
                        step: Step::StartingResolver,
                        cause: format!(
                            "could not listen on [{address}]:{} after {}ms: {cause}",
                            limits::RESOLVER_PORT,
                            waited.as_millis()
                        ),
                        left: Vec::new(),
                    });
                }
            }
        }
    }

    /// Where it is listening.
    ///
    /// # Errors
    ///
    /// When the socket cannot say.
    pub fn address(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Answers one query, reading the roster as it is right now.
    ///
    /// The state is fetched *after* the query arrives, not before. A resolver
    /// holding a snapshot would keep answering for a device revoked while it was
    /// waiting, which is exactly the window a revocation exists to close.
    ///
    /// A message that is not a question this daemon should answer produces no
    /// reply at all — replying to something we could not parse means replying to
    /// whatever the sender wanted us to think it was.
    ///
    /// # Errors
    ///
    /// When the socket fails.
    pub async fn answer_one(&self, node: &Node) -> std::io::Result<()> {
        let mut buffer = vec![0u8; limits::MAX_DNS_MESSAGE];
        let (len, from) = self.socket.recv_from(&mut buffer).await?;

        let Ok(state) = node.state().await else {
            // A roster that describes no network answers nothing, rather than
            // answering wrongly.
            return Ok(());
        };

        let query = buffer.get(..len).unwrap_or_default();
        if let Some(response) = wire::respond(&state, &node.ipv4_view(), query) {
            self.socket.send_to(&response, from).await?;
        }
        Ok(())
    }
}

/// The real resolver, started when the tunnel comes up.
#[derive(Debug, Default, Clone, Copy)]
pub struct Sockets;

/// Stops the task when dropped.
struct Running(tokio::task::JoinHandle<()>);

impl Answering for Running {
    fn stop(&self) {
        self.0.abort();
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop();
    }
}

#[async_trait::async_trait]
impl Resolving for Sockets {
    async fn start(&self, address: Ipv6Addr, node: Arc<Node>) -> Result<Box<dyn Answering>> {
        let resolver = Resolver::bind(address).await?;

        let task = tokio::spawn(async move {
            loop {
                if let Err(cause) = resolver.answer_one(&node).await {
                    node.record(crate::node::Severity::Event, "resolver", cause).await;
                    // One bad datagram is not a reason to stop answering names
                    // for the rest of the session.
                    tokio::time::sleep(core::time::Duration::from_millis(50)).await;
                }
            }
        });
        Ok(Box::new(Running(task)))
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// The rules are `wire`'s and `names`'. Nothing here decides what a name
    /// means, and a scan is cheaper than trusting that it stays so.
    #[test]
    fn the_socket_decides_nothing_about_names() {
        let code = crate::code_of(include_str!("sockets.rs"));

        for forbidden in ["suffix", "devices", "NXDomain", "address_of("] {
            assert!(!code.contains(forbidden), "`{forbidden}` is a decision, and belongs in core");
        }
        assert!(code.contains("wire::respond"), "the answers come from `wire`");
    }

    /// A desktop installs a rule for the suffix, so its resolver forwards nothing.
    ///
    /// Android sends every lookup to one resolver and has to forward what is not
    /// its own; `daemon::route` exists for that. The exception is named in the
    /// spec so it cannot be read as permission here, and this is the half that
    /// holds the desktop to it: the only thing this resolver ever sends is its own
    /// answer back to whoever asked, and nothing in this edge decides where else a
    /// query could go.
    #[test]
    fn the_desktop_resolver_forwards_nothing() {
        let code = crate::code_of(include_str!("sockets.rs"));
        let sends = code.matches("send_to(").count();
        assert_eq!(sends, 1, "exactly one send, and it is the answer");
        assert!(code.contains("send_to(&response, from)"), "back to the asker, and only there");
        for forwarding in ["connect(", ".send(", "upstream", "forward"] {
            assert!(!code.contains(forwarding), "`{forwarding}` would reach another resolver");
        }
    }

    /// Not loopback. A resolver on 127.0.0.1 outlives the tunnel and can answer
    /// with a roster nobody is refreshing.
    #[test]
    fn the_resolver_does_not_bind_loopback() {
        let code = crate::code_of(include_str!("sockets.rs"));
        for forbidden in ["LOCALHOST", "127.0.0.1", "::1", "UNSPECIFIED"] {
            assert!(
                !code.contains(forbidden),
                "`{forbidden}` would leave the resolver reachable with the tunnel down"
            );
        }
    }

    /// Binding an address the machine does not have fails rather than falling
    /// back to one it does.
    #[tokio::test]
    async fn binding_an_address_this_machine_lacks_is_refused() {
        let elsewhere: Ipv6Addr = "fd00:dead:beef::1".parse().expect("valid");

        match Resolver::bind(elsewhere).await {
            Err(Error::BringUp { step, cause, .. }) => {
                assert_eq!(step, Step::StartingResolver);
                assert!(cause.contains("fd00:dead:beef::1"), "{cause}");
            }
            Err(other) => panic!("expected a bind refusal, got {other:?}"),
            Ok(_) => panic!("this machine should not hold an overlay address in a test"),
        }
    }
}

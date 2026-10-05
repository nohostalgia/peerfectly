//! The resolver's socket, which is the portable one.
//!
//! It lived here until Linux needed the same socket. What stays is the scan
//! that this edge — the files that make up the Windows desktop — takes no
//! forwarding decision anywhere.

pub use daemon::resolving::sockets::{Resolver, Sockets};

#[cfg(test)]
#[allow(clippy::panic, reason = "a test reports failure by panicking")]
mod tests {
    /// A desktop installs a rule for the suffix, so its resolver forwards nothing.
    ///
    /// Android sends every lookup to one resolver and has to forward what is not
    /// its own; `daemon::route` exists for that. The exception is named in the
    /// spec so it cannot be read as permission here: nothing in this edge, nor
    /// the socket it uses, decides where else a query could go. That the socket
    /// sends only its answer back is asserted beside it, in `daemon`.
    #[test]
    fn the_desktop_edge_takes_no_forwarding_decision() {
        let edge: &[(&str, &str)] = &[
            ("resolver.rs", include_str!("resolver.rs")),
            (
                "daemon/src/resolving/sockets.rs",
                include_str!("../../../daemon/src/resolving/sockets.rs"),
            ),
            ("machine.rs", include_str!("machine.rs")),
            ("connectivity.rs", include_str!("connectivity.rs")),
            ("nrpt.rs", include_str!("nrpt.rs")),
            ("mod.rs", include_str!("mod.rs")),
            ("programs/daemon.rs", include_str!("../programs/daemon.rs")),
            ("programs/command_line.rs", include_str!("../programs/command_line.rs")),
            ("cli/src/lib.rs", include_str!("../../../cli/src/lib.rs")),
        ];
        for (file, source) in edge {
            let code = crate::code_of(source);
            for decision in ["daemon::route(", "Belongs", "names::route(", "Held {"] {
                assert!(
                    !code.contains(decision),
                    "`{file}` names `{decision}`, the forwarding decision a desktop never takes"
                );
            }
        }
    }
}

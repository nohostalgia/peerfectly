//! The node as a program: what it decides, what it answers, and the loops that
//! drive it.
//!
//! Eight crates decided things and none of them ran. `roster-sync` has no loop,
//! `rendezvous` no cache policy, `local-discovery` no schedule, `transport-iroh`
//! no opinion about when to connect, `tunnel` no device. Every one of them wrote
//! "the daemon owns this". This is the daemon.
//!
//! # This half decides; another half acts
//!
//! Everything here is ordinary Rust and builds anywhere. It owns what is a
//! *decision*: which routes should exist given the signed parameters, what answer
//! a name deserves given the roster, which session a packet belongs to, when to
//! sync and publish and announce, and what the daemon will tell a person who
//! asks.
//!
//! What it never does is touch a machine. Creating an adapter, writing a route,
//! installing a resolution rule, drawing a tray icon, listening on a pipe: each
//! is behind a trait this crate defines — [`Machine`], [`Connectivity`],
//! [`Resolving`] — and implemented by an edge crate that decides nothing.
//! `windows-daemon` is one such edge; a phone would be another.
//!
//! The reason to be strict is not tidiness. A route plan computed by a pure
//! function can be tested exhaustively on any machine; `CreateIpForwardEntry2`
//! can only be tested by holding Administrator on Windows. Binding the two
//! together would leave the part most worth testing — the part that decides
//! whether a default route can ever be installed — in the half nothing can
//! exercise. That is the same split that made `transport-session`, `tunnel` and
//! the NAT measurement honest, and it is the fourth time it has been the right
//! answer.
//!
//! A change that puts policy in an edge has been made wrongly even if it works.
//!
//! # What is public here is a decision
//!
//! Everything reachable is an invitation, and this crate is about to be reached
//! by more than one consumer. The modules below are the list; widening it is an
//! edit somebody makes, and a test says so.
//!
//! Some acts are reachable in a partial form as well as a whole one, because the
//! suites that drive an assembled node need the part. Each such part is named for
//! what it omits — [`Node::admit_without_activating`] against [`Service::admit`]
//! — so that nobody reaches one believing it is the other. A language binding
//! must offer the whole act and never the part.
//!
//! # What this crate does not decide
//!
//! Membership, roles, and whether a device is authorised. Those belong to the
//! roster and to the crates that already implement its rules. This one assembles
//! and supervises; it holds no list of permitted devices and caches no
//! authorisation, so a revocation takes effect without it having to notice.
//!
//! Nor does it reinterpret [`tunnel`]'s packet rules. Where the two could
//! disagree, `tunnel` decides.

pub mod admitting;
pub mod attesting;
pub mod channel;
pub(crate) mod clock;
pub mod confirmations;
pub mod conflicts;
pub mod connectivity;
pub(crate) mod contacts;
pub mod control;
pub(crate) mod describing;
pub(crate) mod discovery;
pub mod drawing;
pub(crate) mod endpoints;
pub mod error;
pub mod exposing;
pub mod founding;
pub mod gateway;
pub mod joining;
pub mod keys;
pub mod lifecycle;
pub mod limits;
pub mod logging;
pub mod machine;
pub(crate) mod names;
pub mod networks;
pub mod node;
pub mod relay;
pub mod resolving;
pub mod revoking;
pub mod router;
pub mod routes;
pub mod rule;
pub mod schedule;
pub(crate) mod service;
pub mod signing;
pub mod snapshots;
pub mod state;
pub mod views;
pub mod wire;

pub use connectivity::Connectivity;
pub use control::{Command, Outcome, Report, Standing};
pub use endpoints::Endpoints;
pub use error::{Error, Residue, Result, Step};
pub use gateway::{Departure, Gateway};
pub use lifecycle::{Lifecycle, Up};
pub use machine::Machine;
pub use names::{Answer, Belongs, Held, route};
pub use node::{Fault, Node};
pub use resolving::{Answering, Resolving};
pub use router::Router;
pub use routes::{Interface, Plan, Route};
pub use rule::Rule;
pub use schedule::{Announcing, Publishing, Schedule};
pub use service::Service;
pub use state::{Choice, Log, Paths};

/// The source of a module with its comments and its own tests removed.
///
/// Several tests here assert that something is *absent* from the code. Reading
/// the whole file makes such a test match its own assertion — the string it
/// looks for is written in the line that looks for it — so it passes while the
/// crate is clean and passes just as well when it is not. Cutting at the test
/// module is what makes the check mean anything.
#[cfg(test)]
pub(crate) fn code_of(source: &str) -> String {
    let body = source.split("#[cfg(test)]").next().unwrap_or(source);
    body.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test reports failure by panicking")]
mod surface {
    /// What this crate offers is a list, and widening it is an edit somebody made.
    ///
    /// While the only caller lived in the same crate, everything being reachable
    /// cost nothing. It is about to be reached by an edge, by another edge on a
    /// phone, and eventually across a language boundary, where every public item
    /// becomes a callable function and nobody reads the module documentation on
    /// the way. So the surface is written down here, and a module that becomes
    /// public without joining the list fails this.
    const OFFERED: &[&str] = &[
        "admitting",
        "attesting",
        "channel",
        "confirmations",
        "conflicts",
        "connectivity",
        "control",
        "drawing",
        "error",
        "exposing",
        "founding",
        "gateway",
        "joining",
        "keys",
        "lifecycle",
        "limits",
        "logging",
        "machine",
        "networks",
        "node",
        "relay",
        "resolving",
        "revoking",
        "router",
        "routes",
        "rule",
        "schedule",
        "signing",
        "snapshots",
        "state",
        "views",
        "wire",
    ];

    #[test]
    fn the_public_surface_is_the_written_list() {
        let source = include_str!("lib.rs");
        let declared: Vec<&str> = source
            .lines()
            .filter_map(|line| line.trim().strip_prefix("pub mod "))
            .filter_map(|rest| rest.strip_suffix(';'))
            .collect();

        for name in &declared {
            assert!(
                OFFERED.contains(name),
                "`{name}` is public and is not among what this crate offers. Add it to \
                 OFFERED deliberately, or make it `pub(crate)`."
            );
        }
        for name in OFFERED {
            assert!(declared.contains(name), "`{name}` is offered and no longer declared");
        }
    }

    /// What this half says about protecting stored state rests on no platform.
    ///
    /// It used to carry an argument about a Windows profile's inherited access:
    /// careful and honest where it was written, and dangerous the moment the same
    /// file compiled for a phone, because it read as though somebody had checked
    /// and nobody had checked anything about a phone.
    ///
    /// So this half states the requirement — readable only by whoever owns the
    /// device — and each edge states how its platform meets it, and what that
    /// protection does not defend against.
    #[test]
    fn the_requirement_to_protect_state_names_no_platform() {
        let state = include_str!("state.rs");

        for mechanism in ["%LOCALAPPDATA%", "icacls", "SetNamedSecurityInfo", "DPAPI", "Keychain"] {
            assert!(
                !state.contains(mechanism),
                "`{mechanism}` is one platform's answer, and this half must not rest on it"
            );
        }
        // Collapsed first: a requirement worth writing is a sentence, and a
        // sentence wraps. A guard that looks for the unwrapped form passes only
        // while the text happens to be short, which is not what it is checking.
        let flowed = state
            .lines()
            .map(|line| line.trim().trim_start_matches("///").trim_start_matches("//!"))
            .collect::<Vec<_>>()
            .join(" ");
        let flowed = flowed.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flowed.contains("readable **only by whoever owns the device**"),
            "and it must still say what it requires"
        );
    }

    /// The obligations a renderer of the report owes are written where the next
    /// renderer's author will look, and they name the fields that carry them.
    ///
    /// A field renamed in `control.rs` without this document following would leave
    /// the Android client's author reading about a field that no longer exists.
    #[test]
    fn what_a_renderer_owes_is_written_down_against_the_fields_that_carry_it() {
        let surface = include_str!("../SURFACE.md");
        let control = include_str!("control.rs");

        assert!(surface.contains("## What a renderer of the report owes"), "the section exists");
        for field in [
            "signer_clock",
            "signed_here",
            "NoneRecorded",
            "NotRecorded",
            "waiting_unlisted",
            "reason",
            "rendezvous",
        ] {
            assert!(surface.contains(field), "SURFACE.md says what to do with `{field}`");
            assert!(control.contains(field), "`{field}` is still a name in control.rs");
        }
        for owed in ["seen, not obeyed", "never as \"never\"", "not of applying", "short id"] {
            assert!(surface.contains(owed), "SURFACE.md states: {owed}");
        }
    }

    /// A partial act is named for what it omits.
    ///
    /// Some acts are reachable in a partial form because the suites that drive an
    /// assembled node need the part — `admit_without_activating` exists so a test
    /// can put an operation into a roster without a tunnel coming up. That is
    /// legitimate, and it is also how `revoke` once skipped the activation every
    /// administrative action is required to do.
    ///
    /// So the part stays reachable and stops being able to pass for the whole
    /// thing: whoever reaches for it reads what it does not do. The list of such
    /// parts is in `SURFACE.md`, for the binding that must exclude them.
    #[test]
    fn no_partial_act_is_named_as_though_it_were_complete() {
        let node = include_str!("node.rs");

        assert!(
            !node.contains("pub async fn admit_local"),
            "`admit_local` does not say that it leaves the network down"
        );
        assert!(
            node.contains("pub async fn admit_without_activating"),
            "the partial form is named for what it omits"
        );
    }
}

/// What a person reads is whole sentences.
#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a test reports failure by panicking, and reads the text it scans by position"
)]
mod sentences {
    /// **No message has a hole in the middle of it.**
    ///
    /// A long message is written across lines with a `\` at the end of each, and
    /// Rust joins them. Lose the `\` and the newline and the next line's
    /// indentation stay in the string: *"Type the six                     digits
    /// into it"*. Twenty-nine of them were found at once, across the daemon,
    /// in the refusals and the reasons a person is most likely to be reading —
    /// all written by tooling that swallowed the backslash, none caught by a test,
    /// because every test asserted a fragment on one side of the hole.
    #[test]
    fn no_message_is_broken_by_a_run_of_spaces() {
        let sources = [
            ("admitting.rs", include_str!("admitting.rs")),
            ("control.rs", include_str!("control.rs")),
            ("joining.rs", include_str!("joining.rs")),
            ("service.rs", include_str!("service.rs")),
            ("snapshots.rs", include_str!("snapshots.rs")),
            ("views.rs", include_str!("views.rs")),
        ];
        let before = |c: char| c.is_ascii_alphabetic() || ",.;:)`'".contains(c);
        let after = |c: char| c.is_ascii_alphabetic() || "{`(".contains(c);

        for (file, source) in sources {
            for (index, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || !line.contains('"') {
                    continue;
                }
                let chars: Vec<char> = line.chars().collect();
                let mut at = 0;
                while at < chars.len() {
                    if chars[at] != ' ' {
                        at += 1;
                        continue;
                    }
                    let start = at;
                    while at < chars.len() && chars[at] == ' ' {
                        at += 1;
                    }
                    let run = at - start;
                    let bounded = start > 0
                        && at < chars.len()
                        && before(chars[start - 1])
                        && after(chars[at]);
                    assert!(
                        !(run >= 6 && bounded),
                        "{file}:{} has a message broken by {run} spaces, a lost line \
                         continuation:\n{line}",
                        index + 1
                    );
                }
            }
        }
    }
}

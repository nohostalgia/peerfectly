//! What went wrong, which step it went wrong at, and what it left on the machine.
//!
//! The last of those is the part a library would not need. Every other crate in
//! this workspace fails without consequence: a refused operation changes
//! nothing, a dropped packet leaves nothing behind. This one edits the machine's
//! routing table and its name resolution, so a failure halfway through bringing
//! the tunnel up leaves a machine in a state somebody has to be told about.
//!
//! An error that says only "failed" is, here, an error that leaves a person to
//! discover a blackholed prefix on their own.

use core::fmt;
use std::path::PathBuf;

/// The result of a daemon operation.
pub type Result<T> = core::result::Result<T, Error>;

/// What the daemon was doing when it failed.
///
/// Named rather than described, so an error can be matched on and so the same
/// step is called the same thing in a message, a log and a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Step {
    /// Opening or creating the directory state lives in.
    OpeningState,
    /// Reading the device's own identity.
    LoadingIdentity,
    /// Reading the roster and deriving its state.
    LoadingRoster,
    /// Creating the packet adapter.
    CreatingAdapter,
    /// Writing routes for the network's prefix.
    InstallingRoutes,
    /// Writing the name-resolution rule for the suffix.
    InstallingRule,
    /// Binding the resolver.
    StartingResolver,
    /// Starting the transport.
    StartingTransport,
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::OpeningState => "opening the state directory",
            Self::LoadingIdentity => "loading the identity",
            Self::LoadingRoster => "loading the roster",
            Self::CreatingAdapter => "creating the adapter",
            Self::InstallingRoutes => "installing routes",
            Self::InstallingRule => "installing the resolution rule",
            Self::StartingResolver => "starting the resolver",
            Self::StartingTransport => "starting the transport",
        };
        f.write_str(text)
    }
}

/// Something the daemon put on the machine that is still there.
///
/// A failure reports these so a person knows what the machine looks like now.
/// An empty list is itself the useful answer: the daemon undid what it had done.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Residue {
    /// The packet adapter still exists.
    Adapter,
    /// A route the daemon installed is still in the table.
    Route {
        /// The prefix it covers, as text.
        prefix: String,
    },
    /// The name-resolution rule is still in the registry.
    ResolutionRule {
        /// The suffix it claims.
        suffix: String,
    },
}

impl fmt::Display for Residue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adapter => f.write_str("the adapter"),
            Self::Route { prefix } => write!(f, "a route for {prefix}"),
            Self::ResolutionRule { suffix } => write!(f, "the resolution rule for {suffix}"),
        }
    }
}

/// Why the daemon could not do what was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Bringing the tunnel up failed partway.
    ///
    /// Carries the step and what is left on the machine, because the useful
    /// question after this failure is not why it happened but what the machine
    /// looks like now.
    BringUp {
        /// Where it failed.
        step: Step,
        /// What the platform said.
        cause: String,
        /// What is still installed. Empty means the daemon undid its work.
        left: Vec<Residue>,
    },

    /// State on disk could not be read or written.
    State {
        /// The path involved.
        path: PathBuf,
        /// What the filesystem said.
        cause: String,
    },

    /// A network's label is not usable as one.
    ///
    /// The only place a person's free text becomes a path component, so it is
    /// checked before it is used rather than after the filesystem refuses it.
    Label {
        /// What was asked for.
        label: String,
        /// Why it will not do.
        cause: String,
    },

    /// This device holds no network yet.
    ///
    /// Not a failure of anything: the daemon runs before a person has founded a
    /// network or joined one, and most of what it can be asked for has no answer
    /// until then. Distinct from a network that is down, because the remedies are
    /// opposites — one is `up`, the other is founding or joining — and a report
    /// that conflated them would send a person to the wrong command.
    NoNetwork,

    /// This device holds no network under that name.
    NoSuchNetwork {
        /// What was asked for.
        label: String,
    },

    /// A command that acts on a network named none, and several could be meant.
    ///
    /// Refused rather than guessed. Picking one would be the daemon deciding
    /// something only the person can, and the cost of guessing wrong is that a
    /// person switching off a client's network is cut off from their own house.
    WhichNetwork {
        /// The networks it could have meant.
        held: Vec<String>,
    },

    /// The network's parameters do not describe a usable network.
    Parameters {
        /// What is wrong with them.
        cause: String,
    },

    /// An operation authored here was refused, or could not be recorded.
    ///
    /// Both are failures of the same act. An operation the roster accepted but
    /// the log did not keep is worse than one that was refused outright: it takes
    /// effect now and vanishes at the next restart, and nobody is told.
    Refused {
        /// What went wrong.
        cause: String,
    },

    /// A peer could not be reached.
    ///
    /// Distinct from [`Self::Refused`], which is about an operation the roster
    /// would not take. Reusing that one made a failed dial report "the operation
    /// was not recorded", which is true of nothing that happened.
    Unreachable {
        /// What the transport said.
        cause: String,
    },

    /// A command needs the tunnel up and it is down.
    NotUp,

    /// The daemon is not running, or cannot be reached.
    NotRunning,
}

impl Error {
    /// What is still installed on the machine after this failure.
    ///
    /// Empty for every failure that changed nothing, which is most of them.
    #[must_use]
    pub fn left_behind(&self) -> &[Residue] {
        match self {
            Self::BringUp { left, .. } => left,
            _ => &[],
        }
    }

    /// The step that failed, when the failure had one.
    #[must_use]
    pub const fn step(&self) -> Option<Step> {
        match self {
            Self::BringUp { step, .. } => Some(*step),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BringUp { step, cause, left } => {
                write!(f, "failed while {step}: {cause}")?;
                if left.is_empty() {
                    f.write_str("; nothing was left on the machine")
                } else {
                    f.write_str("; still installed:")?;
                    for item in left {
                        write!(f, " {item};")?;
                    }
                    Ok(())
                }
            }
            Self::State { path, cause } => write!(f, "{}: {cause}", path.display()),
            Self::Label { label, cause } => {
                write!(f, "`{label}` will not do as a name for a network: {cause}")
            }
            Self::NoSuchNetwork { label } => {
                write!(f, "this device holds no network called `{label}`")
            }
            Self::WhichNetwork { held } => {
                write!(f, "which network? this device holds {}", held.join(", "))
            }
            Self::NoNetwork => f.write_str(
                "this device has no network yet. Found one with `peerfectly found`, or join an existing one with `peerfectly join`",
            ),
            Self::Parameters { cause } => write!(f, "the network parameters are unusable: {cause}"),
            Self::Refused { cause } => write!(f, "the operation was not recorded: {cause}"),
            Self::Unreachable { cause } => f.write_str(cause),
            Self::NotUp => f.write_str("the tunnel is not up"),
            Self::NotRunning => f.write_str("the daemon is not running"),
        }
    }
}

impl core::error::Error for Error {}

impl From<tunnel::Error> for Error {
    /// A prefix the overlay cannot use is a network this daemon cannot bring up.
    fn from(cause: tunnel::Error) -> Self {
        Self::Parameters { cause: cause.to_string() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_names_the_step() {
        let failure = Error::BringUp {
            step: Step::InstallingRoutes,
            cause: "access denied".to_owned(),
            left: Vec::new(),
        };
        assert_eq!(failure.step(), Some(Step::InstallingRoutes));
        assert!(failure.to_string().contains("installing routes"), "{failure}");
    }

    /// The scenario the type exists for: a failure after a route was installed
    /// must say whether the route is still there.
    #[test]
    fn a_failure_says_what_is_left_on_the_machine() {
        let cleaned = Error::BringUp {
            step: Step::InstallingRule,
            cause: "denied".to_owned(),
            left: Vec::new(),
        };
        assert!(cleaned.left_behind().is_empty());
        assert!(cleaned.to_string().contains("nothing was left"), "{cleaned}");

        let leaked = Error::BringUp {
            step: Step::InstallingRule,
            cause: "denied".to_owned(),
            left: vec![Residue::Route { prefix: "fd00::/64".to_owned() }],
        };
        assert_eq!(leaked.left_behind().len(), 1);
        let message = leaked.to_string();
        assert!(message.contains("still installed"), "{message}");
        assert!(message.contains("fd00::/64"), "{message}");
    }

    #[test]
    fn a_failure_that_changed_nothing_says_so() {
        let failure = Error::NotUp;
        assert!(failure.left_behind().is_empty());
        assert_eq!(failure.step(), None);
    }
}

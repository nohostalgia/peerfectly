//! The daemon as a Windows service: what it is called, how it registers itself,
//! and how the service control manager starts and stops it.
//!
//! # Why it is a service at all
//!
//! Everything else in this change rests on one property: **the daemon is running
//! before anybody logs in**. That is what makes the control channel's name its
//! own — taking it first would need code running earlier still, which is already
//! privileged — and it is what lets a network the person left up come back after
//! a cold boot on a machine nobody sits at.
//!
//! # Why it registers itself
//!
//! `install` and `uninstall` write and remove the service entry directly, so the
//! whole change works end to end from a build directory before anybody has bought
//! a certificate or chosen an installer.
//!
//! # Two ways to run, neither built on the other
//!
//! Running in the foreground is not a debugging mode of the service and the
//! service is not a wrapper around the foreground. Both do the same three things
//! in the same order — start, wait, stop — and differ only in **what they wait
//! on**: the foreground waits on a message loop and a tray icon, the service
//! waits on the control manager. A daemon that could only be observed through a
//! service control manager is a daemon that cannot be debugged.
//!
//! What decides which is [`Asked`], from the words the process was started with,
//! and the decision is a pure function so it is tested as one.

#![cfg(windows)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceDependency, ServiceErrorControl, ServiceInfo, ServiceStartType,
    ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// The name the service control manager knows it by.
pub const NAME: &str = "peerfectly";

/// The name a person reads in the services list.
pub const DISPLAY: &str = "peerfectly";

/// What that list says it does.
pub const DESCRIPTION: &str = "Carries the networks this machine holds, and answers the peerfectly \
                               command line. Runs with nobody logged in.";

/// The word the control manager starts it with.
///
/// Written into the registered command line by [`install`], so that being a
/// service is something this process is **told**, not something it discovers by
/// trying to be one and seeing whether it works.
pub const AS_A_SERVICE: &str = "--service";

/// What the daemon was asked to do.
///
/// Decided from the words alone, with nothing read and nothing started, so that
/// the decision is a value a test can make and compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked {
    /// Register the service and stop.
    Install,
    /// Remove the service entry and stop.
    Uninstall,
    /// Run under the service control manager.
    Service,
    /// Run here, in this console, until stopped.
    Foreground,
}

impl Asked {
    /// What these words ask for.
    ///
    /// The words are the ones after the program's own, and the order is
    /// deliberate: `install` and `uninstall` do not run the daemon at all, so
    /// they are answered first and a stray [`AS_A_SERVICE`] cannot turn one into
    /// a service that installs itself.
    ///
    /// Anything else is the foreground, because **the foreground is the
    /// default**. A daemon that had to be told to run in front would be a daemon
    /// whose ordinary use was the special case.
    #[must_use]
    pub fn from_words<S: AsRef<str>>(words: impl IntoIterator<Item = S>) -> Self {
        let mut service = false;
        for word in words {
            match word.as_ref() {
                "install" => return Self::Install,
                "uninstall" => return Self::Uninstall,
                AS_A_SERVICE => service = true,
                _ => {}
            }
        }
        if service { Self::Service } else { Self::Foreground }
    }

    /// What this process was started with.
    #[must_use]
    pub fn from_this_process() -> Self {
        Self::from_words(std::env::args().skip(1))
    }
}

/// What went wrong registering or removing the service.
#[derive(Debug)]
pub enum Refusal {
    /// The service control manager would not do it.
    Manager(windows_service::Error),
    /// This program's own path could not be established.
    Whereabouts(std::io::Error),
    /// It is already registered, or already gone.
    Already(String),
    /// Who may start it could not be set.
    Access(String),
}

/// What installing did.
#[derive(Debug)]
pub enum Installed {
    /// Registered, running this program.
    Registered(PathBuf),
    /// Already registered: only who may start it was brought up to date.
    Updated,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Manager(cause) => write!(
                out,
                "the service control manager refused: {cause}. \
                 Registering a service needs an administrator."
            ),
            Self::Whereabouts(cause) => {
                write!(out, "this program's own location could not be established: {cause}")
            }
            Self::Already(what) | Self::Access(what) => write!(out, "{what}"),
        }
    }
}

impl std::error::Error for Refusal {}

/// The services this one cannot work without.
///
/// A network the person left up is brought up at startup, and bringing it up
/// binds a transport and writes a resolution rule. Started before `Tcpip` there
/// is nothing to bind to, and before `Dnscache` the rule has nowhere to go —
/// so the daemon would come up, fail at both, and sit there having reported a
/// fault that was only ever *too early*.
///
/// These are ordering, not a guarantee: the control manager waits for them to
/// have started, not for a network cable to be plugged in. The retrying in
/// `Lifecycle` is what covers the rest, and this is what keeps it from being
/// asked to cover a boot.
pub const NEEDS: &[&str] = &["Tcpip", "Dnscache"];

/// Registers the service, so that it starts with the machine.
///
/// The registered command line carries [`AS_A_SERVICE`] and the arguments this
/// install was given, other than `install` itself — which is how a daemon
/// installed from a build directory stays installed with its override.
///
/// Who may start and stop it is set explicitly, also on a service
/// already registered: installing again is how one registered before that is
/// brought up to date.
///
/// # Errors
///
/// When the control manager refuses, which for an ordinary user it will, or when
/// this program's own path cannot be established.
pub fn install(with: &[String]) -> Result<Installed, Refusal> {
    let program = std::env::current_exe().map_err(Refusal::Whereabouts)?;

    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
            .map_err(Refusal::Manager)?;

    let mut words = vec![OsString::from(AS_A_SERVICE)];
    words.extend(with.iter().map(OsString::from));

    let entry = ServiceInfo {
        name: OsString::from(NAME),
        display_name: OsString::from(DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        // With the machine, not when somebody asks. A service started on demand
        // would come up when the first command arrived, which is after the boot
        // during which the network was supposed to already be there.
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: program.clone(),
        launch_arguments: words,
        dependencies: NEEDS
            .iter()
            .map(|needed| ServiceDependency::Service((*needed).into()))
            .collect(),
        // `LocalSystem`. What this daemon does — create an adapter, write routes,
        // write a resolution rule, open a key the machine holds — is the
        // machine's, and there is no person whose account it could run as with
        // nobody logged in.
        account_name: None,
        account_password: None,
    };

    let service = match manager
        .create_service(&entry, ServiceAccess::CHANGE_CONFIG | ServiceAccess::WRITE_DAC)
    {
        Ok(service) => service,
        // Already registered: who may start it is brought up to date, and nothing
        // else changes — registering a different copy is `uninstall` first.
        Err(windows_service::Error::Winapi(ref io)) if io.raw_os_error() == Some(ALREADY_THERE) => {
            let there =
                manager.open_service(NAME, ServiceAccess::WRITE_DAC).map_err(Refusal::Manager)?;
            crate::platform::protected::protect_service(&there).map_err(Refusal::Access)?;
            return Ok(Installed::Updated);
        }
        Err(other) => return Err(Refusal::Manager(other)),
    };
    service.set_description(DESCRIPTION).map_err(Refusal::Manager)?;
    crate::platform::protected::protect_service(&service).map_err(Refusal::Access)?;

    Ok(Installed::Registered(program))
}

/// Removes the service entry, stopping it first if it is running.
///
/// # Errors
///
/// When the control manager refuses, or when it is not registered.
pub fn uninstall() -> Result<(), Refusal> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(Refusal::Manager)?;

    let wanted = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = manager.open_service(NAME, wanted).map_err(|cause| match cause {
        windows_service::Error::Winapi(ref io) if io.raw_os_error() == Some(NO_SUCH_SERVICE) => {
            Refusal::Already(format!("`{NAME}` is not registered; there is nothing to remove."))
        }
        other => Refusal::Manager(other),
    })?;

    // Stopped first, and **waited for**. A delete while it runs is accepted and
    // deferred until the process exits, which leaves a machine where the service
    // is gone from the list and still holding the adapter.
    let running = service.query_status().map_err(Refusal::Manager)?;
    if running.current_state != ServiceState::Stopped {
        service.stop().map_err(Refusal::Manager)?;
        for _ in 0..STOPS_WITHIN.as_secs() {
            std::thread::sleep(Duration::from_secs(1));
            if matches!(service.query_status(), Ok(now) if now.current_state == ServiceState::Stopped)
            {
                break;
            }
        }
    }

    service.delete().map_err(Refusal::Manager)
}

/// How long a stop is waited for before the entry is removed anyway.
///
/// Taking the network down means removing an adapter, its routes and a
/// resolution rule, and none of that is instant. Waiting for ever would hang a
/// person's console on a service that has wedged.
pub const STOPS_WITHIN: Duration = Duration::from_secs(30);

/// `ERROR_SERVICE_EXISTS`.
const ALREADY_THERE: i32 = 1073;

/// `ERROR_SERVICE_DOES_NOT_EXIST`.
const NO_SUCH_SERVICE: i32 = 1060;

/// `ERROR_ACCESS_DENIED`.
const NOT_ALLOWED: i32 = 5;

/// `ERROR_SERVICE_ALREADY_RUNNING`.
const ALREADY_RUNNING: i32 = 1056;

/// What asking the control manager to start the service came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Starting {
    /// It was asked to start, or was already running.
    Asked,
    /// It is not registered on this machine.
    NotInstalled,
    /// This person may not start it: registered before anyone using the machine
    /// was allowed to, or by a policy of the machine's.
    NotAllowed,
    /// The control manager said something else.
    Failed(String),
}

/// Asks the control manager to start the service, as whoever runs this.
///
/// Starting a running service is answered as already running, so two people's
/// trays starting it at once is harmless.
#[must_use]
pub fn start_it() -> Starting {
    let said = |cause: windows_service::Error| match cause {
        windows_service::Error::Winapi(ref io) => match io.raw_os_error() {
            Some(NO_SUCH_SERVICE) => Starting::NotInstalled,
            Some(NOT_ALLOWED) => Starting::NotAllowed,
            Some(ALREADY_RUNNING) => Starting::Asked,
            _ => Starting::Failed(cause.to_string()),
        },
        other => Starting::Failed(other.to_string()),
    };
    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    {
        Ok(manager) => manager,
        Err(cause) => return said(cause),
    };
    let service = match manager.open_service(NAME, ServiceAccess::START) {
        Ok(service) => service,
        Err(cause) => return said(cause),
    };
    match service.start::<&str>(&[]) {
        Ok(()) => Starting::Asked,
        Err(cause) => said(cause),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The foreground is the default.**
    ///
    /// Nothing said means run here, in this console. A daemon that had to be told
    /// to run in front would be one whose ordinary use was the special case, and
    /// the debugging path is exactly the one that must not need arranging.
    #[test]
    fn nothing_said_is_the_foreground() {
        assert_eq!(Asked::Foreground, Asked::from_words(Vec::<String>::new()));
        assert_eq!(Asked::Foreground, Asked::from_words(["--allow-unsafe-location"]));
    }

    /// Being a service is something it is told, never something it infers.
    #[test]
    fn the_service_is_named() {
        assert_eq!(Asked::Service, Asked::from_words([AS_A_SERVICE]));
        assert_eq!(
            Asked::Service,
            Asked::from_words(["--allow-unsafe-location", AS_A_SERVICE]),
            "and the other words are still there"
        );
    }

    /// Registering is not running.
    ///
    /// The command line an install registers carries [`AS_A_SERVICE`], so an
    /// `install` re-read with that word still present must not become a service
    /// that registers itself on every start.
    #[test]
    fn installing_is_not_a_kind_of_running() {
        assert_eq!(Asked::Install, Asked::from_words(["install"]));
        assert_eq!(Asked::Install, Asked::from_words([AS_A_SERVICE, "install"]));
        assert_eq!(Asked::Uninstall, Asked::from_words(["uninstall"]));
        assert_eq!(Asked::Uninstall, Asked::from_words([AS_A_SERVICE, "uninstall"]));
    }

    /// It waits for what a network needs before it comes up.
    #[test]
    fn it_starts_after_the_network_stack() {
        assert!(NEEDS.contains(&"Tcpip"), "there is nothing to bind to before it");
        assert!(NEEDS.contains(&"Dnscache"), "and nowhere to put a resolution rule");
    }
}

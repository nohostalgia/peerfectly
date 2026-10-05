//! The daemon.
//!
//! Assembles the node, answers the command line over a pipe, and shows a tray
//! icon. Everything it decides lives in the library; this is the shell that
//! starts it, holds it together and stops it.
//!
//! # The shape of the threads
//!
//! The tray icon needs a Win32 message loop on the thread that created it, and an
//! async runtime does not provide one. So the **main thread owns the icon and
//! pumps messages**, the runtime runs on its own threads, and the two speak
//! through the service.
//!
//! Getting this wrong produces an icon that appears and then stops responding —
//! a failure that looks like a hang rather than like a threading mistake, which
//! is why it is written down rather than left to be rediscovered.
//!
//! # Nothing is started here
//!
//! Assembling reads what is on disk and builds objects. It creates no adapter,
//! binds no transport, and sends nothing anywhere. Section 2.6c requires that a
//! daemon whose network is off reach no infrastructure, and a transport bound at
//! startup has already contacted its relay by the time anybody looks.
//!
//! So the adapter and the transport are both brought into being by `up`, and
//! dropped by `down`. Until a person asks, this process is inert.
//!
//! # Two ways to run
//!
//! Under the service control manager, and here in a console. **Neither is built
//! on the other**: both call `start` and then `stop`, and differ only in what
//! they wait on in between — the control manager, or a message loop with a tray
//! icon. What decides which is `service::Asked`, from the words this process was
//! started with, and it is told rather than inferred.

/// Runs the daemon: registers or removes the service, runs as one, or runs here.
pub fn main() -> std::process::ExitCode {
    run()
}

/// What this process was asked to do.
///
/// Registering is answered before either way of running, because registering is
/// not a kind of running: it writes a service entry and stops.
#[cfg(windows)]
fn run() -> std::process::ExitCode {
    use crate::service::Asked;

    match Asked::from_this_process() {
        Asked::Install => install(),
        Asked::Uninstall => uninstall(),
        Asked::Service => as_a_service(),
        Asked::Foreground => in_the_foreground(),
    }
}

/// Registers the service, carrying forward the words this install was given.
///
/// An install run from a build directory with the override keeps it, because
/// otherwise the service would be registered to refuse to start and the person
/// would find out at the next boot rather than now.
#[cfg(windows)]
fn install() -> std::process::ExitCode {
    use std::process::ExitCode;

    let carried: Vec<String> = std::env::args().skip(1).filter(|word| word != "install").collect();

    match crate::service::install(&carried) {
        Ok(crate::service::Installed::Updated) => {
            println!("`{}` was already registered.", crate::service::NAME);
            println!("Who may start it is brought up to date: anyone using this machine may");
            println!("start it, and only an administrator may stop it.");
            println!("To register a different copy, run `peerfectlyd uninstall` first.");
            ExitCode::SUCCESS
        }
        Ok(crate::service::Installed::Registered(program)) => {
            println!("registered `{}`:", crate::service::NAME);
            println!("  {}", program.display());
            if !carried.is_empty() {
                println!("  with: {}", carried.join(" "));
            }
            say_what_the_firewall_did(&program);
            println!();
            println!("It starts with the machine. To start it now, without rebooting:");
            println!("  sc start {}", crate::service::NAME);
            ExitCode::SUCCESS
        }
        Err(cause) => {
            eprintln!("{cause}");
            ExitCode::FAILURE
        }
    }
}

/// Narrows this program's inbound rules to UDP, and says what changed (F-11).
///
/// Windows' own prompt allows a program TCP and UDP on every port, on public
/// networks too. The transport is QUIC over UDP and the control channel is a
/// pipe, so UDP is all this program needs to receive. A failure here does not
/// undo the registration: it is said, with how to try again.
#[cfg(windows)]
fn say_what_the_firewall_did(program: &std::path::Path) {
    match crate::platform::firewall::narrow_program(program) {
        Ok(narrowed) => {
            for name in &narrowed.removed {
                println!("  replaced the firewall rule `{name}` for this program");
            }
            for name in &narrowed.kept {
                println!("  left `{name}` alone: another program's rule has the same name");
            }
            println!(
                "  firewall: `{}` admits UDP to this program, and nothing else",
                crate::platform::firewall::DAEMON_RULE
            );
        }
        Err(cause) => {
            eprintln!("  the firewall rule could not be made: {cause}");
            eprintln!(
                "  the service is registered; run `peerfectlyd install` again to retry the rule"
            );
        }
    }
}

/// Stops the service if it runs, and removes its entry.
///
/// **Nothing on disk is touched.** The networks this machine holds stay where
/// they are, so that removing the service and registering it again from another
/// place is not a way to lose them.
#[cfg(windows)]
fn uninstall() -> std::process::ExitCode {
    use std::process::ExitCode;

    match crate::service::uninstall() {
        Ok(()) => {
            println!("removed `{}`.", crate::service::NAME);
            let removed = std::env::current_exe()
                .map_err(|cause| cause.to_string())
                .and_then(|program| crate::platform::firewall::remove_program_rule(&program));
            match removed {
                Ok(0) => {}
                Ok(_) => println!(
                    "removed the firewall rule `{}`.",
                    crate::platform::firewall::DAEMON_RULE
                ),
                Err(cause) => eprintln!("the firewall rule could not be removed: {cause}"),
            }
            println!("The networks this machine holds are untouched.");
            ExitCode::SUCCESS
        }
        Err(cause) => {
            eprintln!("{cause}");
            ExitCode::FAILURE
        }
    }
}

/// Whether this program may run from where it is, and says why when it may not.
///
/// **Warned every time, not once.** A warning shown on a first start and not
/// afterwards is a warning that stops being read, on exactly the machine where
/// it still applies — and the override exists for a build directory, which is
/// started over and over.
#[cfg(windows)]
fn may_run_from_here() -> bool {
    let who = crate::who_else_can_write_where_this_runs();
    if who.is_empty() {
        return true;
    }

    let allowed = std::env::args().any(|word| word == crate::ALLOW_UNSAFE_LOCATION);
    let here = std::env::current_exe()
        .ok()
        .and_then(|program| program.parent().map(std::path::Path::to_path_buf))
        .unwrap_or_default();

    eprintln!();
    eprintln!("This daemon runs privileged, and {} can write where it is:", who.join(", "));
    eprintln!("  {}", here.display());
    eprintln!();
    eprintln!("Anyone who can write there chooses what runs as the system on this machine.");

    if allowed {
        eprintln!();
        eprintln!("Continuing anyway: {} was given.", crate::ALLOW_UNSAFE_LOCATION);
        return true;
    }
    eprintln!();
    eprintln!("Install it somewhere only administrators can write, or pass");
    eprintln!("  {}", crate::ALLOW_UNSAFE_LOCATION);
    eprintln!("to run from a build directory anyway.");
    false
}

/// Names anything still where a per-person daemon kept its networks.
///
/// Nothing is read, moved or adopted: what is there is sealed to one person and
/// this daemon is not that person. Saying nothing would leave somebody to
/// conclude the product lost their network.
///
/// Silent from the service, and that is correct rather than a gap: `LocalSystem`
/// has its own profile, so the place a person kept theirs is not one it can
/// name. The command line, which runs as the person, is what finds them.
#[cfg(windows)]
fn say_what_was_left_behind() {
    let left = crate::left_where_a_person_kept_them();
    if left.is_empty() {
        return;
    }
    eprintln!();
    eprintln!("These are where a per-person daemon kept its networks, and are not used:");
    for label in &left {
        eprintln!("  {label}");
    }
    eprintln!();
    eprintln!("Nothing there has been changed or removed. Their keys are sealed to one person");
    eprintln!("and this daemon runs as the machine, so they cannot be opened or moved.");
    eprintln!("Found or join each network again; then that folder is yours to remove.");
}

#[cfg(not(windows))]
fn run() -> std::process::ExitCode {
    eprintln!(
        "This daemon binds a Windows adapter, routing table and resolver; it runs on Windows only."
    );
    eprintln!("The rules it enforces are in the library, and their tests run everywhere.");
    std::process::ExitCode::FAILURE
}

/// What a started daemon is: the node, and the flag that ends it.
#[cfg(windows)]
struct Running {
    /// Everything this daemon holds.
    service: std::sync::Arc<daemon::Service>,
    /// Set by whoever decides it is over — the tray, or the control manager.
    stopping: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Everything both ways of running do, before either begins to wait.
///
/// **Shared rather than duplicated**, because a second copy of this is a second
/// place for the order to be wrong — and the order is load-bearing: the location
/// is checked before anything is assembled, and the keys are chosen before the
/// networks are loaded.
#[cfg(windows)]
fn start(runtime: &tokio::runtime::Runtime) -> Result<Running, std::process::ExitCode> {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    if !may_run_from_here() {
        return Err(std::process::ExitCode::FAILURE);
    }

    let service = match runtime.block_on(assemble()) {
        Ok(service) => service,
        Err(cause) => {
            tracing::error!(%cause, "could not start");
            return Err(std::process::ExitCode::FAILURE);
        }
    };

    // A rule from a run that crashed is breaking name resolution for the suffix
    // right now, whether or not this run brings the tunnel up.
    match runtime.block_on(service.sweep()) {
        Ok(true) => tracing::info!("removed a resolution rule left by an earlier run"),
        Ok(false) => {}
        Err(cause) => tracing::warn!(%cause, "could not sweep an earlier run's rule"),
    }

    // A port left open to a network this machine no longer holds (F-11): the
    // rules are the machine's and outlive the network, so they are swept here too.
    match runtime.block_on(service.sweep_exposures()) {
        Ok(0) => {}
        Ok(gone) => tracing::info!(gone, "removed firewall rules for networks no longer held"),
        Err(cause) => tracing::warn!(%cause, "could not sweep the firewall's rules"),
    }

    // Reading the driver's digest is a local file read: no adapter is created, no
    // socket opened, nothing sent anywhere, so §2.6c is untouched. It happens at
    // startup because finding out the driver is missing or unpinned at the moment
    // somebody needs the network is the worst time to find out.
    match crate::platform::driver::verify() {
        Ok(path) => tracing::info!(driver = %path.display(), "the driver is pinned"),
        Err(cause) => {
            tracing::warn!(%cause, "the network will not come up until the driver is sorted out");
        }
    }

    // Back to whatever the person last chose. A daemon that always started down
    // would have overruled someone who left the network on, and they would find
    // out by their machine being unreachable after a reboot.
    match runtime.block_on(service.resume()) {
        Ok(true) => tracing::info!("the networks left on are on again"),
        Ok(false) => {}
        Err(cause) => tracing::warn!(%cause, "a network left on would not come up"),
    }

    let stopping = Arc::new(AtomicBool::new(false));
    runtime.spawn(serve_commands(Arc::clone(&service), Arc::clone(&stopping)));
    // IPv4 routes follow the roster and this machine's networks while it runs:
    // a device admitted gains a host route, and a peer that starts to conflict
    // with the Wi-Fi the laptop just joined loses one.
    runtime.spawn(Arc::clone(&service).reconcile_forever());

    Ok(Running { service, stopping })
}

/// Everything both ways of running do, after either stops waiting.
///
/// The same shutdown whoever asked for it: stopping from the tray, from the
/// command line or from the control manager must not be three paths, two of
/// which leave a route behind.
#[cfg(windows)]
fn stop(runtime: &tokio::runtime::Runtime, running: &Running) -> std::process::ExitCode {
    if let Err(cause) = runtime.block_on(running.service.take_all_down()) {
        eprintln!("{cause}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

/// Runs here, in this console, until a command or Ctrl+C says otherwise.
///
/// **Not a debugging mode.** A daemon observable only through a service control
/// manager is a daemon that cannot be debugged, so this is a way of running in
/// its own right — and it is the default, so that the way somebody reaches for
/// first is the one that needs no arranging.
///
/// It draws nothing. The tray is `peerfectly tray`, in the person's own session,
/// because a service has no desktop to draw on and a menu drawn by a process
/// running as the machine is a menu offering the machine's authority.
#[cfg(windows)]
fn in_the_foreground() -> std::process::ExitCode {
    use std::process::ExitCode;
    use std::sync::atomic::Ordering;

    // The log goes where the person running it is watching.
    if let Err(cause) = crate::log::to_standard_error() {
        eprintln!("the log could not be started: {cause}");
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(cause) => {
            eprintln!("could not start the runtime: {cause}");
            return ExitCode::FAILURE;
        }
    };

    let running = match start(&runtime) {
        Ok(running) => running,
        Err(code) => return code,
    };

    eprintln!();
    eprintln!("Running in the foreground. Ctrl+C stops it, and so does `peerfectly stop`.");
    eprintln!("For the tray icon, run `peerfectly tray` — it is a program of your own now.");

    runtime.block_on(async {
        loop {
            tokio::select! {
                // A console daemon is stopped by the console.
                _ = tokio::signal::ctrl_c() => break,
                () = tokio::time::sleep(LOOKS_AGAIN) => {
                    if running.stopping.load(Ordering::SeqCst)
                        || running.service.is_stopping().await
                    {
                        break;
                    }
                }
            }
        }
    });

    stop(&runtime, &running)
}

/// The callback the control manager bootstraps the service through.
///
/// `define_windows_service!` generates it, and what it generates contains the
/// one `unsafe` block in this file: reading the argument vector the control
/// manager passes as a count and a pointer. **Nothing here is hand-written
/// unsafe** — the allowance is on the macro so that it cannot quietly cover
/// anything else, and `README.md` accounts for this file alongside the modules
/// that really do call the platform.
#[cfg(windows)]
#[allow(unsafe_code)]
mod bootstrap {
    windows_service::define_windows_service!(ffi_begin, begin);

    /// What the control manager calls on its own thread.
    ///
    /// The arguments are the ones the service entry was registered with, which
    /// this process already read from its own command line. They are ignored
    /// here rather than read twice: two readings of the same words are two
    /// places for them to be understood differently.
    fn begin(_words: Vec<std::ffi::OsString>) {
        if let Err(cause) = super::carry_the_service() {
            // Nowhere for this to be seen from a service, and said anyway: a
            // console run is how somebody finds out what a failing start does.
            tracing::error!(%cause, "the service could not be carried");
        }
    }

    /// The callback, by a name outside this module.
    pub(super) const ENTRY: extern "system" fn(u32, *mut *mut u16) = ffi_begin;
}

/// Hands this process to the service control manager.
///
/// It returns when the service has stopped. Reached only when this process was
/// **told** it is a service, so a failure here is a real one rather than the
/// ordinary case of having been started from a console.
#[cfg(windows)]
fn as_a_service() -> std::process::ExitCode {
    use std::process::ExitCode;

    match windows_service::service_dispatcher::start(crate::service::NAME, bootstrap::ENTRY) {
        Ok(()) => ExitCode::SUCCESS,
        Err(cause) => {
            eprintln!("this process was started as a service and is not one: {cause}");
            eprintln!("Run it without `{}` to run it here.", crate::service::AS_A_SERVICE);
            ExitCode::FAILURE
        }
    }
}

/// Runs under the control manager until it says stop, or the daemon does.
///
/// **Both**, and that is the point of the wait below rather than a plain
/// `recv`. A `stop` from the command line ends the daemon, and a service that
/// kept running with nothing left in it would sit there as a process the
/// control manager still calls started.
#[cfg(windows)]
fn carry_the_service() -> Result<(), windows_service::Error> {
    use std::sync::atomic::Ordering;
    use std::sync::mpsc;
    use std::time::Duration;

    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let (asked_to_stop, stop_was_asked) = mpsc::channel();
    let told = service_control_handler::register(crate::service::NAME, move |control| {
        match control {
            // Answered, and nothing more: the control manager is asking whether
            // this process is still there, and the answer is the status it
            // already holds.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            // Shutdown as well as stop. A machine turning off that only handled
            // `Stop` would be killed with its adapter and routes still in place.
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = asked_to_stop.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })?;

    let saying =
        |state: ServiceState, accepting: ServiceControlAccept, within: Duration, how: u32| {
            told.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: accepting,
                // Zero is no error at all, and said as such: a service-specific zero
                // is reported by Windows as 1066, "service-specific error", which
                // any monitoring tool reads as a failure.
                exit_code: if how == 0 {
                    ServiceExitCode::Win32(0)
                } else {
                    ServiceExitCode::ServiceSpecific(how)
                },
                checkpoint: 0,
                wait_hint: within,
                process_id: None,
            })
        };

    // Starting is said before it starts, with how long it may take. Assembling
    // reads every network this machine holds and opens each one's key, and a
    // control manager told nothing assumes a process that has not answered has
    // hung.
    saying(ServiceState::StartPending, ServiceControlAccept::empty(), STARTS_WITHIN, 0)?;

    // First, so that everything after it is recorded. A service has nowhere else
    // to say anything, and a log that cannot be opened is not a reason to leave
    // the machine's networks off.
    let _ = crate::log::to_the_file();

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(cause) => {
            tracing::error!(%cause, "could not start the runtime");
            return saying(ServiceState::Stopped, ServiceControlAccept::empty(), NOW, 1);
        }
    };

    let running = match start(&runtime) {
        Ok(running) => running,
        // It said why on the way out. Reported as stopped with a code rather
        // than left pending, so that `sc start` fails now instead of timing out.
        Err(_) => return saying(ServiceState::Stopped, ServiceControlAccept::empty(), NOW, 1),
    };

    let accepting = ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN;
    saying(ServiceState::Running, accepting, NOW, 0)?;

    while stop_was_asked.recv_timeout(LOOKS_AGAIN).is_err() {
        if running.stopping.load(Ordering::SeqCst)
            || runtime.block_on(running.service.is_stopping())
        {
            break;
        }
    }

    // Taking the network down removes an adapter, its routes and a resolution
    // rule, none of which is instant. Said as pending first, for the same reason
    // starting was.
    saying(ServiceState::StopPending, ServiceControlAccept::empty(), STOPS_WITHIN, 0)?;
    let how = if stop(&runtime, &running) == std::process::ExitCode::SUCCESS { 0 } else { 1 };
    saying(ServiceState::Stopped, ServiceControlAccept::empty(), NOW, how)
}

/// How long the control manager is asked to allow for starting.
#[cfg(windows)]
const STARTS_WITHIN: std::time::Duration = std::time::Duration::from_secs(30);

/// And for stopping. The same wait `peerfectlyd uninstall` gives it.
#[cfg(windows)]
const STOPS_WITHIN: std::time::Duration = crate::service::STOPS_WITHIN;

/// Nothing is pending, so nothing is being waited for.
#[cfg(windows)]
const NOW: std::time::Duration = std::time::Duration::ZERO;

/// How often the daemon is asked whether it stopped itself.
///
/// Only reached while nothing has asked it to stop, so this is idle work: short
/// enough that a `peerfectly stop` does not leave a service claiming to run, long
/// enough not to be a poll worth noticing.
#[cfg(windows)]
const LOOKS_AGAIN: std::time::Duration = std::time::Duration::from_millis(500);

/// Builds the node from what is on disk.
#[cfg(windows)]
async fn assemble() -> daemon::Result<std::sync::Arc<daemon::Service>> {
    use std::sync::Arc;

    use crate::platform::connectivity::Iroh;
    use crate::platform::machine::Windows;
    use crate::platform::resolver::Sockets;
    use daemon::lifecycle::Lifecycle;
    use daemon::{Connectivity, Machine, Resolving, Service};

    let home = crate::home_for_this_machine()?;
    home.create()?;

    // Each network this device holds is assembled from its own directory, with
    // its own identity. No identity is created here: keys belong to a network
    // rather than to the machine, so a daemon that holds nothing holds none, and
    // one is made when a network is founded or joined.
    //
    // A network whose identity will not open, or whose record cannot be read, is
    // reported and stops that network alone. The daemon runs either way: it
    // answers the command line, says what it holds, and waits. Refusing to start
    // is what used to force founding and joining into a separate process, writing
    // a roster behind a daemon that could not see it.
    // **Before the networks are loaded, not after.** Loading one opens its
    // identity, and an identity whose signing key the machine's key store holds
    // cannot be opened without that store: `Service::over` would report every
    // such network as *"this device's identity will not open"*, and a
    // `with_keys` afterwards would be too late to matter. Found by a machine
    // doing exactly that.
    //
    // Where this machine can protect a signing key, that is where a network's
    // key is made and kept. Where it cannot, the daemon runs anyway with the
    // keys it can hold: such a device is a member and not an admin, and what it
    // may not do is refused when a person asks for it, in words, rather than by
    // a daemon that would not start.
    let keys: Arc<dyn daemon::keys::Keys> = match crate::keys::MachineKeys::open() {
        Ok(held) => Arc::new(held),
        Err(cause) => {
            tracing::warn!(
                %cause,
                "this machine cannot hold a protected signing key: it can join a network as \
                 a member, and founding here is refused"
            );
            Arc::new(crate::keys::MemberOnlyKeys::because(cause))
        }
    };

    let service = Service::over_with_keys(
        home,
        Lifecycle::new(Arc::new(Windows::new()) as Arc<dyn Machine>),
        Arc::new(Iroh) as Arc<dyn Connectivity>,
        Arc::new(Sockets) as Arc<dyn Resolving>,
        keys,
    )?
    .with_exposing(
        Arc::new(crate::platform::firewall::Firewall) as Arc<dyn daemon::exposing::Exposing>
    );

    // A network that could not be carried is logged by the daemon, which knows.
    say_what_was_left_behind();

    Ok(Arc::new(service))
}

/// Answers the command line for as long as the daemon runs.
///
/// **One connection is one exchange, and who made it is read off the channel.**
/// Nothing the client sends decides what it may do: a request that named a
/// person would be a request naming who it would like to be.
#[cfg(windows)]
async fn serve_commands(
    service: std::sync::Arc<daemon::Service>,
    stopping: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::Arc;

    use crate::platform::pipe;

    let listener = match pipe::listen() {
        Ok(listener) => listener,
        Err(cause) => {
            tracing::error!(%cause, "the control channel could not be opened");
            stopping.store(true, std::sync::atomic::Ordering::SeqCst);
            return;
        }
    };

    loop {
        let Ok(stream) = listener.accept().await else {
            continue;
        };

        // **One task per connection.** Answered in this loop, a client that
        // connected and said nothing would hold up everybody behind it — and the
        // whole of what it takes to do that is to open a pipe and stop. Nothing
        // that must not overlap is serialised by this loop: enrolment is
        // serialised by `Service::pending`, which is where it belongs, and which
        // `a_second_enrolment_is_refused_while_one_is_pending` holds.
        let served = Arc::clone(&service);
        let ending = Arc::clone(&stopping);
        tokio::spawn(async move {
            if let Err(cause) = serve_one(Arc::clone(&served), stream).await {
                // One client failing is not a reason to stop answering the next.
                tracing::warn!(%cause, "a command could not be answered");
            }
            if served.is_stopping().await {
                ending.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });
    }
}

/// One connection: read what was asked, establish who asked, answer.
///
/// **In that order, and the order is the rule.** Who is calling can only be read
/// off a named pipe once the client's first bytes have arrived — a server that
/// asked before them gets an answer about itself. So the request is read first,
/// and it is read into a value that decides nothing.
///
/// A connection whose caller cannot be established is **refused**, not served.
/// A daemon that could not tell who was asking and answered anyway would be
/// deciding as though nobody were, which is the one caller every network on this
/// machine would let through.
#[cfg(windows)]
async fn serve_one(
    service: std::sync::Arc<daemon::Service>,
    mut stream: crate::platform::pipe::Stream,
) -> std::io::Result<()> {
    use crate::platform::{pipe, who};
    use daemon::control::{Command, Outcome};

    let asked: Command = pipe::read_request_in_time(&mut stream).await?;

    let outcome = match who::the_caller(&stream) {
        Ok(caller) => service.handle_for(&caller, asked).await,
        Err(cause) => Outcome::refused(format!(
            "this machine would not say who is asking, so nothing was decided: {cause}"
        )),
    };

    pipe::write_answer(&mut stream, &outcome).await
}

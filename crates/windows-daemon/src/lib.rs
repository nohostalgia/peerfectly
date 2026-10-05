//! The daemon's Windows edge: the calls that make its decisions real.
//!
//! Every decision is [`daemon`]'s. This crate owns the adapter, the routing
//! table, the registry, the tray and the pipe — and decides nothing. A change
//! that puts policy here has been made wrongly even if it works.
//!
//! # How this platform protects what the daemon stores
//!
//! `daemon` requires that the keys and the roster it keeps be readable only by
//! whoever owns the device, and states that requirement without saying how any
//! platform meets it. Here is how this one does.
//!
//! **The daemon does not set an ACL; it relies on the one it inherits.**
//! `%LOCALAPPDATA%` is inside the user's profile, and a directory created under
//! it inherits that profile's access. Observed on a development machine, a fresh
//! directory there carries exactly:
//!
//! ```text
//! NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
//! BUILTIN\Administrators:(I)(OI)(CI)(F)
//! <machine>\<user>:(I)(OI)(CI)(F)
//! ```
//!
//! — no `Users` and no `Everyone`, which is the access this daemon wants.
//!
//! Setting one instead would mean calling `SetNamedSecurityInfo`, a fourth
//! `unsafe` module for a result the platform already gives; reading one to check
//! would mean parsing localized `icacls` output, the same trade rejected for
//! routes. So this is a **dependency, written down as one**, and the assertion
//! that another user genuinely cannot read it is `VERIFICATION.md` step 9.
//!
//! What it does **not** defend against: a privileged process, a filesystem
//! backup, or a disk pulled from the machine. The roster is not sealed at all,
//! and the identity is sealed with DPAPI — `identity`'s own table says what each
//! of those holds against.
//!
//! # What only a real machine can show
//!
//! Creating the adapter, writing a route, installing the resolution rule. None of
//! it runs without Administrator, and none of it runs in CI. `VERIFICATION.md`
//! records what was checked on a real machine and what was not, and `README.md`
//! carries the table separating the two. Anything only observable on a real
//! machine is stated as unverified rather than left to look tested.

pub mod at_login;
#[cfg(windows)]
pub mod keys;
pub mod log;
pub mod platform;
pub mod programs;
#[cfg(windows)]
pub mod service;

/// The flag that lets the daemon run from somewhere anybody can write.
///
/// For a build directory, which is where it is developed and which every
/// ordinary person can write by construction. Explicit, spelled out, and
/// impossible to pass by accident.
pub const ALLOW_UNSAFE_LOCATION: &str = "--allow-unsafe-location";

/// Who, besides the system and administrators, can write where this program is.
///
/// **A privileged process started from a place an ordinary person can write is
/// a privileged process somebody else chooses the code for.** They replace the
/// executable and wait; nothing about it looks wrong until it is running as the
/// system with their code in it.
///
/// Empty is the only answer a service may start on. What comes back are the
/// accounts as the access control named them, so a refusal can say **who**.
///
/// Empty as well when the program's own location cannot be established or its
/// access control cannot be read — see `platform::writable`, which argues why
/// the unreadable case answers *nobody* rather than stopping every machine.
#[cfg(windows)]
#[must_use]
pub fn who_else_can_write_where_this_runs() -> Vec<String> {
    let Ok(program) = std::env::current_exe() else { return Vec::new() };
    let Some(directory) = program.parent() else { return Vec::new() };
    let Ok(carried) = platform::protected::describe(directory) else { return Vec::new() };
    platform::writable::who_else_can_write(&carried)
}

/// Where this machine keeps the networks it holds.
///
/// **The machine's, not a person's, and that is the whole of this change.** The
/// daemon is a service now: it runs with nobody logged in, because the keys it
/// must reach are the ones that have to work with nobody present — the transport
/// key on every packet, and the attestation key that dates a roster unattended.
/// A place inside somebody's profile cannot be read by something that is not
/// them, and a network whose attestations stop at the logout screen is a network
/// that goes stale for a reason that has nothing to do with its security.
///
/// Which person a network is *for* is not answered by where it is kept. It is
/// recorded in the network itself, and only that person may use it.
///
/// `daemon` does not know and must not: reading `PROGRAMDATA` is one platform's
/// answer to a question every platform answers differently, and a portable half
/// that knew this one would be a portable half with a Windows assumption in it.
/// So the edge names the place and hands it over, which is what
/// [`daemon::networks::Home::under`] is for.
///
/// The directory is created carrying an access control that admits only the
/// system and administrators — see [`platform::protected`], which also explains
/// why it is read back rather than believed.
///
/// # Errors
///
/// When the environment does not say where the machine's own state belongs, or
/// when the directory cannot be made carrying its access control.
#[cfg(windows)]
pub fn home_for_this_machine() -> daemon::Result<daemon::networks::Home> {
    let base = std::env::var_os("PROGRAMDATA").ok_or_else(|| daemon::Error::State {
        path: std::path::PathBuf::from("%PROGRAMDATA%"),
        cause: "the environment does not say where the machine's own state belongs".to_owned(),
    })?;
    home_under(&std::path::PathBuf::from(base))
}

/// The same, under a directory the caller names.
///
/// Separate so that what it does can be tested without the environment being
/// changed underneath a running process — which is unsafe in this edition, and
/// would be a poor reason to open that door in a crate that forbids it.
///
/// # Errors
///
/// When the directory cannot be made carrying its access control.
#[cfg(windows)]
pub fn home_under(base: &std::path::Path) -> daemon::Result<daemon::networks::Home> {
    let root = base.join(daemon::limits::PRODUCT);

    platform::protected::create_protected(&root)
        .map_err(|cause| daemon::Error::State { path: root.clone(), cause })?;

    Ok(daemon::networks::Home::under(root))
}

/// The networks left where a per-person daemon kept them, by the name each was
/// known by.
///
/// **Named so that a person is told, not so that anything is done with them.**
/// What is under there is sealed to one person, and this daemon is no longer
/// that person: it cannot be read, moved or adopted. Saying nothing would leave
/// somebody to conclude the product lost their network.
///
/// # Who actually finds them
///
/// **The command line, running as the person — not the service.** A service runs
/// as `LocalSystem`, whose `%LOCALAPPDATA%` is its own profile under
/// `system32\config`, so the place a person kept their networks is not a place
/// it can even name. Looking for them there would find nothing and report
/// nothing, every time, for ever.
///
/// The daemon run in the foreground *is* the person, so it finds them too. Both
/// use this, and neither touches what it finds.
///
/// Empty when there is nothing there, when the environment does not say where a
/// person's state goes, or when the directory cannot be read — all three are
/// *nothing to tell somebody about*, and none is a fault worth reporting on its
/// own.
#[cfg(windows)]
#[must_use]
pub fn left_where_a_person_kept_them() -> Vec<String> {
    let Ok(home) = where_a_person_kept_them() else { return Vec::new() };
    let Ok(entries) = std::fs::read_dir(home.networks()) else { return Vec::new() };

    let mut found: Vec<String> = entries
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    // Sorted, so what a person is shown does not depend on the order a
    // filesystem happened to hand things back.
    found.sort();
    found
}

/// Where a per-person daemon used to keep them.
///
/// Kept only so that what is there can be **found and refused**: the material
/// under it is sealed to one person and this daemon is no longer that person, so
/// it cannot be read, moved or adopted. Naming it is the difference between a
/// person being told to found again and a person concluding the product lost
/// their network.
///
/// # Errors
///
/// When the environment does not say where per-user state belongs.
#[cfg(windows)]
pub fn where_a_person_kept_them() -> daemon::Result<daemon::networks::Home> {
    let base = std::env::var_os("LOCALAPPDATA").ok_or_else(|| daemon::Error::State {
        path: std::path::PathBuf::from("%LOCALAPPDATA%"),
        cause: "the environment does not say where per-user state belongs".to_owned(),
    })?;
    Ok(daemon::networks::Home::under(std::path::PathBuf::from(base).join(daemon::limits::PRODUCT)))
}

/// The source of a module with its comments and its own tests removed.
///
/// Several tests here assert that something is *absent* from the code. Reading
/// the whole file makes such a test match its own assertion — the string it
/// looks for is written in the line that looks for it — so it passes while the
/// crate is clean and passes just as well when it is not. Cutting at the test
/// module is what makes the check mean anything.
///
/// A copy of [`daemon`]'s, because a test helper cannot cross a crate boundary
/// without being part of what that crate offers, and this one has no business on
/// the portable half's public surface.
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
mod startup {
    /// Starting the daemon reaches nothing, and that is asserted rather than
    /// inherited.
    ///
    /// §2.6c used to hold by construction: a daemon without a tunnel had no
    /// transport and no endpoint, so there was nothing that *could* speak. That
    /// shape is gone — the daemon runs before any network exists and can open an
    /// enrolment endpoint on request — so the guarantee is a rule somebody has to
    /// keep. The two licences to speak are the tunnel being up and a person's
    /// request being in flight; assembly is neither.
    ///
    /// **It lives here because its subject does.** It used to sit in the module
    /// that assembles the service and read across to the binary. The assembly is
    /// now portable and the binary is not, so the scan follows the startup path
    /// rather than the code that used to hold it — and the five names it forbids
    /// were always this half's.
    #[test]
    fn nothing_in_the_startup_path_reaches_infrastructure() {
        let daemon = crate::code_of(include_str!("programs/daemon.rs"));

        for speaking in [
            "IrohTransport::bind",
            "Waiting::listen",
            "Adapter::create()",
            "connectivity.start",
            "Multicast::",
        ] {
            assert!(
                !daemon.contains(speaking),
                "`{speaking}` in the startup path would contact something before a person asked. Starting is not one of the two things that license it."
            );
        }

        // And assembly reads what is on disk, which reaches nothing. Each
        // network's node is built from its own directory inside `Service::over`,
        // so what the startup path names is the survey rather than the log.
        assert!(
            daemon.contains("Service::over"),
            "the daemon assembles from storage, which reaches nothing"
        );
    }

    /// The keys are chosen before the networks are loaded.
    ///
    /// Loading a network opens its identity, and an identity whose signing key
    /// the machine's key store holds cannot be opened without that store. Built
    /// the other way round — `Service::over` and then `with_keys` — every such
    /// network was reported as *"this device's identity will not open"*, with the
    /// key sitting in the store all along.
    ///
    /// Nothing failed: the daemon started, and said something true about a
    /// network it had loaded the only way it knew how. A machine found it.
    #[test]
    fn the_keys_are_chosen_before_the_networks_are_loaded() {
        let daemon = crate::code_of(include_str!("programs/daemon.rs"));

        assert!(
            daemon.contains("Service::over_with_keys"),
            "the keys go in where the networks are built, not after"
        );
        assert!(
            !daemon.contains(".with_keys("),
            "`with_keys` after assembly is too late: the identities are already open or refused"
        );

        let choosing = daemon.find("MachineKeys::open").expect("the keys are chosen");
        let building = daemon.find("Service::over_with_keys").expect("the service is built");
        assert!(choosing < building, "and chosen first");
    }
}

/// Where the machine's state goes, and where it no longer goes.
#[cfg(all(test, windows))]
mod home {
    /// The machine's home is made where it is told, carrying its own protection.
    #[test]
    fn the_machine_makes_its_own_place_protected() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = super::home_under(scratch.path()).expect("makes it");

        assert!(home.root().starts_with(scratch.path()), "{}", home.root().display());
        assert!(home.root().exists(), "and it was made");

        let carried =
            super::platform::protected::describe(home.root()).expect("says what protects it");
        assert!(carried.starts_with("D:P"), "carrying its own access control: {carried}");
    }

    /// **A service has no `LOCALAPPDATA`, and that must not matter.**
    ///
    /// Running with nobody logged in is the case this whole change exists for,
    /// and it is the one a per-person path cannot serve. Asserted on the code
    /// rather than by removing the variable from a running process: the
    /// statement wanted is *never*, under any environment, and a test that
    /// removed it once would only say *not this time*.
    #[test]
    fn the_machines_home_never_consults_a_persons_variable() {
        let source = crate::code_of(include_str!("lib.rs"));
        let machine = source
            .split("pub fn home_for_this_machine()")
            .nth(1)
            .and_then(|rest| rest.split("\n}").next())
            .expect("it is declared");

        assert!(machine.contains("PROGRAMDATA"), "it asks the machine: {machine}");
        assert!(
            !machine.contains("LOCALAPPDATA") && !machine.contains("USERPROFILE"),
            "and never a person: {machine}"
        );
    }

    /// Nothing there is touched, only named.
    ///
    /// The material under it is sealed to one person, so there is nothing a
    /// daemon running as the machine could do with it even if it tried — and
    /// trying is how a half-moved network appears. Asserted on the code, because
    /// a behavioural test can only show that this run left it alone.
    #[test]
    fn nothing_is_done_with_what_a_person_left() {
        let source = crate::code_of(include_str!("lib.rs"));
        let listing = source
            .split("pub fn left_where_a_person_kept_them()")
            .nth(1)
            .and_then(|rest| rest.split("\n}").next())
            .expect("it is declared");

        for doing in ["remove_dir", "rename", "copy", "write", "create_protected", "unseal"] {
            assert!(
                !listing.contains(doing),
                "`{doing}` would do something with what a person left. It is named and left."
            );
        }
        assert!(listing.contains("read_dir"), "it looks, and that is all");
    }

    /// An unreadable or absent old place is nothing to tell somebody about.
    ///
    /// Reported as a fault it would be a permanent warning on every machine that
    /// never had an old network — which is every machine from here on.
    #[test]
    fn no_old_place_is_not_a_fault() {
        let source = crate::code_of(include_str!("lib.rs"));
        let listing = source
            .split("pub fn left_where_a_person_kept_them()")
            .nth(1)
            .and_then(|rest| rest.split("\n}").next())
            .expect("it is declared");

        assert!(
            listing.contains("return Vec::new()"),
            "absence answers with nothing, not with a refusal: {listing}"
        );
        assert!(
            !listing.contains("Err(") || listing.contains("let Ok("),
            "and nothing there is raised as an error"
        );
    }

    /// The old place is still nameable, because what is there must be found and
    /// refused rather than quietly ignored.
    #[test]
    fn where_a_person_kept_them_is_still_nameable() {
        let source = crate::code_of(include_str!("lib.rs"));
        let old = source
            .split("pub fn where_a_person_kept_them()")
            .nth(1)
            .and_then(|rest| rest.split("\n}").next())
            .expect("it is declared");

        assert!(old.contains("LOCALAPPDATA"), "that is where a person kept them: {old}");
        assert!(
            !old.contains("create_protected"),
            "and nothing is made there: it is read to be refused, not to be used"
        );
    }
}

/// Where this program may run from.
#[cfg(all(test, windows))]
mod location {
    /// **The warning is shown every time, not once.**
    ///
    /// A warning that stops after a first start is a warning that stops being
    /// read — and the override exists for a build directory, which is started
    /// over and over. Asserted on the code, because a test that started the
    /// daemon twice would be asserting one run and then another.
    #[test]
    fn the_override_keeps_saying_so() {
        let daemon = crate::code_of(include_str!("programs/daemon.rs"));
        // Cut at the next function's attribute, not at the first closing brace:
        // `code_of` trims every line, so an inner block's brace starts one.
        let deciding = daemon
            .split("fn may_run_from_here()")
            .nth(1)
            .and_then(|rest| rest.split("#[cfg(windows)]").next())
            .expect("it is declared");

        // Nothing that would make the warning conditional on having warned.
        for once in ["Once", "ONCE", "already_warned", "static ", "AtomicBool"] {
            assert!(
                !deciding.contains(once),
                "`{once}` would make this a warning that stops: {deciding}"
            );
        }
        assert!(
            deciding.contains("Continuing anyway"),
            "and taking the override says so rather than passing quietly"
        );
    }

    /// The refusal says **who** can write, not only that somebody can.
    ///
    /// *«Somebody can write here»* leaves a person with nothing to do about it.
    #[test]
    fn the_refusal_names_who() {
        let daemon = crate::code_of(include_str!("programs/daemon.rs"));
        let deciding = daemon
            .split("fn may_run_from_here()")
            .nth(1)
            .and_then(|rest| rest.split("#[cfg(windows)]").next())
            .expect("it is declared");

        assert!(deciding.contains("who.join("), "the accounts are named: {deciding}");
        assert!(deciding.contains("here.display()"), "and so is the directory");
    }

    /// **The check's own answer is the whole of what decides.**
    ///
    /// Found by removing the rule: putting `false &&` in front of the call broke
    /// nothing at all. The guards below say the check is *called* early and that
    /// its refusal reads well, and a call whose answer is thrown away satisfies
    /// both — the daemon would start anywhere, having asked.
    ///
    /// So what is asserted is the condition itself: nothing beside it, and what
    /// follows is leaving rather than a line printed.
    #[test]
    fn the_location_check_is_what_decides() {
        let daemon = crate::code_of(include_str!("programs/daemon.rs"));
        let starting = {
            let at = daemon.find("fn start(runtime:").expect("it is declared");
            let rest = &daemon[at..];
            let end = rest.find("#[cfg(windows)]").unwrap_or(rest.len());
            &rest[..end]
        };

        assert!(
            starting.contains("if !may_run_from_here() {"),
            "the answer is the whole condition, with nothing able to short it: {starting}"
        );
        assert!(
            starting.contains("return Err(std::process::ExitCode::FAILURE);"),
            "and a refusal is leaving, not a line printed on the way past: {starting}"
        );
    }

    /// Nothing runs before the check.
    ///
    /// A daemon that assembled, opened its channel and *then* noticed where it
    /// was would already be answering from a place somebody else chose the code
    /// for.
    #[test]
    fn nothing_starts_before_the_check() {
        let daemon = crate::code_of(include_str!("programs/daemon.rs"));
        let check = daemon.find("may_run_from_here()").expect("it is called");
        let assembling = daemon.find("assemble()").expect("it assembles");
        assert!(check < assembling, "the check comes first");
    }
}

/// Two ways to run, and neither is a mode of the other.
#[cfg(all(test, windows))]
#[allow(clippy::panic, reason = "a test reports failure by panicking")]
mod two_ways {
    /// **Both ways exist, and both are reached from one place.**
    ///
    /// The four things this program can be asked to do are decided once, from the
    /// words it was started with. A second place that decided it — a fallback
    /// that tried to be a service and ran in the foreground when that failed —
    /// would make *which way it is running* something nobody could read off the
    /// command line.
    #[test]
    fn what_it_was_asked_is_decided_in_one_place() {
        let daemon = crate::code_of(include_str!("programs/daemon.rs"));

        for way in [
            "Asked::Install => install()",
            "Asked::Uninstall => uninstall()",
            "Asked::Service => as_a_service()",
            "Asked::Foreground => in_the_foreground()",
        ] {
            assert!(daemon.contains(way), "`{way}` is how it is reached");
        }
        assert_eq!(
            1,
            daemon.matches("Asked::from_this_process()").count(),
            "and the words are read once"
        );
    }

    /// **The foreground is not a special case of the service.**
    ///
    /// A daemon observable only through a service control manager is a daemon
    /// that cannot be debugged, so running in a console is a way of running in
    /// its own right. This fails if it ever becomes a thing the service does with
    /// a flag: the foreground must not touch the dispatcher, and the service must
    /// not touch the tray.
    #[test]
    fn neither_way_is_built_on_the_other() {
        let daemon = crate::code_of(include_str!("programs/daemon.rs"));
        let front = body_of(&daemon, "fn in_the_foreground()");
        let behind = body_of(&daemon, "fn carry_the_service()");

        for manager in ["service_dispatcher", "set_service_status", "ServiceState"] {
            assert!(
                !front.contains(manager),
                "`{manager}` in the foreground would make the console a service that pretends"
            );
        }
        for desk in ["Tray::show", "pump::run_until"] {
            assert!(
                !behind.contains(desk),
                "`{desk}` under the control manager: a service has no desktop to draw on"
            );
        }
    }

    /// **What they share, they share rather than copy.**
    ///
    /// The order inside starting is load-bearing — the location is checked before
    /// anything is assembled, and the keys are chosen before the networks are
    /// loaded — and a second copy of it is a second place for that order to be
    /// wrong. Both ways call the same two functions, and neither assembles for
    /// itself.
    #[test]
    fn both_ways_start_and_stop_through_the_same_two_functions() {
        let daemon = crate::code_of(include_str!("programs/daemon.rs"));
        let front = body_of(&daemon, "fn in_the_foreground()");
        let behind = body_of(&daemon, "fn carry_the_service()");

        for way in [("the foreground", front), ("the service", behind)] {
            let (named, body) = way;
            assert!(body.contains("start(&runtime)"), "{named} starts through `start`");
            assert!(body.contains("stop(&runtime, &running)"), "{named} stops through `stop`");
            assert!(
                !body.contains("assemble()"),
                "{named} does not assemble for itself: that is what `start` is"
            );
        }
    }

    /// Registering is not a kind of running.
    ///
    /// `install` writes a service entry and stops. One that assembled first would
    /// need the machine's networks readable to register a service, and would run
    /// a daemon nobody asked for on the way through.
    #[test]
    fn registering_starts_nothing() {
        let daemon = crate::code_of(include_str!("programs/daemon.rs"));
        let registering = body_of(&daemon, "fn install() -> std::process::ExitCode");

        for running in ["start(&runtime)", "assemble()", "Runtime", "Tray::show"] {
            assert!(!registering.contains(running), "`{running}` is running, and this registers");
        }
    }

    /// One function's own code, and nothing of what follows it.
    ///
    /// Cut at the next `#[cfg(windows)]`, because every item in that file carries
    /// one. Cutting at a closing brace would need it escaped through this file,
    /// and `code_of` trims every line, so the first inner block would end it —
    /// which is how a scan of the whole file comes to pass on a file it never
    /// read past.
    fn body_of<'a>(code: &'a str, from: &str) -> &'a str {
        let at = code.find(from).unwrap_or_else(|| panic!("`{from}` is declared"));
        let rest = &code[at..];
        let end = rest.find("#[cfg(windows)]").unwrap_or(rest.len());
        assert!(end > from.len(), "`{from}` has a body");
        &rest[..end]
    }
}

/// How the daemon answers one connection.
#[cfg(all(test, windows))]
#[allow(clippy::panic, reason = "a test reports failure by panicking")]
mod serving {
    /// **Who is asking comes from the channel, and the command decides nothing
    /// about it.**
    ///
    /// The request is read into a value before anybody is identified, and that
    /// value reaches `handle_for` as *what was asked* and never as *who asked*.
    /// A daemon that took a name out of the request would be taking a name from
    /// whoever wrote the request.
    #[test]
    fn the_caller_is_read_off_the_channel() {
        let daemon = crate::code_of(include_str!("programs/daemon.rs"));
        let one = serving(&daemon);

        assert!(one.contains("who::the_caller(&stream)"), "the channel says who: {one}");
        assert!(
            !one.contains("Caller::Identified"),
            "a caller assembled here would be one this code chose rather than found"
        );
        assert!(
            !one.contains("asked.") && !one.contains("asked,"),
            "and nothing is read out of the request before it is handled: {one}"
        );
    }

    /// **The request is read before the caller, because it has to be.**
    ///
    /// A named pipe says who is on the other end once the client's first bytes
    /// have arrived; asked before them, the server is told about itself. So this
    /// is not a preference about ordering, it is the only order that answers.
    #[test]
    fn what_was_asked_is_read_before_who_asked() {
        let daemon = crate::code_of(include_str!("programs/daemon.rs"));
        let one = serving(&daemon);

        let read = one.find("read_request").expect("it reads the request");
        let whom = one.find("the_caller").expect("it establishes the caller");
        let answered = one.find("handle_for").expect("it answers");
        assert!(read < whom, "the bytes arrive before the channel will say who sent them");
        assert!(whom < answered, "and nothing is decided before that");
    }

    /// A connection nobody can be attributed to is refused, never served.
    ///
    /// Answering it would mean deciding as though nobody were asking, and
    /// *nobody* is the one caller every network on this machine would let
    /// through — an unowned network is opened by an unnamed caller, by the rule
    /// in `Caller::is`.
    #[test]
    fn a_caller_that_cannot_be_established_is_refused() {
        let daemon = crate::code_of(include_str!("programs/daemon.rs"));
        let one = serving(&daemon);

        assert!(one.contains("Outcome::refused"), "it is refused in words: {one}");
        assert!(
            !one.contains("Caller::Unattributed"),
            "falling back to nobody would hand it every network that has no owner"
        );
        assert!(!one.contains("service.handle("), "and `handle` is the unattributed one");
    }

    /// **Each connection is its own task.**
    ///
    /// What holds `bounded::a_silent_client_does_not_stop_the_next_one` to the
    /// daemon: that test builds a loop of this shape and shows that a mute client
    /// blocks nobody, and this says the daemon's loop is that shape. Awaited in
    /// the accept loop instead, one client could hold the queue for as long as it
    /// liked, having sent nothing and holding no privilege at all.
    #[test]
    fn each_connection_is_its_own_task() {
        let daemon = crate::code_of(include_str!("programs/daemon.rs"));
        let loop_of_it = {
            let at = daemon.find("async fn serve_commands").expect("it is declared");
            let rest = &daemon[at..];
            let end = rest.find("async fn serve_one").unwrap_or(rest.len());
            &rest[..end]
        };

        assert!(loop_of_it.contains("tokio::spawn"), "the connection goes to a task: {loop_of_it}");
        assert!(
            !loop_of_it.contains("serve_one(Arc::clone(&service), stream).await"),
            "awaited in the loop, one client holds up everybody behind it"
        );
    }

    /// The code of `serve_one`, and nothing after it.
    fn serving(daemon: &str) -> &str {
        let at = daemon.find("async fn serve_one").expect("it is declared");
        let rest = &daemon[at..];
        let end = rest.find("#[cfg(windows)]").unwrap_or(rest.len());
        &rest[..end]
    }
}

/// Where the tray went, and what it is now.
#[cfg(all(test, windows))]
#[allow(clippy::panic, reason = "a test reports failure by panicking")]
mod the_tray {
    /// **The daemon draws nothing.**
    ///
    /// A service has no desktop, so an icon it created would be one nobody could
    /// see — and a boot with nobody logged in is precisely the case the whole
    /// change is for. A daemon still holding a tray would also be a daemon
    /// offering the machine's authority from a menu next to somebody's clock.
    #[test]
    fn the_daemon_has_no_tray_anywhere_in_it() {
        let daemon = crate::code_of(include_str!("programs/daemon.rs"));

        for drawing in ["Tray::", "tray::", "pump::", "Wish::"] {
            assert!(!daemon.contains(drawing), "`{drawing}` is a desktop the daemon does not have");
        }
    }

    /// **The tray holds no state of its own.**
    ///
    /// What it shows comes from the report and what it does is a `Command`. A
    /// tray that remembered whether the tunnel was up would be a second place the
    /// truth lived — and the one a person is actually looking at, so the one that
    /// would be believed when they disagreed.
    #[test]
    fn the_tray_asks_rather_than_remembers() {
        let client = crate::code_of(include_str!("programs/command_line.rs"));
        let drawing = {
            let at = client.find("fn in_the_tray()").expect("it is declared");
            let rest = &client[at..];
            let end = rest.find("#[cfg(windows)]").unwrap_or(rest.len());
            &rest[..end]
        };

        // Everything it knows, it was told.
        assert!(drawing.contains("what_the_daemon_says()"), "it asks: {drawing}");
        // And everything it does goes the same way as every other command:
        // on the channel, or as `peerfectly stop` run elevated so the daemon decides.
        assert!(drawing.contains("ask_the_daemon(command)"), "it asks for that too");
        assert!(
            drawing.contains("run_elevated(&beside(&program, COMMAND_LINE), \"stop\")"),
            "stopping is `peerfectly stop`, the command line beside the tray"
        );

        for holding in ["daemon::Service", "Node::", "networks::Home", "state::", "identity::"] {
            assert!(
                !drawing.contains(holding),
                "`{holding}` would make the tray a second place the truth lives"
            );
        }
    }

    /// It asks on a timer rather than every turn of the pump.
    ///
    /// The loop spins many times a second, and every ask is a connection. A tray
    /// opening one each time would be a load on the daemon that nobody asked for
    /// — and the daemon serves everyone on that channel.
    #[test]
    fn the_tray_does_not_ask_on_every_turn() {
        let client = crate::code_of(include_str!("programs/command_line.rs"));
        assert!(client.contains("ASKS_EVERY"), "there is an interval");
        assert!(
            client.contains("asked_at.get().elapsed() >= ASKS_EVERY"),
            "and it is what decides whether to ask"
        );
    }
}

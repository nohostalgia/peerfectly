//! The command line on Windows: the named pipe, the machine's key store, and
//! the tray. Everything else — every command, what is signed and how it is
//! checked — is the portable command line in `crates/cli`.

/// Runs the command line: `tray` here, everything else through `crates/cli`.
pub fn main() -> std::process::ExitCode {
    run()
}

/// The portable command line, given the pipe and the key store; the tray is a
/// mode of this program and is answered here first.
#[cfg(windows)]
fn run() -> std::process::ExitCode {
    // The tray is a program of the person's rather than a part of the daemon.
    // **A service has no desktop**, so an icon drawn there would be one nobody
    // could see — and a menu drawn by a process running as the machine. It runs
    // in the person's own session and speaks the same protocol as every other
    // command here. `peerfectly tray` starts it and returns.
    if std::env::args().nth(1).as_deref() == Some("tray") {
        return start_the_tray();
    }
    cli::Cli {
        channel: &Pipe,
        custody: &KeyStore,
        extras: cli::Extras {
            // Started at login by itself; named so a person who closed it can
            // reopen it.
            usage: "  peerfectly tray  (the icon, in your own session; it starts at login)\n",
            privileged: "Administrator",
            after_status: say_what_was_left_behind,
        },
    }
    .run()
}

/// The daemon, over the named pipe.
#[cfg(windows)]
struct Pipe;

#[cfg(windows)]
#[async_trait::async_trait]
impl cli::Channel for Pipe {
    async fn ask(
        &self,
        command: daemon::control::Command,
    ) -> std::io::Result<daemon::control::Outcome> {
        use crate::platform::pipe;

        let mut stream = pipe::connect().await.map_err(|cause| {
            // Access denied here almost always means the daemon is running elevated
            // and this is not. Windows gives an object created by a high-integrity
            // process a high-integrity label, and the default policy forbids a
            // medium-integrity process from writing to it — and connecting to a
            // duplex pipe is a write.
            //
            // Saying so is the difference between a minute and an afternoon.
            let message = if cause.kind() == std::io::ErrorKind::PermissionDenied {
                "the daemon refused this connection. It is most likely running as Administrator while this command is not: Windows will not let a normal process talk to a pipe an elevated one created. Run this from an Administrator console too."
                    .to_owned()
            } else {
                format!("the daemon is not running, or is not reachable: {cause}")
            };
            std::io::Error::new(cause.kind(), message)
        })?;

        pipe::ask(&mut stream, &command).await
    }
}

/// The machine's key store, which asks the person before it protects or uses a key.
#[cfg(windows)]
struct KeyStore;

#[cfg(windows)]
impl cli::Custody for KeyStore {
    /// Makes the signing key the daemon asked for.
    ///
    /// This is where the key store puts its *protect this key* prompt on the screen,
    /// and that prompt is the consent: it is fixed when the key is made, which is why
    /// it names the network rather than an act, and why there is one key per network.
    ///
    /// The key goes into the **machine's** container, not this person's. The daemon
    /// has to be able to open it later to read its public half, and the daemon is a
    /// different account. What that costs is an elevated console, which founding and
    /// joining already needed.
    fn make_key(&self, wanted: &daemon::control::KeyWanted) -> Result<cli::MadeKey, String> {
        use crate::platform::custody::Store;

        let store = Store::open().map_err(|cause| {
            format!("this machine's key store could not be opened, so no key was made: {cause}")
        })?;

        println!();
        if wanted.network.is_empty() {
            println!(
                "Making a signing key for the network being joined in this machine's key store."
            );
        } else {
            println!("Making a signing key for `{}` in this machine's key store.", wanted.network);
        }
        println!("The key store will ask you to protect it. That asking is what guards the key:");
        println!("it happens again every time the key signs, and nothing this program shows");
        println!("stands in for it.");
        println!();

        let public = store.create(&wanted.name, &wanted.network).map_err(|refusal| {
            format!("the key store would not make the key, so nothing was created: {refusal}")
        })?;
        // Never handed back unlocked: the key store asks on every use, and that
        // asking is the protection.
        Ok(cli::MadeKey { public, unlocked: None })
    }

    /// Has the machine's key store sign the batch, which is where it asks the
    /// person.
    ///
    /// The asking is the key's: it was created with a policy that makes CNG require
    /// the person before every use of the private half, so this call is what puts
    /// the prompt on the screen and no prompt of ours stands in for it. What this
    /// adds is said before it: that the dialog is coming, and what it is for —
    /// whatever the dialog itself manages to show.
    fn sign_all(&self, asking: &cli::Asking<'_>) -> Result<Vec<Vec<u8>>, String> {
        use crate::platform::custody::{Store, is_declined};

        let store = Store::open().map_err(|cause| {
            format!("this machine's key store could not be opened, so nothing was signed: {cause}")
        })?;

        println!("Windows will now ask you to confirm. That confirmation is what signs the acts");
        println!("above; refuse it if they are not what you asked for.");

        let mut noted = Vec::new();
        let signed = store.sign_all(asking.key, asking.messages, asking.summary, &mut noted);
        for note in noted {
            eprintln!("(the key store's dialog could not be told everything: {note})");
        }
        signed.map_err(|refusal| {
            if is_declined(&refusal) {
                "not signed. Nothing changed.".to_owned()
            } else {
                format!("the key store would not sign, so nothing changed: {refusal}")
            }
        })
    }
}

/// Sends one command and reads the answer.
#[cfg(windows)]
/// Names anything still where a per-person daemon kept its networks.
///
/// Nothing there is read, moved or adopted. It is sealed to this person and the
/// daemon is the machine now, so the only thing that can be done about it is to
/// found or join again — and the only thing worth doing here is saying so,
/// because silence reads as the product having lost a network.
#[cfg(windows)]
fn say_what_was_left_behind() {
    let left = crate::left_where_a_person_kept_them();
    if left.is_empty() {
        return;
    }
    println!();
    println!("You have networks where they used to be kept, and they are not in use:");
    for label in &left {
        println!("  {label}");
    }
    println!();
    println!("Nothing there has been changed or removed, and nothing can open it: those keys");
    println!("are sealed to you and the daemon runs as the machine. Found or join each one");
    println!("again, and then that folder is yours to remove.");
}

/// The tray program's file name, beside the command line.
pub const TRAY: &str = "peerfectly-tray.exe";

/// The command line's file name, beside the tray.
pub const COMMAND_LINE: &str = "peerfectly.exe";

/// The program called `name` in the same folder as `program`.
///
/// The three programs are installed together, and each finds the others there
/// rather than on the `PATH`, which a person can change.
#[must_use]
pub fn beside(program: &std::path::Path, name: &str) -> std::path::PathBuf {
    program.with_file_name(name)
}

/// The tray, as `peerfectly-tray.exe` runs it: the icon, until the person quits.
#[cfg(windows)]
#[must_use]
pub fn tray() -> std::process::ExitCode {
    in_the_tray()
}

/// `peerfectly tray`: starts the tray program beside this one, and returns.
///
/// The tray is a desktop program, so it takes no console and the one this ran
/// in is free at once. What it inherits is nothing: its standard streams are
/// closed, since there is no console for them.
#[cfg(windows)]
fn start_the_tray() -> std::process::ExitCode {
    use std::process::{Command, ExitCode, Stdio};

    let tray = std::env::current_exe().map(|program| beside(&program, TRAY));
    let started = tray.as_ref().map_err(ToString::to_string).and_then(|tray| {
        Command::new(tray)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|cause| format!("{}: {cause}", tray.display()))
    });
    match started {
        Ok(_tray) => ExitCode::SUCCESS,
        Err(cause) => {
            eprintln!("the tray could not be started: {cause}");
            eprintln!("It is {TRAY}, installed beside {COMMAND_LINE}.");
            ExitCode::FAILURE
        }
    }
}

/// Draws the tray icon until the person quits.
///
/// **It holds no state.** What it shows is read off the daemon's report and what
/// it does is a `Command` on the channel — the same two things every other mode
/// of this program does. A tray that remembered whether a network was up would
/// be a second place the truth lived, and the one a person is looking at.
///
/// **It outlives the daemon.** When the daemon stops answering, the tray shows
/// it stopped and offers to start it, rather than disappearing: an icon that
/// vanishes is how a person learns nothing.
#[cfg(windows)]
fn in_the_tray() -> std::process::ExitCode {
    use std::process::ExitCode;

    use crate::at_login::AtLogin;
    use crate::platform::{desktop, pump, tray};

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(cause) => {
            desktop::tell(&format!("The peerfectly icon could not start: {cause}"));
            return ExitCode::FAILURE;
        }
    };
    let program = std::env::current_exe().unwrap_or_default();

    // Before the menu exists, so that it is drawn dark from the start.
    let _ = desktop::prefer_dark_menus();

    let at_login = AtLogin::for_this_person();
    let starts_at_login = at_login.on_start(&program).unwrap_or(false);

    // A tray opened while the daemon is stopped starts it, where this person may.
    let offers = match runtime.block_on(what_the_daemon_says()) {
        Some(report) => tray::Offers::from(&report),
        None => started_and_asked(&runtime),
    };

    let icon = match tray::Tray::show(&offers, starts_at_login) {
        Ok(icon) => std::cell::RefCell::new(icon),
        Err(cause) => {
            // Here this *is* a fault: the icon is the whole of what this program does.
            desktop::tell(&format!("The peerfectly icon could not be shown: {cause}"));
            return ExitCode::FAILURE;
        }
    };

    let offers = std::cell::RefCell::new(offers);
    let over = std::cell::Cell::new(false);
    let asked_at = std::cell::Cell::new(std::time::Instant::now());

    pump::run_until(|| {
        let wished = icon.borrow().wish();
        if let Some(wish) = wished {
            let sent = tray::sends(&wish, &offers.borrow());
            match sent {
                tray::Sends::Commands(commands) => {
                    for command in commands {
                        let _ = runtime.block_on(ask_the_daemon(command));
                    }
                }
                // The machine's act, so the daemon's own check decides, as an
                // administrator who said yes to Windows' prompt.
                tray::Sends::ElevatedStop => {
                    let _ = desktop::run_elevated(&beside(&program, COMMAND_LINE), "stop");
                }
                tray::Sends::StartTheService => {
                    *offers.borrow_mut() = started_and_asked(&runtime);
                }
                tray::Sends::AtLogin(on) => {
                    if at_login.set(on, &program).is_err() {
                        icon.borrow().starts_at_login(at_login.is_on());
                    }
                }
            }
            if wish == tray::Wish::Quit {
                over.set(true);
            }
            // Asked again now, so the menu says what the click did.
            asked_at.set(
                std::time::Instant::now()
                    .checked_sub(ASKS_EVERY)
                    .unwrap_or_else(std::time::Instant::now),
            );
        }

        // **Not every turn of the pump.** The loop spins many times a second and
        // each ask is a connection; a tray that opened one each time would be a
        // load on the daemon that nothing asked for.
        if asked_at.get().elapsed() >= ASKS_EVERY {
            asked_at.set(std::time::Instant::now());
            let said = match runtime.block_on(what_the_daemon_says()) {
                Some(report) => tray::Offers::from(&report),
                // Keep saying why it is stopped, once that is known.
                None => tray::Offers::stopped(offers.borrow().why.clone()),
            };
            *offers.borrow_mut() = said;
        }

        icon.borrow_mut().showing(&offers.borrow());
        over.get()
    });

    ExitCode::SUCCESS
}

/// Asks the control manager to start the service, waits for the daemon to
/// answer, and says what it holds — or why it is stopped.
///
/// Messages are pumped while waiting, so the icon does not stop responding.
#[cfg(windows)]
fn started_and_asked(runtime: &tokio::runtime::Runtime) -> crate::platform::tray::Offers {
    use crate::platform::{pump, tray};
    use crate::service::Starting;

    let why = match crate::service::start_it() {
        Starting::Asked => None,
        Starting::NotInstalled => {
            Some("it is not installed: run `peerfectlyd install` as an administrator".to_owned())
        }
        Starting::NotAllowed => Some(
            "it may not be started from here: run `peerfectlyd install` again as an administrator"
                .to_owned(),
        ),
        Starting::Failed(cause) => Some(format!("it would not start: {cause}")),
    };
    if why.is_some() {
        return tray::Offers::stopped(why);
    }

    let began = std::time::Instant::now();
    while began.elapsed() < STARTS_WITHIN {
        if let Some(report) = runtime.block_on(what_the_daemon_says()) {
            return tray::Offers::from(&report);
        }
        let _ = pump::drain();
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    tray::Offers::stopped(Some("it was started and has not answered yet".to_owned()))
}

/// How long the tray waits for a service it started to answer.
#[cfg(windows)]
const STARTS_WITHIN: std::time::Duration = std::time::Duration::from_secs(10);

/// How often the tray asks the daemon what it holds.
#[cfg(windows)]
const ASKS_EVERY: std::time::Duration = std::time::Duration::from_secs(2);

/// What the daemon says it holds, or nothing if it will not answer.
#[cfg(windows)]
async fn what_the_daemon_says() -> Option<daemon::control::Report> {
    match ask_the_daemon(daemon::control::Command::Status).await {
        Ok(daemon::control::Outcome::Reported(report)) => Some(report),
        _ => None,
    }
}

/// Asks the daemon one thing, and says nothing about how it went.
///
/// For the tray, which has nowhere to print and no person watching a console.
#[cfg(windows)]
async fn ask_the_daemon(
    command: daemon::control::Command,
) -> std::io::Result<daemon::control::Outcome> {
    use crate::platform::pipe;

    let mut stream = pipe::connect().await?;
    pipe::ask(&mut stream, &command).await
}

#[cfg(not(windows))]
fn run() -> std::process::ExitCode {
    eprintln!(
        "This daemon binds a Windows adapter, routing table and resolver; it runs on Windows only."
    );
    eprintln!("The rules it enforces are in the library, and their tests run everywhere.");
    std::process::ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{COMMAND_LINE, TRAY, beside};

    /// The three programs are installed together, and find each other in the
    /// folder they share rather than on the `PATH`.
    #[test]
    fn the_tray_and_the_command_line_find_each_other_beside_themselves() {
        let tray = Path::new(r"C:\Program Files\peerfectly\peerfectly-tray.exe");
        let command_line = Path::new(r"C:\Program Files\peerfectly\peerfectly.exe");
        assert_eq!(command_line, beside(tray, COMMAND_LINE));
        assert_eq!(tray, beside(command_line, TRAY));
    }

    /// **Stopping from the tray runs the command line, elevated**, not the
    /// tray: the tray elevated would only draw a second icon, as an
    /// administrator, and stop nothing.
    #[test]
    fn stopping_from_the_tray_runs_the_command_line() {
        let code = crate::code_of(include_str!("command_line.rs"));
        assert!(
            code.contains(r#"desktop::run_elevated(&beside(&program, COMMAND_LINE), "stop")"#),
            "the elevated stop names {COMMAND_LINE}"
        );
        assert!(!code.contains(r#"run_elevated(&program, "stop")"#), "and never the tray itself");
    }
}

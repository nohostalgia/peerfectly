//! The daemon, on Linux.
//!
//! Assembles the node, answers the command line over the control socket, and
//! stops cleanly on a signal. Everything it decides lives in `daemon`; this is
//! the shell that starts it, holds it together and stops it.
//!
//! # Nothing is started here
//!
//! Assembling reads what is on disk and builds objects. It creates no
//! interface, binds no transport, and sends nothing anywhere: a daemon whose
//! networks are off reaches no infrastructure (§2.6c). The one thing written at
//! start is the firewall table, which judges nothing until an interface exists.
//!
//! # One way to run
//!
//! In the foreground, always. Under systemd that is what a service is; by hand
//! it is the same process, and there is nothing to register.

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use daemon::control::{Command, Outcome};

/// How often the wait loop looks at whether the daemon was asked to stop.
const LOOKS_AGAIN: Duration = Duration::from_millis(500);

/// Runs the daemon until it is stopped.
#[must_use]
pub fn main() -> ExitCode {
    crate::quiet::before_any_thread();
    if let Err(cause) = crate::log::to_standard_error() {
        eprintln!("the log could not be started: {cause}");
    }
    if !may_run_from_here() {
        return ExitCode::FAILURE;
    }
    // Held until `main` returns, which is how long this is the only daemon.
    let _only = match crate::socket::only_one() {
        Ok(held) => held,
        Err(cause) => {
            tracing::error!(%cause, "not starting");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(cause) => {
            tracing::error!(%cause, "could not start the runtime");
            return ExitCode::FAILURE;
        }
    };

    let service = match runtime.block_on(start()) {
        Ok(service) => service,
        Err(cause) => {
            tracing::error!(%cause, "could not start");
            return ExitCode::FAILURE;
        }
    };

    let stopping = Arc::new(AtomicBool::new(false));
    runtime.spawn(serve_commands(Arc::clone(&service), Arc::clone(&stopping)));
    runtime.spawn(Arc::clone(&service).reconcile_forever());
    tracing::info!("running");

    runtime.block_on(wait(&service, &stopping));

    // `take_all_down` says it is stopping and that it has stopped.
    match runtime.block_on(service.take_all_down()) {
        Ok(_) => ExitCode::SUCCESS,
        Err(cause) => {
            tracing::error!(%cause, "a network did not come down cleanly");
            ExitCode::FAILURE
        }
    }
}

/// Waits for a signal, or for `peerfectly stop`.
async fn wait(service: &Arc<daemon::Service>, stopping: &AtomicBool) {
    use tokio::signal::unix::{SignalKind, signal};

    let (Ok(mut terminate), Ok(mut interrupt)) =
        (signal(SignalKind::terminate()), signal(SignalKind::interrupt()))
    else {
        tracing::error!("the signals that stop the daemon cannot be listened for");
        return;
    };
    loop {
        tokio::select! {
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            () = tokio::time::sleep(LOOKS_AGAIN) => {
                if stopping.load(Ordering::SeqCst) || service.is_stopping().await {
                    break;
                }
            }
        }
    }
}

/// Whether this program may run from where it is, and says why when it may
/// not. **Warned every time**: a warning shown once stops being read, on
/// exactly the machine where it still applies.
fn may_run_from_here() -> bool {
    let who = crate::home::who_else_can_write_where_this_runs();
    if who.is_empty() {
        return true;
    }
    let allowed = std::env::args().any(|word| word == crate::ALLOW_UNSAFE_LOCATION);
    eprintln!();
    eprintln!("This daemon runs as root, and somebody else can write where it is:");
    for line in &who {
        eprintln!("  {line}");
    }
    eprintln!();
    eprintln!("Anyone who can write there chooses what runs as root on this machine.");
    if allowed {
        eprintln!();
        eprintln!("Continuing anyway: {} was given.", crate::ALLOW_UNSAFE_LOCATION);
        return true;
    }
    eprintln!();
    eprintln!("Install it somewhere only root can write, such as /usr/local/bin, or pass");
    eprintln!("  {}", crate::ALLOW_UNSAFE_LOCATION);
    eprintln!("to run from a build directory anyway.");
    false
}

/// Assembles the service, writes the firewall table, and brings back what was
/// left on.
async fn start() -> daemon::Result<Arc<daemon::Service>> {
    use daemon::connectivity::Iroh;
    use daemon::lifecycle::Lifecycle;
    use daemon::resolving::sockets::Sockets;
    use daemon::{Connectivity, Machine, Resolving, Service};

    let home = crate::home::home_for_this_machine()?;
    home.create()?;
    let keys = crate::custody::keys::LinuxKeys::open(home.root())?;
    let firewall = crate::firewall::Nftables::under(home.root());

    let service = Arc::new(
        Service::over_with_keys(
            home,
            Lifecycle::new(
                Arc::new(crate::machine::Linux::new(firewall.clone())) as Arc<dyn Machine>
            ),
            Arc::new(Iroh) as Arc<dyn Connectivity>,
            Arc::new(Sockets) as Arc<dyn Resolving>,
            Arc::new(keys),
        )?
        .with_exposing(Arc::new(firewall.clone()) as Arc<dyn daemon::exposing::Exposing>),
    );

    // **Before anything comes up.** Every bring-up writes it again, and refuses
    // when it cannot; this is so the table is there, and current, from the
    // first moment.
    match tokio::task::spawn_blocking(move || firewall.ensure()).await {
        Ok(Ok(())) => tracing::info!("the firewall table is in place"),
        Ok(Err(cause)) => {
            tracing::error!(%cause, "the firewall table could not be written: no network will come up");
        }
        Err(cause) => tracing::error!(%cause, "the firewall table could not be written"),
    }

    match service.sweep_exposures().await {
        Ok(0) => {}
        Ok(gone) => tracing::info!(gone, "removed firewall rules for networks no longer held"),
        Err(cause) => tracing::warn!(%cause, "could not sweep the firewall's rules"),
    }
    match service.resume().await {
        Ok(true) => tracing::info!("the networks left on are on again"),
        Ok(false) => {}
        Err(cause) => tracing::warn!(%cause, "a network left on would not come up"),
    }
    Ok(service)
}

/// Answers the command line, one task per connection.
async fn serve_commands(service: Arc<daemon::Service>, stopping: Arc<AtomicBool>) {
    let listener = match crate::socket::listen() {
        Ok(listener) => listener,
        Err(cause) => {
            tracing::error!(%cause, "the control channel could not be opened");
            stopping.store(true, Ordering::SeqCst);
            return;
        }
    };
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let served = Arc::clone(&service);
        let ending = Arc::clone(&stopping);
        tokio::spawn(async move {
            if let Err(cause) = serve_one(Arc::clone(&served), stream).await {
                tracing::warn!(%cause, "a command could not be answered");
            }
            if served.is_stopping().await {
                ending.store(true, Ordering::SeqCst);
            }
        });
    }
}

/// One request, who asked it, and the answer.
async fn serve_one(
    service: Arc<daemon::Service>,
    mut stream: tokio::net::UnixStream,
) -> std::io::Result<()> {
    use daemon::control::framing;

    let asked: Command = framing::read_request_in_time(&mut stream).await?;
    let outcome = match crate::who::the_caller(&stream) {
        Ok(caller) => service.handle_for(&caller, asked).await,
        Err(cause) => Outcome::refused(format!(
            "this machine would not say who is asking, so nothing was decided: {cause}"
        )),
    };
    framing::write_answer(&mut stream, &outcome).await
}

#[cfg(test)]
mod tests {
    /// Nothing here starts a transport or an interface: §2.6c.
    #[test]
    fn nothing_in_the_startup_path_reaches_infrastructure() {
        let code: String = include_str!("daemon.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for speaking in [
            "IrohTransport::bind",
            "Waiting::listen",
            "Tun::open",
            "connectivity.start",
            "Multicast::",
        ] {
            assert!(
                !code.contains(speaking),
                "`{speaking}` in the startup path would reach something"
            );
        }
        assert!(
            code.find("firewall.ensure()") < code.find("service.resume()"),
            "the table before anything comes up"
        );
    }
}

//! The daemon, on whichever platform this is built for.
//!
//! Nothing here: the body is the platform's, in its own crate. See this crate's
//! manifest for why the name lives apart from it.

fn main() -> std::process::ExitCode {
    #[cfg(windows)]
    return windows_daemon::programs::daemon::main();

    #[cfg(target_os = "linux")]
    return linux_daemon::programs::daemon::main();

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        eprintln!("peerfectlyd has no body for this platform.");
        std::process::ExitCode::FAILURE
    }
}

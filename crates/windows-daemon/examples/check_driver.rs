//! Asks the daemon's own driver check about a file, for the package build.
//!
//! ```text
//! cargo run --release -p windows-daemon --example check_driver -- path\to\wintun.dll
//! ```
//!
//! `deploy/windows/package.ps1` runs this on the `wintun.dll` it is about to
//! pack. The answer is the one the installed daemon will give before loading
//! the file — the same function, the same pins, the same signature check — so a
//! package can never carry a driver its own daemon refuses. A second list of
//! digests, kept in the build script, could drift from `PINNED`; this cannot.
//!
//! Exits 0 when the driver would be loaded, 1 with the reason when it would
//! not, and 2 when no path was given.

#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use std::process::ExitCode;

    use windows_daemon::platform::driver::{PINNED, checked};

    let Some(path) = std::env::args_os().nth(1) else {
        eprintln!("usage: check_driver <path to wintun.dll>");
        return ExitCode::from(2);
    };
    match checked(std::path::Path::new(&path), PINNED) {
        Ok(_held) => {
            println!("{}: pinned, and its signature is valid", path.to_string_lossy());
            ExitCode::SUCCESS
        }
        Err(refused) => {
            eprintln!("{refused}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() {}

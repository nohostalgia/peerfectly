//! The tray icon, as a program of its own.
//!
//! A desktop program, not a console one: Windows gives a console program a
//! console window whenever it starts without one — from the Start menu, at
//! login — and a console that started it waits for it. This one has neither.
//! The body is the tray `peerfectly tray` always ran; `peerfectly tray` now starts this.

#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() -> std::process::ExitCode {
    #[cfg(windows)]
    return windows_daemon::programs::command_line::tray();

    #[cfg(not(windows))]
    {
        eprintln!("peerfectly-tray is the Windows notification-area icon; there is none here.");
        std::process::ExitCode::FAILURE
    }
}

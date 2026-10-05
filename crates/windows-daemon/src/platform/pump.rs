//! The Win32 message loop the tray icon needs.
//!
//! A tray icon on Windows is a window, and a window without a thread pumping its
//! messages stops responding — the icon stays on screen and its menu never
//! opens, which reads to a person as the daemon having hung rather than as a
//! threading mistake.
//!
//! `tray-icon` requires a Win32 event loop on the thread that created the icon.
//! There are two ways to have one:
//!
//! - **`winit`**, which wraps the loop safely and brings a windowing toolkit,
//!   its rendering backends and their transitive tree into a process that runs as
//!   Administrator.
//! - **These three calls.**
//!
//! The same reasoning that rejected shelling out to `netsh` applies in reverse
//! here: what matters is the surface, not the count of `unsafe` keywords. Three
//! documented Win32 calls are a smaller thing to review — and a smaller thing to
//! run elevated — than a windowing toolkit imported for an icon.
//!
//! # What is not tested here
//!
//! A message loop needs a message queue and a desktop session. `VERIFICATION.md`
//! records that the icon responded on a real machine; nothing here is covered by
//! the automated suite.

#![allow(
    unsafe_code,
    reason = "a Win32 message loop has no safe wrapper outside a windowing toolkit; the unsafe \
              surface is three calls, and none of them touches this daemon's own state"
)]

use core::mem;
use core::time::Duration;

use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, MSG, PM_REMOVE, PeekMessageW, TranslateMessage,
};

/// How long to wait when the queue is empty.
///
/// The loop polls rather than blocking in `GetMessage`, so the caller's stop
/// condition is checked on a bounded delay without another thread having to post
/// a message to wake it. Short enough that quitting feels immediate.
const IDLE: Duration = Duration::from_millis(50);

/// Delivers pending window messages once.
///
/// Returns how many were handled, so a caller can tell a busy loop from an idle
/// one.
pub fn drain() -> usize {
    let mut handled = 0usize;

    loop {
        // SAFETY: `message` is a valid, writable allocation of exactly `MSG`,
        // which is a plain-old-data structure for which an all-zero bit pattern
        // is valid. A null window handle asks for messages belonging to any
        // window on this thread, which is what a tray icon's messages are.
        let mut message: MSG = unsafe { mem::zeroed() };
        let present =
            unsafe { PeekMessageW(&raw mut message, core::ptr::null_mut(), 0, 0, PM_REMOVE) };

        if present == 0 {
            return handled;
        }

        // SAFETY: `message` was filled in by the call above and is not read
        // after being dispatched.
        unsafe {
            TranslateMessage(&raw const message);
            DispatchMessageW(&raw const message);
        }
        handled = handled.saturating_add(1);
    }
}

/// Pumps messages until the caller says to stop.
///
/// Blocking, and meant for the thread that owns the tray icon. Everything else
/// in this daemon runs on the async runtime's own threads.
pub fn run_until(stop: impl Fn() -> bool) {
    while !stop() {
        if drain() == 0 {
            std::thread::sleep(IDLE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Draining an empty queue is not an error and does not block. This is the
    /// one thing about the loop that can be checked without a desktop session.
    #[test]
    fn draining_an_empty_queue_returns() {
        let handled = drain();
        assert!(handled < 10_000, "a test thread has no flood of window messages");
    }

    #[test]
    fn a_stop_condition_that_is_already_true_pumps_nothing() {
        run_until(|| true);
    }

    /// Nothing about the daemon's state is reachable from here. A message loop
    /// that could change the tunnel would be a second way to change it, on a
    /// thread with different rules.
    #[test]
    fn the_pump_touches_no_daemon_state() {
        let code = crate::code_of(include_str!("pump.rs"));
        for forbidden in ["Node", "Lifecycle", "RosterState", "Machine", "Tunnel"] {
            assert!(!code.contains(forbidden), "`{forbidden}` has no business in a message loop");
        }
    }
}

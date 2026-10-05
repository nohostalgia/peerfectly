//! The TSS library, kept off the terminal.
//!
//! `libtss2` writes its own warnings and errors to standard error — a wrong
//! passphrase arrives as three lines about `Esys_Sign_Finish` before this
//! program has said, in words, that the passphrase was wrong. The spec asks for
//! the second and not the first: a wrong passphrase is an ordinary outcome, and
//! a person shown a library's error codes reads it as a failure.
//!
//! The library reads `TSS2_LOG` when it is first used, and nothing else
//! configures it. So each program sets it, first thing.
//!
//! # Why this is `unsafe`
//!
//! Setting the environment is `unsafe` in this edition, because another thread
//! reading it at the same moment is undefined behaviour. [`before_any_thread`]
//! is called as the first statement of each program's `main`, before a runtime
//! or any thread exists, so there is nobody to race.

#![allow(
    unsafe_code,
    reason = "setting TSS2_LOG needs `set_var`, which is unsafe in this edition; it is called \
              before any thread exists"
)]

/// Silences the TSS library's own logging. Call it first in `main`, and
/// nowhere else.
pub fn before_any_thread() {
    // SAFETY: called as the first statement of `main`, before any runtime,
    // thread or library that could read the environment has been started.
    unsafe { std::env::set_var("TSS2_LOG", "all+NONE") };
}

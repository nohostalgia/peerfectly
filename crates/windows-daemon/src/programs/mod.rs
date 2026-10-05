//! The two programs, as the `programs` crate starts them on Windows.
//!
//! They were binaries of this crate, and moved here unchanged when Linux gained
//! programs of the same names: two packages in one workspace cannot both build a
//! `peerfectlyd`, so one crate owns the names and each platform owns the bodies.

pub mod command_line;
pub mod daemon;

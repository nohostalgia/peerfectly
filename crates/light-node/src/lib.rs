//! A light member's protocol, with no input or output of its own.
//!
//! A light member holds no roster: one root, its own leaf and proof, and the
//! leaves of the full members it keeps (`roster::member::LightMember`). What
//! it asks of them, of whom, and what it believes of an answer is decided here,
//! from what is handed in, so that the daemon, the simulator and a
//! microcontroller's firmware run the same rules. Sockets, tasks and files are
//! theirs.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod channel;
pub mod engine;
pub mod lookup;
pub mod member;
pub mod provision;
pub mod seeking;
pub mod sessions;

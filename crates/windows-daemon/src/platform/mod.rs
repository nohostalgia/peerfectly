//! The Windows edge.
//!
//! Everything here makes a decision real and makes none. Which routes should
//! exist, what a name resolves to, when to sync — all of that is decided in the
//! portable core and can be tested on any machine. This half calls the platform.
//!
//! The reason for the line is that nothing in this module can run in CI. It needs
//! Administrator, a driver, and a real network stack. Anything that decided
//! something here would be a decision no test could reach — and the decisions in
//! question include whether a default route can ever be installed.

pub mod adapter;
pub mod connectivity;
pub mod custody;
pub mod desktop;
pub mod driver;
pub mod firewall;
pub mod machine;
pub mod nrpt;
pub mod pipe;
pub mod protected;
pub mod pump;
pub mod resolver;
pub mod route_table;
pub mod tray;
pub mod who;
pub mod writable;

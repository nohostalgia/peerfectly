//! The convesso binding: the transport interface over convesso. The daemon and
//! the Android core run their sessions on it.

pub mod enrolment;
pub mod error;
pub mod frame;
pub mod members;
pub mod node;
pub mod relay;
pub mod session;

pub use error::{BuildError, Result};
pub use node::ConvessoTransport;

#[cfg(feature = "fixture")]
pub mod fixture;

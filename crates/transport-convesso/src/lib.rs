//! The convesso binding: the transport interface over convesso.
//!
//! **A local experiment.** It depends on convesso by path, outside this
//! repository, and lives on a branch that is not merged. On that branch the
//! daemon and the Android core run on it, in place of `transport-iroh`.

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

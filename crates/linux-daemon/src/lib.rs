//! The daemon's Linux edge: the calls that make its decisions real.
//!
//! Every decision is [`daemon`]'s, as on Windows. This crate owns the packet
//! device, the netlink calls, systemd-resolved, the firewall table, the control
//! socket and the key store — and decides nothing.
//!
//! What calls the kernel or the TPM only compiles on Linux. What is a pure
//! function — an interface's name, the arguments a tool is given, the ruleset's
//! text, who a caller is from what the kernel said — compiles and is tested
//! everywhere, so the Windows suite runs it too.

/// The flag that lets the daemon run from somewhere an ordinary account can
/// write — a build directory. The same word as on Windows, explicit and
/// impossible to pass by accident.
pub const ALLOW_UNSAFE_LOCATION: &str = "--allow-unsafe-location";

pub mod custody;
pub mod firewall;
pub mod home;
pub mod ifname;
pub mod resolved;
pub mod who;

#[cfg(target_os = "linux")]
pub mod log;
#[cfg(target_os = "linux")]
pub mod machine;
#[cfg(target_os = "linux")]
pub mod netlink;
#[cfg(target_os = "linux")]
pub mod programs;
#[cfg(target_os = "linux")]
pub mod quiet;
#[cfg(target_os = "linux")]
pub mod socket;
#[cfg(target_os = "linux")]
pub mod tun;

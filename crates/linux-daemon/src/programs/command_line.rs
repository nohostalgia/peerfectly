//! The command line on Linux: the control socket and the machine's custody.
//! Everything else — every command, what is signed and how it is checked — is
//! the portable command line in `crates/cli`.

use crate::custody::command_line::{LinuxCustody, Socket};

/// Runs the command line.
#[must_use]
pub fn main() -> std::process::ExitCode {
    crate::quiet::before_any_thread();
    cli::Cli {
        channel: &Socket,
        custody: &LinuxCustody::of_this_machine(),
        extras: cli::Extras {
            usage: "\n  An act that signs asks for the network's passphrase.\n",
            privileged: "sudo",
            after_status: say_whether_names_resolve,
        },
    }
    .run()
}

/// After the report: whether systemd-resolved is there to send names to the
/// networks, read from this machine as the daemon reads it.
fn say_whether_names_resolve() {
    if let Some(why) = crate::resolved::not_in_use(&crate::resolved::Found::here()) {
        println!();
        println!("{}", crate::resolved::status_line(why));
    }
}

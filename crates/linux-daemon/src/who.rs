//! Who is at the other end of the control socket.
//!
//! **From the kernel, never from what was sent.** A client that says who it is,
//! is a client saying who it would like to be. The kernel records the account
//! that connected (`SO_PEERCRED`), and that is what is read.
//!
//! # A person, and root
//!
//! An account that is not root is the person that account belongs to, known by
//! its uid — a number the kernel reports and ownership records keep, which a
//! rename cannot move — and is not privileged.
//!
//! Root is privileged. **Under `sudo` the act is the person's who ran it**: a
//! network founded with `sudo peerfectly found` must belong to them and not to root,
//! or they could never bring it up again without `sudo`.
//!
//! # How the person behind root is found
//!
//! By the process tree, which the kernel keeps: up from the process that
//! connected, the first ancestor whose **real** uid is not root's is the person
//! who started the root process. `sudo` is set-uid, so it runs with the real uid
//! of whoever typed it; `pkexec` the same. A root process with nothing but root
//! above it — a service, a cron job, a root login — is root's own act.
//!
//! Each step reads `/proc/<pid>/status`, which anybody may read. The first
//! version read `SUDO_UID` from `/proc/<pid>/environ` instead, and that is
//! gated by the same check as ptrace: a daemon whose capabilities systemd has
//! bounded may not read the environment of a root process that holds them all,
//! which `sudo peerfectly` does — so under the service every such act would have
//! been root's. The tree is also not something a process can set for itself,
//! where an environment is.
//!
//! What this trusts is that a non-root account can only get a root process
//! through a set-uid program that means to give it one; and root can already
//! rewrite this daemon's state directly, so attributing a root act to a person
//! gives nobody a power they did not have.

use daemon::control::Caller;

/// How far up the tree to look before deciding the act is root's.
pub const DEPTH: usize = 16;

/// One process, as `/proc/<pid>/status` describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process {
    /// Its real uid.
    pub real: u32,
    /// Its effective uid.
    pub effective: u32,
    /// Its parent.
    pub parent: u32,
}

/// Reads what [`Process`] needs from `/proc/<pid>/status`.
#[must_use]
pub fn process_from_status(status: &str) -> Option<Process> {
    let field = |name: &str| status.lines().find_map(|line| line.strip_prefix(name)).map(str::trim);
    let mut uids = field("Uid:")?.split_whitespace();
    let real = uids.next()?.parse().ok()?;
    let effective = uids.next()?.parse().ok()?;
    let parent = field("PPid:")?.parse().ok()?;
    Some(Process { real, effective, parent })
}

/// The caller, from what the kernel said at connection and the tree above the
/// connecting process.
///
/// `connected` is that process as it is now: when it no longer runs as root, its
/// id was reused by something else, and the act is root's alone. `above` is its
/// ancestors, nearest first.
#[must_use]
pub fn caller(uid: u32, connected: Option<Process>, above: &[Process]) -> Caller {
    if uid != 0 {
        return Caller::Identified {
            name: uid.to_string(),
            privileged: false,
            // No surface on Linux offers an act it would then ask for again
            // elevated, and reading who may `sudo` would be a guess about the
            // sudoers file.
            could_be_privileged: false,
        };
    }
    let still_root = connected.is_some_and(|process| process.real == 0 && process.effective == 0);
    let acting_for = still_root
        .then(|| above.iter().take(DEPTH).map(|process| process.real).find(|real| *real != 0))
        .flatten();
    Caller::Identified {
        name: acting_for.unwrap_or(0).to_string(),
        privileged: true,
        could_be_privileged: false,
    }
}

/// Whether the process answering on the socket is the daemon: root, and
/// nothing else.
///
/// # Errors
///
/// When it is not, naming what answered.
pub fn judge_server(uid: u32, pid: Option<i32>) -> Result<(), String> {
    if uid == 0 {
        return Ok(());
    }
    let which = pid.map_or_else(String::new, |pid| format!(", process {pid}"));
    Err(format!(
        "the control socket was answered by uid {uid}{which}, not by the daemon, which runs as \
         root; nothing was sent to it"
    ))
}

#[cfg(target_os = "linux")]
pub use self::real::the_caller;

#[cfg(target_os = "linux")]
mod real {
    use daemon::control::Caller;
    use tokio::net::UnixStream;

    use super::{DEPTH, Process, caller, process_from_status};

    /// One process, read now.
    fn process(pid: u32) -> Option<Process> {
        process_from_status(&std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?)
    }

    /// Who connected, from the kernel.
    ///
    /// # Errors
    ///
    /// When the kernel will not say.
    pub fn the_caller(stream: &UnixStream) -> std::io::Result<Caller> {
        let credentials = stream.peer_cred()?;
        let uid = credentials.uid();
        if uid != 0 {
            return Ok(caller(uid, None, &[]));
        }
        let Some(pid) = credentials.pid().and_then(|pid| u32::try_from(pid).ok()) else {
            return Ok(caller(0, None, &[]));
        };
        let connected = process(pid);
        let mut above = Vec::new();
        let mut next = connected.map(|process| process.parent);
        while let Some(parent) = next.filter(|parent| *parent > 1 && above.len() < DEPTH) {
            let Some(found) = process(parent) else { break };
            above.push(found);
            next = Some(found.parent);
        }
        Ok(caller(0, connected, &above))
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    fn named(caller: &Caller) -> (&str, bool) {
        match caller {
            Caller::Identified { name, privileged, .. } => (name.as_str(), *privileged),
            _ => panic!("Linux always identifies"),
        }
    }

    const fn process(real: u32, effective: u32, parent: u32) -> Process {
        Process { real, effective, parent }
    }

    const ROOT: Process = process(0, 0, 900);

    #[test]
    fn a_person_is_their_uid_and_not_privileged() {
        assert_eq!(("1000", false), named(&caller(1000, None, &[])));
        // What is above a person's process changes nothing: they are themselves.
        assert_eq!(
            ("1000", false),
            named(&caller(1000, Some(process(1000, 1000, 5)), &[process(1001, 1001, 1)]))
        );
    }

    #[test]
    fn root_with_nothing_but_root_above_is_root() {
        assert_eq!(
            ("0", true),
            named(&caller(0, Some(ROOT), &[process(0, 0, 800), process(0, 0, 1)]))
        );
        assert_eq!(("0", true), named(&caller(0, Some(ROOT), &[])));
    }

    /// **Under `sudo`, the person's act**, with root's privilege: `sudo` runs
    /// with the real uid of whoever typed it.
    #[test]
    fn root_through_sudo_acts_for_the_person() {
        let sudo = process(1000, 0, 700);
        let shell = process(1000, 1000, 600);
        assert_eq!(("1000", true), named(&caller(0, Some(ROOT), &[sudo, shell])));
        // sudo's own monitor in between, as recent versions start one.
        let monitor = process(0, 0, 750);
        assert_eq!(("1000", true), named(&caller(0, Some(ROOT), &[monitor, sudo, shell])));
    }

    /// The connecting process no longer runs as root: its id was taken by
    /// something else, and nothing read about it names anybody.
    #[test]
    fn a_process_no_longer_root_names_nobody() {
        let sudo = process(1000, 0, 700);
        assert_eq!(("0", true), named(&caller(0, Some(process(1001, 1001, 900)), &[sudo])));
        assert_eq!(("0", true), named(&caller(0, None, &[sudo])));
    }

    #[test]
    fn the_search_stops_at_its_depth() {
        let mut above = vec![process(0, 0, 2); DEPTH];
        above.push(process(1000, 0, 1));
        assert_eq!(("0", true), named(&caller(0, Some(ROOT), &above)));
    }

    #[test]
    fn a_process_is_read_from_its_status() {
        let status = "Name:\tpeerfectly\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t42\nPid:\t42\nPPid:\t41\nUid:\t1000\t0\t0\t0\nGid:\t0\t0\t0\t0\n";
        assert_eq!(Some(process(1000, 0, 41)), process_from_status(status));
        assert_eq!(None, process_from_status("nothing here"));
    }

    #[test]
    fn only_root_is_the_daemon() {
        assert!(judge_server(0, Some(1)).is_ok());
        let said = judge_server(1000, Some(4242)).unwrap_err();
        assert!(said.contains("uid 1000") && said.contains("4242"), "{said}");
    }
}

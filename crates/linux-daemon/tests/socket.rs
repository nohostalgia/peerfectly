//! The control socket, and who the kernel says is at each end.
//!
//! Run as root, with `runuser`, `sudo`, `nc` and an account `alice` that may
//! use `sudo` — the testbed's `tests` image: `#[ignore]`d, run there.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::panic, reason = "a test reports failure by panicking")]

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use daemon::control::Caller;
use linux_daemon::{socket, who};

fn place(name: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("peerfectly-socket-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory.join("control.sock")
}

fn named(caller: &Caller) -> (String, bool) {
    match caller {
        Caller::Identified { name, privileged, .. } => (name.clone(), *privileged),
        _ => panic!("Linux always identifies"),
    }
}

/// Anybody may connect; the daemon reads who from the kernel — and under
/// `sudo`, the person who ran it.
#[tokio::test]
#[ignore = "needs root: run in the testbed"]
async fn the_daemon_reads_who_called_from_the_kernel() {
    let path = place("who");
    let listener = socket::listen_at(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(0o666, mode, "any account may connect");

    // A root client with no `sudo` behind it.
    let _client = socket::connect_at(&path).await.unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    assert_eq!(("0".to_owned(), true), named(&who::the_caller(&accepted).unwrap()));

    // A root client started by a person through `sudo`, still running while
    // it is looked at: the act is theirs, with root's privilege.
    let mut through_sudo = Command::new("runuser")
        .args(["-u", "alice", "--", "sudo", "nc", "-U", path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    assert_eq!(("1000".to_owned(), true), named(&who::the_caller(&accepted).unwrap()));
    through_sudo.kill().unwrap();
    let _ = through_sudo.wait();

    // A person, who is not privileged whatever they set in their environment.
    let mut person = Command::new("runuser")
        .args(["-u", "nobody", "--", "env", "SUDO_UID=0", "nc", "-U", path.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    assert_eq!(("65534".to_owned(), false), named(&who::the_caller(&accepted).unwrap()));
    person.kill().unwrap();
    let _ = person.wait();
}

/// **An impostor on the socket is refused, and sent nothing.**
#[tokio::test]
#[ignore = "needs root, runuser and nc: run in the testbed"]
async fn a_socket_answered_by_somebody_else_is_refused() {
    let path = place("impostor");
    let directory = path.parent().unwrap();
    std::fs::create_dir_all(directory).unwrap();
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o777)).unwrap();

    let mut impostor = Command::new("runuser")
        .args(["-u", "nobody", "--", "nc", "-lU", path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..50 {
        if path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let refused = socket::connect_at(&path).await.unwrap_err().to_string();
    assert!(refused.contains("uid 65534") && refused.contains("nothing was sent"), "{refused}");

    impostor.kill().unwrap();
    let heard = impostor.wait_with_output().unwrap();
    assert!(
        heard.stdout.is_empty(),
        "the impostor heard: {:?}",
        String::from_utf8_lossy(&heard.stdout)
    );
}

/// **Only one daemon**: a second is refused while the first holds the lock,
/// and may start once the first has gone.
#[test]
#[ignore = "needs root: run in the testbed"]
fn a_second_daemon_is_refused() {
    let path = place("lock").with_file_name("peerfectlyd.lock");
    let first = socket::only_one_at(&path).unwrap();
    let refused = socket::only_one_at(&path).unwrap_err();
    assert_eq!(std::io::ErrorKind::AddrInUse, refused.kind());
    assert!(refused.to_string().contains("already running"), "{refused}");
    drop(first);
    assert!(socket::only_one_at(&path).is_ok(), "the lock goes with its holder");
}

/// Something that is not the daemon's socket at the path is refused, not
/// removed.
#[tokio::test]
#[ignore = "needs root: run in the testbed"]
async fn a_path_held_by_something_else_is_not_taken() {
    let path = place("held");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"somebody's file").unwrap();
    assert!(socket::listen_at(&path).is_err());
    assert_eq!(b"somebody's file".as_slice(), std::fs::read(&path).unwrap().as_slice());
}

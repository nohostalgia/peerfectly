//! The state directory, on a real filesystem, as root.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, reason = "a test reports failure by panicking")]

use std::os::unix::fs::PermissionsExt as _;

/// Created root's and closed; a loosened one is refused and named.
#[test]
#[ignore = "needs root: run in the testbed"]
fn the_state_directory_is_made_closed_and_a_loose_one_refused() {
    let root = std::env::temp_dir().join(format!("peerfectly-home-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    linux_daemon::home::home_under(&root).unwrap();
    assert_eq!(0o700, std::fs::metadata(&root).unwrap().permissions().mode() & 0o777);

    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let refused = linux_daemon::home::home_under(&root).unwrap_err().to_string();
    assert!(refused.contains(&root.display().to_string()) && refused.contains("755"), "{refused}");
    std::fs::remove_dir_all(&root).unwrap();
}

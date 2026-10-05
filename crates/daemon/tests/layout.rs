//! Which way the Android client depends, held by a test.
//!
//! The daemon and the command line are released on their own, so they must build
//! from the root with no Android toolchain present. That stays true only while
//! nothing shared reaches into the client — one careless line in a manifest away
//! from not being true. The client lives outside this repository and declares a
//! workspace of its own, so the root has nothing to exclude.

#![allow(clippy::panic, reason = "a test reports failure by panicking")]

use std::path::{Path, PathBuf};

/// The repository root, two levels above this crate.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap_or_else(|| panic!("the crate sits two levels under the root"))
        .to_path_buf()
}

/// No member of the root workspace is under `android/`.
#[test]
fn the_root_workspace_has_no_android_member() {
    let manifest = std::fs::read_to_string(root().join("Cargo.toml"))
        .unwrap_or_else(|cause| panic!("the root manifest is readable: {cause}"));
    assert!(!manifest.contains("\"android/"), "nothing under android/ is a member");
}

/// No shared crate depends on anything under `android/`.
///
/// The dependency runs from the client to the core. The other direction would
/// make a Windows release need the Android project to build.
#[test]
fn no_shared_crate_reaches_into_the_android_client() {
    let crates = root().join("crates");
    let entries =
        std::fs::read_dir(&crates).unwrap_or_else(|cause| panic!("crates/ is readable: {cause}"));
    let mut checked = 0usize;
    for entry in entries.flatten() {
        let manifest = entry.path().join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&manifest) else { continue };
        checked = checked.saturating_add(1);
        for line in text.lines().map(str::trim).filter(|line| !line.starts_with('#')) {
            let normalised = line.replace('\\', "/");
            assert!(
                !normalised.contains("/android/") && !normalised.contains("\"android/"),
                "{} names a path under android/: {line}",
                manifest.display()
            );
        }
    }
    assert!(checked >= 10, "every shared crate was read, found {checked}");
}

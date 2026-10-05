//! The installer build packs only a driver the daemon would load.
//!
//! The build cannot keep a list of acceptable drivers of its own: that list
//! would be a copy of [`PINNED`], and a copy drifts. It asks the daemon's own
//! check instead, through `examples/check_driver.rs`. What these tests guard is
//! that it keeps asking, and that what it asks is the real check with the real
//! pins — the two lines that, removed, would let a package carry a driver the
//! installed daemon refuses at its first start.
//!
//! [`PINNED`]: windows_daemon::platform::driver::PINNED

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

/// The build script runs the daemon's driver check on what it packs, and stops
/// when the check refuses.
#[test]
fn the_build_asks_the_daemon_about_the_driver() {
    let script = include_str!("../../../deploy/windows/package.ps1");
    let asking = script
        .lines()
        .find(|line| line.contains("--example check_driver"))
        .unwrap_or_else(|| panic!("package.ps1 must run the daemon's driver check"));
    assert!(asking.contains("$driver"), "on the driver it packs: {asking}");

    let checked = script.find("Invoke-Checked \"The daemon's driver check\"").unwrap();
    let packed = script.find("Copy-Item $driver $Stage").unwrap();
    assert!(checked < packed, "and before it packs it, with its refusal stopping the build");
}

/// What the build asks is the function the daemon runs before loading, with the
/// pins the daemon loads by.
#[test]
fn the_check_is_the_daemons_with_its_pins() {
    let example = include_str!("../examples/check_driver.rs");
    assert!(
        example.contains("checked(std::path::Path::new(&path), PINNED)"),
        "the daemon's own check, with PINNED: {example}"
    );
    assert!(example.contains("ExitCode::FAILURE"), "and a refusal fails the build");
}

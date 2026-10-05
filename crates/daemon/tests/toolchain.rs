//! The Rust a build uses is one version, wherever the build runs.
//!
//! `rust-toolchain.toml` pins it for CI, releases and local builds. The Docker
//! builds do not read that file: each starts from a `rust:<version>-bookworm`
//! image of its own. A bump that moved one and not the other would ship a Linux
//! archive built by a compiler nothing else was checked with.

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

fn read(relative: &str) -> String {
    std::fs::read_to_string(root().join(relative))
        .unwrap_or_else(|cause| panic!("{relative} is readable: {cause}"))
}

/// The channel `rust-toolchain.toml` pins.
fn pinned() -> String {
    read("rust-toolchain.toml")
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("channel"))
        .and_then(|rest| rest.split('"').nth(1))
        .map(str::to_owned)
        .unwrap_or_else(|| panic!("rust-toolchain.toml names a channel"))
}

/// Every Docker build that compiles Rust starts from the pinned version.
#[test]
fn the_docker_builds_use_the_pinned_rust() {
    let channel = pinned();
    let expected = format!("FROM rust:{channel}-bookworm");
    for dockerfile in [
        "deploy/linux/package.Dockerfile",
        "deploy/server/Dockerfile",
        "crates/linux-daemon/testbed/Dockerfile",
    ] {
        let text = read(dockerfile);
        let from = text
            .lines()
            .find(|line| line.starts_with("FROM rust:"))
            .unwrap_or_else(|| panic!("{dockerfile} starts from a Rust image"));
        assert!(
            from.starts_with(&expected),
            "{dockerfile} builds with `{from}`, and rust-toolchain.toml pins {channel}"
        );
    }
}

/// The pin is an exact release line, never a moving channel.
#[test]
fn the_pin_is_not_a_moving_channel() {
    let channel = pinned();
    assert!(
        channel.split('.').all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())),
        "`{channel}` must be a version such as 1.95, not stable, beta or nightly"
    );
}

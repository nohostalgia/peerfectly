//! What the documents promise, held to the code.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

/// Every module with `unsafe` is in the README's table, and there is no other.
#[test]
fn the_unsafe_modules_are_accounted_for() {
    let readme = include_str!("../README.md");
    let listed = ["tun.rs", "quiet.rs"];
    for module in listed {
        assert!(
            readme.contains(&format!("`{module}`")),
            "`{module}` must be listed as an unsafe module"
        );
    }

    let sources: &[(&str, &str)] = &[
        ("custody/command_line.rs", include_str!("../src/custody/command_line.rs")),
        ("custody/keys.rs", include_str!("../src/custody/keys.rs")),
        ("custody/mod.rs", include_str!("../src/custody/mod.rs")),
        ("custody/prompt.rs", include_str!("../src/custody/prompt.rs")),
        ("custody/tpm.rs", include_str!("../src/custody/tpm.rs")),
        ("firewall.rs", include_str!("../src/firewall.rs")),
        ("home.rs", include_str!("../src/home.rs")),
        ("ifname.rs", include_str!("../src/ifname.rs")),
        ("lib.rs", include_str!("../src/lib.rs")),
        ("log.rs", include_str!("../src/log.rs")),
        ("machine.rs", include_str!("../src/machine.rs")),
        ("netlink.rs", include_str!("../src/netlink.rs")),
        ("programs/command_line.rs", include_str!("../src/programs/command_line.rs")),
        ("programs/daemon.rs", include_str!("../src/programs/daemon.rs")),
        ("programs/mod.rs", include_str!("../src/programs/mod.rs")),
        ("quiet.rs", include_str!("../src/quiet.rs")),
        ("resolved.rs", include_str!("../src/resolved.rs")),
        ("socket.rs", include_str!("../src/socket.rs")),
        ("tun.rs", include_str!("../src/tun.rs")),
        ("who.rs", include_str!("../src/who.rs")),
    ];
    for (file, source) in sources {
        let allows = source.contains("unsafe_code");
        let listed = listed.iter().any(|module| file.ends_with(module));
        assert_eq!(
            listed, allows,
            "`{file}`: an `unsafe` module is listed, and a listed one is the only kind"
        );
    }

    // Every source file is in the list above: a module added later cannot hide
    // an `unsafe` block by not being scanned.
    let mut on_disk = Vec::new();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![root.clone()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                on_disk
                    .push(path.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/"));
            }
        }
    }
    on_disk.sort();
    let mut scanned: Vec<String> = sources.iter().map(|(file, _)| (*file).to_owned()).collect();
    scanned.sort();
    assert_eq!(scanned, on_disk, "every source file is scanned");
}

/// The verification procedure covers what the suite cannot, and says what
/// was not run.
#[test]
fn the_verification_procedure_covers_what_the_suite_cannot() {
    let procedure = include_str!("../VERIFICATION.md");
    for step in [
        "The nodes build and start",
        "Somebody who may not is told so",
        "Exposing needs `sudo`, and survives a restart",
        "A second daemon does not start",
        "the Windows PC and the phone",
        "Names resolve through systemd-resolved",
        "a kill leaves nothing",
        "Without systemd-resolved, the tunnel still works",
        "A boot brings it back",
    ] {
        assert!(procedure.contains(step), "the procedure must cover: {step}");
    }
    assert!(procedure.contains("**Run so far**"), "and say how much of it was run");
}

/// The unit keeps what the README says it keeps, and nothing more.
#[test]
fn the_unit_keeps_two_capabilities() {
    // Line endings normalised: a checkout on Windows with git's default
    // `autocrlf` writes this file with CRLF, and markers span lines.
    let unit = include_str!("../../../deploy/linux/peerfectlyd.service").replace("\r\n", "\n");
    assert!(unit.contains("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE\n"), "{unit}");
    assert!(unit.contains("NoNewPrivileges=yes"));
    assert!(unit.contains("StateDirectoryMode=0700"));
    assert!(!unit.contains("CAP_SYS_PTRACE"), "who is calling is read without it");
}

//! What the documents have to say, checked.
//!
//! The same pattern the other crates use. It matters more here than anywhere
//! else in this workspace, because most of this daemon's behaviour cannot be
//! tested — so the record of what was and was not verified is doing work that
//! elsewhere a test would do.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

/// The README explains why, not only what.
#[test]
fn the_readme_records_the_reasoning() {
    let readme = include_str!("../README.md");

    for topic in [
        "builds and passes on Linux",
        "not to add a check",
        "no idle timeout",
        "sweeps on startup",
        "binds inside the tunnel",
        "wrong measure",
        "which file loads",
        "nothing consequential",
        // A weaker property than a fresh install has, so it is said where a
        // person would look for it rather than left to be discovered.
        "a network the device already had",
    ] {
        assert!(
            readme.to_lowercase().contains(&topic.to_lowercase()),
            "the README must explain `{topic}`"
        );
    }
}

/// The line between what is tested and what is not is drawn explicitly, because
/// an untested branch that looks tested is worse than one that admits it.
#[test]
fn the_readme_separates_tested_from_verified_by_hand() {
    let readme = include_str!("../README.md");

    assert!(
        readme.matches("`VERIFICATION.md` only").count() >= 6,
        "the table must name every behaviour only a real run can show"
    );
    assert!(
        readme.contains("unverified until a person runs it"),
        "and say plainly that those are unverified"
    );
}

/// Every deferral names where it went.
#[test]
fn every_deferral_names_its_destination() {
    let readme = include_str!("../README.md");

    for destination in ["enrollment-flow", "a later change", "equivocation-detection", "§7.3"] {
        assert!(readme.contains(destination), "a deferral must name `{destination}`");
    }
}

/// Every place with `unsafe` is listed, with the reason each exists.
#[test]
fn the_unsafe_modules_are_accounted_for() {
    let readme = include_str!("../README.md");

    for module in [
        "platform/route_table.rs",
        "platform/driver.rs",
        "platform/pump.rs",
        "platform/custody.rs",
        "platform/protected.rs",
        "platform/who.rs",
        "platform/desktop.rs",
        "programs/daemon.rs",
    ] {
        assert!(readme.contains(module), "`{module}` must be listed as an unsafe module");
    }
}

/// A verification procedure written before it is run, and followable by somebody
/// who did not write it.
#[test]
fn the_verification_procedure_covers_what_the_suite_cannot() {
    let procedure = include_str!("../VERIFICATION.md");

    for step in [
        "A packet crosses between two real machines",
        "The address, the route, and no default route",
        "Everything is removed on the way down",
        "Names resolve, and only under the suffix",
        "A killed daemon leaves nothing behind",
        "Nothing reaches infrastructure while the network is off",
        "The MTU, exercised by a transfer",
        "Another user cannot reach the control pipe",
        "The tray",
    ] {
        assert!(procedure.contains(step), "the procedure must cover `{step}`");
    }

    assert!(procedure.contains("What you need"), "and say what a person needs to run it");
    assert!(procedure.contains("Pin the driver"), "including pinning the driver first");
}

/// Nothing is claimed as verified before it has been.
///
/// The document states at the top how many steps have been run. This checks that
/// number against the results below, so filling a result in without moving the
/// count — or moving the count without filling a result in — fails here. Which
/// keeps the summary a reader sees first from drifting away from the evidence
/// underneath it.
#[test]
fn no_result_is_claimed_before_it_is_run() {
    let procedure = include_str!("../VERIFICATION.md");

    let steps = procedure.matches("**Result**:").count();
    let unrun = procedure.matches("**Result**: not run.").count();

    assert!(steps >= 10, "every step must carry a result line, run or not");

    let (claimed, outof) = declared(procedure);
    assert_eq!(outof, steps, "the count at the top must be out of every step below");
    assert_eq!(
        steps.checked_sub(unrun).expect("a result cannot be unrun more often than it exists"),
        claimed,
        "a step recorded as passing when it was not run converts an open question into a false \
         answer — the count at the top must match the results below"
    );
}

/// How many steps the document says have been run, and out of how many.
fn declared(procedure: &str) -> (usize, usize) {
    let line = procedure
        .lines()
        .find_map(|line| line.strip_prefix("**Run so far**: "))
        .expect("the document must say at the top how many steps have been run");
    let mut words = line.split_whitespace();
    let run = words.next().expect("the count comes first");
    let _of = words.next();
    let outof = words.next().expect("and what it is out of");
    let digits =
        |word: &str| word.trim_matches(|c: char| !c.is_ascii_digit()).parse().expect("a number");
    (digits(run), digits(outof))
}

/// The core/edge line, asserted from the side that could break it.
///
/// It used to read four modules in this crate. Those modules are now a crate of
/// their own, and the line between them is a dependency rather than a
/// convention: `daemon` cannot name a Windows type, because it does not depend
/// on anything that has one, and the Linux build says so every time it runs.
///
/// What is left to assert is the half that *can* break — this one. A platform
/// type reaching into the portable half would now be a compile error there; a
/// decision reaching into this half would not, so that is what is checked.
#[test]
fn the_split_is_asserted_and_not_only_described() {
    let manifest = include_str!("../Cargo.toml");

    assert!(
        manifest.contains(r#"daemon = { path = "../daemon" }"#),
        "the dependency runs one way: this crate knows `daemon`, and never the reverse"
    );

    let portable = include_str!("../../daemon/Cargo.toml");
    for platform in ["wintun", "windows-sys", "winreg", "tray-icon", "interprocess"] {
        assert!(
            !portable.contains(platform),
            "`{platform}` in the portable half would put a machine call where a decision \
             belongs"
        );
    }
    assert!(
        !portable.contains("windows-daemon"),
        "and the portable half must not depend on its own edge"
    );
}

/// The seeding fixture is gone, and nothing quietly grew back in its place.
///
/// `peerfectly-seed` wrote a roster with none of the pairing §6.2 asks for — no
/// confirmation code, no proof of possession — and a person who learned that
/// workflow would have kept using it. It was kept behind a feature until
/// `enrollment-flow` was verified between two real machines, and removed once it
/// was. This asserts the removal rather than trusting it: a build that produced
/// it again, or a manifest that carried the feature again, would be a way into
/// the network that no code review was looking at.
#[test]
fn the_seeding_fixture_is_gone() {
    // Three manifests since the programs moved, and the fixture must be absent
    // from all: a target that built it again would be a way in wherever it was
    // declared.
    let manifest = include_str!("../Cargo.toml");
    let portable = include_str!("../../daemon/Cargo.toml");
    let programs = include_str!("../../programs/Cargo.toml");

    for (where_, text) in
        [("the edge", manifest), ("the portable half", portable), ("the programs", programs)]
    {
        assert!(!text.contains("peerfectly-seed"), "no target in {where_} may build it again");
        assert!(!text.contains("[features]"), "nor carry the feature that gated it: {where_}");
    }

    // The binaries are declared where every platform's are, now.
    for binary in ["name = \"peerfectlyd\"", "name = \"peerfectly\""] {
        assert!(programs.contains(binary), "the real binaries stay: {binary}");
    }
}

/// The verification cannot start without a network, and the procedure says how
/// to make one and how to join it.
///
/// It used to say "run the fixture". It now shows the commands a person will
/// actually keep using, and the one step no software can take for them.
#[test]
fn the_procedure_says_how_to_get_a_network() {
    let procedure = include_str!("../VERIFICATION.md");

    assert!(procedure.contains("peerfectly.exe found"), "the procedure must show founding one");
    assert!(procedure.contains("peerfectly.exe join"), "and joining a second device to it");
    assert!(procedure.contains("peerfectly.exe admit"), "and admitting that device");

    assert!(
        procedure.contains("Now look at B's screen"),
        "and it must tell the person to compare the two screens, which is the whole check"
    );
    assert!(
        procedure.contains("nothing has been signed"),
        "and say what a mismatch costs, which is nothing"
    );
    assert!(
        !procedure.contains("peerfectly-seed.exe found"),
        "founding through the fixture is not the procedure any more"
    );
}

/// The command line writes no state of its own.
///
/// Founding and joining used to happen in this process, appending to a roster the
/// running daemon could not see — so both required the daemon to be stopped and
/// started again. `admitting.rs` had already written down why that is wrong; these
/// two did it anyway, because the daemon refused to run without a network and so
/// there was no daemon to ask.
///
/// Now there is. This asserts the command line has not kept a way back: one
/// process owns the state, which is also half of the two-rosters-in-two-profiles
/// confusion gone.
#[test]
fn the_command_line_owns_no_state() {
    // Both halves of the command line: the platform's, and the portable logic
    // every platform's `peerfectly` runs.
    let cli =
        [include_str!("../src/programs/command_line.rs"), include_str!("../../cli/src/lib.rs")]
            .concat();

    for writing in ["Log::at", "Paths::for_this_user", "founding::found", "joining::join"] {
        assert!(
            !cli.contains(writing),
            "`{writing}` in the command line means a second process writing the roster, which the running daemon would not see until it restarted"
        );
    }

    // And the two commands still exist — through the daemon.
    assert!(cli.contains("Command::Found"), "founding is a command now");
    assert!(cli.contains("Command::Join"), "and so is joining");
}

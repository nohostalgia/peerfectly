//! What this crate must not become.
//!
//! Enrolment is the one ceremony that has to run on every platform this product
//! will ever reach: a Windows daemon today, a phone in change 15, whatever comes
//! after. The moment it depends on a socket or an operating system, the phone
//! reimplements it — and a second implementation of a pairing ceremony is two
//! chances to get it wrong.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

/// The manifest names no platform crate and no transport crate.
///
/// This crate decides what bytes mean. Sockets, waiting, deadlines and terminals
/// belong to whatever is driving it.
#[test]
fn nothing_here_depends_on_a_platform_or_a_transport() {
    let manifest = include_str!("../Cargo.toml");
    let dependencies =
        manifest.split("[dev-dependencies]").next().expect("the manifest has a dependency section");

    for forbidden in [
        "windows",
        "wintun",
        "winreg",
        "tokio",
        "iroh",
        "socket2",
        "transport",
        "reqwest",
        "rustls",
        "hyper",
    ] {
        assert!(
            !dependencies.contains(forbidden),
            "`{forbidden}` must not be a dependency: this crate has to compile for a phone"
        );
    }
}

/// The two derivations are separated from each other and from everything else.
///
/// A signature made to prove possession must not be usable as anything else, and
/// the confirmation code must not be reachable by any other derivation in the
/// system. Both are one string away from being wrong, so both are asserted.
#[test]
fn the_two_domains_are_distinct_and_specific() {
    assert_ne!(enrollment::DOMAIN_CODE, enrollment::DOMAIN_POSSESSION);

    for domain in [enrollment::DOMAIN_CODE, enrollment::DOMAIN_POSSESSION] {
        assert!(domain.starts_with("peerfectly enrolment"), "{domain} must name this ceremony");
        assert!(domain.ends_with("v1"), "{domain} must carry a version");
    }
}

/// A payload says who is asking. Everything that decides what they may become
/// lives in the roster, and none of those words belong in this crate's format.
#[test]
fn the_payload_format_names_nothing_it_could_grant() {
    for field in enrollment::payload::JOINING_SCHEMA {
        for forbidden in ["role", "admin", "founder", "capab", "token", "secret"] {
            assert!(!field.contains(forbidden), "`{field}` would let a payload ask for something");
        }
    }
}

/// The document and the encoder agree on the field order.
///
/// `FORMAT.md` is what a second implementation reads. If it drifts from the
/// encoder, the two implementations disagree about bytes and nothing says so
/// until they fail to talk to each other.
#[test]
fn the_document_states_the_order_the_encoder_uses() {
    let format = include_str!("../FORMAT.md");
    let mut at = 0_usize;

    for field in enrollment::payload::JOINING_SCHEMA {
        let quoted = format!("\"{field}\"");
        let found = format[at..]
            .find(&quoted)
            .unwrap_or_else(|| panic!("`{field}` is missing from FORMAT.md"));
        at = at.saturating_add(found).saturating_add(quoted.len());
    }
}

/// Both derivation contexts appear in the document exactly as the code spells
/// them. A context that differs by one character is a different derivation.
#[test]
fn the_document_quotes_the_domains_exactly() {
    let format = include_str!("../FORMAT.md");
    assert!(format.contains(enrollment::DOMAIN_CODE), "FORMAT.md must quote the code's context");
    assert!(
        format.contains(enrollment::DOMAIN_POSSESSION),
        "FORMAT.md must quote the possession context"
    );
}

/// The README carries the reasoning a reader needs, and the parts that are
/// easiest to lose are asserted by name.
///
/// Each of these is a decision that cost something to reach. A rewrite that
/// dropped one would leave the crate looking like an arbitrary choice of
/// ceremony rather than a set of answers to specific attacks.
#[test]
fn the_readme_covers_what_it_must() {
    // Line endings normalised: a checkout on Windows with git's default
    // `autocrlf` writes this file with CRLF, and markers span lines.
    let readme = include_str!("../README.md").replace("\r\n", "\n");

    for (topic, marker) in [
        ("why the joiner waits", "unreachable in both directions"),
        ("why the admin dials", "thirty-two bytes, which nobody types"),
        ("where the exception lands", "nothing to lose"),
        ("why admitting never listens", "listener at all"),
        ("why the code is bound to the channel", "does not exist\nuntil the channel does"),
        ("the grinding attack it prevents", "space of one\nmillion"),
        ("what the joiner's confirmation defends", "would accept it"),
        ("what the admin's confirmation defends", "substituted on its way"),
        ("why both keys are proved", "first** admission of a device id"),
        ("that delivery proves nothing", "Delivery proves nothing"),
        ("the relay accepted on sight", "never confirmed"),
        ("what the bounds do not buy", "Denial of the enrolment remains possible"),
        ("the limit that stays", "accepted\nlimit"),
    ] {
        assert!(readme.contains(marker), "the README must explain {topic}");
    }
}

/// A deferral has to name where the work went, or it is a shrug.
#[test]
fn every_deferral_names_its_destination() {
    let readme = include_str!("../README.md");
    for destination in ["windows-daemon", "transport-iroh", "roster", "§10.2"] {
        assert!(readme.contains(destination), "a deferral must name `{destination}`");
    }
}

//! What `deploy/server/` says, held to what this program and the spec need.
//!
//! The relay reads its certificate's paths from a file and this program from
//! its arguments. The files that deploy them are the only place both meet, so
//! they are what is checked: two settings that drifted apart would give the
//! two services different certificates, and devices pinning the relay would
//! refuse the rendezvous.

#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use rendezvous_server::{CERT_DEFAULT, CERT_VARIABLE, KEY_DEFAULT, KEY_VARIABLE};

fn deployed(file: &str) -> String {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/server").join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|cause| panic!("{}: {cause}", path.display()))
}

/// Lines that are not comments.
fn code(text: &str) -> String {
    text.lines().filter(|line| !line.trim_start().starts_with('#')).collect::<Vec<_>>().join("\n")
}

/// **The relay's configuration names the certificate only through the
/// placeholders**, which its entrypoint fills from the one setting.
#[test]
fn the_relay_reads_the_certificate_through_the_one_setting() {
    let config = code(&deployed("relay.toml"));
    assert!(config.contains(r#"manual_cert_path = "@PEERFECTLY_CERT@""#), "{config}");
    assert!(config.contains(r#"manual_key_path = "@PEERFECTLY_KEY@""#), "{config}");

    let entrypoint = code(&deployed("relay-entrypoint.sh"));
    for (placeholder, variable, default) in [
        ("@PEERFECTLY_CERT@", CERT_VARIABLE, CERT_DEFAULT),
        ("@PEERFECTLY_KEY@", KEY_VARIABLE, KEY_DEFAULT),
    ] {
        assert!(entrypoint.contains(placeholder), "{placeholder} is filled in");
        assert!(
            entrypoint.contains(&format!("${{{variable}:-{default}}}")),
            "from {variable}, defaulting to {default} as this program does"
        );
    }
}

/// **The image defaults the setting to what this program defaults to.**
#[test]
fn the_image_defaults_agree_with_the_program() {
    let dockerfile = code(&deployed("Dockerfile"));
    assert!(dockerfile.contains(&format!("{CERT_VARIABLE}={CERT_DEFAULT}")), "{dockerfile}");
    assert!(dockerfile.contains(&format!("{KEY_VARIABLE}={KEY_DEFAULT}")), "{dockerfile}");
}

/// **Compose gives neither service a path of its own**: the one setting is the
/// only way to move the certificate.
#[test]
fn compose_names_no_certificate_path_of_its_own() {
    let compose = code(&deployed("compose.yaml"));
    for own in [".crt", ".key", "--cert", "--key", "manual_cert_path"] {
        assert!(!compose.contains(own), "`{own}` in compose.yaml would be a second setting");
    }
}

/// **The relay's access is stated, bounded, and its metrics off**, as the spec
/// requires rather than as the defaults happen to be.
#[test]
fn the_relay_states_its_access_and_limits() {
    let config = code(&deployed("relay.toml"));
    for stated in [
        r#"access = "everyone""#,
        "enable_metrics = false",
        "accept_conn_limit",
        "bytes_per_second",
    ] {
        assert!(config.contains(stated), "`{stated}` must be written down: {config}");
    }
}

/// **The services run with the least they need.**
#[test]
fn the_services_run_with_little() {
    let compose = code(&deployed("compose.yaml"));
    for stated in [
        r#"user: "10001:10001""#,
        "read_only: true",
        "cap_drop: [ALL]",
        "no-new-privileges:true",
        ":ro",
        "RUST_LOG: warn",
    ] {
        assert!(compose.contains(stated), "`{stated}`: {compose}");
    }
    assert!(!compose.contains("cap_add"), "no capability is added back");
    assert!(!compose.contains("network_mode"), "published ports, not the host's network");
}

/// **The image copies in no certificate or key**, and the build context
/// leaves out anything that could be one.
#[test]
fn the_image_holds_no_key() {
    let dockerfile = code(&deployed("Dockerfile"));
    for line in dockerfile.lines().filter(|line| line.trim_start().starts_with("COPY")) {
        for material in [".crt", ".key", ".pem", "certs"] {
            assert!(!line.contains(material), "copied into the image: {line}");
        }
    }
    let ignored = deployed("Dockerfile.dockerignore");
    for pattern in ["**/*.key", "**/*.pem"] {
        assert!(ignored.contains(pattern), "{pattern} left out of the build context");
    }
}

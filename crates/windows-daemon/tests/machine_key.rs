//! This machine's own key in the TPM, on a real machine.
//!
//! `#[ignore]`d: it needs a TPM and an elevated console, which CI has neither
//! of. Run from an elevated console with
//! `cargo test -p windows-daemon --test machine_key -- --ignored`, and record
//! the run in `VERIFICATION.md`. It uses a key of its own, removed at the end,
//! and never the daemon's.

#![cfg(windows)]
#![allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]

use windows_daemon::keys::MachineKeys;

const NAME: &str = "peerfectly.machine.check";

#[test]
#[ignore = "needs a TPM and an elevated console: run by hand, recorded in VERIFICATION.md"]
fn the_machine_key_is_made_in_the_tpm_once_and_signs_with_nobody_asked() {
    let keys = MachineKeys::open().expect("this machine's TPM can hold a key");
    let home = tempfile::tempdir().unwrap();

    let (first, made) = keys.machine_key_named(home.path(), NAME).unwrap();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert!(made, "made now");
        assert_eq!(std::fs::read_to_string(home.path().join("machine.kind")).unwrap(), "hardware");
        assert!(!home.path().join("machine.key").exists(), "and no software key");

        let (again, made) = keys.machine_key_named(home.path(), NAME).unwrap();
        assert!(!made, "opened, not made again");
        assert_eq!(first.public(), again.public(), "the same key, as the TPM reports it");

        // No prompt appears: a key used with nobody present.
        let signature = again.sign(b"a checkpoint").unwrap();
        first.public().verify(b"a checkpoint", &signature).unwrap();
        assert!(first.public().verify(b"another checkpoint", &signature).is_err());
    }));

    keys.store().remove(NAME).expect("the check's key is removed");
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }

    // Gone from the TPM, it is lost and not replaced.
    assert!(keys.machine_key_named(home.path(), NAME).is_err());
}

/// **The transport and attestation keys' file opens only on this TPM**, and
/// what DPAPI sealed before still opens.
#[test]
#[ignore = "needs a TPM and an elevated console: run by hand, recorded in VERIFICATION.md"]
fn identities_are_sealed_under_a_key_the_tpm_wraps() {
    use identity::store::Sealer as _;

    let keys = MachineKeys::open().expect("this machine's TPM can hold a key");
    let sealer = keys.sealer();
    let stored = sealer.seal(b"the transport key").unwrap();
    assert!(stored.starts_with(b"peerfectly wrapped v1"), "wrapped, not DPAPI");
    assert_eq!(sealer.unseal(&stored).unwrap(), b"the transport key");

    let before = identity::store::PlatformSealer.seal(b"written before").unwrap();
    assert_eq!(sealer.unseal(&before).unwrap(), b"written before");
}

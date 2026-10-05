//! The signing key in a TPM, against `swtpm`.
//!
//! Each test starts its own `swtpm` with its own state, on its own port, so the
//! tests can run side by side and a second TPM is a second seed. What these show
//! is that the commands are right and the refusals are worded; what a hardware
//! TPM defends against is the chip's.
//!
//! `#[ignore]`d: they need `swtpm` and `tpm2-tools`, which the testbed has.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "a test reports failure by panicking, and counts its own ports"
)]

use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use linux_daemon::custody::tpm::{Authorisation, LOCKED_OUT, Stored, Tpm, WRONG_PASSPHRASE};
use roster::sign::PublicKey;
use roster::types::Algorithm;
use tss_esapi::tcti_ldr::{NetworkTPMConfig, TctiNameConf};

/// A port per TPM, never the same twice in one run.
static NEXT: AtomicU16 = AtomicU16::new(23_210);

/// A software TPM, stopped when it goes.
struct Swtpm {
    child: Child,
    port: u16,
    _state: tempfile::TempDir,
}

impl Swtpm {
    fn start() -> Self {
        let port = NEXT.fetch_add(2, Ordering::SeqCst);
        let state = tempfile::tempdir().unwrap();
        let child = Command::new("swtpm")
            .args([
                "socket",
                "--tpm2",
                "--tpmstate",
                &format!("dir={}", state.path().display()),
                "--server",
                &format!("type=tcp,port={port},bindaddr=127.0.0.1"),
                "--ctrl",
                &format!("type=tcp,port={},bindaddr=127.0.0.1", port + 1),
                "--flags",
                "not-need-init,startup-clear",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        for _ in 0..50 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Self { child, port, _state: state }
    }

    fn name(&self) -> String {
        format!("swtpm:host=127.0.0.1,port={}", self.port)
    }

    fn tpm(&self) -> Tpm {
        Tpm::at(TctiNameConf::Swtpm(NetworkTPMConfig::from_str_lossy(&self.name())))
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `NetworkTPMConfig` from `host=…,port=…`, as `tss-esapi` parses it.
trait FromStrLossy {
    fn from_str_lossy(name: &str) -> Self;
}

impl FromStrLossy for NetworkTPMConfig {
    fn from_str_lossy(name: &str) -> Self {
        let config = name.split_once(':').map_or(name, |(_, config)| config);
        config.parse().unwrap()
    }
}

#[test]
#[ignore = "needs swtpm: run in the testbed"]
fn a_key_is_made_signs_and_verifies_with_the_rosters_p256() {
    let swtpm = Swtpm::start();
    let tpm = swtpm.tpm();
    tpm.usable().unwrap();

    let stored = tpm.create(b"correct horse").unwrap();
    assert!(stored.attributes_hold().unwrap(), "fixedTPM, userWithAuth, and never noDA");
    let stored = Stored::from_bytes(&stored.to_bytes()).unwrap();

    let public = stored.public_key().unwrap();
    assert_eq!(public, tpm.load_check(&stored).unwrap(), "the file is this TPM's");

    let signature = tpm.sign(&stored, b"correct horse", b"admit the laptop").unwrap();
    let key = PublicKey::new(Algorithm::P256, public).unwrap();
    key.verify(b"admit the laptop", &signature).unwrap();
    assert!(key.verify(b"admit another laptop", &signature).is_err());
}

#[test]
#[ignore = "needs swtpm: run in the testbed"]
fn a_wrong_passphrase_signs_nothing_and_says_so() {
    let swtpm = Swtpm::start();
    let tpm = swtpm.tpm();
    let stored = tpm.create(b"correct horse").unwrap();
    assert_eq!(Err(WRONG_PASSPHRASE.to_owned()), tpm.sign(&stored, b"correct horsf", b"revoke"));
}

/// **Guessing is limited by the TPM.** Its dictionary-attack settings are
/// lowered for the test — two tries — and the third refusal is the lockout's.
#[test]
#[ignore = "needs swtpm and tpm2-tools: run in the testbed"]
fn repeated_wrong_passphrases_reach_the_lockout() {
    let swtpm = Swtpm::start();
    let lowered = Command::new("tpm2_dictionarylockout")
        .args([
            "--setup-parameters",
            "--max-tries=2",
            "--recovery-time=600",
            "--lockout-recovery-time=600",
        ])
        .env("TPM2TOOLS_TCTI", swtpm.name())
        .output()
        .unwrap();
    assert!(lowered.status.success(), "{}", String::from_utf8_lossy(&lowered.stderr));

    let tpm = swtpm.tpm();
    let stored = tpm.create(b"correct horse").unwrap();
    let mut answers = Vec::new();
    for _ in 0..4 {
        answers.push(tpm.sign(&stored, b"wrong guess", b"revoke").unwrap_err());
    }
    assert!(answers.contains(&LOCKED_OUT.to_owned()), "{answers:?}");
    assert_eq!(
        Err(LOCKED_OUT.to_owned()),
        tpm.sign(&stored, b"correct horse", b"revoke"),
        "even the right one, for now"
    );
}

/// **Useless on another TPM**: its storage key is another seed's.
#[test]
#[ignore = "needs swtpm: run in the testbed"]
fn a_key_file_does_not_load_on_another_tpm() {
    let first = Swtpm::start();
    let second = Swtpm::start();
    let stored = first.tpm().create(b"correct horse").unwrap();
    let refused = second.tpm().load_check(&stored).unwrap_err();
    assert!(refused.contains("cannot load"), "{refused}");
    assert!(second.tpm().sign(&stored, b"correct horse", b"revoke").is_err());
}

/// **No TPM, no TPM custody**: the probe fails and says why, and the machine
/// uses sealed files.
#[test]
#[ignore = "run in the testbed, beside the others"]
fn without_a_tpm_the_probe_says_so() {
    let absent = Tpm::at(TctiNameConf::Device(tss_esapi::tcti_ldr::DeviceConfig::from_str_path(
        "/dev/no-such-tpm",
    )));
    let why = absent.usable().unwrap_err();
    assert!(why.contains("cannot be reached"), "{why}");
    assert_eq!(
        linux_daemon::custody::Kind::Sealed,
        linux_daemon::custody::kind_for(absent.usable().is_ok())
    );
}

/// `DeviceConfig` at a path, as `tss-esapi` parses one.
trait FromStrPath {
    fn from_str_path(path: &str) -> Self;
}

impl FromStrPath for tss_esapi::tcti_ldr::DeviceConfig {
    fn from_str_path(path: &str) -> Self {
        path.parse().unwrap()
    }
}

/// How many wrong authorisations this TPM is counting now.
fn lockout_counter(swtpm: &Swtpm) -> u32 {
    let tcti = TctiNameConf::Swtpm(NetworkTPMConfig::from_str_lossy(&swtpm.name()));
    let mut context = tss_esapi::Context::new(tcti).unwrap();
    context
        .get_tpm_property(tss_esapi::constants::PropertyTag::LockoutCounter)
        .unwrap()
        .unwrap_or(0)
}

/// **A batch is signed from one authorisation**: one session and one load, a
/// signature per message, every one verifying; a wrong passphrase signs none.
#[test]
#[ignore = "needs swtpm: run in the testbed"]
fn a_batch_is_signed_whole_from_one_authorisation() {
    let swtpm = Swtpm::start();
    let tpm = swtpm.tpm();
    let stored = tpm.create(b"correct horse").unwrap();
    let key = PublicKey::new(Algorithm::P256, stored.public_key().unwrap()).unwrap();

    let messages: [&[u8]; 3] = [b"revoke the laptop", b"admit the laptop", b"the snapshot"];
    let signatures =
        tpm.sign_all(&stored, &Authorisation::of(b"correct horse"), &messages).unwrap();
    assert_eq!(3, signatures.len());
    for (message, signature) in messages.iter().zip(&signatures) {
        key.verify(message, signature).unwrap();
    }

    assert_eq!(
        Err(WRONG_PASSPHRASE.to_owned()),
        tpm.sign_all(&stored, &Authorisation::of(b"correct horsf"), &messages),
        "and nothing at all with a wrong one"
    );
}

/// **An empty entry refuses without costing a guess.** It never reaches the
/// TPM, so the dictionary-attack counter does not move — where a wrong
/// passphrase moves it, which is what makes the counter the thing to watch.
#[test]
#[ignore = "needs swtpm and root: run in the testbed"]
fn an_empty_entry_refuses_without_costing_a_guess() {
    use cli::Custody as _;
    use linux_daemon::custody::command_line::LinuxCustody;

    let swtpm = Swtpm::start();
    let tpm = swtpm.tpm();
    let stored = tpm.create(b"correct horse").unwrap();
    let keys = tempfile::tempdir().unwrap();
    let name = "peerfectly.casa.0123456789abcdef.signing";
    let path = linux_daemon::custody::file_for(keys.path(), name, linux_daemon::custody::Kind::Tpm)
        .unwrap();
    std::fs::write(&path, stored.to_bytes()).unwrap();

    let before = lockout_counter(&swtpm);
    let custody = LinuxCustody::with(keys.path().to_path_buf(), tpm.clone(), |_| {
        Ok(zeroize::Zeroizing::new(String::new()))
    });
    let messages: [&[u8]; 1] = [b"revoke the laptop"];
    let refused = custody
        .sign_all(&cli::Asking { key: name, network: "casa", summary: "", messages: &messages })
        .unwrap_err();
    assert_eq!(linux_daemon::custody::REFUSED, refused);
    assert_eq!(before, lockout_counter(&swtpm), "an empty entry is not a guess");

    assert!(tpm.sign(&stored, b"wrong guess", b"revoke").is_err());
    assert!(lockout_counter(&swtpm) > before, "where a wrong passphrase is one");
}

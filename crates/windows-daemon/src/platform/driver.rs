//! Loading the adapter driver, and refusing to load the wrong one.
//!
//! One `unsafe` call. It is here rather than in [`super::adapter`] because the
//! interesting thing about it is not the keyword.
//!
//! # Which file runs matters more than which keyword marks it
//!
//! `Wintun.dll` is a signed kernel driver. Loading a library runs code from it,
//! and this daemon runs as Administrator, so anyone who can substitute that file
//! gets code execution in an elevated process and, through the driver, in the
//! kernel. That is the largest exposure this crate introduces, and no amount of
//! care with the `unsafe` block addresses it.
//!
//! Two things do:
//!
//! **The path is absolute, derived from the executable's own location.** Loading
//! by name uses the Windows DLL search order, which is a well-trodden way to end
//! up with somebody else's library.
//!
//! **The digest is checked before the load.** [`PINNED`] lists what may be
//! loaded. It starts empty, and an empty list refuses everything — the daemon
//! fails closed and tells the operator the digest it found, so pinning is a
//! deliberate act with a value they can read off rather than a default nobody
//! chose.
//!
//! **The signature is checked too, and from the same handle.** A digest says
//! *this is the file you pinned*; it says nothing about whether the file was ever
//! worth pinning. A person following the refusal below pastes a line, and the
//! line is only as good as the check they did before pasting it — so the daemon
//! does that check itself rather than trusting that somebody did.
//!
//! # One handle, opened once, held across the load
//!
//! Checking a path and then loading that path is two decisions about two files
//! that happen to share a name. Between them, the file can change.
//!
//! So the file is opened once, **forbidding writers and deleters**, and the
//! handle is held until the library is loaded. The digest is read through it and
//! the signature is verified through it, and while it is open the file cannot be
//! replaced, truncated, renamed or removed. What the daemon checked is what the
//! daemon loads, and that is a property of the handle rather than a hope about
//! timing.
//!
//! **Nothing is fetched to do it.** Revocation checking would have the daemon
//! reach a certificate authority at startup, which §2.6c forbids outright — a
//! daemon whose network is off must reach nothing. The verification is told to
//! use what is cached and check no revocation, so a signature that was valid when
//! the driver was pinned stays valid here whatever the network is doing.
//!
//! What this does **not** defend against is somebody who can write the
//! executable's own directory: they could replace the daemon as easily as the
//! driver. The protection there is the directory's ACL. What it does catch is the
//! driver being swapped while the binary is not — which is exactly the situation
//! when the daemon runs from a build or downloads directory, and so is how it
//! will run during the verification in group 12.

#![allow(
    unsafe_code,
    reason = "loading a library is unsafe in Rust because it runs code from the file, and \
              asking Windows whether that file is signed has no safe wrapper; what is loaded \
              is checked first, through the handle it is loaded from"
)]

use std::io::Read as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};

use daemon::error::{Error, Result, Step};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_SAFER_FLAG,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
};
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

/// The driver's file name.
const DRIVER: &str = "wintun.dll";

/// The digests this daemon will load.
///
/// **Empty as shipped.** With nothing pinned nothing loads, and the failure says
/// which digest was found. Pinning is then a deliberate act: paste the line the
/// daemon printed, having satisfied yourself the file is the one you meant.
///
/// A default that accepted anything would be a default nobody chose, in the one
/// place where the consequence is kernel code execution.
///
/// What this cannot do is make the decision for you. Pinning records a judgement;
/// it does not form one. Paste a digest without checking the signature and the
/// daemon will faithfully load that file forever, with the appearance of a
/// security control and none of its substance. See `README.md`.
pub const PINNED: &[[u8; 32]] = &[
    // Wintun 0.14.1 amd64, from wintun.net.
    // SHA-256 e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce,
    // Authenticode valid, signed by WireGuard LLC.
    [
        0xe2, 0x61, 0x4f, 0x29, 0x1e, 0x3f, 0x02, 0x03, 0x07, 0x99, 0x82, 0x51, 0x14, 0x17, 0x0d,
        0xbd, 0x87, 0xae, 0x75, 0xc2, 0x6c, 0xca, 0x3f, 0x45, 0x04, 0x7d, 0x3d, 0xa8, 0x3b, 0x8f,
        0xa2, 0x75,
    ],
];
/// Where the driver must be: beside the executable, by absolute path.
///
/// # Errors
///
/// When the executable's own location cannot be determined.
pub fn expected_path() -> Result<PathBuf> {
    let executable = std::env::current_exe().map_err(|cause| Error::BringUp {
        step: Step::CreatingAdapter,
        cause: format!("the executable's own location is unknown: {cause}"),
        left: Vec::new(),
    })?;
    let directory = executable.parent().ok_or_else(|| Error::BringUp {
        step: Step::CreatingAdapter,
        cause: "the executable has no directory".to_owned(),
        left: Vec::new(),
    })?;
    Ok(directory.join(DRIVER))
}

/// The driver, open, and held open.
///
/// **While this exists the file cannot change.** It is opened permitting other
/// readers and nobody else: no writer, no deleter, no renamer. So the digest read
/// through it, the signature verified through it and the library loaded while it
/// is held are all the same bytes, and that is the handle's doing rather than a
/// hope about how little time passes.
#[derive(Debug)]
pub struct Held {
    /// Where it is, for the messages and for the load.
    path: PathBuf,
    /// The handle. Held for its own sake as much as for reading.
    file: std::fs::File,
}

impl Held {
    /// Opens the driver, forbidding anyone else from changing it.
    ///
    /// # Errors
    ///
    /// When the file is missing, unreadable, or already open to somebody who is
    /// writing it — which is itself worth refusing on.
    pub fn open(path: &Path) -> Result<Self> {
        use std::os::windows::fs::OpenOptionsExt as _;

        let file = std::fs::OpenOptions::new()
            .read(true)
            // Readers yes; writers, deleters and renamers no. Sharing is mutual,
            // so this both refuses to open a file somebody is already writing and
            // stops anybody starting while it is held.
            .share_mode(FILE_SHARE_READ)
            .open(path)
            .map_err(|cause| Error::BringUp {
                step: Step::CreatingAdapter,
                cause: format!("{} could not be opened: {cause}", path.display()),
                left: Vec::new(),
            })?;

        Ok(Self { path: path.to_path_buf(), file })
    }

    /// Where it is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The digest of what this handle holds.
    ///
    /// # Errors
    ///
    /// When the handle will not read.
    pub fn digest(&mut self) -> Result<[u8; 32]> {
        let mut bytes = Vec::new();
        self.file.read_to_end(&mut bytes).map_err(|cause| Error::BringUp {
            step: Step::CreatingAdapter,
            cause: format!("{} could not be read: {cause}", self.path.display()),
            left: Vec::new(),
        })?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    /// Whether Windows will say this file carries a valid Authenticode
    /// signature.
    ///
    /// Asked of **this handle**, not of the path, so it is the same file the
    /// digest came from. Nothing is fetched: revocation is not checked and no
    /// URL is retrieved, because §2.6c says a daemon whose network is off reaches
    /// nothing, and this runs at startup.
    ///
    /// # Errors
    ///
    /// The code Windows gave, which is the useful thing to look up.
    pub fn signature(&self) -> core::result::Result<(), i32> {
        let wide: Vec<u16> =
            self.path.display().to_string().encode_utf16().chain(core::iter::once(0)).collect();

        let mut about = WINTRUST_FILE_INFO {
            cbStruct: u32::try_from(size_of::<WINTRUST_FILE_INFO>()).unwrap_or(0),
            pcwszFilePath: wide.as_ptr(),
            hFile: self.file.as_raw_handle() as HANDLE,
            pgKnownSubject: core::ptr::null_mut(),
        };

        let mut asking = WINTRUST_DATA {
            cbStruct: u32::try_from(size_of::<WINTRUST_DATA>()).unwrap_or(0),
            pPolicyCallbackData: core::ptr::null_mut(),
            pSIPClientData: core::ptr::null_mut(),
            // No window: this runs as a service, where there is no desktop to put
            // one on and nobody to answer it.
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &raw mut about },
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: core::ptr::null_mut(),
            pwszURLReference: core::ptr::null_mut(),
            dwProvFlags: WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL,
            dwUIContext: 0,
            pSignatureSettings: core::ptr::null_mut(),
        };

        let mut what = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: both structures are ours and alive for the call, and the file
        // information they point at outlives it. The state this opens is closed
        // below, on every path.
        let said = unsafe {
            WinVerifyTrust(core::ptr::null_mut(), &raw mut what, (&raw mut asking).cast())
        };

        // **Closed whatever the answer was.** The verification allocates state
        // behind `hWVTStateData`, and a daemon that verified once per start and
        // never closed it would leak a little every time.
        asking.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: the same structure, now asking for the state to be released.
        unsafe {
            WinVerifyTrust(core::ptr::null_mut(), &raw mut what, (&raw mut asking).cast());
        }

        if said == 0 { Ok(()) } else { Err(said) }
    }
}

/// Whether a digest is one this daemon will load.
#[must_use]
pub fn is_pinned(digest: &[u8; 32]) -> bool {
    PINNED.contains(digest)
}

/// Renders a digest as a line that pastes into [`PINNED`] unchanged.
///
/// [`PINNED`] is a slice **of arrays**, so a bare list of bytes does not compile
/// there. The first version printed one, and the first person to follow the
/// instruction pasted it and got a type error. A message that tells somebody to
/// paste a thing has to produce a thing that can be pasted.
#[must_use]
pub fn as_pin(digest: &[u8; 32]) -> String {
    let mut out = String::from("    [");
    for (index, byte) in digest.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!("0x{byte:02x}"));
    }
    out.push_str("],");
    out
}

/// Opens the driver and establishes that it is one this daemon may load.
///
/// Both checks, in order, through one handle — which is returned still open, so
/// that whoever loads it loads what was checked.
///
/// The pins are handed in so that the decision can be tested against a file a
/// test made, rather than only against whatever this machine happens to have
/// beside the executable.
///
/// # Errors
///
/// When the file is missing or unreadable, when its digest is not pinned, or
/// when it carries no valid signature.
pub fn checked(path: &Path, pinned: &[[u8; 32]]) -> Result<Held> {
    let mut held = Held::open(path)?;
    let digest = held.digest()?;

    if !pinned.contains(&digest) {
        return Err(Error::BringUp {
            step: Step::CreatingAdapter,
            cause: format!(
                "{} is not a pinned driver.\n\nCheck it first: its Authenticode signature should \
                 be valid and signed by WireGuard LLC. Then paste this line inside the brackets \
                 of `PINNED` in platform/driver.rs and rebuild:\n\n{}\n\nNothing is pinned by \
                 default, because the consequence of loading the wrong driver is kernel code \
                 execution. Pasting without checking gives you the appearance of that protection \
                 and none of it.",
                path.display(),
                as_pin(&digest)
            ),
            left: Vec::new(),
        });
    }

    // **After the digest, and refused separately.** A file that matches a pin and
    // carries no valid signature is the interesting case: it means the pin
    // records a judgement nobody made, or the file it recorded has been replaced
    // by one that hashes the same — and either way the refusal must say
    // *signature*, because a person told their digest was wrong will go and
    // re-pin the very file being refused.
    if let Err(said) = held.signature() {
        return Err(Error::BringUp {
            step: Step::CreatingAdapter,
            cause: format!(
                "{} matches a pinned digest but carries no valid Authenticode signature \
                 (0x{said:08x}).\n\nThe digest is not the problem and re-pinning will not help. \
                 Windows will not vouch for this file, so this daemon will not load it into the \
                 kernel. Replace it with the signed driver from wintun.net.",
                path.display()
            ),
            left: Vec::new(),
        });
    }

    Ok(held)
}

/// Checks the driver beside the executable, without loading it.
///
/// Separated from [`load`] so the check can be tested, and so a person can ask
/// what the daemon would load before it loads anything.
///
/// The handle is dropped on the way out, and that is the difference between this
/// and [`load`]: this answers a question, and the answer is about a moment.
/// Loading needs the file to still be that file, which is why it keeps the
/// handle rather than calling this.
///
/// # Errors
///
/// When the file is missing, unreadable, not one of the pinned digests, or
/// unsigned.
pub fn verify() -> Result<PathBuf> {
    let path = expected_path()?;
    let held = checked(&path, PINNED)?;
    Ok(held.path().to_path_buf())
}

/// Loads the driver, having checked it, **without letting go in between**.
///
/// # Errors
///
/// When the check fails, or the library will not load.
pub fn load() -> Result<wintun::Wintun> {
    let path = expected_path()?;
    let held = checked(&path, PINNED)?;

    // SAFETY: loading a library runs its initialisation code, so the guarantee
    // needed is about the file rather than about memory. `held` is open on this
    // exact path with writers and deleters forbidden, and it stays open across
    // this call — so the bytes whose digest was pinned and whose signature
    // Windows vouched for are the bytes being loaded. The path is absolute and
    // derived from the executable's own location rather than from the DLL search
    // order.
    let loaded = unsafe { wintun::load_from_path(held.path()) };

    // Explicit, and after the load. Left to the end of the function it would
    // still be right, and it would be right by accident.
    drop(held);

    loaded.map_err(|cause| Error::BringUp {
        step: Step::CreatingAdapter,
        cause: format!("{} would not load: {cause}", path.display()),
        left: Vec::new(),
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// The digest of a file, through the handle the daemon would use.
    ///
    /// Not a second way of hashing: it opens the file exactly as `checked` does,
    /// so a test that says two files differ is saying it about what the daemon
    /// would read.
    fn digest_of(path: &Path) -> Result<[u8; 32]> {
        Held::open(path)?.digest()
    }

    /// A file that is not a driver, in a directory of its own.
    fn a_file_saying(what: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let file = dir.path().join(DRIVER);
        std::fs::write(&file, what).expect("writes");
        (dir, file)
    }

    /// **Nobody can change it while the daemon holds it.**
    ///
    /// This is what makes one handle worth the trouble. Checking a path and then
    /// loading that path is two decisions about two files that happen to share a
    /// name; between them, the file can change. While this handle is open it
    /// cannot: not written, not truncated, not renamed, not removed.
    #[test]
    fn a_held_driver_cannot_be_written_or_removed() {
        let (_dir, file) = a_file_saying(b"not really a driver");
        let held = Held::open(&file).expect("opens");

        let writing = std::fs::OpenOptions::new().write(true).open(&file);
        assert!(writing.is_err(), "a writer got in while the daemon held it");

        assert!(std::fs::remove_file(&file).is_err(), "and so did a deleter");
        assert!(std::fs::rename(&file, file.with_extension("old")).is_err(), "and a renamer");

        // And it is the handle doing it, not the file being special.
        drop(held);
        assert!(
            std::fs::OpenOptions::new().write(true).open(&file).is_ok(),
            "let go, it is a file"
        );
    }

    /// Another reader is still let in.
    ///
    /// The share mode forbids changing it, not looking at it. A driver nobody
    /// else could even read would break anything that inspects it — and there is
    /// no threat in reading a file that is about to be loaded into every process
    /// that wants a tunnel.
    #[test]
    fn a_held_driver_can_still_be_read() {
        let (_dir, file) = a_file_saying(b"not really a driver");
        let _held = Held::open(&file).expect("opens");
        assert!(std::fs::read(&file).is_ok(), "reading is not changing");
    }

    /// **A file that matches a pin and is not signed is refused, naming the
    /// signature.**
    ///
    /// The case the digest alone cannot see. A person told their *digest* is
    /// wrong will go and re-pin the very file being refused — which is the worst
    /// possible outcome, because they will have done it on the daemon's own
    /// advice. So the refusal has to say which check failed.
    #[test]
    fn a_pinned_but_unsigned_driver_is_refused_for_its_signature() {
        let (_dir, file) = a_file_saying(b"not really a driver, and not signed either");
        let digest = digest_of(&file).expect("hashes");

        let refused = checked(&file, &[digest]).expect_err("nothing vouches for it");
        let said = refused.to_string();

        assert!(said.contains("signature"), "it says which check failed: {said}");
        assert!(
            !said.contains("not a pinned driver"),
            "and does not send them back to re-pin it: {said}"
        );
        assert!(said.contains("re-pinning will not help"), "in so many words: {said}");
    }

    /// An unpinned file is refused for its digest, and told what to paste.
    #[test]
    fn an_unpinned_driver_is_refused_for_its_digest() {
        let (_dir, file) = a_file_saying(b"not really a driver");
        let refused = checked(&file, &[]).expect_err("nothing is pinned");
        let said = refused.to_string();

        assert!(said.contains("not a pinned driver"), "{said}");
        assert!(said.contains("0x"), "and gives the line to paste: {said}");
        assert!(!said.contains("Authenticode signature ("), "the signature is not what failed");
    }

    /// **Nothing loads except through a held handle.**
    ///
    /// The pair this replaced was a check by path and a load by path, which is
    /// the shape the whole module exists to not have. Asserted on the code,
    /// because a load that raced would pass a behavioural test every time but
    /// one.
    #[test]
    fn nothing_is_loaded_that_was_not_held() {
        let code = crate::code_of(include_str!("driver.rs"));
        let loading = {
            let at = code.find("pub fn load()").expect("it is declared");
            let rest = &code[at..];
            let end = rest.find("#[cfg(test)]").unwrap_or(rest.len());
            &rest[..end]
        };

        assert_eq!(1, code.matches("load_from_path").count(), "loaded in one place");
        let checked_at = loading.find("checked(&path").expect("it checks");
        let loaded_at = loading.find("load_from_path").expect("it loads");
        let let_go = loading.find("drop(held)").expect("it lets go, explicitly");
        assert!(checked_at < loaded_at, "checked before loaded");
        assert!(loaded_at < let_go, "and not let go until after");

        // And no second way in that skips the handle.
        assert!(
            !code.contains("fn digest_of(path"),
            "a digest read from a path is a digest of a file that may not be the one loaded"
        );
    }

    /// Nothing is fetched to verify a signature.
    ///
    /// §2.6c: a daemon whose network is off reaches nothing, and this runs at
    /// startup. Revocation checking would have it call a certificate authority
    /// before anybody had asked for anything.
    #[test]
    fn verifying_a_signature_reaches_nothing() {
        let code = crate::code_of(include_str!("driver.rs"));
        assert!(code.contains("WTD_REVOKE_NONE"), "no revocation is checked");
        assert!(code.contains("WTD_CACHE_ONLY_URL_RETRIEVAL"), "and nothing is retrieved");
        for reaching in ["WTD_REVOKE_WHOLECHAIN", "WTD_USE_IE4_STATE_FLAG"] {
            assert!(!code.contains(reaching), "`{reaching}` would reach for a certificate");
        }
    }

    /// The state the verification opens is closed on every answer.
    #[test]
    fn the_verification_closes_what_it_opened() {
        let code = crate::code_of(include_str!("driver.rs"));
        assert!(code.contains("WTD_STATEACTION_CLOSE"), "it is closed");
        assert!(
            code.find("WTD_STATEACTION_CLOSE") < code.find("if said == 0"),
            "before the answer is looked at, so no way out skips it"
        );
    }

    /// Never by name. `load()` with a bare name searches, and the search order
    /// is how a process ends up with somebody else's library.
    #[test]
    fn the_driver_is_looked_for_beside_the_executable() {
        let path = expected_path().expect("the executable has a location");

        assert!(path.is_absolute(), "{path:?}");
        assert!(path.ends_with(DRIVER), "{path:?}");

        let executable = std::env::current_exe().expect("known");
        assert_eq!(path.parent(), executable.parent(), "beside the executable, nowhere else");
    }

    /// Fail closed. Whatever is pinned, everything else is refused.
    ///
    /// This used to assert `PINNED.is_empty()`, which was wrong: it made the
    /// build fail the moment an operator did exactly what the daemon told them
    /// to do. The property worth holding is that nothing unpinned loads — not
    /// that nothing is ever pinned.
    #[test]
    fn an_unpinned_digest_is_refused() {
        assert!(!is_pinned(&[0u8; 32]));
        assert!(!is_pinned(&[0xff; 32]));
        assert!(!is_pinned(&[0x5a; 32]));
    }

    /// A pin is a whole digest. A prefix would match more than one file.
    #[test]
    fn every_pin_is_a_whole_digest() {
        for pin in PINNED {
            assert_eq!(pin.len(), 32);
        }
    }

    /// The refusal has to be actionable, or the operator's next move is to
    /// delete the check.
    #[test]
    fn the_refusal_says_what_to_pin() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let file = dir.path().join(DRIVER);
        std::fs::write(&file, b"not really a driver").expect("writes");

        let digest = digest_of(&file).expect("hashes");
        let pin = as_pin(&digest);

        assert!(pin.trim_start().starts_with("[0x"), "{pin}");
        assert!(pin.trim_end().ends_with("],"), "an element of the slice, not a bare list");
        assert_eq!(pin.matches("0x").count(), 32, "every byte, ready to paste");
        assert!(!is_pinned(&digest));
    }

    #[test]
    fn the_digest_follows_the_file() {
        let dir = tempfile::tempdir().expect("a scratch directory");
        let one = dir.path().join("one");
        let two = dir.path().join("two");
        std::fs::write(&one, b"a").expect("writes");
        std::fs::write(&two, b"b").expect("writes");

        assert_ne!(digest_of(&one).expect("hashes"), digest_of(&two).expect("hashes"));
        assert_eq!(digest_of(&one).expect("hashes"), digest_of(&one).expect("hashes"));
    }

    #[test]
    fn a_missing_driver_is_refused_with_the_path() {
        let missing = Path::new("C:/nowhere/at/all/wintun.dll");
        match digest_of(missing) {
            Err(Error::BringUp { step, cause, .. }) => {
                assert_eq!(step, Step::CreatingAdapter);
                assert!(cause.contains("wintun.dll"), "{cause}");
            }
            other => panic!("expected a refusal naming the path, got {other:?}"),
        }
    }

    /// A test binary has no driver beside it, so verification fails there
    /// whatever is pinned. That is the honest outcome in CI.
    #[test]
    fn verification_fails_where_there_is_no_driver() {
        assert!(verify().is_err(), "no driver sits beside a test binary");
    }

    /// **`load` does not go through `verify`, and that is deliberate.**
    ///
    /// They look like the same check and one looks like tidying the other away.
    /// But `verify` answers a question and lets go of the handle on its way out,
    /// so a `load` built on it would be checking one file and loading whatever
    /// was there afterwards — which is exactly the pair this module replaced.
    ///
    /// `nothing_is_loaded_that_was_not_held` holds the order. This holds the
    /// shape that makes the order mean anything.
    #[test]
    fn loading_does_not_go_through_the_check_that_lets_go() {
        let code = crate::code_of(include_str!("driver.rs"));
        let loading = {
            let at = code.find("pub fn load()").expect("it is declared");
            let rest = &code[at..];
            let end = rest.find("#[cfg(test)]").unwrap_or(rest.len());
            &rest[..end]
        };

        assert!(
            !loading.contains("verify()"),
            "`verify` drops the handle, so loading through it loads what came after: {loading}"
        );
        assert!(loading.contains("checked(&path, PINNED)?"), "it keeps the handle: {loading}");
    }
}

#[cfg(test)]
mod wiring {
    /// The check runs at startup, not only when the tunnel comes up.
    ///
    /// `verify` exists separately from `load` so the daemon can say at startup
    /// what it would load — and for a while it existed and nothing called it, so
    /// a missing or unpinned driver was only discovered at the moment somebody
    /// asked for the network. That is the worst moment to discover it.
    #[test]
    fn the_daemon_checks_the_driver_before_anybody_asks_for_the_network() {
        let daemon = crate::code_of(include_str!("../programs/daemon.rs"));

        assert!(daemon.contains("driver::verify()"), "the daemon must check the driver at startup");
        assert!(
            !daemon.contains("driver::load()"),
            "but must not load it there: that belongs to bring-up, with the adapter"
        );
    }
}

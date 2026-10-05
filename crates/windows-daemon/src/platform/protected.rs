//! A directory only the system and administrators may touch.
//!
//! Where the machine keeps its networks. A service reads it with nobody logged
//! in, so what protects the material inside cannot be a sealing bound to a
//! person — it is this.
//!
//! # Why an access control here, when one was refused before
//!
//! `platform::pipe` records an explicit DACL being **considered and rejected**:
//! *"SID lookup and ACE ordering are fiddly, and a subtly wrong access control is
//! worse than none, because it claims a protection it does not deliver."*
//!
//! That objection is right and it is answered rather than ignored:
//!
//! - **Nothing is assembled by hand.** One SDDL string, parsed by the platform.
//!   No ACEs built in Rust, no ordering to get wrong.
//! - **No SIDs are looked up.** `SY` and `BA` are well-known and resolve without
//!   asking a domain anything, so the string means the same on every machine and
//!   cannot fail on one that is offline.
//! - **It is read back.** The tests create a real directory, ask Windows for the
//!   descriptor it ended up with, and compare. An access control nobody verified
//!   is exactly what the objection warns about; one that is read back is not.
//!
//! # What the string says
//!
//! ```text
//! D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)
//!  │ │ │ │    │     └── to: SY = Local System, BA = Builtin Administrators
//!  │ │ │ │    └──────── generic all
//!  │ │ │ └───────────── inherited by files and directories inside
//!  │ │ └─────────────── allow
//!  │ └───────────────── protected: inherits nothing from the parent
//!  └─────────────────── this is the DACL
//! ```
//!
//! `P` is what makes it a floor rather than an addition: whatever `%ProgramData%`
//! grants — and it grants ordinary users the right to create things — stops at
//! this directory. The inheritance flags are what carry it to every network's own
//! directory, so the portable half goes on creating those the way it always has.

#![cfg(windows)]
#![allow(
    unsafe_code,
    reason = "creating a directory, or setting a service's descriptor, with a chosen access \
              control has no safe wrapper; confined to this module"
)]

use std::path::Path;

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, GetSecurityInfo,
    SE_FILE_OBJECT, SE_SERVICE,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::System::Services::{SC_HANDLE, SetServiceObjectSecurity};

/// What went wrong, in words a person can act on.
pub type Refusal = String;

/// The access control the machine's own state carries.
///
/// Read by the tests as well as used, so that what is asserted is what is
/// applied rather than a second copy of it.
pub const ONLY_THE_SYSTEM_AND_ADMINISTRATORS: &str = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)";

/// Who may do what to the service.
///
/// ```text
/// (A;;CCLCSWRPWPDTLOCRRC;;;SY)        the system: what the default gives it
/// (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA) administrators: the same
/// (A;;CCLCSWRPLOCRRC;;;IU)            a person at the machine: query, and RP, start
/// ```
///
/// **Start, and not stop.** Starting brings up only what each network's owner
/// last chose, so it harms nobody; stopping takes every person's networks off the
/// machine at once, so it stays an administrator's. Interactive users rather
/// than authenticated ones: a service account or a network logon has no business
/// starting it, and a person at the machine or over a remote desktop does.
pub const WHO_MAY_START_THE_SERVICE: &str =
    "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)";

/// Gives the service [`WHO_MAY_START_THE_SERVICE`].
///
/// Takes the service as the control manager opened it, with `WRITE_DAC`.
///
/// # Errors
///
/// When the descriptor will not parse or the control manager refuses it.
pub fn protect_service(service: &windows_service::service::Service) -> Result<(), Refusal> {
    let handle: SC_HANDLE = service.raw_handle();
    let sddl = Wide::new(WHO_MAY_START_THE_SERVICE);
    let mut descriptor: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
    // SAFETY: `sddl` outlives the call; the out parameter is ours, freed by `Owned`.
    let parsed = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &raw mut descriptor,
            core::ptr::null_mut(),
        )
    };
    let held = Owned(descriptor);
    if parsed == 0 {
        return Err("the service's access control did not parse".to_owned());
    }
    // SAFETY: the handle is the caller's and open for the call; the descriptor is
    // alive in `held` until after it returns.
    let set = unsafe { SetServiceObjectSecurity(handle, DACL_SECURITY_INFORMATION, held.0) };
    if set == 0 {
        return Err(format!(
            "who may start the service could not be set: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// The access control a service carries, as SDDL, read back from Windows.
///
/// Takes the service as the control manager opened it, with `READ_CONTROL`.
///
/// # Errors
///
/// When the descriptor cannot be read or rendered.
pub fn describe_service(service: &windows_service::service::Service) -> Result<String, Refusal> {
    let handle: SC_HANDLE = service.raw_handle();
    let mut descriptor: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
    // SAFETY: the handle is the caller's and open for the call; every pointer we
    // do not want is null, and the descriptor is ours to free from here.
    let read = unsafe {
        GetSecurityInfo(
            handle,
            SE_SERVICE,
            DACL_SECURITY_INFORMATION,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    let held = Owned(descriptor);
    if read != 0 {
        return Err(format!("the service would not say who may use it: {read}"));
    }
    rendered(&held, DACL_SECURITY_INFORMATION)
}

/// A descriptor as SDDL.
fn rendered(held: &Owned, what: u32) -> Result<String, Refusal> {
    let mut text: windows_sys::core::PWSTR = core::ptr::null_mut();
    let mut length: u32 = 0;
    // SAFETY: `held` is a valid descriptor for the call; the out pointer is ours
    // to free.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            held.0,
            1,
            what,
            &raw mut text,
            &raw mut length,
        )
    };
    if ok == 0 || text.is_null() {
        return Err("an access control would not render".to_owned());
    }
    // SAFETY: the platform wrote `length` units at `text`, terminated.
    let units = unsafe { core::slice::from_raw_parts(text, length as usize) };
    let said = String::from_utf16_lossy(units);
    // SAFETY: allocated by the call above, freed exactly once.
    unsafe { LocalFree(text.cast::<core::ffi::c_void>() as HLOCAL) };
    Ok(said.trim_end_matches('\0').to_owned())
}

/// A null-terminated wide string, alive while a call borrows it.
struct Wide(Vec<u16>);

impl Wide {
    fn new(text: &str) -> Self {
        Self(text.encode_utf16().chain(core::iter::once(0)).collect())
    }

    fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }
}

/// A descriptor the platform allocated, freed when it goes.
struct Owned(PSECURITY_DESCRIPTOR);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a Convert… call, which allocates
            // with `LocalAlloc`, and is freed exactly once here.
            unsafe { LocalFree(self.0.cast::<core::ffi::c_void>() as HLOCAL) };
        }
    }
}

/// Creates `path` carrying the access control, if it is not there already.
///
/// **Created carrying it, never created and then tightened.** However brief, a
/// directory that exists unprotected is a directory somebody can be waiting for.
///
/// Does nothing when the directory already exists: changing the access control of
/// something already holding material is a different act, and doing it quietly
/// here would mean a downgrade elsewhere could be undone without anybody seeing.
/// [`describe`] is how a caller checks what is there.
///
/// # Errors
///
/// When the descriptor will not parse, or the directory cannot be created.
pub fn create_protected(path: &Path) -> Result<(), Refusal> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)
            .map_err(|cause| format!("{} could not be made: {cause}", parent.display()))?;
    }

    let sddl = Wide::new(ONLY_THE_SYSTEM_AND_ADMINISTRATORS);
    let mut descriptor: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
    // SAFETY: `sddl` outlives the call; the out parameter is a pointer we own
    // from here, and `Owned` frees it.
    let parsed = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &raw mut descriptor,
            core::ptr::null_mut(),
        )
    };
    let held = Owned(descriptor);
    if parsed == 0 {
        return Err("the access control for the machine's own state did not parse".to_owned());
    }

    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(core::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: held.0,
        bInheritHandle: 0,
    };
    let wide_path = Wide::new(&path.display().to_string());
    // SAFETY: both pointers are valid for the call, and the descriptor is alive
    // in `held` until after it returns.
    let made = unsafe { CreateDirectoryW(wide_path.as_ptr(), &raw const attributes) };
    if made == 0 {
        return Err(format!(
            "{} could not be made with an access control of its own: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// What to ask for about the control channel: who may use it, and how far up it
/// may be written to.
///
/// **Both, because either alone is a descriptor half read.** The channel's DACL
/// admits the people who may speak on it and its label admits the integrity they
/// may speak from, and a daemon running as the system creates it at the system's
/// own integrity unless it says otherwise — which no DACL can undo.
pub const WHAT_THE_CHANNEL_CARRIES: u32 = DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;

/// The access control `path` actually carries, as SDDL.
///
/// **This is what makes the protection checkable.** Applying a descriptor and
/// believing it was applied is the failure this module exists to avoid.
///
/// # Errors
///
/// When the descriptor cannot be read or rendered.
pub fn describe(path: &Path) -> Result<String, Refusal> {
    describe_including(path, DACL_SECURITY_INFORMATION)
}

/// What the object carries, and what kind of information to ask for.
///
/// The directory this module makes cares about the DACL alone. **The control
/// channel also carries an integrity label**, which is a different part of the
/// same descriptor and is invisible to a reader that asked only for the DACL —
/// so a check of the channel that used `describe` would report a descriptor it
/// had not read, and report it as correct.
///
/// [`WHAT_THE_CHANNEL_CARRIES`] is the pairing for that case.
///
/// # Errors
///
/// When the descriptor cannot be read or rendered.
pub fn describe_including(path: &Path, what: u32) -> Result<String, Refusal> {
    let wide_path = Wide::new(&path.display().to_string());
    let mut descriptor: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
    // SAFETY: the path outlives the call; every pointer we do not want is null,
    // and the descriptor is ours to free from here.
    let read = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            what,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    let held = Owned(descriptor);
    if read != 0 {
        return Err(format!("{} would not say what protects it: {read}", path.display()));
    }

    let mut rendered: windows_sys::core::PWSTR = core::ptr::null_mut();
    let mut length: u32 = 0;
    // SAFETY: `held` is a valid descriptor for the call; the out pointer is ours
    // to free.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            held.0,
            1,
            what,
            &raw mut rendered,
            &raw mut length,
        )
    };
    if ok == 0 || rendered.is_null() {
        return Err(format!("{}'s access control would not render", path.display()));
    }
    // SAFETY: the platform wrote `length` units at `rendered`, terminated.
    let text = unsafe { core::slice::from_raw_parts(rendered, length as usize) };
    let text = String::from_utf16_lossy(text);
    // SAFETY: allocated by the call above, freed exactly once.
    unsafe { LocalFree(rendered.cast::<core::ffi::c_void>() as HLOCAL) };
    Ok(text)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// **The test the design says this stands or falls on.**
    ///
    /// The directory is made, and then Windows is asked what protects it. What
    /// comes back must be the two entries that were asked for and nothing else,
    /// and it must be protected — a descriptor that merely *added* these to what
    /// `%ProgramData%` already grants would let an ordinary person in while
    /// looking correct in a diff.
    #[test]
    fn what_was_asked_for_is_what_the_directory_carries() {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("peerfectly-state");
        create_protected(&path).expect("makes it");

        let carried = describe(&path).expect("says what protects it");

        assert!(carried.starts_with("D:P"), "it inherits nothing from its parent: {carried}");
        assert!(carried.contains(";;;SY)"), "the system may use it: {carried}");
        assert!(carried.contains(";;;BA)"), "administrators may use it: {carried}");

        // And nobody else. Two entries, counted, so an added one fails this.
        assert_eq!(2, carried.matches("(A;").count(), "two entries and no others: {carried}");
        assert_eq!(0, carried.matches("(D;").count(), "and nothing denied: {carried}");
    }

    /// **Written because the first version of it was refused, which was the
    /// answer.**
    ///
    /// It tried to create a directory inside and assert the protection was
    /// inherited. Run as an ordinary person it was denied — which is the whole
    /// property, arriving as a failure instead of as an assertion. So it asserts
    /// that instead.
    ///
    /// Both branches say something true, and which one runs says what this
    /// process is:
    ///
    /// - refused, and an ordinary person cannot put anything in the machine's
    ///   state, which is the point of the directory;
    /// - allowed, so this is privileged — and then what it made must carry the
    ///   protection onward, because the service creates each network's directory
    ///   inside this one and the portable half knows nothing about any of it.
    #[test]
    fn an_ordinary_process_is_kept_out_and_a_privileged_one_passes_it_on() {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("peerfectly-state");
        create_protected(&path).expect("makes it");

        let inside = path.join("casa");
        match std::fs::create_dir(&inside) {
            Err(refused) => assert_eq!(
                std::io::ErrorKind::PermissionDenied,
                refused.kind(),
                "an ordinary process is kept out, and for that reason: {refused}"
            ),
            Ok(()) => {
                let carried = describe(&inside).expect("says what protects it");
                assert!(carried.contains(";;;SY)"), "carried onward: {carried}");
                assert!(carried.contains(";;;BA)"), "carried onward: {carried}");
                assert_eq!(0, carried.matches("(D;").count(), "nothing denied: {carried}");
            }
        }
    }

    /// **A person at the machine may start the service and not stop it**; the
    /// system and administrators keep what the default gives them.
    #[test]
    fn a_person_may_start_the_service_and_not_stop_it() {
        let entries: Vec<&str> = WHO_MAY_START_THE_SERVICE
            .trim_start_matches("D:")
            .split(')')
            .filter(|entry| !entry.is_empty())
            .collect();
        let rights = |who: &str| -> Vec<String> {
            let entry = entries.iter().find(|entry| entry.ends_with(&format!(";;;{who}"))).unwrap();
            let granted = entry.split(';').nth(2).unwrap();
            granted.as_bytes().chunks(2).map(|pair| String::from_utf8_lossy(pair).into()).collect()
        };

        let person = rights("IU");
        assert!(person.contains(&"RP".to_owned()), "start: {person:?}");
        for never in ["WP", "DC", "SD", "WD", "WO", "DT"] {
            assert!(!person.contains(&never.to_owned()), "`{never}` is not a person's: {person:?}");
        }
        assert!(rights("BA").contains(&"WP".to_owned()), "administrators may stop it");
        assert!(rights("SY").contains(&"WP".to_owned()), "and the system");
        assert_eq!(3, entries.len(), "and nobody else: {entries:?}");
    }

    /// Reading a service's descriptor back works, on one every machine has and
    /// anybody may read.
    #[test]
    fn a_services_access_control_is_read_back() {
        use windows_service::service::ServiceAccess;
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).unwrap();
        let dns = manager.open_service("Dnscache", ServiceAccess::READ_CONTROL).unwrap();
        let carried = describe_service(&dns).unwrap();

        assert!(carried.starts_with("D:"), "{carried}");
        assert!(carried.contains(";;;SY)"), "{carried}");
    }

    /// Making it twice is not an error, and does not quietly change what is there.
    #[test]
    fn making_it_again_changes_nothing() {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("peerfectly-state");
        create_protected(&path).expect("makes it");
        let first = describe(&path).expect("reads");

        create_protected(&path).expect("is content that it exists");
        assert_eq!(first, describe(&path).expect("reads"), "nothing was rewritten");
    }

    /// **It is created carrying the protection, never created and then tightened.**
    ///
    /// A behavioural test cannot see the difference: a directory made permissive
    /// and fixed a microsecond later reads the same afterwards as one made right.
    /// The difference is a window somebody can wait for, and the only place it is
    /// visible is the code. So the code is what is asserted.
    #[test]
    fn nothing_here_tightens_a_directory_after_making_it() {
        // Up to the tests, because below this line the forbidden names appear in
        // the list that forbids them.
        let source = include_str!("protected.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("the file has a first part");

        for afterwards in ["set_permissions", "SetNamedSecurityInfo", "SetFileSecurity"] {
            assert!(
                !source.contains(afterwards),
                "`{afterwards}` would change an access control after the thing exists, which \
                 leaves a window. The descriptor goes in at creation."
            );
        }
        assert!(
            source.contains("CreateDirectoryW(wide_path.as_ptr(), &raw const attributes)"),
            "the directory is made with the descriptor, in one call"
        );
        assert!(
            !source.contains("std::fs::create_dir(&path)"),
            "the ordinary create would make it with whatever the parent grants"
        );
    }
}

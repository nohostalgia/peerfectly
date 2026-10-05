//! Protecting private key material at rest, the way each platform does it.
//!
//! The platforms give **different guarantees**, and this module says so rather
//! than presenting one:
//!
//! | | Another local user or app | A process as the owning person | A privileged process | A backup or a stolen disk |
//! |---|---|---|---|---|
//! | Unix, `0600` | defended | **not** defended | **not** defended | **not** defended |
//! | Windows, DPAPI to the account | defended | **not** defended | **not** defended | defended |
//! | Windows, DPAPI to the machine, behind an access control | defended | **defended** | **not** defended | defended |
//! | Android, keystore sealer | defended | **not** defended | **not** defended | defended |
//!
//! The row that looks like a loosening is not one. Binding to the machine means
//! any process that can **read the bytes** may ask for them to be opened — so
//! the sealing stops being the protection and the access control becomes it. And
//! against the attacker this whole thing is about, a process running as the
//! person, an access control that refuses the read is stronger than a sealing
//! that opens for whoever is that person. What it gives up is nothing that was
//! ever held: a privileged process could already read the person's file and open
//! it as them.
//!
//! Android is a Unix and does not take the Unix row. Its sealing is supplied by
//! the app through [`crate::store::Sealer`]: a non-exportable keystore key seals
//! the material before it is written into the app's private storage, so a copy
//! of that storage — a backup, an image of the phone — is not the key. What it
//! does not defend against is code running as the app itself, which can ask the
//! keystore exactly as the app does; a rooted phone is that case.
//!
//! Unix stores the material in the clear and relies on file permissions, so
//! anything that can read the file gets the key: root, a filesystem backup, a
//! disk pulled out of a machine. Windows seals the material to the user
//! account, and the sealing key derives from that account's credentials rather
//! than sitting next to the file, so a copy of the file alone is not enough.
//!
//! An explicit owner-only DACL was considered for Windows and rejected: SID
//! lookup and ACE ordering are fiddly, and a subtly wrong access control is
//! worse than none, because it claims a protection it does not deliver. DPAPI
//! is two calls and is what the platform provides for exactly this job.

use crate::error::Result;

/// Who the sealing binds the material to.
///
/// Two answers, and which one is right depends on **what will need to open it**
/// rather than on which is stronger in the abstract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    /// To the account that sealed it.
    ///
    /// A copy of the file taken elsewhere is not the key, because the sealing
    /// key derives from that account's credentials. What it does not defend
    /// against is a process running **as that person**, which can ask for it
    /// exactly as the person's own software does.
    Account,
    /// To the machine.
    ///
    /// Any process on the machine that can **read the bytes** can ask for them
    /// to be opened, so the sealing alone is not the protection — where the file
    /// is kept, and who may read it, is the other half, and neither stands
    /// alone. A copy taken to another machine is still not the key.
    ///
    /// This is what a service needs. A secret bound to a person cannot be opened
    /// by something running with nobody logged in, and the keys that must work
    /// with nobody present are exactly the ones a service holds.
    Machine,
}

/// Seals key material for storage on this platform.
///
/// On Unix this is the identity function — the protection is the file mode, so
/// there is nothing to do to the bytes.
///
/// # Errors
///
/// When the platform will not seal the material.
pub fn seal_bound_to(plain: &[u8], bound: Bound) -> Result<Vec<u8>> {
    platform::seal(plain, bound)
}

/// Reverses [`seal_bound_to`].
///
/// # Errors
///
/// When the bytes are not sealed material this process may open.
pub fn unseal_bound_to(stored: &[u8], bound: Bound) -> Result<Vec<u8>> {
    platform::unseal(stored, bound)
}

/// Seals to the account that seals it.
///
/// # Errors
///
/// As [`seal_bound_to`].
pub fn seal(plain: &[u8]) -> Result<Vec<u8>> {
    seal_bound_to(plain, Bound::Account)
}

/// Reverses [`seal`].
///
/// # Errors
///
/// As [`unseal_bound_to`].
pub fn unseal(stored: &[u8]) -> Result<Vec<u8>> {
    unseal_bound_to(stored, Bound::Account)
}

/// Whether stored bytes are protected by their content rather than by the
/// filesystem.
///
/// True on Windows, false on Unix. Callers use it to decide whether a
/// permission check is the thing standing between the file and an attacker.
#[must_use]
pub const fn material_is_sealed() -> bool {
    platform::MATERIAL_IS_SEALED
}

#[cfg(not(windows))]
mod platform {
    use super::Result;

    /// Unix leaves the bytes as they are; the file mode is the protection.
    pub(super) const MATERIAL_IS_SEALED: bool = false;

    /// Returns the material unchanged.
    ///
    /// The scope is accepted and ignored: there is no sealing here to bind to
    /// anything, and pretending otherwise would let a caller believe a Unix file
    /// carried a protection it does not.
    pub(super) fn seal(plain: &[u8], bound: super::Bound) -> Result<Vec<u8>> {
        let _ = bound;
        Ok(plain.to_vec())
    }

    /// Returns the material unchanged.
    pub(super) fn unseal(stored: &[u8], bound: super::Bound) -> Result<Vec<u8>> {
        let _ = bound;
        Ok(stored.to_vec())
    }
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "DPAPI is a Win32 API and has no safe wrapper; the unsafe surface is \
              confined to this module and is two calls wide"
)]
mod platform {
    use super::Result;
    use crate::error::Error;

    use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CryptProtectData, CryptUnprotectData,
    };

    /// Windows protects the bytes themselves.
    pub(super) const MATERIAL_IS_SEALED: bool = true;

    /// A blob returned by DPAPI, freed when it goes.
    ///
    /// DPAPI allocates with `LocalAlloc`, so the caller must `LocalFree`. Tying
    /// that to a drop means an early return cannot leak it.
    struct OwnedBlob {
        /// The blob DPAPI filled in.
        blob: CRYPT_INTEGER_BLOB,
    }

    impl OwnedBlob {
        /// An empty blob for DPAPI to fill.
        const fn empty() -> Self {
            Self { blob: CRYPT_INTEGER_BLOB { cbData: 0, pbData: core::ptr::null_mut() } }
        }

        /// Copies the contents out.
        fn to_vec(&self) -> Vec<u8> {
            if self.blob.pbData.is_null() {
                return Vec::new();
            }
            let len = self.blob.cbData as usize;
            // SAFETY: DPAPI reported `cbData` bytes at `pbData`, and the blob is
            // alive for the duration of this borrow.
            unsafe { core::slice::from_raw_parts(self.blob.pbData, len) }.to_vec()
        }
    }

    impl Drop for OwnedBlob {
        fn drop(&mut self) {
            if !self.blob.pbData.is_null() {
                // SAFETY: `pbData` came from DPAPI, which allocates with
                // `LocalAlloc`, and is freed exactly once here.
                unsafe {
                    LocalFree(self.blob.pbData.cast::<core::ffi::c_void>() as HLOCAL);
                }
            }
        }
    }

    /// The flag DPAPI takes for a scope.
    const fn flag(bound: super::Bound) -> u32 {
        match bound {
            super::Bound::Account => 0,
            super::Bound::Machine => CRYPTPROTECT_LOCAL_MACHINE,
        }
    }

    /// Seals material, bound as asked.
    pub(super) fn seal(plain: &[u8], bound: super::Bound) -> Result<Vec<u8>> {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(plain.len())
                .map_err(|_| Error::Storage { detail: "material too large to seal".to_owned() })?,
            pbData: plain.as_ptr().cast_mut(),
        };
        let mut output = OwnedBlob::empty();

        // SAFETY: `input` points at `plain` for the duration of the call, and
        // `output` is a valid blob DPAPI fills in. The optional arguments are
        // null, which the API documents as "not used".
        let ok = unsafe {
            CryptProtectData(
                &raw mut input,
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                flag(bound),
                &raw mut output.blob,
            )
        };
        if ok == 0 {
            return Err(Error::Storage { detail: "the system could not seal the key".to_owned() });
        }
        Ok(output.to_vec())
    }

    /// Unseals material this process may open.
    ///
    /// Fails when the material was sealed somewhere this process cannot reach —
    /// another account, or another machine — which is the protection working
    /// rather than an error to route around.
    pub(super) fn unseal(stored: &[u8], bound: super::Bound) -> Result<Vec<u8>> {
        let mut input = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(stored.len()).map_err(|_| Error::CorruptIdentity)?,
            pbData: stored.as_ptr().cast_mut(),
        };
        let mut output = OwnedBlob::empty();

        // SAFETY: as above; `input` borrows `stored` for the call only.
        let ok = unsafe {
            CryptUnprotectData(
                &raw mut input,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                flag(bound),
                &raw mut output.blob,
            )
        };
        if ok == 0 {
            // Either the bytes are not a DPAPI blob, or they belong somewhere
            // this process cannot reach. Both mean this identity is not ours.
            return Err(Error::CorruptIdentity);
        }
        Ok(output.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::{Bound, material_is_sealed, seal, seal_bound_to, unseal, unseal_bound_to};

    #[test]
    fn sealing_round_trips() {
        let material = b"thirty-two bytes of key material".as_slice();
        let sealed = seal(material).expect("seals");
        assert_eq!(unseal(&sealed).expect("unseals"), material);
    }

    /// On a platform that seals, the stored bytes must not be the material. On
    /// one that does not, the file mode is the protection and the bytes are
    /// expected to be the material.
    #[test]
    fn sealing_hides_the_material_where_it_claims_to() {
        let material = b"thirty-two bytes of key material".as_slice();
        let sealed = seal(material).expect("seals");
        if material_is_sealed() {
            assert_ne!(sealed, material, "sealed storage must not hold the plain material");
            assert!(
                !sealed.windows(material.len()).any(|window| window == material),
                "and must not contain it anywhere"
            );
        } else {
            assert_eq!(sealed, material, "unsealed storage relies on the file mode instead");
        }
    }

    #[test]
    fn corrupted_sealed_material_is_refused() {
        if !material_is_sealed() {
            return;
        }
        let sealed = seal(b"key material".as_slice()).expect("seals");
        let mut broken = sealed;
        if let Some(first) = broken.first_mut() {
            *first ^= 0xff;
        }
        assert!(unseal(&broken).is_err(), "tampered sealed material must not unseal");
    }

    /// **What DPAPI does across the two scopes, measured rather than assumed.**
    ///
    /// A blob sealed either way opens either way, from this account on this
    /// machine: the flag steers the *sealing* and is ignored on opening. So
    /// there is no test to write in which one scope refuses the other's bytes,
    /// and writing one would mean adding a marker of our own and asserting our
    /// own marker.
    ///
    /// What the scopes actually separate is **who else** can open them, and that
    /// needs a second account or a second machine. It is in `VERIFICATION.md`,
    /// not here, and this test exists so that nobody looks for it here.
    ///
    /// Where nothing is sealed — Unix, where the file mode is the protection —
    /// both scopes leave the bytes as they are, and that is what is asserted.
    #[test]
    fn the_scopes_differ_in_the_sealing_and_not_in_the_opening() {
        let material = b"thirty-two bytes of key material".as_slice();
        let by_account = seal_bound_to(material, Bound::Account).expect("seals");
        let by_machine = seal_bound_to(material, Bound::Machine).expect("seals");

        if !material_is_sealed() {
            assert_eq!(material, by_account, "nothing to seal to an account here");
            assert_eq!(material, by_machine, "nor to a machine");
            return;
        }
        assert_ne!(by_account, by_machine, "the two sealings really are different");
        assert_eq!(material, unseal_bound_to(&by_account, Bound::Account).expect("opens"));
        assert_eq!(material, unseal_bound_to(&by_machine, Bound::Machine).expect("opens"));
    }

    /// Whatever the scope, what is written down is not the material — where the
    /// platform seals at all. Where it does not, the bytes are the material and
    /// the file mode protects them, as `sealing_hides_the_material_where_it_claims_to`
    /// already says.
    #[test]
    fn neither_scope_writes_the_material_down() {
        let material = b"thirty-two bytes of key material".as_slice();
        for bound in [Bound::Account, Bound::Machine] {
            let sealed = seal_bound_to(material, bound).expect("seals");
            if !material_is_sealed() {
                assert_eq!(material, sealed, "{bound:?}: unsealed storage relies on the file mode");
                continue;
            }
            assert!(
                !sealed.windows(material.len()).any(|window| window == material),
                "{bound:?} left the material in the bytes"
            );
        }
    }

    /// Bytes that are not sealed material are refused, in both scopes — where
    /// there is sealing to tell them apart. Where there is none, every byte
    /// string is what it says, and is handed back as it is.
    #[test]
    fn nonsense_is_refused_in_both_scopes() {
        let nonsense = b"not a sealed thing at all".as_slice();
        for bound in [Bound::Account, Bound::Machine] {
            if material_is_sealed() {
                assert!(unseal_bound_to(nonsense, bound).is_err(), "{bound:?}");
            } else {
                assert_eq!(nonsense, unseal_bound_to(nonsense, bound).expect("opens"), "{bound:?}");
            }
        }
    }
}

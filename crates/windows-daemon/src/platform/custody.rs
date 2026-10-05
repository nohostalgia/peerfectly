//! The machine's own key store, where a network's signing key is made and kept.
//!
//! A P-256 key created inside the TPM through CNG's `Microsoft Platform Crypto
//! Provider`, marked non-exportable, living in the key store of the person who
//! made it. Its private half never exists as a value anywhere: it is generated
//! in the chip and used in the chip, and what this module handles is the public
//! half and signatures.
//!
//! # The asking is the key's
//!
//! The key is created with a UI policy that makes **CNG itself** require the
//! person before every use of the private half. That is the whole point, and it
//! is not the same as asking first and then signing.
//!
//! `UserConsentVerifier` would let the prompt name the act, and is *advisory*:
//! our code asks, then our code signs. Malware running as the person — the
//! attacker this exists to stop — does not run our code. It calls
//! `NCryptSignHash` itself, and a key protected that way signs without a word.
//! The TPM would then be stopping the key from being **taken** while leaving it
//! free to be **used**, and admissions and revocations are permanent.
//!
//! `android-client` already settled this for the phone: *"a prompt shown by the
//! app alone SHALL NOT be presented as that protection"*. This is the same rule
//! on a different machine. The cost is that CNG's prompt is fixed when the key
//! is created and cannot name the act, so it names the network — there is one
//! signing key per network. What the person is told they are authorising is read
//! off the bytes, elsewhere, and this module makes no claim about it.
//!
//! # The key belongs to the machine, not to whoever made it
//!
//! Every key here is created and opened with `NCRYPT_MACHINE_KEY_FLAG`, and that
//! is load-bearing rather than tidy. CNG keeps keys in **per-user containers**,
//! so without it a key lands in the container of whatever account happened to
//! create it — and the two halves of this are two accounts: the daemon makes the
//! key running as `LocalSystem`, and the signature is obtained by `peerfectly.exe`
//! running as the person. The key would be made where the signer could not look.
//!
//! What it costs is that a machine key's default descriptor admits `SYSTEM` and
//! administrators, so signing needs an elevated console. That is the bar those
//! acts already have: founding, admitting and revoking all need Administrator,
//! and reading state — which needs no key — needs nothing.
//!
//! # Why the `unsafe` is here
//!
//! CNG is a C API with no safe wrapper, and `platform` is where this crate keeps
//! what cannot run in CI and what needs `unsafe` — beside `route_table`. Nothing
//! here decides anything: which key, when to sign and what the signature means
//! are all decided in the portable half.
//!
//! **Nothing here can be tested in CI**, because a TPM does not simulate. What
//! it does is recorded in `VERIFICATION.md` against expectations written before
//! the run.

#![cfg(windows)]
#![allow(
    unsafe_code,
    reason = "CNG is a Win32 API with no safe wrapper; the unsafe surface is confined to this \
              module, as `route_table` and `identity::seal` confine theirs"
)]

use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, MS_PLATFORM_CRYPTO_PROVIDER,
    NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_KEY_HANDLE, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_PERSIST_FLAG,
    NCRYPT_PROV_HANDLE, NCRYPT_UI_POLICY, NCRYPT_UI_POLICY_PROPERTY, NCRYPT_UI_PROTECT_KEY_FLAG,
    NCRYPT_USE_CONTEXT_PROPERTY, NCRYPT_WINDOW_HANDLE_PROPERTY, NCryptCreatePersistedKey,
    NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
};

/// What went wrong, in words a person can act on.
pub type Refusal = String;

/// A null-terminated wide string, kept alive while a call borrows it.
struct Wide(Vec<u16>);

impl Wide {
    /// The string, with the terminator CNG expects.
    fn new(text: &str) -> Self {
        Self(text.encode_utf16().chain(core::iter::once(0)).collect())
    }

    /// A pointer CNG may read for as long as this value lives.
    fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }
}

/// Turns an `HRESULT` into a refusal naming what failed.
fn checked(status: i32, doing: &str) -> Result<(), Refusal> {
    if status == 0 {
        return Ok(());
    }
    // A person declining, or the prompt timing out. CNG reports it as cancelled
    // by the user, and it is an ordinary outcome rather than a fault.
    if status == self::status::USER_CANCELLED {
        return Err(DECLINED.to_owned());
    }
    if status == self::status::BAD_KEYSET {
        return Err(NO_SUCH_KEY.to_owned());
    }
    // A machine key admits SYSTEM and administrators, so from an ordinary
    // console this is the answer, and the code alone does not say what to do.
    if status == self::status::PERM {
        return Err(format!(
            "{doing} failed: the key is this machine's, and only an administrator may use it.              Run this from an elevated console."
        ));
    }
    Err(format!("{doing} failed: the key store answered 0x{status:08x}"))
}

/// The `HRESULT`s this module tells apart, written as the hex CNG documents.
///
/// **Written in hex and cast, not as decimals.** They were decimals first, and
/// one of them was wrong: `-2_146_893_802` is `NTE_BAD_KEYSET`, not
/// `NTE_USER_CANCELLED`, so a key that was simply not there was reported as a
/// person declining to sign — and a network that would not open said the wrong
/// thing about why. A decimal is not checkable by eye against the documentation;
/// the hex is.
mod status {
    /// A person declined, or the prompt timed out.
    pub const USER_CANCELLED: i32 = 0x8009_0036_u32 as i32;
    /// There is no key under that name.
    pub const BAD_KEYSET: i32 = 0x8009_0016_u32 as i32;
    /// Access denied: a machine key opened by somebody who is not an administrator.
    pub const PERM: i32 = 0x8009_0010_u32 as i32;
}

/// What a refusal says when the key store holds no such key.
///
/// Distinct from every other refusal on purpose. *No such key* is an answer —
/// this device was given an identity naming a key that is gone — and *the store
/// would not answer* is a fault. Reporting the second as the first is how the
/// reason for a network that will not open gets thrown away.
pub const NO_SUCH_KEY: &str = "the key store holds no key under that name";

/// Whether a refusal is the key simply not being there.
#[must_use]
pub fn is_absent(refusal: &str) -> bool {
    refusal == NO_SUCH_KEY
}

/// What a refusal says when a person declined.
///
/// Matched rather than parsed by the caller: a decline is not a failure, and the
/// surfaces above say so in their own words.
pub const DECLINED: &str = "the person did not authorise the key store to sign";

/// Whether a refusal is a person declining rather than something going wrong.
#[must_use]
pub fn is_declined(refusal: &str) -> bool {
    refusal == DECLINED
}

/// The machine's key store, opened once.
pub struct Store {
    /// CNG's handle on the platform provider.
    provider: NCRYPT_PROV_HANDLE,
}

// The handle is a kernel object CNG serialises access to; nothing in this type
// is shared mutable state of ours.
unsafe impl Send for Store {}
unsafe impl Sync for Store {}

impl Drop for Store {
    fn drop(&mut self) {
        // Nothing to report: a handle that will not close is not a thing a person
        // can do anything about, and the process is on its way out.
        let _closed = unsafe { NCryptFreeObject(self.provider) };
    }
}

/// One key in the store, closed when it goes out of scope.
struct Key {
    /// CNG's handle on it.
    handle: NCRYPT_KEY_HANDLE,
}

impl Drop for Key {
    fn drop(&mut self) {
        let _closed = unsafe { NCryptFreeObject(self.handle) };
    }
}

impl Store {
    /// Opens the platform provider, which is the TPM.
    ///
    /// # Errors
    ///
    /// When this machine has no platform provider — which is a machine with no
    /// TPM, and is an answer rather than a fault.
    pub fn open() -> Result<Self, Refusal> {
        let mut provider: NCRYPT_PROV_HANDLE = 0;
        let status =
            unsafe { NCryptOpenStorageProvider(&raw mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) };
        checked(status, "opening the machine's key store")?;
        Ok(Self { provider })
    }

    /// Whether this machine can actually hold a protected signing key.
    ///
    /// **Asked by doing it.** Opening the provider is not the test: a TPM 1.2 has
    /// no elliptic curves at all, and a provider that opens and then cannot make
    /// a P-256 key would have answered yes to the wrong question. So a scratch
    /// key is created, used and removed, and what that does is the answer.
    ///
    /// The scratch key carries no UI policy, because nobody is here to answer one
    /// and the question is about the curve rather than about the prompt.
    #[must_use]
    pub fn usable(&self) -> bool {
        const SCRATCH: &str = "peerfectly.probe";

        let made = self.create_key(SCRATCH, None);
        let Ok(key) = made else { return false };
        let works = self.public_key_of(&key).is_ok();
        // Removed whether or not it worked: a probe that left keys behind would
        // fill a person's key store with them.
        let _removed = unsafe { NCryptDeleteKey(key.handle, 0) };
        core::mem::forget(key);
        works
    }

    /// Creates a network's signing key, and returns its public half.
    ///
    /// Non-exportable, and — when `asking` names a network — protected by CNG's
    /// own consent prompt, which then stands for every use of the private half
    /// however it is reached.
    ///
    /// # Errors
    ///
    /// When the key cannot be created, or its public half cannot be read.
    pub fn create(&self, name: &str, network: &str) -> Result<Vec<u8>, Refusal> {
        let key = self.create_key(name, Some(network))?;
        self.public_key_of(&key)
    }

    /// The compressed public point of the key called `name`.
    ///
    /// # Errors
    ///
    /// When there is no such key, or its public half is not a P-256 point.
    pub fn public_key(&self, name: &str) -> Result<Vec<u8>, Refusal> {
        let key = self.open_key(name)?;
        self.public_key_of(&key)
    }

    /// Signs `message` with the key called `name`.
    ///
    /// # Errors
    ///
    /// As [`Self::sign_with`].
    pub fn sign(&self, name: &str, message: &[u8]) -> Result<Vec<u8>, Refusal> {
        let key = self.open_key(name)?;
        Self::sign_with(&key, message)
    }

    /// Signs every message of a batch with the key called `name`, through one
    /// open handle.
    ///
    /// Before the first signature the handle is given what CNG lets a caller
    /// put on its dialog: `context`, a line saying what the batch is, and the
    /// console window as the dialog's owner, so it opens in front of the command
    /// that asked rather than behind it. **Neither is the protection** — the
    /// key's own policy asks whether or not they are set — so a version of
    /// Windows that will not take one is told about it in `noted` and signing
    /// goes on. Whether one dialog answers for the whole handle or one appears per
    /// signature is CNG's; this asks through one handle so it can be one.
    ///
    /// All or nothing: a refusal partway hands back no signatures.
    ///
    /// # Errors
    ///
    /// As [`Self::sign_with`], for any item.
    pub fn sign_all(
        &self,
        name: &str,
        messages: &[&[u8]],
        context: &str,
        noted: &mut Vec<Refusal>,
    ) -> Result<Vec<Vec<u8>>, Refusal> {
        let key = self.open_key(name)?;
        noted.extend(Self::tell_the_dialog(&key, context));
        messages.iter().map(|message| Self::sign_with(&key, message)).collect()
    }

    /// Gives the key's dialog the act and its owner window, and says which of
    /// the two Windows would not take.
    fn tell_the_dialog(key: &Key, context: &str) -> Vec<Refusal> {
        let mut not_taken = Vec::new();

        let wide = Wide::new(context);
        let bytes = u32::try_from(wide.0.len().saturating_mul(2)).unwrap_or(0);
        let status = unsafe {
            NCryptSetProperty(
                key.handle,
                NCRYPT_USE_CONTEXT_PROPERTY,
                wide.as_ptr().cast::<u8>(),
                bytes,
                0,
            )
        };
        if let Err(refusal) = checked(status, "describing the act on the key store's dialog") {
            not_taken.push(refusal);
        }

        let owner = unsafe { windows_sys::Win32::System::Console::GetConsoleWindow() };
        if !owner.is_null() {
            let status = unsafe {
                NCryptSetProperty(
                    key.handle,
                    NCRYPT_WINDOW_HANDLE_PROPERTY,
                    (&raw const owner).cast::<u8>(),
                    u32::try_from(core::mem::size_of_val(&owner)).unwrap_or(0),
                    0,
                )
            };
            if let Err(refusal) = checked(status, "putting the key store's dialog in front") {
                not_taken.push(refusal);
            }
        }
        not_taken
    }

    /// Signs `message` with an open key.
    ///
    /// CNG signs a hash rather than a message, and for ECDSA it produces a fixed
    /// `r‖s` — not the DER a phone's keystore produces for the same curve. Both
    /// are read by `identity::encodings`, which is where every key store's
    /// dialect is turned into the one the roster takes.
    ///
    /// # Errors
    ///
    /// When the person declines, or when what came back is not a signature this
    /// roster can use.
    fn sign_with(key: &Key, message: &[u8]) -> Result<Vec<u8>, Refusal> {
        let digest = what_the_curve_hashes_with(message);

        let mut written: u32 = 0;
        let status = unsafe {
            NCryptSignHash(
                key.handle,
                core::ptr::null(),
                digest.as_ptr(),
                32,
                core::ptr::null_mut(),
                0,
                &raw mut written,
                0,
            )
        };
        checked(status, "asking the key store how long a signature is")?;

        let mut signature = vec![0_u8; written as usize];
        let status = unsafe {
            NCryptSignHash(
                key.handle,
                core::ptr::null(),
                digest.as_ptr(),
                32,
                signature.as_mut_ptr(),
                written,
                &raw mut written,
                0,
            )
        };
        checked(status, "signing")?;
        signature.truncate(written as usize);

        identity::encodings::signature_from_fixed(&signature).map_err(|cause| cause.to_string())
    }

    /// Removes the key called `name`.
    ///
    /// # Errors
    ///
    /// When there is no such key, or it will not be removed.
    pub fn remove(&self, name: &str) -> Result<(), Refusal> {
        let key = self.open_key(name)?;
        let status = unsafe { NCryptDeleteKey(key.handle, 0) };
        // Deleting frees the handle, so the guard must not free it again.
        core::mem::forget(key);
        checked(status, "removing the key")
    }

    /// Creates a persisted, non-exportable P-256 key.
    fn create_key(&self, name: &str, network: Option<&str>) -> Result<Key, Refusal> {
        let wide_name = Wide::new(name);
        let mut handle: NCRYPT_KEY_HANDLE = 0;
        let status = unsafe {
            NCryptCreatePersistedKey(
                self.provider,
                &raw mut handle,
                BCRYPT_ECDSA_P256_ALGORITHM,
                wide_name.as_ptr(),
                0,
                // Never `NCRYPT_OVERWRITE_KEY_FLAG`: a name that is taken is
                // refused, not emptied of the key a network depends on.
                NCRYPT_MACHINE_KEY_FLAG,
            )
        };
        checked(status, "creating a key in the machine's key store")?;
        let key = Key { handle };

        // Non-exportable, before the key exists rather than after. A key that
        // could be exported for even an instant is a key that may have been.
        let policy: u32 = 0;
        let status = unsafe {
            NCryptSetProperty(
                key.handle,
                NCRYPT_EXPORT_POLICY_PROPERTY,
                (&raw const policy).cast::<u8>(),
                4,
                NCRYPT_PERSIST_FLAG,
            )
        };
        checked(status, "marking the key non-exportable")?;

        // And the asking, fixed on the key, so that it holds for every use of the
        // private half however it is reached — including by code that is not ours.
        if let Some(network) = network {
            let title = Wide::new("peerfectly");
            let friendly = Wide::new(&format!(
                "peerfectly — {}",
                if network.is_empty() { "a joined network" } else { network }
            ));
            let description = Wide::new(&creation_description(network));
            let ui = NCRYPT_UI_POLICY {
                dwVersion: 1,
                dwFlags: NCRYPT_UI_PROTECT_KEY_FLAG,
                pszCreationTitle: title.as_ptr(),
                pszFriendlyName: friendly.as_ptr(),
                pszDescription: description.as_ptr(),
            };
            let status = unsafe {
                NCryptSetProperty(
                    key.handle,
                    NCRYPT_UI_POLICY_PROPERTY,
                    (&raw const ui).cast::<u8>(),
                    u32::try_from(core::mem::size_of::<NCRYPT_UI_POLICY>()).unwrap_or(0),
                    NCRYPT_PERSIST_FLAG,
                )
            };
            checked(status, "making the key ask before it signs")?;
        }

        let status = unsafe { NCryptFinalizeKey(key.handle, 0) };
        checked(status, "finishing the key")?;
        Ok(key)
    }

    /// Opens the key called `name`.
    fn open_key(&self, name: &str) -> Result<Key, Refusal> {
        let wide_name = Wide::new(name);
        let mut handle: NCRYPT_KEY_HANDLE = 0;
        let status = unsafe {
            NCryptOpenKey(
                self.provider,
                &raw mut handle,
                wide_name.as_ptr(),
                0,
                NCRYPT_MACHINE_KEY_FLAG,
            )
        };
        checked(status, &format!("opening the key `{name}`"))?;
        Ok(Key { handle })
    }

    /// Reads a key's public half as the roster's compressed point.
    fn public_key_of(&self, key: &Key) -> Result<Vec<u8>, Refusal> {
        let mut written: u32 = 0;
        let status = unsafe {
            NCryptExportKey(
                key.handle,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                core::ptr::null(),
                core::ptr::null_mut(),
                0,
                &raw mut written,
                0,
            )
        };
        checked(status, "asking the key store for the public key's size")?;

        let mut blob = vec![0_u8; written as usize];
        let status = unsafe {
            NCryptExportKey(
                key.handle,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                core::ptr::null(),
                blob.as_mut_ptr(),
                written,
                &raw mut written,
                0,
            )
        };
        checked(status, "reading the public key")?;
        blob.truncate(written as usize);

        // `BCRYPT_ECCKEY_BLOB` is a magic value and a coordinate size, then the
        // two coordinates. Eight bytes of header, thirty-two each.
        let x = blob.get(8..40).ok_or_else(|| {
            "the key store's public key is too short to be a P-256 point".to_owned()
        })?;
        let y = blob.get(40..72).ok_or_else(|| {
            "the key store's public key is too short to be a P-256 point".to_owned()
        })?;
        identity::encodings::public_key_from_point(x, y).map_err(|cause| cause.to_string())
    }
}

/// What the key store's dialog says of a network's key, fixed when it is made.
///
/// CNG shows this every time the key is used and it cannot change afterwards,
/// so it cannot name the act. It names the network, says where the act is
/// named, and says what to do when nothing was asked — which is the case this
/// dialog exists for: code that is not ours using the key.
#[must_use]
pub fn creation_description(network: &str) -> String {
    // A key made while joining is made before the network has a name here, and
    // the description is fixed for good; so it says what is always true of it.
    if network.is_empty() {
        return "peerfectly is asking to sign for a network this device joined. The window you asked \
                from says what. If you did not just ask for something, refuse."
            .to_owned();
    }
    format!(
        "peerfectly is asking to sign an administrative act for the network \"{network}\". The \
         window you asked from says which act. If you did not just ask for one, refuse."
    )
}

/// SHA-256 of a message, which is what CNG signs for a P-256 key.
///
/// Named for what it is **not**: the roster hashes with BLAKE3 everywhere else,
/// and this is the one place a different hash is required — by ECDSA over P-256,
/// which fixes it. A reader who assumed BLAKE3 here would produce signatures
/// that verify nowhere, and find out on another device.
fn what_the_curve_hashes_with(message: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.finalize().into()
}

#[cfg(test)]
#[allow(clippy::panic, reason = "a test reports failure by panicking")]
mod tests {
    use super::{checked, status};

    /// **Made and opened in the same container, which is the machine's.**
    ///
    /// CNG keeps keys per user. The daemon makes this one as `LocalSystem` and
    /// `peerfectly.exe` opens it as the person, so a key without this flag is made
    /// where the signer cannot look — and the failure reads *"no such key"*, a
    /// long way from the cause. A behavioural test cannot see it in one process,
    /// because in one process both halves are the same account.
    #[test]
    fn a_key_in_the_store_is_never_replaced() {
        // Comments are stripped, so the one saying why the flag is absent does
        // not count: this is about the call.
        let code = crate::code_of(include_str!("custody.rs"));
        let at = code.find("NCryptCreatePersistedKey(").expect("the call");
        let rest = &code[at..];
        let call = &rest[..rest.find(';').unwrap_or(rest.len())];
        assert!(
            !call.contains("NCRYPT_OVERWRITE_KEY_FLAG"),
            "a name that is taken must be refused, not emptied of its network's key"
        );
    }

    #[test]
    fn a_key_is_the_machines_at_both_ends() {
        let code = crate::code_of(include_str!("custody.rs"));

        for call in ["NCryptCreatePersistedKey(", "NCryptOpenKey("] {
            // The open paren is what tells the call from the import list, where
            // the same name appears first and followed by a comma.
            let at = code.find(call).unwrap_or_else(|| panic!("`{call}` is called"));
            let rest = &code[at..];
            let end = rest.find(';').unwrap_or(rest.len());
            assert!(
                rest[..end].contains("NCRYPT_MACHINE_KEY_FLAG"),
                "`{call}` without the machine flag looks in the calling account's container"
            );
        }
    }

    /// The codes are what CNG documents, checked against the hex rather than
    /// against a decimal nobody can read.
    ///
    /// This exists because one of them was wrong and nothing said so: a key that
    /// was not there came back as a person declining, which is a different thing
    /// to tell somebody and sent a machine run looking in the wrong place.
    #[test]
    fn the_codes_are_the_ones_cng_documents() {
        assert_eq!(0x8009_0036_u32, status::USER_CANCELLED as u32, "NTE_USER_CANCELLED");
        assert_eq!(0x8009_0016_u32, status::BAD_KEYSET as u32, "NTE_BAD_KEYSET");
        assert_ne!(status::USER_CANCELLED, status::BAD_KEYSET, "and they are two codes");
        assert_eq!(0x8009_0010_u32, status::PERM as u32, "NTE_PERM");
        let refused = checked(status::PERM, "opening the key").expect_err("refused");
        assert!(refused.contains("elevated console"), "and says what to do: {refused}");
    }

    /// **A new key's dialog says where the act is named, and to refuse what was
    /// not asked.**
    #[test]
    fn a_new_key_says_to_refuse_what_was_not_asked() {
        let said = super::creation_description("casa");
        assert!(said.contains("\"casa\""), "{said}");
        assert!(said.contains("window you asked from says which act"), "{said}");
        assert!(said.contains("did not just ask for one, refuse"), "{said}");

        let joined = super::creation_description("");
        assert!(joined.contains("a network this device joined"), "{joined}");
        assert!(!joined.contains("\"\""), "never an empty name: {joined}");
    }

    /// The two answers a caller must tell apart stay apart.
    #[test]
    fn a_missing_key_and_a_declining_person_are_different_answers() {
        assert!(super::is_declined(super::DECLINED));
        assert!(!super::is_declined(super::NO_SUCH_KEY));
        assert!(super::is_absent(super::NO_SUCH_KEY));
        assert!(!super::is_absent(super::DECLINED));
    }
}

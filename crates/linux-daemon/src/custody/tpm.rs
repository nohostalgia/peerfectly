//! A network's signing key in the TPM, behind the person's passphrase.
//!
//! # What the TPM is asked for
//!
//! - **The parent** is the storage key the TCG's provisioning guidance defines
//!   — ECC P-256, restricted, decrypting, under the owner hierarchy with empty
//!   authorisation — **created each time it is needed**. Its seed makes it the
//!   same key every time, so nothing is persisted in the TPM and no handle is
//!   claimed: software that manages the TPM's persistent handles (clevis,
//!   systemd-cryptenroll) is never touched.
//! - **The key** is ECC P-256 for ECDSA with SHA-256, `fixedTPM | fixedParent |
//!   sensitiveDataOrigin | userWithAuth | sign`, and **not** `noDA`: the TPM's
//!   dictionary-attack protection applies to it, so wrong passphrases lock it
//!   out for a time instead of being tried without end.
//! - **Its authorisation value** is SHA-256 of a domain string and the
//!   passphrase — thirty-two bytes, the most a SHA-256 key takes. No slow
//!   derivation: the TPM limits guesses, which is the whole difference from a
//!   passphrase file.
//!
//! What is written to disk is the key's public area and its private area as the
//! TPM wraps it. The wrapping is under this TPM's storage key: the file loads on
//! this TPM and on no other, and even here it signs only with the passphrase.
//!
//! # The passphrase never crosses the bus in clear
//!
//! Every command that carries or uses it runs in an **HMAC session salted with
//! the storage key**, with parameter encryption:
//!
//! - creating the key, the new authorisation value travels encrypted;
//! - signing, the passphrase is not sent at all — the command carries an HMAC
//!   keyed by it, and the salt makes that HMAC useless to somebody recording
//!   the bus who would otherwise try passphrases against it offline.
//!
//! A password session, which sends the value as it is, is never started.
//!
//! # What is not tested here
//!
//! The testbed runs these against `swtpm`, which shows the commands and the
//! refusals are right. It does not show what a hardware TPM defends against;
//! that is the chip's.

use sha2::{Digest as _, Sha256};
use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::SessionType;
use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Auth, Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket, Private, Public, PublicBuilder,
    PublicEccParametersBuilder, Signature, SignatureScheme, SymmetricDefinition,
    SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::{Marshall as _, UnMarshall as _};
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::{Context, Error};

/// What goes before the passphrase, so its hash is this key's and nothing else's.
const DOMAIN: &[u8] = b"peerfectly tpm key v1";

/// A refusal, in words a person can act on.
pub type Refusal = String;

/// What a refusal says when the passphrase was wrong.
pub const WRONG_PASSPHRASE: &str = "the passphrase is wrong; nothing was signed";

/// What a refusal says when the TPM is refusing for a time.
pub const LOCKED_OUT: &str = "the TPM is refusing for now after too many wrong passphrases; \
     nothing was signed. Try again later.";

/// A key as it is kept on disk: its public area, and its private area as this
/// TPM wrapped it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    /// `TPMT_PUBLIC`, marshalled.
    pub public: Vec<u8>,
    /// The private area, wrapped by this TPM's storage key.
    pub private: Vec<u8>,
}

impl Stored {
    /// The bytes written to the key file: a version, then both areas, each
    /// with its length.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![1_u8];
        for part in [&self.public, &self.private] {
            out.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    /// Reads what [`Self::to_bytes`] wrote.
    ///
    /// # Errors
    ///
    /// When the bytes are not a key file this build reads.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Refusal> {
        let corrupt = || "the key file is not one this build reads".to_owned();
        let (version, mut rest) = bytes.split_first().ok_or_else(corrupt)?;
        if *version != 1 {
            return Err(corrupt());
        }
        let mut parts = Vec::new();
        for _ in 0..2 {
            let (length, after) = rest.split_first_chunk::<4>().ok_or_else(corrupt)?;
            let length = usize::try_from(u32::from_be_bytes(*length)).map_err(|_| corrupt())?;
            let (part, after) = after.split_at_checked(length).ok_or_else(corrupt)?;
            parts.push(part.to_vec());
            rest = after;
        }
        if !rest.is_empty() {
            return Err(corrupt());
        }
        let private = parts.pop().ok_or_else(corrupt)?;
        let public = parts.pop().ok_or_else(corrupt)?;
        Ok(Self { public, private })
    }

    /// The key's public half, compressed as the roster spells it, read from the
    /// file without the TPM.
    ///
    /// # Errors
    ///
    /// When the public area is not a P-256 point.
    pub fn public_key(&self) -> Result<Vec<u8>, Refusal> {
        let public = Public::unmarshall(&self.public).map_err(|cause| cause.to_string())?;
        compressed(&public)
    }

    /// Whether the key's attributes are the ones this module creates: bound to
    /// the TPM, used only with its authorisation, and under dictionary-attack
    /// protection.
    ///
    /// # Errors
    ///
    /// When the public area does not read.
    pub fn attributes_hold(&self) -> Result<bool, Refusal> {
        let public = Public::unmarshall(&self.public).map_err(|cause| cause.to_string())?;
        let attributes = public.object_attributes();
        Ok(attributes.fixed_tpm()
            && attributes.fixed_parent()
            && attributes.sensitive_data_origin()
            && attributes.user_with_auth()
            && attributes.sign_encrypt()
            && !attributes.no_da())
    }
}

/// The authorisation value a passphrase stands for.
fn auth_for(passphrase: &[u8]) -> Result<Auth, Refusal> {
    Authorisation::of(passphrase).auth()
}

/// The authorisation a passphrase stands for, held for the signatures of one
/// batch.
///
/// Derived once and given to the TPM for **every** signature: the TPM checks it
/// each time, so holding it saves the person typing, not the TPM checking.
/// Zeroised when dropped, which is at the end of the batch it was derived for.
pub struct Authorisation(zeroize::Zeroizing<Vec<u8>>);

impl Authorisation {
    /// What `passphrase` authorises.
    #[must_use]
    pub fn of(passphrase: &[u8]) -> Self {
        let digest = Sha256::new().chain_update(DOMAIN).chain_update(passphrase).finalize();
        Self(zeroize::Zeroizing::new(digest.to_vec()))
    }

    /// As the TPM takes it.
    fn auth(&self) -> Result<Auth, Refusal> {
        Auth::try_from(self.0.to_vec()).map_err(|cause| cause.to_string())
    }
}

/// The compressed public point of a P-256 public area.
fn compressed(public: &Public) -> Result<Vec<u8>, Refusal> {
    let Public::Ecc { unique, .. } = public else {
        return Err("the key is not an elliptic-curve key".to_owned());
    };
    let (x, y) = (padded(unique.x().value())?, padded(unique.y().value())?);
    identity::encodings::public_key_from_point(&x, &y).map_err(|cause| cause.to_string())
}

/// A coordinate, left-padded to the thirty-two bytes P-256 uses. The TPM drops
/// leading zeroes.
fn padded(value: &[u8]) -> Result<[u8; 32], Refusal> {
    let mut out = [0_u8; 32];
    let start = 32_usize
        .checked_sub(value.len())
        .ok_or_else(|| "a coordinate longer than P-256's".to_owned())?;
    out.get_mut(start..)
        .ok_or_else(|| "a coordinate out of range".to_owned())?
        .copy_from_slice(value);
    Ok(out)
}

/// The TPM a process uses.
#[derive(Debug, Clone)]
pub struct Tpm {
    /// How it is reached.
    tcti: TctiNameConf,
    /// Why there is none to reach, when that is known without asking.
    absent: Option<String>,
}

/// The kernel's resource manager, which is the machine's TPM when it has one.
const RESOURCE_MANAGER: &str = "/dev/tpmrm0";

impl Tpm {
    /// The machine's TPM: `TPM2TOOLS_TCTI` when set — the variable every tpm2
    /// tool honours, which the testbed uses for `swtpm` — and otherwise the
    /// kernel's resource manager, `/dev/tpmrm0`.
    ///
    /// `sudo` resets the environment, so a person's shell cannot point the
    /// command line running as root at a TPM of their own.
    ///
    /// A machine with no `/dev/tpmrm0` has no TPM, and is answered so without
    /// the TSS library being asked — which would only repeat it, louder, on
    /// standard error.
    #[must_use]
    pub fn of_this_machine() -> Self {
        if let Ok(named) = TctiNameConf::from_environment_variable() {
            return Self { tcti: named, absent: None };
        }
        let device: DeviceConfig = RESOURCE_MANAGER.parse().unwrap_or_default();
        let absent = (!std::path::Path::new(RESOURCE_MANAGER).exists())
            .then(|| format!("this machine has no TPM ({RESOURCE_MANAGER} is not there)"));
        Self { tcti: TctiNameConf::Device(device), absent }
    }

    /// A TPM reached as named — for tests, which run `swtpm`.
    #[must_use]
    pub const fn at(tcti: TctiNameConf) -> Self {
        Self { tcti, absent: None }
    }

    /// Whether this machine's TPM can hold a signing key: **asked by doing it**.
    ///
    /// A TPM 1.2, a TPM without P-256, and an owner hierarchy with a password
    /// all fail here, and the reason is kept for the log.
    ///
    /// # Errors
    ///
    /// When it cannot, with why.
    pub fn usable(&self) -> Result<(), Refusal> {
        let mut context = self.context()?;
        let parent = parent(&mut context)?;
        let session = salted_session(&mut context, parent)?;
        let result = (|| {
            let made = context
                .execute_with_session(Some(session), |context| {
                    context.create(parent, signing_template()?, None, None, None, None)
                })
                .map_err(|cause| format!("making a P-256 key: {cause}"))?;
            let key = context
                .execute_with_session(Some(session), |context| {
                    context.load(parent, made.out_private, made.out_public)
                })
                .map_err(|cause| format!("loading it: {cause}"))?;
            let signed = context.execute_with_session(Some(session), |context| {
                context.sign(key, digest_of(b"probe")?, SignatureScheme::Null, null_ticket()?)
            });
            let _ = context.flush_context(key.into());
            signed.map(|_| ()).map_err(|cause| format!("signing with it: {cause}"))
        })();
        let _ = context.flush_context(session_handle(session));
        let _ = context.flush_context(parent.into());
        result
    }

    /// Makes a network's signing key, protected by `passphrase`.
    ///
    /// # Errors
    ///
    /// When the TPM will not make it.
    pub fn create(&self, passphrase: &[u8]) -> Result<Stored, Refusal> {
        let auth = auth_for(passphrase)?;
        let mut context = self.context()?;
        let parent = parent(&mut context)?;
        let session = salted_session(&mut context, parent)?;
        let made = context.execute_with_session(Some(session), |context| {
            context.create(parent, signing_template()?, Some(auth), None, None, None)
        });
        let _ = context.flush_context(session_handle(session));
        let _ = context.flush_context(parent.into());
        let made = made.map_err(|cause| format!("the TPM would not make the key: {cause}"))?;
        Ok(Stored {
            public: made.out_public.marshall().map_err(|cause| cause.to_string())?,
            private: made.out_private.value().to_vec(),
        })
    }

    /// Loads a stored key into this TPM and reads its public half back:
    /// **proof that the file is this TPM's**, since no other TPM's storage key
    /// can unwrap it. Needs no passphrase.
    ///
    /// # Errors
    ///
    /// When this TPM cannot load it.
    pub fn load_check(&self, stored: &Stored) -> Result<Vec<u8>, Refusal> {
        let mut context = self.context()?;
        let parent = parent(&mut context)?;
        let session = salted_session(&mut context, parent)?;
        let loaded = load(&mut context, session, parent, stored);
        let result = loaded.and_then(|key| {
            let public = context.read_public(key).map_err(|cause| cause.to_string());
            let _ = context.flush_context(key.into());
            public.and_then(|(public, _, _)| compressed(&public))
        });
        let _ = context.flush_context(session_handle(session));
        let _ = context.flush_context(parent.into());
        result
    }

    /// Signs `message` with a stored key, with the passphrase.
    ///
    /// # Errors
    ///
    /// As [`Self::sign_all`].
    pub fn sign(
        &self,
        stored: &Stored,
        passphrase: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, Refusal> {
        let mut signed = self.sign_all(stored, &Authorisation::of(passphrase), &[message])?;
        signed.pop().ok_or_else(|| "the TPM signed nothing".to_owned())
    }

    /// Signs every message of a batch with a stored key, with one authorisation.
    ///
    /// One storage key, one salted session and one load for the whole batch, and
    /// then a `TPM2_Sign` for each message — each carrying an HMAC keyed by the
    /// authorisation, which the TPM checks every time. The TPM signs the SHA-256
    /// of each message — ECDSA over P-256 fixes the hash — and each `r ‖ s` is
    /// turned into the signature the roster takes.
    ///
    /// All or nothing: a refusal partway through hands back no signatures.
    ///
    /// # Errors
    ///
    /// [`WRONG_PASSPHRASE`], [`LOCKED_OUT`], or why the TPM would not.
    pub fn sign_all(
        &self,
        stored: &Stored,
        authorisation: &Authorisation,
        messages: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, Refusal> {
        let auth = authorisation.auth()?;
        let mut context = self.context()?;
        let parent = parent(&mut context)?;
        let session = salted_session(&mut context, parent)?;
        let result = load(&mut context, session, parent, stored).and_then(|key| {
            let signed = context.tr_set_auth(key.into(), auth).map_err(worded).and_then(|()| {
                let mut signatures = Vec::with_capacity(messages.len());
                for message in messages {
                    let signature = context
                        .execute_with_session(Some(session), |context| {
                            context.sign(
                                key,
                                digest_of(message)?,
                                SignatureScheme::Null,
                                null_ticket()?,
                            )
                        })
                        .map_err(worded)?;
                    signatures.push(signature);
                }
                Ok(signatures)
            });
            let _ = context.flush_context(key.into());
            signed
        });
        let _ = context.flush_context(session_handle(session));
        let _ = context.flush_context(parent.into());
        result?.into_iter().map(fixed_signature).collect()
    }

    /// A context on this TPM.
    fn context(&self) -> Result<Context, Refusal> {
        if let Some(absent) = &self.absent {
            return Err(absent.clone());
        }
        Context::new(self.tcti.clone())
            .map_err(|cause| format!("the TPM cannot be reached: {cause}"))
    }
}

/// An ECDSA signature from the TPM, as the roster takes it.
fn fixed_signature(signature: Signature) -> Result<Vec<u8>, Refusal> {
    let Signature::EcDsa(signature) = signature else {
        return Err("the TPM answered with something that is not an ECDSA signature".to_owned());
    };
    let mut fixed = padded(signature.signature_r().value())?.to_vec();
    fixed.extend_from_slice(&padded(signature.signature_s().value())?);
    identity::encodings::signature_from_fixed(&fixed).map_err(|cause| cause.to_string())
}

/// The storage key, created from its standard template.
fn parent(context: &mut Context) -> Result<KeyHandle, Refusal> {
    let template = storage_template()?;
    context
        .execute_with_nullauth_session(|context| {
            context.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })
        .map(|made| made.key_handle)
        .map_err(|cause: Error| {
            format!(
                "the TPM's storage key cannot be made — its owner hierarchy may have a \
                 password, which this program does not use: {cause}"
            )
        })
}

/// An HMAC session salted with the storage key, encrypting what it carries.
fn salted_session(context: &mut Context, parent: KeyHandle) -> Result<AuthSession, Refusal> {
    let session = context
        .start_auth_session(
            Some(parent),
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|cause| format!("the TPM would not open a session: {cause}"))?
        .ok_or_else(|| "the TPM opened no session".to_owned())?;
    let (attributes, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .with_continue_session(true)
        .build();
    context
        .tr_sess_set_attributes(session, attributes, mask)
        .map_err(|cause| format!("the session would not take its attributes: {cause}"))?;
    Ok(session)
}

/// Loads a stored key under the storage key.
fn load(
    context: &mut Context,
    session: AuthSession,
    parent: KeyHandle,
    stored: &Stored,
) -> Result<KeyHandle, Refusal> {
    let public = Public::unmarshall(&stored.public).map_err(|cause| cause.to_string())?;
    let private = Private::try_from(stored.private.clone()).map_err(|cause| cause.to_string())?;
    context
        .execute_with_session(Some(session), |context| context.load(parent, private, public))
        .map_err(|cause| format!("this machine's TPM cannot load the key: {cause}"))
}

/// The session's handle, for flushing it.
fn session_handle(session: AuthSession) -> tss_esapi::handles::ObjectHandle {
    tss_esapi::handles::SessionHandle::from(session).into()
}

/// The standard ECC storage key: restricted, decrypting, AES-128-CFB for its
/// children.
fn storage_template() -> Result<Public, Refusal> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .with_no_da(true)
        .build()
        .map_err(|cause| cause.to_string())?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                EccCurve::NistP256,
            )
            .build()
            .map_err(|cause| cause.to_string())?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|cause| cause.to_string())
}

/// The signing key: P-256, ECDSA with SHA-256, used only with its
/// authorisation, and **not** exempt from dictionary-attack protection.
fn signing_template() -> tss_esapi::Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_no_da(false)
        .build()?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_unrestricted_signing_key(
                EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
                EccCurve::NistP256,
            )
            .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

/// The SHA-256 of a message, as the TPM takes a digest.
fn digest_of(message: &[u8]) -> tss_esapi::Result<Digest> {
    Digest::try_from(Sha256::digest(message).to_vec())
}

/// The ticket that says the digest was not made by the TPM — the one an
/// unrestricted key signs with.
fn null_ticket() -> tss_esapi::Result<HashcheckTicket> {
    HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
        tag: tss_esapi::constants::tss::TPM2_ST_HASHCHECK,
        hierarchy: tss_esapi::constants::tss::TPM2_RH_NULL,
        digest: Default::default(),
    })
}

/// A TPM refusal, worded for a person where it is one they caused.
fn worded(cause: Error) -> Refusal {
    if let Error::Tss2Error(code) = cause {
        match code.kind() {
            Some(Tss2ResponseCodeKind::AuthFail | Tss2ResponseCodeKind::BadAuth) => {
                return WRONG_PASSPHRASE.to_owned();
            }
            Some(Tss2ResponseCodeKind::Lockout) => return LOCKED_OUT.to_owned(),
            _ => {}
        }
    }
    format!("the TPM would not sign: {cause}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    #[test]
    fn a_key_file_round_trips_and_nothing_else_reads() {
        let stored = Stored { public: vec![1, 2, 3], private: vec![4, 5] };
        assert_eq!(stored, Stored::from_bytes(&stored.to_bytes()).unwrap());
        let mut longer = stored.to_bytes();
        longer.push(0);
        assert!(Stored::from_bytes(&longer).is_err());
        assert!(Stored::from_bytes(&[2]).is_err());
        assert!(Stored::from_bytes(&[]).is_err());
    }

    /// The key's template: bound to this TPM, used only with its
    /// authorisation, and **not** `noDA`.
    #[test]
    fn the_signing_template_keeps_dictionary_attack_protection() {
        let attributes = signing_template().unwrap().object_attributes();
        assert!(attributes.fixed_tpm() && attributes.fixed_parent());
        assert!(attributes.sensitive_data_origin(), "made in the TPM, never imported");
        assert!(attributes.user_with_auth(), "used with its authorisation value");
        assert!(!attributes.no_da(), "wrong passphrases count");
        assert!(attributes.sign_encrypt() && !attributes.decrypt());
    }

    /// Never a password session: the only sessions started are salted HMAC ones.
    #[test]
    fn no_password_session_is_ever_started() {
        // Line endings removed, so the check reads the code and not how a checkout
        // wrote it.
        let source = include_str!("tpm.rs").replace('\r', "");
        let code = source.split("#[cfg(test)]").next().unwrap_or_default();
        assert!(!code.contains("SessionType::Policy") && !code.contains("PasswordSession"));
        assert!(
            !code.contains("AuthSession::Password"),
            "a password session sends the value in clear"
        );
        assert!(
            code.contains(
                "Some(parent),\n            None,\n            None,\n            SessionType::Hmac"
            ),
            "salted"
        );
    }

    #[test]
    fn the_authorisation_is_the_passphrase_hashed_under_a_domain() {
        let one = auth_for(b"correct horse").unwrap();
        assert_eq!(32, one.value().len());
        assert_ne!(one.value(), auth_for(b"correct horsf").unwrap().value());
        assert_ne!(one.value(), Sha256::digest(b"correct horse").as_slice(), "domain-separated");
    }
}

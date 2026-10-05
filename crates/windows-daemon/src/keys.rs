//! Where a network's keys come from on this machine.
//!
//! The portable half asks one question — *give me this network's identity,
//! creating it only if there is none* — and this answers it the way this
//! platform can: the signing key is made inside the TPM and stays there, and the
//! two keys that must be usable with nobody present stay here.
//!
//! This is the same shape the Android client's keystore has, and deliberately:
//! a phone and a desktop differ in which key store they reach, and in nothing
//! else. What they do **not** share is how the key is reached once it is found,
//! and that difference is one method — see [`MachineCustodian::answers_here`].
//!
//! # Which keys, and why not all of them
//!
//! | key | where | why |
//! |---|---|---|
//! | signing | the TPM, non-exportable | it is the device's authority, and it is permanent |
//! | transport | here, sealed at rest | every packet needs it |
//! | attestation | here, sealed at rest | dating a roster happens with nobody present |
//!
//! What protects the two that stay on disk is `identity::store::PlatformSealer`
//! — DPAPI, in the scope of the person the daemon runs as. `identity::seal`'s
//! own table says what that does and does not defend against, and it is a thing
//! `windows-service-install` changes rather than this.
//!
//! The attestation key is the one that looks like an omission and is not.
//! `crates/identity/src/identity.rs` says why where the key is declared: a key
//! that asks is a key that cannot date a roster unattended, and an admin machine
//! whose only key asked would let its network go stale whenever nobody was at
//! it. What that concedes is bounded by what an attestation can say, which is a
//! date.

#![cfg(windows)]

use std::sync::Arc;

use daemon::error::{Error, Result};
use daemon::keys::Keys;
use daemon::state::Paths;
use identity::detached::{KeyCustodian, SigningRequest};
use identity::store::Custodians;
use identity::{NodeIdentity, PrivateKey};
use roster::sign::PublicKey;
use roster::types::Algorithm;

use crate::platform::custody::Store;

/// A name for a new signing key in the machine's key store.
///
/// Fresh every time, never derived again: see [`identity::fresh_key_name`]. The
/// identity written beside the network records it, and that is how the key is
/// found afterwards.
///
/// # Errors
///
/// When the system has no randomness to give.
pub fn fresh_signing_name(paths: &Paths) -> identity::Result<String> {
    let directory = paths.root().file_name().and_then(|name| name.to_str()).unwrap_or("network");
    identity::fresh_key_name(directory)
}

/// A signing key the machine's key store holds.
///
/// Carries the public half and the name, and no way to reach the private half
/// from here — which is not a limitation of this type but the point of it.
pub struct MachineCustodian {
    /// The key store.
    store: Arc<Store>,
    /// What it knows this key by.
    name: String,
    /// The public half, read once.
    public: PublicKey,
}

impl MachineCustodian {
    /// The key under `name`, if the store holds one.
    ///
    /// # Errors
    ///
    /// When there is no such key, or its public half is not one the roster takes.
    pub fn open(store: Arc<Store>, name: String) -> identity::Result<Self> {
        let compressed = store
            .public_key(&name)
            .map_err(|detail| identity::Error::CustodianFailed { detail })?;
        let public = PublicKey::new(Algorithm::P256, compressed)?;
        Ok(Self { store, name, public })
    }

    /// Makes the key under `name`, for the network a person will see named.
    ///
    /// # Errors
    ///
    /// When the key cannot be made, which on a machine whose key store was
    /// reported usable is a fault rather than an answer.
    pub fn create(store: Arc<Store>, name: String, network: &str) -> identity::Result<Self> {
        let compressed = store
            .create(&name, network)
            .map_err(|detail| identity::Error::CustodianFailed { detail })?;
        let public = PublicKey::new(Algorithm::P256, compressed)?;
        Ok(Self { store, name, public })
    }

    /// What the key store knows this key by.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Signs a prepared request, where the key can be reached.
    ///
    /// **Not reachable from the daemon**, and that is what
    /// [`Self::answers_here`] exists to say. It is what the component running as
    /// the person calls once it holds a request: the key store asks them, and
    /// what comes back is the signature.
    ///
    /// # Errors
    ///
    /// When the person declines, or the key store will not sign.
    pub fn signs(&self, message: &[u8]) -> identity::Result<Vec<u8>> {
        match self.store.sign(&self.name, message) {
            Ok(signature) => Ok(signature),
            Err(refusal) if crate::platform::custody::is_declined(&refusal) => {
                Err(identity::Error::Declined)
            }
            Err(detail) => Err(identity::Error::CustodianFailed { detail }),
        }
    }
}

impl KeyCustodian for MachineCustodian {
    fn public_key(&self) -> PublicKey {
        self.public.clone()
    }

    fn sign_request(&self, request: &SigningRequest) -> identity::Result<Vec<u8>> {
        // Reached only if something ignored `answers_here`. `identity` refuses
        // before this, so this is the net under that net — and it must not
        // quietly succeed, because succeeding here would mean the daemon had
        // used a key that only the person's own session can reach.
        let _ = request;
        Err(identity::Error::SignedElsewhere)
    }

    fn answers_here(&self) -> bool {
        // The key store answers in the session of the person who owns the key.
        // The daemon is not that session — today because it is a different
        // process, and after `windows-service-install` because it is a different
        // account. Either way the act must stop and be signed where the key is.
        false
    }
}

/// This machine's keys: the signing one in the TPM, the rest here.
pub struct MachineKeys {
    /// The key store, opened once.
    store: Arc<Store>,
}

impl MachineKeys {
    /// Opens the machine's key store.
    ///
    /// # Errors
    ///
    /// When this machine has no usable one — which is an answer about the
    /// machine, and the caller says what the device may do instead.
    pub fn open() -> core::result::Result<Self, String> {
        let store = Store::open()?;
        if !store.usable() {
            return Err(
                "this machine's key store cannot hold a signing key: it has no TPM, or one too \
                 old for the curve this network uses"
                    .to_owned(),
            );
        }
        Ok(Self { store: Arc::new(store) })
    }

    /// The key store, for the component that can reach it.
    #[must_use]
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }
}

impl Custodians for MachineKeys {
    fn find(
        &self,
        reference: &str,
    ) -> identity::Result<Option<Arc<dyn KeyCustodian + Send + Sync>>> {
        match MachineCustodian::open(Arc::clone(&self.store), reference.to_owned()) {
            Ok(held) => Ok(Some(Arc::new(held) as Arc<dyn KeyCustodian + Send + Sync>)),
            // **Absent and broken are not the same answer.**
            //
            // A key that is gone is `None`, and `identity` turns that into the
            // refusal naming the key — and refuses rather than making a new one,
            // which would make this a different device.
            //
            // A key store that answered something *else* is a fault, and saying
            // `None` for it would report *"this device's identity will not
            // open"* while throwing away the only line that says why. That was
            // written here first, and it cost a machine run to find out.
            Err(identity::Error::CustodianFailed { detail })
                if crate::platform::custody::is_absent(&detail) =>
            {
                Ok(None)
            }
            Err(cause) => Err(cause),
        }
    }
}

impl MachineKeys {
    /// The identity already under `paths`, if there is one.
    ///
    /// # Errors
    ///
    /// When one exists and will not open, or holds its signing key in a file on
    /// a machine that can do better.
    fn existing(&self, paths: &Paths) -> Result<Option<NodeIdentity>> {
        let path = paths.identity();
        let failed =
            |cause: identity::Error| Error::State { path: path.clone(), cause: cause.to_string() };

        if path.exists() {
            let held = identity::store::load_with(&path, &identity::store::PlatformSealer, self)
                .map_err(failed)?;

            // A network whose signing key is a file, on a machine that can
            // protect one. It is refused rather than carried: a device that can
            // sign as an admin with a key any process running as the person can
            // read is the finding this exists to close, and running it in a
            // declared weaker mode does not close it.
            //
            // Nothing here is deleted or rewritten. A person reads it, or removes
            // it, deliberately.
            if held.signing_key().custodian().is_none() {
                return Err(Error::State {
                    path,
                    cause: "this network's signing key is held in a file, and this machine can hold one where no process can read it. It is refused rather than carried: found or join this network again on this device. Nothing has been changed or removed."
                        .to_owned(),
                });
            }
            return Ok(Some(held));
        }
        Ok(None)
    }

    /// What the network under `paths` is called, for the key store's prompt.
    fn network_of(paths: &Paths) -> &str {
        paths.root().file_name().and_then(|label| label.to_str()).unwrap_or("network")
    }
}

impl Keys for MachineKeys {
    fn identity(&self, paths: &Paths) -> Result<NodeIdentity> {
        if let Some(held) = self.existing(paths)? {
            return Ok(held);
        }
        // **This process cannot make one, and must not pretend it failed for
        // some other reason.** The key store asks a person before it will protect
        // a key, and asking needs a desktop this daemon does not have. Whoever
        // wanted an identity here should have gone through `identity_or_ask`.
        Err(Error::State {
            path: paths.identity(),
            cause: "this network has no identity yet, and its signing key must be made where a \
                    person can be asked for it. Found or join the network from the command line."
                .to_owned(),
        })
    }

    /// Deletes the network's signing key from the machine's key store.
    ///
    /// The daemon runs as the machine, which may: a machine key admits `SYSTEM`
    /// and administrators. The name is the one the identity records; a key
    /// already gone is fine.
    fn forget(&self, paths: &Paths) -> Result<()> {
        let Some(name) = daemon::keys::signing_key_named_in(paths) else { return Ok(()) };
        let failed = |cause: String| Error::State { path: paths.identity(), cause };
        let store = crate::platform::custody::Store::open().map_err(failed)?;
        match store.remove(&name) {
            Ok(()) => {
                tracing::info!(key = %name, "the network's key was deleted from the key store");
                Ok(())
            }
            Err(refusal) if crate::platform::custody::is_absent(&refusal) => Ok(()),
            Err(refusal) => Err(failed(format!("the key `{name}` would not go: {refusal}"))),
        }
    }

    fn must_be_made_elsewhere(&self, paths: &Paths) -> Option<daemon::keys::Asked> {
        // The file, not the key store: a key with no identity beside it is a key
        // from an act that never finished, and it is left where it is — the new
        // key has a name of its own. What decides whether this network has an
        // identity is the identity.
        if paths.identity().exists() {
            return None;
        }
        // No randomness means no key can be named safely. Not asking leads to
        // `identity`, which refuses: a failure rather than a reused name.
        let name = fresh_signing_name(paths).ok()?;
        Some(daemon::keys::Asked { name, network: Self::network_of(paths).to_owned() })
    }

    fn identity_from(&self, paths: &Paths, made: &daemon::keys::Made) -> Result<NodeIdentity> {
        let path = paths.identity();
        let failed =
            |cause: identity::Error| Error::State { path: path.clone(), cause: cause.to_string() };

        if let Some(held) = self.existing(paths)? {
            return Ok(held);
        }
        paths.create()?;

        // **The public half is read from the key store, not taken from what was
        // sent.** The name is the daemon's own — the one it asked for, kept on
        // its side — so opening it here establishes that the key exists and what
        // it is.
        // A public key arriving over the channel is a claim, and building an
        // identity around a claim would let whoever answered choose the key the
        // network is founded on.
        let custodian =
            MachineCustodian::open(Arc::clone(&self.store), made.name.clone()).map_err(failed)?;
        if custodian.public_key().as_bytes() != made.public.as_slice() {
            return Err(Error::State {
                path,
                cause: "the key that was made is not the key that was reported. Nothing was \
                        created."
                    .to_owned(),
            });
        }

        // Held here, both of them, and for reasons that are not the same reason:
        // the transport key is needed on every packet, and the attestation key
        // must be usable while nobody is present.
        let transport = PrivateKey::generate(Algorithm::Ed25519).map_err(failed)?;
        let attestation = PrivateKey::generate(Algorithm::Ed25519).map_err(failed)?;

        let identity = NodeIdentity::with_custodian(
            made.name.clone(),
            Arc::new(custodian) as Arc<dyn KeyCustodian + Send + Sync>,
            transport,
            attestation,
        )
        .map_err(failed)?;

        identity::store::save_with(&identity, &path, &identity::store::PlatformSealer)
            .map_err(failed)?;
        Ok(identity)
    }
}

/// Keys on a machine whose key store cannot hold a signing key.
///
/// Everything a member needs, held the way this platform holds a local secret,
/// and an explicit answer to the one question such a machine must answer
/// differently. A device like this joins a network and works; it does not found
/// one, and it does not sign the acts that decide who is in it.
///
/// Producing a software signing key quietly and letting a person believe the
/// network is protected is the thing this exists to prevent. A machine that
/// cannot is told so when it is asked, in words.
pub struct MemberOnlyKeys {
    /// Why this machine cannot, as the key store reported it.
    reason: String,
}

impl MemberOnlyKeys {
    /// A machine that answered that it cannot hold a protected signing key.
    #[must_use]
    pub fn because(reason: String) -> Self {
        Self { reason }
    }
}

impl Keys for MemberOnlyKeys {
    fn identity(&self, paths: &Paths) -> Result<NodeIdentity> {
        daemon::state::identity_of(paths)
    }

    fn admin_refusal(&self) -> Option<String> {
        Some(self.reason.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The name says which directory it was made in, and is never the same
    /// twice: **a join reuses its provisional directory, and a key made under a
    /// name the store holds replaced the key there.** That is how a second join
    /// destroyed the first network's key.
    #[test]
    fn a_keys_name_is_never_made_twice() {
        let paths = Paths::under(std::path::Path::new(r"C:\x\network"));
        let first = fresh_signing_name(&paths).expect("a name is drawn");
        let second = fresh_signing_name(&paths).expect("a second is drawn");
        assert!(first.starts_with("peerfectly.network.") && first.ends_with(".signing"), "{first}");
        assert_ne!(first, second, "the same directory, two keys");
    }
}

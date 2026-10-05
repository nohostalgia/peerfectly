//! Where a network's keys come from, which is the one thing about an identity
//! that depends on the device.
//!
//! On a desktop the keys are generated here and sealed the way the platform seals
//! a local secret. On a phone the signing key is generated inside the keystore and
//! never leaves it, and the transport key is sealed by a keystore key. Everything
//! else about an identity — which device it is, what it signs, how a stored one
//! must never be replaced — is the same, and stays in `identity` and `state`.
//!
//! So the seam is exactly one question: *give me this network's identity,
//! creating it only if there is none*. The rule that an identity which exists and
//! will not open is a reason to stop, never a reason to mint new keys, is part of
//! the question and every implementation owes it.

use identity::NodeIdentity;

use crate::error::Result;
use crate::state::Paths;

/// A signing key made where a person could be asked about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Made {
    /// What the key store knows it by.
    pub name: String,
    /// Its public half, as the roster spells one.
    pub public: Vec<u8>,
}

/// A signing key that has to be made where a person can be asked about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    /// What to call it in the key store.
    pub name: String,
    /// The network it is for, which is what the key store's own prompt will
    /// name — it is fixed when the key is made and cannot name an act.
    pub network: String,
}

/// Supplies a network's identity.
pub trait Keys: Send + Sync {
    /// The identity kept under `paths`, created only when there is none.
    ///
    /// # Errors
    ///
    /// When an identity exists and cannot be opened — which must never be
    /// answered by creating a new one — or when one cannot be created.
    fn identity(&self, paths: &Paths) -> Result<NodeIdentity>;

    /// The signing key this network needs and this process may not make, if any.
    ///
    /// **A question, and nothing more.** It creates nothing, writes nothing and
    /// makes no directory: it is asked before anything else, so anything it did
    /// would happen to networks that are never founded.
    ///
    /// `Some` where a key store asks a person before it will protect a key. The
    /// asking needs a desktop, and a daemon running as the machine has none, so
    /// the making has to happen where the person is — the same split as signing,
    /// one step earlier. `None` everywhere else, which is the honest default: a
    /// platform whose key store answers on the call has nothing to ask about.
    fn must_be_made_elsewhere(&self, paths: &Paths) -> Option<Asked> {
        let _unused = paths;
        None
    }

    /// The identity, built around a key somebody else has just made.
    ///
    /// Called once, with what [`Needed::AKey`] asked for. It must **not** make a
    /// key of its own: the one it is given is the one a person consented to.
    ///
    /// # Errors
    ///
    /// When the key is not there, or the identity cannot be written.
    fn identity_from(&self, paths: &Paths, made: &Made) -> Result<NodeIdentity> {
        let _unused = made;
        self.identity(paths)
    }

    /// Why this machine may not hold an admin's key, if it may not.
    ///
    /// `None` on every platform that has not said otherwise, which is the honest
    /// default: a machine is presumed able to be what its roster says it is, and
    /// only a platform that has looked knows better.
    ///
    /// `Some(reason)` is a fact about the **machine**, not about the network. A
    /// device that answers so can join, carry traffic, synchronise and date
    /// nothing — everything a member does. What it may not do is sign the acts
    /// that change who is in the network, because the key that signs them would
    /// be one this platform cannot protect. Founding is refused before anything
    /// is created, and an admin role the roster gives it anyway is declared
    /// rather than exercised.
    ///
    /// The reason is carried rather than left to the caller to invent, because a
    /// person told *"this machine cannot do that"* and not why will go looking
    /// in the wrong place.
    fn admin_refusal(&self) -> Option<String> {
        None
    }

    /// How this platform holds the signing key of the identity it gave.
    ///
    /// Read off the identity by default — a key somebody else holds is in a key
    /// store, a key this process holds is a file — because what a report says a
    /// device holds must be what it holds. A platform with a third kind, a key
    /// sealed with a passphrase, says so here: the identity alone cannot tell a
    /// passphrase from hardware, and the report must.
    fn custody_of(&self, identity: &NodeIdentity) -> crate::control::Custody {
        if identity.signing_key().custodian().is_some() {
            crate::control::Custody::KeyStore
        } else {
            crate::control::Custody::HeldHere
        }
    }

    /// Deletes every key this platform keeps for the network under `paths`
    /// **outside** that directory: a key store's entry, a key file beside the
    /// networks, a keystore alias.
    ///
    /// Called when a network is removed, before its directory goes — the
    /// identity in it is what names the key. A key already missing is `Ok`:
    /// it is gone, which is what was asked.
    ///
    /// `Ok(())` by default, which is right where every key is in the directory
    /// and goes with it. A platform that keeps one elsewhere must say so here,
    /// or removing a network leaves material for an identity the person
    /// believes is gone.
    ///
    /// # Errors
    ///
    /// When a key that is there will not go. The network's directory is then
    /// kept, so that whatever names the key is not lost before the key is.
    fn forget(&self, paths: &Paths) -> Result<()> {
        let _unused = paths;
        Ok(())
    }
}

/// The name of the signing key the identity under `paths` refers to, read
/// without opening that key.
///
/// A key kept outside the network's directory — in a key store, a keystore, a
/// key file — is found again by the name its identity records. That name cannot
/// be worked out from the directory: it carries random bits, and for a join it
/// was made under the provisional directory a join starts in. So it is read from
/// the stored identity, by answering the one question loading asks of a
/// custodian — *which key?* — and nothing else.
///
/// `None` where there is no identity, where it cannot be read at all, or where
/// its signing key is held in the directory and names no custodian.
#[must_use]
pub fn signing_key_named_in(paths: &Paths) -> Option<String> {
    signing_key_named_in_sealed(paths, &identity::store::PlatformSealer)
}

/// The same, for an identity sealed by `sealer` — a phone seals with its
/// keystore, not as a desktop does.
#[must_use]
pub fn signing_key_named_in_sealed(
    paths: &Paths,
    sealer: &dyn identity::store::Sealer,
) -> Option<String> {
    /// Remembers the key asked for, and hands back none.
    struct Named(std::sync::Mutex<Option<String>>);

    impl identity::store::Custodians for Named {
        fn find(
            &self,
            reference: &str,
        ) -> identity::Result<
            Option<std::sync::Arc<dyn identity::detached::KeyCustodian + Send + Sync>>,
        > {
            if let Ok(mut named) = self.0.lock() {
                *named = Some(reference.to_owned());
            }
            Ok(None)
        }
    }

    let named = Named(std::sync::Mutex::new(None));
    let _ = identity::store::load_with(&paths.identity(), sealer, &named);
    named.0.into_inner().ok().flatten()
}

/// This platform's own keys: generated here, sealed as `identity::store` does.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlatformKeys;

impl Keys for PlatformKeys {
    fn identity(&self, paths: &Paths) -> Result<NodeIdentity> {
        crate::state::identity_of(paths)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::{Keys as _, PlatformKeys};

    /// **Where every key is in the directory, forgetting touches nothing**: the
    /// directory's removal is what takes the keys, and it is not this.
    #[test]
    fn the_default_forget_leaves_the_directory_as_it_was() {
        let scratch = tempfile::tempdir().unwrap();
        let paths = crate::state::Paths::under(scratch.path());
        let identity = PlatformKeys.identity(&paths).unwrap();
        let before = std::fs::read(paths.identity()).unwrap();

        PlatformKeys.forget(&paths).unwrap();

        assert_eq!(before, std::fs::read(paths.identity()).unwrap(), "untouched");
        assert_eq!(identity.device_id(), PlatformKeys.identity(&paths).unwrap().device_id());
    }

    /// **The key a stored identity names is read back without opening it** —
    /// which is how a key kept outside the directory is found to be deleted.
    #[test]
    fn the_signing_key_an_identity_names_is_read_without_opening_it() {
        let scratch = tempfile::tempdir().unwrap();
        let paths = crate::state::Paths::under(scratch.path());
        paths.create().unwrap();
        let custodian = std::sync::Arc::new(roster::sign::Ed25519Signer::from_seed([7; 32]))
            as std::sync::Arc<dyn identity::detached::KeyCustodian + Send + Sync>;
        let made = identity::NodeIdentity::with_custodian(
            "peerfectly.casa.0011223344556677.signing",
            custodian,
            identity::PrivateKey::generate(roster::types::Algorithm::Ed25519).unwrap(),
            identity::PrivateKey::generate(roster::types::Algorithm::Ed25519).unwrap(),
        )
        .unwrap();
        identity::store::save_with(&made, &paths.identity(), &identity::store::PlatformSealer)
            .unwrap();

        assert_eq!(
            Some("peerfectly.casa.0011223344556677.signing".to_owned()),
            super::signing_key_named_in(&paths)
        );
    }

    /// No identity, or one whose key is in the directory, names nothing.
    #[test]
    fn an_identity_holding_its_own_key_names_none() {
        let scratch = tempfile::tempdir().unwrap();
        let paths = crate::state::Paths::under(scratch.path());
        assert_eq!(None, super::signing_key_named_in(&paths), "no identity");
        PlatformKeys.identity(&paths).unwrap();
        assert_eq!(None, super::signing_key_named_in(&paths), "a key held here");
    }
}

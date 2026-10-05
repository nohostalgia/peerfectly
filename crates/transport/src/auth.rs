//! Proving a peer holds the key it claims, and asking the roster who that is.
//!
//! Two steps, kept separate because they fail for different reasons:
//!
//! 1. **Possession.** The peer signs a challenge with the private half of the
//!    transport key it presents. A peer that cannot is lying or broken, and
//!    nothing about the roster is wrong.
//! 2. **Membership.** The presented key is resolved to a device in the roster
//!    state this node derives, and that device must not be revoked. A key that
//!    names nobody is a stranger; a revoked one was expelled. Those are
//!    different things to tell a person.
//!
//! # The transport key, never the signing key
//!
//! Resolution asks the roster for a device holding this key **for the transport
//! purpose**. A device's two keys are distinct by construction precisely so one
//! cannot stand in for the other, and a lookup that ignored purpose would let a
//! signing key open a session — the cross-protocol confusion the separation
//! exists to prevent.
//!
//! # The challenge is domain-separated
//!
//! A transport key signs only challenges, and a challenge is prefixed with a tag
//! belonging to this capability. So a signature gathered here cannot be replayed
//! as anything else, and nothing signed elsewhere can be presented as a
//! handshake.

use roster::id::{DeviceId, KeyId};
use roster::sign::PublicKey;
use roster::state::RosterState;
use roster::types::KeyPurpose;

use crate::error::{Error, Result};

/// The tag every handshake signature is bound to.
pub const HANDSHAKE_DOMAIN_TAG: &str = "transport-session/v1";

/// Length of a handshake challenge.
pub const CHALLENGE_LEN: usize = 32;

/// The bytes a peer signs to prove possession.
///
/// Framed the way the roster frames its own signing inputs: the tag and the
/// nonce each preceded by a big-endian `u16` length, so no two inputs can
/// concatenate to the same bytes.
#[must_use]
pub fn challenge_bytes(nonce: &[u8; CHALLENGE_LEN]) -> Vec<u8> {
    let tag = HANDSHAKE_DOMAIN_TAG.as_bytes();
    let mut out = Vec::with_capacity(tag.len().saturating_add(CHALLENGE_LEN).saturating_add(4));
    push_framed(&mut out, tag);
    push_framed(&mut out, nonce);
    out
}

/// Appends a component preceded by its big-endian `u16` length.
fn push_framed(out: &mut Vec<u8>, component: &[u8]) {
    let len = u16::try_from(component.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(component);
}

/// What a peer offers to establish a session.
///
/// Inert on its own: it proves nothing until checked against a challenge this
/// node chose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    /// The transport key the peer claims.
    pub key: PublicKey,
    /// A signature over the challenge this node issued.
    pub signature: Vec<u8>,
}

impl Handshake {
    /// The key id the peer claims.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.key.key_id()
    }
}

/// Checks a peer holds the key it presents, and that the roster names it.
///
/// The order matters. Possession is checked first because it needs no roster
/// state and because a peer that cannot prove possession has told us nothing
/// worth looking up — resolving an unproven key would let anyone learn whether
/// a given key is a member by presenting it.
pub fn authenticate(
    state: &RosterState,
    handshake: &Handshake,
    nonce: &[u8; CHALLENGE_LEN],
) -> Result<DeviceId> {
    let challenge = challenge_bytes(nonce);
    handshake
        .key
        .verify(&challenge, &handshake.signature)
        .map_err(|_| Error::PossessionNotProven)?;

    authorize(state, &handshake.key_id())
}

/// Resolves a transport key the roster must name, for a caller that already has
/// proof the peer holds it.
///
/// **Possession is deliberately not checked here.** The caller supplies a key
/// whose possession something else has already established, and for a real
/// transport that something is the connection's own handshake — which proves it
/// *bound to the channel*, so the proof cannot be gathered on one connection and
/// presented on another. A challenge-and-signature exchange carried inside an
/// already-established channel proves strictly less than that, and costs a round
/// trip.
///
/// It follows that this MUST NOT be called with a key nothing has authenticated.
/// On its own it answers "does the roster name this key", which is not the same
/// question as "is this peer that key's holder". [`authenticate`] is the entry
/// point for a caller that must establish both.
///
/// The key is resolved **for the transport purpose**. A device's two keys are
/// distinct by construction precisely so one cannot stand in for the other, and
/// a lookup ignoring purpose would let a signing key open a session — the
/// cross-protocol confusion the separation exists to prevent.
pub fn authorize(state: &RosterState, key: &KeyId) -> Result<DeviceId> {
    let record =
        state.device_for_key_of_purpose(key, KeyPurpose::Transport).ok_or(Error::NotAMember)?;

    if state.revoked.contains(&record.id) {
        // Reached only if a revoked device somehow remains in `devices`; the
        // roster removes them, so this is belt to derived state's braces.
        return Err(Error::Revoked);
    }
    Ok(record.id)
}

/// Whether a device is still a member of the network the state describes.
///
/// Asked of state each time rather than remembered. A transport that cached the
/// answer would be a second, quieter roster, and the one that disagreed with the
/// signed log would be the one actually deciding who is in the network.
#[must_use]
pub fn is_member(state: &RosterState, device: &DeviceId) -> bool {
    state.devices.contains_key(device) && !state.revoked.contains(device)
}

/// Why a device is not a member, for a caller that needs to say which.
#[must_use]
pub fn membership_refusal(state: &RosterState, device: &DeviceId) -> Option<Error> {
    if state.revoked.contains(device) {
        return Some(Error::Revoked);
    }
    if state.devices.contains_key(device) {
        return None;
    }
    Some(Error::NotAMember)
}

#[cfg(test)]
mod tests {
    use super::{CHALLENGE_LEN, HANDSHAKE_DOMAIN_TAG, challenge_bytes};

    /// The tag is in the signed bytes, so a handshake signature cannot be
    /// replayed as a roster operation or snapshot.
    #[test]
    fn the_challenge_carries_its_own_tag() {
        let bytes = challenge_bytes(&[7u8; CHALLENGE_LEN]);
        assert!(
            bytes.windows(HANDSHAKE_DOMAIN_TAG.len()).any(|w| w == HANDSHAKE_DOMAIN_TAG.as_bytes())
        );
        assert_ne!(HANDSHAKE_DOMAIN_TAG, roster::sign::DOMAIN_TAG);
        assert_ne!(HANDSHAKE_DOMAIN_TAG, roster::snapshot::SNAPSHOT_DOMAIN_TAG);
    }

    #[test]
    fn different_nonces_produce_different_challenges() {
        assert_ne!(challenge_bytes(&[1u8; CHALLENGE_LEN]), challenge_bytes(&[2u8; CHALLENGE_LEN]));
    }
}

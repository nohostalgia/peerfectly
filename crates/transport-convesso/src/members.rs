//! Who may open a convesso session with this node, read from roster state.
//!
//! convesso asks the application whether to admit a peer during the handshake,
//! synchronously, by the peer's X25519 id. The roster names devices by their
//! ed25519 transport keys. This is the one place the second becomes the first,
//! asked of the state each time rather than kept beside it: a peer id is the
//! X25519 form of an ed25519 key, the map back gives that key's two possible
//! encodings (the form keeps no sign), and the state's key index says which
//! device, if any, holds either. A map of every member's key, rebuilt at every
//! change, held 179 bytes a device and walked a million at a fleet's size
//! (`scalable-membership` 16.6).
//!
//! What each key is told comes from `transport::auth::authorize`, the decision
//! every binding takes. A key no device holds is a stranger. A key whose device
//! the state still records and also revokes is revoked; a revoked device the
//! roster has dropped altogether is, by its key alone, a stranger — exactly what
//! the interface's own check says.

use std::sync::{Arc, RwLock};

use convesso_core::handshake::{Admission, Decision, RefusalCode};
use convesso_core::identity::{Address, PeerId};
use roster::id::{DeviceId, KeyId};
use roster::state::RosterState;
use transport::error::Error;

/// The handshake's refusal of a stranger.
pub const NOT_A_MEMBER: u16 = 0x0100;
/// The handshake's refusal of a revoked device.
pub const REVOKED: u16 = 0x0101;

/// What the roster says about the transport keys convesso authenticates.
#[derive(Debug, Default, Clone)]
pub struct Members {
    state: Option<RosterState>,
}

impl Members {
    /// The members of this state: a copy of it, which costs its changes.
    #[must_use]
    pub fn from_state(state: &RosterState) -> Self {
        Self { state: Some(state.clone()) }
    }

    /// The transport key, among the two a peer id may stand for, that a
    /// device of the state holds, with the address convesso dials it at.
    fn held(&self, peer: &PeerId) -> Option<(KeyId, Address)> {
        let state = self.state.as_ref()?;
        let montgomery = curve25519_dalek::montgomery::MontgomeryPoint(*peer.as_bytes());
        // Sign 0 first: of two devices whose keys differ in sign alone, which
        // no honest pair of keys does, the same one on every node.
        [0_u8, 1].into_iter().find_map(|sign| {
            let bytes = montgomery.to_edwards(sign)?.compress().to_bytes();
            // A key convesso cannot read can reach nobody here: it would never
            // present itself, and is not a member's for that.
            let address =
                Address::parse(bytes).ok().filter(|address| address.peer_id() == *peer)?;
            let key = KeyId::of_public_key(&bytes);
            state
                .device_for_key_of_purpose(&key, roster::types::KeyPurpose::Transport)
                .filter(|leaf| {
                    leaf.record.keys.iter().any(|entry| {
                        entry.key_id() == key && entry.alg == roster::types::Algorithm::Ed25519
                    })
                })
                .map(|_| (key, address))
        })
    }

    /// What the roster says about the peer convesso authenticated.
    ///
    /// A peer nothing names is a stranger.
    pub fn verdict(&self, peer: &PeerId) -> Result<DeviceId, Error> {
        let (Some(state), Some((key, _))) = (self.state.as_ref(), self.held(peer)) else {
            return Err(Error::NotAMember);
        };
        transport::auth::authorize(state, &key)
    }

    /// The address a peer is dialled at, if the roster names its key.
    #[must_use]
    pub fn address(&self, peer: &PeerId) -> Option<Address> {
        self.held(peer).map(|(_, address)| address)
    }

    /// The device a peer is, if it is a member.
    #[must_use]
    pub fn member(&self, peer: &PeerId) -> Option<DeviceId> {
        self.verdict(peer).ok()
    }
}

/// The refusal code the handshake sends for a verdict, or `None` to admit.
#[must_use]
pub const fn refusal_code(verdict: &Result<DeviceId, Error>) -> Option<u16> {
    match verdict {
        Ok(_) => None,
        Err(Error::Revoked) => Some(REVOKED),
        Err(_) => Some(NOT_A_MEMBER),
    }
}

/// What a refusal code the handshake received means.
#[must_use]
pub const fn refusal(code: u16) -> Option<Error> {
    match code {
        NOT_A_MEMBER => Some(Error::NotAMember),
        REVOKED => Some(Error::Revoked),
        _ => None,
    }
}

/// The admission convesso consults during every handshake, renewals included.
///
/// Holds the map the transport rebuilds, so a revocation handed to the
/// transport is what the next handshake reads. A node holding no roster
/// (`light`) admits every handshake: it has nothing to judge a key by there,
/// and judges the peer by the evidence its first frame carries instead.
pub struct Gate(pub Arc<RwLock<Members>>, pub bool);

impl Admission for Gate {
    fn admit(&mut self, peer: &PeerId, _context: &[u8]) -> Decision {
        if self.1 {
            return Decision::Accept { psk: None };
        }
        let verdict = self.0.read().map_or(Err(Error::NotAMember), |members| members.verdict(peer));
        match refusal_code(&verdict).and_then(RefusalCode::application) {
            None => Decision::Accept { psk: None },
            Some(code) => Decision::Refuse { code, psk: None },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "a test reports failure by panicking")]
mod tests {
    use std::sync::{Arc, RwLock};

    use convesso_core::handshake::{Admission, Decision};
    use convesso_core::identity::Address;
    use identity::NodeIdentity;

    use super::*;

    /// A network founded by one device, with a second admitted.
    fn network() -> (RosterState, Arc<NodeIdentity>, Arc<NodeIdentity>) {
        let network = crate::fixture::Network::found(None);
        (network.state, network.founder, network.joiner)
    }

    fn peer_of(identity: &NodeIdentity) -> PeerId {
        let bytes: [u8; 32] = identity.transport_key().public_key().as_bytes().try_into().unwrap();
        Address::parse(bytes).unwrap().peer_id()
    }

    #[test]
    fn a_member_is_admitted_with_its_device() {
        let (state, _, joiner) = network();
        let members = Members::from_state(&state);
        assert_eq!(members.member(&peer_of(&joiner)), Some(joiner.device_id()));
        let mut gate = Gate(Arc::new(RwLock::new(members)), false);
        assert_eq!(gate.admit(&peer_of(&joiner), b"peerfectly"), Decision::Accept { psk: None });
    }

    /// Every member's key is found back from its peer id, whichever sign its
    /// ed25519 encoding has: a peer id keeps none, and the map back tries both.
    #[test]
    fn every_member_is_found_by_its_peer_id_whatever_its_sign() {
        let (mut state, _, _) = network();
        let devices: Vec<Arc<NodeIdentity>> =
            (0..32).map(|_| Arc::new(NodeIdentity::generate().unwrap())).collect();
        let mut signs = std::collections::BTreeSet::new();
        for device in &devices {
            let spec =
                device.device_spec("board", roster::types::Role::Member, false, vec![]).unwrap();
            let record = spec.into_record(roster::id::OperationId::from_bytes([3; 32])).unwrap();
            state.devices.insert(device.device_id(), record);
            let key = device.transport_key().public_key().as_bytes().to_vec();
            signs.insert(key.last().copied().unwrap_or(0) >> 7);
        }
        assert_eq!(signs.len(), 2, "keys of both signs among them");
        let members = Members::from_state(&state);
        for device in &devices {
            assert_eq!(members.member(&peer_of(device)), Some(device.device_id()));
            assert!(members.address(&peer_of(device)).is_some());
        }
    }

    #[test]
    fn a_stranger_is_refused_as_not_a_member() {
        let (state, _, _) = network();
        let stranger = NodeIdentity::generate().unwrap();
        let mut gate = Gate(Arc::new(RwLock::new(Members::from_state(&state))), false);
        let Decision::Refuse { code, .. } = gate.admit(&peer_of(&stranger), b"peerfectly") else {
            panic!("a stranger is refused");
        };
        assert_eq!(code.get(), NOT_A_MEMBER);
    }

    #[test]
    fn newer_state_drops_a_revoked_device() {
        let (mut state, _, joiner) = network();
        let shared = Arc::new(RwLock::new(Members::from_state(&state)));
        let mut gate = Gate(Arc::clone(&shared), false);

        state.devices.remove(&joiner.device_id());
        state.revoked.insert(joiner.device_id());
        *shared.write().unwrap() = Members::from_state(&state);

        assert!(matches!(gate.admit(&peer_of(&joiner), b"peerfectly"), Decision::Refuse { .. }));
        assert_eq!(shared.read().unwrap().member(&peer_of(&joiner)), None);
    }

    #[test]
    fn refusal_codes_read_back_as_their_errors() {
        assert_eq!(refusal(NOT_A_MEMBER), Some(Error::NotAMember));
        assert_eq!(refusal(REVOKED), Some(Error::Revoked));
        assert_eq!(refusal(0x0200), None);
        assert_eq!(refusal_code(&Err(Error::Revoked)), Some(REVOKED));
    }
}

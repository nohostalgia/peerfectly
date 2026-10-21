//! Who may open a convesso session with this node, read from roster state.
//!
//! convesso asks the application whether to admit a peer during the handshake,
//! synchronously, by the peer's X25519 id. The roster names devices by their
//! ed25519 transport keys. This is the one place the second becomes the first:
//! a map rebuilt whole from the roster state each time newer state arrives, so
//! it is a function of that state and never a second opinion beside it.
//!
//! What each key is told comes from `transport::auth::authorize`, the decision
//! every binding takes. A key no device holds is a stranger. A key whose device
//! the state still records and also revokes is revoked; a revoked device the
//! roster has dropped altogether is, by its key alone, a stranger — exactly what
//! the interface's own check says.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use convesso_core::handshake::{Admission, Decision, RefusalCode};
use convesso_core::identity::{Address, PeerId};
use roster::id::DeviceId;
use roster::state::RosterState;
use roster::types::{Algorithm, KeyPurpose};
use transport::error::Error;

/// The handshake's refusal of a stranger.
pub const NOT_A_MEMBER: u16 = 0x0100;
/// The handshake's refusal of a revoked device.
pub const REVOKED: u16 = 0x0101;

/// What the roster says about one transport key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The key as convesso dials it.
    pub address: Address,
    /// The device, or why it is refused.
    pub verdict: Result<DeviceId, Error>,
}

/// Every transport key the roster names, by the id convesso authenticates.
#[derive(Debug, Default, Clone)]
pub struct Members {
    by_peer: HashMap<[u8; 32], Entry>,
}

impl Members {
    /// The map for this state.
    #[must_use]
    pub fn from_state(state: &RosterState) -> Self {
        let mut by_peer = HashMap::new();
        for record in state.devices.values() {
            for entry in &record.keys {
                if entry.purpose != KeyPurpose::Transport || entry.alg != Algorithm::Ed25519 {
                    continue;
                }
                let Ok(bytes) = <[u8; 32]>::try_from(entry.value.as_slice()) else { continue };
                // A key convesso cannot read can reach nobody here, so it is
                // left out rather than refused: it would never present itself.
                let Ok(address) = Address::parse(bytes) else { continue };
                let verdict = transport::auth::authorize(state, &entry.key_id());
                by_peer.insert(*address.peer_id().as_bytes(), Entry { address, verdict });
            }
        }
        Self { by_peer }
    }

    /// What the roster says about the peer convesso authenticated.
    ///
    /// A peer nothing names is a stranger.
    pub fn verdict(&self, peer: &PeerId) -> Result<DeviceId, Error> {
        self.by_peer
            .get(peer.as_bytes())
            .map_or(Err(Error::NotAMember), |entry| entry.verdict.clone())
    }

    /// The address a peer is dialled at, if the roster names its key.
    #[must_use]
    pub fn address(&self, peer: &PeerId) -> Option<Address> {
        self.by_peer.get(peer.as_bytes()).map(|entry| entry.address)
    }

    /// Every member's key as convesso dials it, but `own`.
    #[must_use]
    pub fn others(&self, own: &PeerId) -> Vec<Address> {
        self.by_peer
            .values()
            .filter(|entry| entry.verdict.is_ok() && entry.address.peer_id() != *own)
            .map(|entry| entry.address)
            .collect()
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
/// transport is what the next handshake reads.
pub struct Gate(pub Arc<RwLock<Members>>);

impl Admission for Gate {
    fn admit(&mut self, peer: &PeerId, _context: &[u8]) -> Decision {
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
        let mut gate = Gate(Arc::new(RwLock::new(members)));
        assert_eq!(gate.admit(&peer_of(&joiner), b"peerfectly"), Decision::Accept { psk: None });
    }

    #[test]
    fn a_stranger_is_refused_as_not_a_member() {
        let (state, _, _) = network();
        let stranger = NodeIdentity::generate().unwrap();
        let mut gate = Gate(Arc::new(RwLock::new(Members::from_state(&state))));
        let Decision::Refuse { code, .. } = gate.admit(&peer_of(&stranger), b"peerfectly") else {
            panic!("a stranger is refused");
        };
        assert_eq!(code.get(), NOT_A_MEMBER);
    }

    #[test]
    fn newer_state_drops_a_revoked_device() {
        let (mut state, _, joiner) = network();
        let shared = Arc::new(RwLock::new(Members::from_state(&state)));
        let mut gate = Gate(Arc::clone(&shared));

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

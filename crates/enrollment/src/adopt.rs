//! Deciding whether a delivered network is one this device may believe.
//!
//! # Delivery proves nothing
//!
//! A roster is signed operations. Whoever hands it over — the admin, a stranger,
//! a file on a stick — changes nothing about whether it is true, so this asks
//! only what it contains:
//!
//! - an operation admitting **this device's own keys**, which is what makes it
//!   the network that was being joined rather than some other network;
//! - and that operation surviving the roster's own rules, which admit a device
//!   only when an admin signed it.
//!
//! A network that satisfies both is adopted no matter who delivered it. One
//! that fails any is refused, and nothing is written.

use identity::NodeIdentity;
use roster::id::DeviceId;
use roster::roster::Roster;
use roster::sign::{PublicKey, RawOperation};
use roster::state::RosterState;
use roster::types::{KeyPurpose, OperationBody};

use crate::error::{Error, Result};

/// A network this device has decided it may believe.
#[derive(Debug, Clone)]
pub struct Adopted {
    /// The state derived from what was delivered.
    pub state: RosterState,
}

/// Decides whether a delivered network may be adopted.
///
/// # Errors
///
/// [`Error::NotAdmitted`] when the network does not admit this device,
/// [`Error::NotSignedByAdmin`] when it contains an admission that an admin did
/// not sign, and [`Error::RosterUnusable`] when what arrived does not derive to
/// a state at all.
pub fn adopt(operations: &[Vec<u8>], identity: &NodeIdentity) -> Result<Adopted> {
    let signing = identity.signing_key().public_key();
    let transport = identity.transport_key().public_key();

    let mut roster = Roster::new();
    for operation in operations {
        roster.offer_bytes(operation);
    }
    let state = roster.state()?;

    let me = DeviceId::of_signing_key(signing.as_bytes());
    let Some(record) = state.devices.get(&me) else {
        // Not a member of what arrived. Either this is a different network, or
        // the admission was refused by the roster's own rules — and the second
        // is worth telling apart, because it means somebody who is not an admin
        // tried to admit this device.
        return Err(if admission_attempted_by_a_non_admin(operations, &me) {
            Error::NotSignedByAdmin
        } else {
            Error::NotAdmitted
        });
    };

    // The identity is derived from the signing key, so a record could name this
    // device while carrying somebody else's transport key. Then sessions would
    // be answered by that somebody.
    let holds_our_transport = record.keys.iter().any(|entry| {
        entry.purpose == KeyPurpose::Transport
            && entry.value == transport.as_bytes()
            && entry.alg == transport.algorithm()
    });
    if !holds_our_transport {
        return Err(Error::NotAdmitted);
    }

    Ok(Adopted { state })
}

/// Whether what arrived contains an admission of this device that the roster
/// refused to apply.
///
/// Used only to tell two refusals apart. It decides nothing about adoption: the
/// roster's own rules already dropped the operation, and this reads the same
/// bytes again to say *why* the device is missing.
fn admission_attempted_by_a_non_admin(operations: &[Vec<u8>], me: &DeviceId) -> bool {
    operations.iter().any(|bytes| {
        let Ok(operation) = RawOperation::decode(bytes) else { return false };
        let OperationBody::AddDevice(spec) = &operation.core().body else { return false };
        spec.device_id().is_ok_and(|id| &id == me)
    })
}

/// Whether a key is the one a record names for the transport purpose.
///
/// Kept beside the check it serves, so a reader of `adopt` does not have to
/// take on faith that "holds our transport key" means what it sounds like.
#[must_use]
pub fn record_holds_transport(record: &roster::types::DeviceRecord, key: &PublicKey) -> bool {
    record
        .keys
        .iter()
        .any(|entry| entry.purpose == KeyPurpose::Transport && entry.value == key.as_bytes())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use roster::id::NetworkId;
    use roster::sign::sign_operation;
    use roster::types::{NetworkParams, OperationCore, Role};

    use super::*;

    /// A founder, and a network that admits `joiner` if `admit` is set.
    fn network(founder: &NodeIdentity, joiner: &NodeIdentity, admit: bool) -> Vec<Vec<u8>> {
        let params = NetworkParams::with_relay(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            Some("https://relay.example:443"),
            "example.internal",
            2_592_000,
        )
        .expect("valid");

        let genesis = OperationCore::new(
            1,
            founder.signing_key().algorithm(),
            OperationBody::CreateNetwork {
                device: founder.device_spec("founder", Role::Admin, true, vec![]).expect("spec"),
                params,
            },
            vec![],
            founder.signing_key().key_id(),
            NetworkId::from_bytes([0; 32]),
        )
        .expect("well-formed");
        let genesis_bytes = sign_operation(&genesis, founder.signer()).expect("signs");
        let network = NetworkId::from_bytes(*genesis.id().as_bytes());

        let mut operations = vec![genesis_bytes];
        if admit {
            let add = OperationCore::new(
                2,
                founder.signing_key().algorithm(),
                OperationBody::AddDevice(
                    joiner.device_spec("joiner", Role::Member, false, vec![]).expect("spec"),
                ),
                vec![genesis.id()],
                founder.signing_key().key_id(),
                network,
            )
            .expect("well-formed");
            operations.push(sign_operation(&add, founder.signer()).expect("signs"));
        }
        operations
    }

    #[test]
    fn a_network_that_admits_this_device_is_adopted() {
        let founder = NodeIdentity::generate().expect("generates");
        let joiner = NodeIdentity::generate().expect("generates");
        let delivered = network(&founder, &joiner, true);

        let adopted = adopt(&delivered, &joiner).expect("adopts");
        assert!(adopted.state.devices.len() >= 2);
    }

    /// Who delivered it is not one of the questions asked.
    #[test]
    fn delivery_by_a_stranger_is_not_itself_a_problem() {
        let founder = NodeIdentity::generate().expect("generates");
        let joiner = NodeIdentity::generate().expect("generates");
        let delivered = network(&founder, &joiner, true);

        // The bytes are the same whoever carried them, and that is the point.
        adopt(&delivered, &joiner).expect("adopts");
    }

    #[test]
    fn a_network_that_does_not_admit_this_device_is_refused() {
        let founder = NodeIdentity::generate().expect("generates");
        let joiner = NodeIdentity::generate().expect("generates");
        let delivered = network(&founder, &joiner, false);

        assert!(matches!(adopt(&delivered, &joiner), Err(Error::NotAdmitted)));
    }

    /// An admission signed by somebody who is not an admin is dropped by the
    /// roster's own rules. Told apart from "a different network" because the two
    /// mean different things to whoever is standing there.
    #[test]
    fn an_admission_by_a_non_admin_is_named_as_such() {
        let founder = NodeIdentity::generate().expect("generates");
        let outsider = NodeIdentity::generate().expect("generates");
        let joiner = NodeIdentity::generate().expect("generates");

        let mut delivered = network(&founder, &joiner, false);
        let genesis = RawOperation::decode(delivered.first().expect("genesis")).expect("decodes");

        let add = OperationCore::new(
            2,
            outsider.signing_key().algorithm(),
            OperationBody::AddDevice(
                joiner.device_spec("joiner", Role::Member, false, vec![]).expect("spec"),
            ),
            vec![genesis.id()],
            outsider.signing_key().key_id(),
            NetworkId::from_bytes(*genesis.id().as_bytes()),
        )
        .expect("well-formed");
        delivered.push(sign_operation(&add, outsider.signer()).expect("signs"));

        assert!(matches!(adopt(&delivered, &joiner), Err(Error::NotSignedByAdmin)));
    }

    #[test]
    fn nothing_at_all_is_refused_rather_than_adopted() {
        let joiner = NodeIdentity::generate().expect("generates");
        assert!(adopt(&[], &joiner).is_err());
    }
}

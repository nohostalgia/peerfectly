//! Making an admin a member again.
//!
//! The roster has always carried a signed demotion, with its rules: an admin
//! may not demote a founder other than itself, a demotion beats a promotion it
//! is concurrent with, and what the demoted admin signed concurrently with it is
//! voided. Nothing a person could type produced one.
//!
//! # This module decides nothing the roster decides
//!
//! Whether this admin may demote that one is the roster's, and a refusal comes
//! back in its words. What happens here is: find the device a person named, the
//! way `revoke` finds it, and refuse two things before anything is signed — a
//! device that is already a member, and the network's only admin. A network with
//! no admin can never sign anything again, and no person demoting a device means
//! that.
//!
//! # The key it leaves behind
//!
//! A demoted device keeps its signing key until the demotion is **settled**:
//! beneath the roster's base, where nothing can void it. See
//! [`settled_member`].

use identity::NodeIdentity;
use roster::id::DeviceId;
use roster::state::RosterState;
use roster::types::{OperationBody, OperationCore, Role};

use crate::control::{Target, short_id, shown};

/// What a person asked for, resolved against the roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Demotion {
    /// The admin to demote.
    pub device: DeviceId,
    /// The name it answers to.
    pub name: String,
}

/// What a person who named one of several devices is told to do instead.
const CHOOSE: &str = "Name the one you mean by its id:\n  peerfectly demote --id <id>";

/// Finds the admin a person named.
///
/// # Errors
///
/// When no device matches or more than one does, when it is already a member,
/// or when it is the only admin in `state`, this device included.
pub fn resolve(state: &RosterState, target: &Target) -> Result<Demotion, String> {
    let found = crate::revoking::find(state, target, CHOOSE)?;
    if found.role != Role::Admin {
        return Err(format!(
            "{} [{}] is already a member. Nothing was signed.",
            shown(&found.name),
            short_id(&found.id)
        ));
    }
    let admins = state.devices.values().filter(|record| record.role == Role::Admin).count();
    if admins <= 1 {
        return Err(format!(
            "{} [{}] is this network's only admin: demoted, the network would have no admin, \
             and nothing could ever be signed for it again. Nothing was signed.",
            shown(&found.name),
            short_id(&found.id)
        ));
    }
    Ok(Demotion { device: found.id, name: found.name.clone() })
}

/// Builds the demotion, up to but not including its signature.
///
/// # Errors
///
/// When the operation cannot be built.
pub fn core(
    demotion: &Demotion,
    identity: &NodeIdentity,
    state: &RosterState,
    heads: Vec<roster::id::OperationId>,
) -> Result<OperationCore, String> {
    OperationCore::new(
        crate::clock::signing_time(),
        identity.signing_key().algorithm(),
        OperationBody::Demote { device: demotion.device },
        heads,
        identity.signing_key().key_id(),
        state.network,
    )
    .map_err(|cause| cause.to_string())
}

/// Builds and signs the demotion, where this device's key can sign it.
///
/// # Errors
///
/// When the operation cannot be built or signed.
pub fn sign(
    demotion: &Demotion,
    identity: &NodeIdentity,
    state: &RosterState,
    heads: Vec<roster::id::OperationId>,
) -> Result<Vec<u8>, String> {
    let core = core(demotion, identity, state, heads)?;
    identity.sign_operation(&core).map_err(|cause| crate::control::declined(&cause))
}

/// Whether `device` is a member in the roster's **base**: the state beneath the
/// window, which nothing still held can change.
///
/// What decides when a demoted device's signing key may go. Seen in the derived
/// state, a demotion may still be voided — one signed by an admin whose
/// revocation was concurrent with it is no demotion — and a key destroyed then
/// could never be had back. Beneath the base, nothing anchoring into the
/// compacted region is accepted any more, so the role is final.
#[must_use]
pub fn settled_member(base: Option<&RosterState>, device: &DeviceId) -> bool {
    base.and_then(|state| state.devices.get(device))
        .is_some_and(|record| record.role == Role::Member)
}

#[cfg(test)]
mod tests {
    use roster::id::NetworkId;
    use roster::roster::Roster;
    use roster::types::NetworkParams;

    use super::*;

    /// A network founded by `nas`, with `laptop` admitted as `role`, and the
    /// founder's identity.
    fn network(role: Role) -> (RosterState, std::sync::Arc<NodeIdentity>) {
        let founder = std::sync::Arc::new(NodeIdentity::generate().expect("generates"));
        let params = NetworkParams::with_relay(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            None::<String>,
            "example.internal",
            2_592_000,
        )
        .expect("valid");
        let genesis = OperationCore::new(
            1,
            founder.signing_key().algorithm(),
            OperationBody::CreateNetwork {
                device: founder.device_spec("nas", Role::Admin, true, vec![]).expect("spec"),
                params,
            },
            vec![],
            founder.signing_key().key_id(),
            NetworkId::from_bytes([0; 32]),
        )
        .expect("well-formed");
        let mut roster = Roster::new();
        assert!(
            roster
                .offer_bytes(
                    &roster::sign::sign_operation(&genesis, founder.signer()).expect("signs")
                )
                .is_accepted()
        );
        let net = NetworkId::from_bytes(*genesis.id().as_bytes());
        let device = NodeIdentity::generate().expect("generates");
        let add = OperationCore::new(
            2,
            founder.signing_key().algorithm(),
            OperationBody::AddDevice(
                device.device_spec("laptop", role, false, vec![]).expect("spec"),
            ),
            vec![genesis.id()],
            founder.signing_key().key_id(),
            net,
        )
        .expect("well-formed");
        assert!(
            roster
                .offer_bytes(&roster::sign::sign_operation(&add, founder.signer()).expect("signs"))
                .is_accepted()
        );
        (roster.state().expect("a network"), founder)
    }

    fn id_of(state: &RosterState, name: &str) -> DeviceId {
        state.devices.values().find(|record| record.name == name).expect("named").id
    }

    #[test]
    fn an_admin_is_found_by_name_and_by_short_id() {
        let (state, _) = network(Role::Admin);
        let by_name = resolve(&state, &Target::Name("laptop".to_owned())).expect("resolves");
        assert_eq!(by_name.device, id_of(&state, "laptop"));
        let by_id =
            resolve(&state, &Target::Id(short_id(&id_of(&state, "laptop")))).expect("resolves");
        assert_eq!(by_id, by_name);
    }

    #[test]
    fn a_member_is_not_demoted() {
        let (state, _) = network(Role::Member);
        let refusal = resolve(&state, &Target::Name("laptop".to_owned())).expect_err("a member");
        assert!(
            refusal.contains("already a member") && refusal.contains("Nothing was signed"),
            "{refusal}"
        );
    }

    /// The only admin, whether another device or this one, is not demoted.
    #[test]
    fn the_only_admin_is_not_demoted() {
        let (state, _) = network(Role::Member);
        let refusal = resolve(&state, &Target::Name("nas".to_owned())).expect_err("the only one");
        assert!(
            refusal.contains("only admin") && refusal.contains("Nothing was signed"),
            "{refusal}"
        );
    }

    /// With another admin present, an admin may demote itself: the founder
    /// rule, which this module does not judge, is the roster's.
    #[test]
    fn with_two_admins_either_may_be_named() {
        let (state, founder) = network(Role::Admin);
        let itself = resolve(&state, &Target::Name("nas".to_owned())).expect("resolves");
        assert_eq!(itself.device, founder.device_id());
    }

    /// A key goes only once the base says member; derived state alone, or a
    /// base that still says admin, keeps it.
    #[test]
    fn only_a_base_that_says_member_settles_a_demotion() {
        let (as_member, _) = network(Role::Member);
        let (as_admin, _) = network(Role::Admin);
        let laptop = id_of(&as_member, "laptop");
        assert!(settled_member(Some(&as_member), &laptop));
        assert!(!settled_member(Some(&as_admin), &id_of(&as_admin, "laptop")));
        assert!(!settled_member(None, &laptop), "no base, nothing settled");
    }
}

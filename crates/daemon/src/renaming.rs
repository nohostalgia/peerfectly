//! Giving a device a new name.
//!
//! The roster has always carried a signed rename, merged by its own rule when
//! two admins rename one device apart, and nothing a person could type produced
//! one. A device named badly at join kept that name, or was revoked and admitted
//! again under new keys.
//!
//! # This module decides nothing about who may rename
//!
//! As with revoking: that is the roster's rule, an admin and not a member, and a
//! refusal comes back in its words. What happens here is: find the device a
//! person named, the way `revoke` finds it, check the new name is one a resolver
//! can answer and that no other device answers to it, and build the operation.

use identity::NodeIdentity;
use roster::id::DeviceId;
use roster::state::RosterState;
use roster::types::{OperationBody, OperationCore};

use crate::control::{Target, short_id, shown};

/// What a person asked for, resolved against the roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Renaming {
    /// The device to rename.
    pub device: DeviceId,
    /// The name it answers to now.
    pub from: String,
    /// The name it is to answer to, usable and in lower case.
    pub to: String,
}

/// What a person who named one of several devices is told to do instead.
const CHOOSE: &str = "Name the one you mean by its id:\n  peerfectly rename --id <id> <new name>";

/// Finds the device a person named and checks the name it is to take.
///
/// # Errors
///
/// When the new name is not usable, when no member matches or more than one
/// does, when another device already answers to the new name (case aside), or
/// when it is already this device's name.
pub fn resolve(state: &RosterState, target: &Target, given: &str) -> Result<Renaming, String> {
    let to = crate::names::usable(given)
        .map_err(|unusable| format!("{unusable}. Nothing was signed."))?;
    let found = crate::revoking::find(state, target, CHOOSE)?;

    if found.name == to {
        return Err(format!("{} is already this device's name. Nothing was signed.", shown(&to)));
    }
    if let Some(holder) = state
        .devices
        .values()
        .find(|record| record.id != found.id && record.name.eq_ignore_ascii_case(&to))
    {
        return Err(format!(
            "{} is already the name of {} [{}]. Nothing was signed.",
            shown(&to),
            shown(&holder.name),
            short_id(&holder.id)
        ));
    }

    Ok(Renaming { device: found.id, from: found.name.clone(), to })
}

/// Builds the rename, up to but not including its signature.
///
/// Separate from [`sign`] for the reason revoking's is: where the key is
/// somewhere this process cannot reach, somebody else signs these bytes.
///
/// # Errors
///
/// When the operation cannot be built.
pub fn core(
    renaming: &Renaming,
    identity: &NodeIdentity,
    state: &RosterState,
    heads: Vec<roster::id::OperationId>,
) -> Result<OperationCore, String> {
    OperationCore::new(
        crate::clock::signing_time(),
        identity.signing_key().algorithm(),
        OperationBody::Rename { device: renaming.device, name: renaming.to.clone() },
        heads,
        identity.signing_key().key_id(),
        state.network,
    )
    .map_err(|cause| cause.to_string())
}

/// Builds and signs the rename, where this device's key can sign it.
///
/// # Errors
///
/// When the operation cannot be built or signed.
pub fn sign(
    renaming: &Renaming,
    identity: &NodeIdentity,
    state: &RosterState,
    heads: Vec<roster::id::OperationId>,
) -> Result<Vec<u8>, String> {
    let core = core(renaming, identity, state, heads)?;
    identity.sign_operation(&core).map_err(|cause| crate::control::declined(&cause))
}

#[cfg(test)]
mod tests {
    use roster::id::NetworkId;
    use roster::roster::Roster;
    use roster::types::{NetworkParams, Role};

    use super::*;

    /// A network of `nas`, `laptop` and whatever else is named, all admitted by
    /// the founder, and the founder's identity.
    fn network(others: &[&str]) -> (RosterState, std::sync::Arc<NodeIdentity>) {
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

        let mut heads = vec![genesis.id()];
        for (at, name) in std::iter::once(&"laptop").chain(others).enumerate() {
            let device = NodeIdentity::generate().expect("generates");
            let add = OperationCore::new(
                u64::try_from(at).expect("small").saturating_add(2),
                founder.signing_key().algorithm(),
                OperationBody::AddDevice(
                    device.device_spec(*name, Role::Member, false, vec![]).expect("spec"),
                ),
                heads.clone(),
                founder.signing_key().key_id(),
                net,
            )
            .expect("well-formed");
            assert!(
                roster
                    .offer_bytes(
                        &roster::sign::sign_operation(&add, founder.signer()).expect("signs")
                    )
                    .is_accepted()
            );
            heads = vec![add.id()];
        }
        (roster.state().expect("a network"), founder)
    }

    fn id_of(state: &RosterState, name: &str) -> DeviceId {
        state.devices.values().find(|record| record.name == name).expect("named").id
    }

    #[test]
    fn a_device_is_renamed_by_name_and_the_new_name_is_lowered() {
        let (state, _) = network(&[]);
        let renaming =
            resolve(&state, &Target::Name("laptop".to_owned()), "Studio").expect("resolves");
        assert_eq!(renaming.device, id_of(&state, "laptop"));
        assert_eq!(renaming.from, "laptop");
        assert_eq!(renaming.to, "studio");
    }

    #[test]
    fn a_device_is_renamed_by_its_short_id() {
        let (state, _) = network(&[]);
        let id = short_id(&id_of(&state, "laptop"));
        let renaming = resolve(&state, &Target::Id(id), "studio").expect("resolves");
        assert_eq!(renaming.device, id_of(&state, "laptop"));
    }

    /// `Nas` and `nas` are one name to the resolver.
    #[test]
    fn a_name_in_use_is_refused_case_aside() {
        let (state, _) = network(&[]);
        let refusal =
            resolve(&state, &Target::Name("laptop".to_owned()), "NAS").expect_err("nas has it");
        assert!(
            refusal.contains("already the name of nas") && refusal.contains("Nothing was signed"),
            "{refusal}"
        );
        assert!(refusal.contains(&short_id(&id_of(&state, "nas"))), "with its id: {refusal}");
    }

    #[test]
    fn an_unusable_name_is_refused_with_a_suggestion() {
        let (state, _) = network(&[]);
        let refusal =
            resolve(&state, &Target::Name("laptop".to_owned()), "nas.casa").expect_err("a dot");
        assert!(refusal.contains("`nas-casa`"), "{refusal}");
    }

    #[test]
    fn the_name_a_device_already_has_signs_nothing() {
        let (state, _) = network(&[]);
        let refusal =
            resolve(&state, &Target::Name("laptop".to_owned()), "laptop").expect_err("the same");
        assert!(refusal.contains("already this device's name"), "{refusal}");
    }

    /// A name from before the rule may be mixed case: lowering it is a rename.
    #[test]
    fn lowering_an_old_mixed_case_name_is_a_rename() {
        let (state, _) = network(&["Desk"]);
        let renaming =
            resolve(&state, &Target::Name("desk".to_owned()), "desk").expect("a change of case");
        assert_eq!((renaming.from.as_str(), renaming.to.as_str()), ("Desk", "desk"));
    }

    /// Two devices answering to one name, from before the rule: nothing chosen.
    #[test]
    fn a_name_two_devices_share_is_refused_listing_both() {
        let (state, _) = network(&["Laptop"]);
        let refusal = resolve(&state, &Target::Name("laptop".to_owned()), "studio")
            .expect_err("two answer to it");
        assert!(refusal.contains("peerfectly rename --id"), "{refusal}");
        for name in ["laptop", "Laptop"] {
            assert!(refusal.contains(&short_id(&id_of(&state, name))), "{name}: {refusal}");
        }
    }

    #[test]
    fn the_operation_is_a_rename_of_that_device() {
        let (state, founder) = network(&[]);
        let renaming =
            resolve(&state, &Target::Name("laptop".to_owned()), "studio").expect("resolves");
        let core = core(&renaming, &founder, &state, vec![]).expect("builds");
        assert_eq!(
            core.body,
            OperationBody::Rename { device: id_of(&state, "laptop"), name: "studio".to_owned() }
        );
    }
}

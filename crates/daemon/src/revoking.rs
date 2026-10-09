//! Expelling a device from the network.
//!
//! Every layer beneath this could already do it. The roster has always been able
//! to express a revocation, `roster-sync` has always carried one, and the
//! transport has always refused a revoked peer. What was missing was anything a
//! person could type — so a device that had been lost or stolen stayed a member
//! for as long as the network existed.
//!
//! That is a worse gap than the one this change set out to fix. A revocation
//! that takes effect late is a window; one that cannot be made at all is a wall.
//!
//! # This module decides nothing about who may revoke
//!
//! Whether *this* device is allowed to expel *that* one is the roster's rule —
//! admin rights, founder protection, and the order operations happened in. All
//! of it is already implemented and tested where the signed log lives. What
//! happens here is: find the device a person named, build the operation, sign it,
//! and hand it to the node. A refusal comes back in the roster's words.
//!
//! A check here that agreed with the roster would be duplication; one that
//! disagreed would be the daemon deciding membership, which
//! [`crate::lib`](crate) says it must never do.

use identity::NodeIdentity;
use roster::id::DeviceId;
use roster::state::RosterState;
use roster::types::{DeviceRecord, OperationBody, OperationCore};

use crate::control::{Target, read_short_id, short_id, shown};

/// What a person asked for, resolved against the roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expulsion {
    /// The device to expel.
    pub device: DeviceId,
    /// The name it answers to, kept for what is said afterwards.
    pub name: String,
    /// Why, as the person wrote it.
    pub reason: String,
}

/// Finds the device a person named.
///
/// **By exact name or exact id, never by prefix or position.** A person revoking
/// a device is doing something irreversible — the log is append-only, so a
/// revocation made by mistake cannot be taken back, only followed by a fresh
/// admission with a new identity. Matching `lap` to `laptop` would save four
/// characters and put the cost of a typo on the wrong side of that.
///
/// # Never one of several
///
/// A name is not unique. Two admins admitting a `phone` while apart give the
/// network two of them, and this used to take whichever sorted first by id — so
/// `peerfectly revoke phone` could expel the phone a person still has and leave the
/// stolen one in, irreversibly. Where more than one member matches, nothing is
/// signed and every match is listed with the id that names it.
///
/// # Errors
///
/// When no member matches, when more than one does, when an id is not all sixteen
/// digits or names a device already revoked, or when the device is this one:
/// revoking oneself is not what anybody means by it, and the roster would accept
/// it, leaving a machine that has expelled itself from a network it still holds.
pub fn resolve(
    state: &RosterState,
    identity: &NodeIdentity,
    target: &Target,
    reason: &str,
) -> Result<Expulsion, String> {
    if reason.trim().is_empty() {
        return Err("a revocation needs a reason: the roster carries one so the person \
                    deciding what to do next has something to read"
            .to_owned());
    }

    let found = find(state, target, CHOOSE)?;

    if found.id == identity.device_id() {
        return Err(format!(
            "{} is this device. Revoking it here would expel this machine from a \
             network it would go on holding a roster for; to leave, remove its state \
             instead.",
            asked_for(target)
        ));
    }

    Ok(Expulsion { device: found.id, name: found.name.clone(), reason: reason.trim().to_owned() })
}

/// What a person who named one of several devices is told to do instead.
const CHOOSE: &str = "Revoking is irreversible, so this will not choose. Name the one you mean by \
                      its id:\n  peerfectly revoke --id <id> <reason>";

/// How a target is quoted back to the person who typed it.
fn asked_for(target: &Target) -> String {
    match target {
        Target::Name(name) => format!("{name:?}"),
        Target::Id(typed) => {
            read_short_id(typed).map_or_else(|| format!("{typed:?}"), |id| format!("the id {id}"))
        }
    }
}

/// Finds the one device a person named, by name (case aside) or by its short id.
///
/// Shared by revoking and renaming, which name a device the same way: exactly,
/// never by prefix or position, and never one of several. `choose` is what the
/// person is told when more than one answers.
///
/// # Errors
///
/// When no member matches, when more than one does, or when an id is not all
/// sixteen digits or names a device already revoked.
pub(crate) fn find<'a>(
    state: &'a RosterState,
    target: &Target,
    choose: &str,
) -> Result<&'a DeviceRecord, String> {
    let (matches, asked): (Vec<&DeviceRecord>, String) = match target {
        Target::Name(name) => (
            state
                .devices
                .values()
                .filter(|record| record.name.eq_ignore_ascii_case(name))
                .collect(),
            format!("{name:?}"),
        ),
        Target::Id(typed) => {
            let Some(id) = read_short_id(typed) else {
                return Err(format!(
                    "{typed:?} is not a device id. An id is all sixteen digits, as the report \
                     shows it: xxxx-xxxx-xxxx-xxxx. Part of one is not accepted."
                ));
            };
            let found: Vec<&DeviceRecord> =
                state.devices.values().filter(|record| short_id(&record.id) == id).collect();
            if found.is_empty() && state.revoked.iter().any(|device| short_id(device) == id) {
                return Err(format!(
                    "the device with id {id} is already revoked from this network. Nothing \
                     was signed."
                ));
            }
            (found, format!("the id {id}"))
        }
    };

    match matches.as_slice() {
        [] => Err(format!("no device in this network answers to {asked}")),
        [one] => Ok(*one),
        several => {
            let listed = several
                .iter()
                .map(|record| format!("  {} [{}]", shown(&record.name), short_id(&record.id)))
                .collect::<Vec<_>>()
                .join("\n");
            Err(format!(
                "{} devices in this network answer to {asked}, and nothing was signed:\n\
                 {listed}\n\
                 {choose}",
                several.len()
            ))
        }
    }
}

/// Builds the revocation, up to but not including its signature.
///
/// It carries the minute it was signed, on this device's clock: the pending
/// screen is titled by when a revocation was signed, and this device's own
/// operation is the only honest source of that. Two revocations of the same
/// device, with the same reason, on the same heads, in the same minute, are one
/// operation — and they are one act.
///
/// Separate from [`sign`] because on some devices the act stops here: the key is
/// somewhere this process cannot reach, and what happens next is that somebody
/// else signs these bytes. Building them is the same either way, and is the half
/// that must not be written twice.
///
/// # Errors
///
/// When the operation cannot be built.
pub fn core(
    expulsion: &Expulsion,
    identity: &NodeIdentity,
    state: &RosterState,
    heads: Vec<roster::id::OperationId>,
) -> Result<OperationCore, String> {
    OperationCore::new(
        crate::clock::signing_time(),
        identity.signing_key().algorithm(),
        OperationBody::RevokeDevice { device: expulsion.device, reason: expulsion.reason.clone() },
        heads,
        identity.signing_key().key_id(),
        state.network,
    )
    .map_err(|cause| cause.to_string())
}

/// Builds and signs the revocation, where this device's key can sign it.
///
/// # Errors
///
/// When the operation cannot be built or signed.
pub fn sign(
    expulsion: &Expulsion,
    identity: &NodeIdentity,
    state: &RosterState,
    heads: Vec<roster::id::OperationId>,
) -> Result<Vec<u8>, String> {
    let core = core(expulsion, identity, state, heads)?;
    identity.sign_operation(&core).map_err(|cause| crate::control::declined(&cause))
}

#[cfg(test)]
#[expect(clippy::panic, reason = "a test reports failure by panicking")]
mod tests {
    use roster::id::NetworkId;
    use roster::roster::Roster;
    use roster::types::{NetworkParams, Role};

    use super::*;

    /// A network of two, and the identities behind it.
    fn network() -> (RosterState, std::sync::Arc<NodeIdentity>, std::sync::Arc<NodeIdentity>) {
        let founder = std::sync::Arc::new(NodeIdentity::generate().expect("generates"));
        let joiner = std::sync::Arc::new(NodeIdentity::generate().expect("generates"));
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
        let genesis_bytes =
            roster::sign::sign_operation(&genesis, founder.signer()).expect("signs");
        let net = NetworkId::from_bytes(*genesis.id().as_bytes());

        let add = OperationCore::new(
            2,
            founder.signing_key().algorithm(),
            OperationBody::AddDevice(
                joiner.device_spec("laptop", Role::Member, false, vec![]).expect("spec"),
            ),
            vec![genesis.id()],
            founder.signing_key().key_id(),
            net,
        )
        .expect("well-formed");
        let add_bytes = roster::sign::sign_operation(&add, founder.signer()).expect("signs");

        let mut roster = Roster::new();
        assert!(roster.offer_bytes(&genesis_bytes).is_accepted());
        assert!(roster.offer_bytes(&add_bytes).is_accepted());
        (roster.state().expect("a network"), founder, joiner)
    }

    #[test]
    fn a_device_is_found_by_the_name_a_person_sees() {
        let (state, founder, joiner) = network();
        let expulsion =
            resolve(&state, &founder, &Target::Name("laptop".to_owned()), "left on a train")
                .expect("resolves");
        assert_eq!(expulsion.device, joiner.device_id());
        assert_eq!(expulsion.name, "laptop");
        assert_eq!(expulsion.reason, "left on a train");
    }

    /// A revocation cannot be taken back — the log is append-only — so a name
    /// that nearly matches must not resolve.
    #[test]
    fn a_name_that_only_nearly_matches_is_refused() {
        let (state, founder, _joiner) = network();
        for near in ["lap", "laptops", "laptop "] {
            let refusal = resolve(&state, &founder, &Target::Name(near.to_owned()), "a reason")
                .expect_err("only an exact name resolves");
            assert!(refusal.contains("answers to"), "{refusal}");
        }
    }

    /// Case aside: DNS does not tell `Laptop` from `laptop`, so neither does a
    /// person naming the device to expel.
    #[test]
    fn a_name_is_found_without_regard_to_case() {
        let (state, founder, joiner) = network();
        let expulsion = resolve(&state, &founder, &Target::Name("Laptop".to_owned()), "a reason")
            .expect("the same name, case aside");
        assert_eq!(expulsion.device, joiner.device_id());
        assert_eq!(expulsion.name, "laptop", "reported as the roster names it");
    }

    #[test]
    fn a_name_nobody_holds_is_refused_without_signing_anything() {
        let (state, founder, _joiner) = network();
        let refusal = resolve(&state, &founder, &Target::Name("nowhere".to_owned()), "a reason")
            .expect_err("no such device");
        assert!(refusal.contains("nowhere"), "the refusal must name what was asked for");
    }

    /// The roster would accept it, which is exactly why it is stopped here: it
    /// would leave a machine holding a roster for a network it had expelled
    /// itself from.
    #[test]
    fn revoking_this_device_is_refused() {
        let (state, founder, _joiner) = network();
        let refusal = resolve(&state, &founder, &Target::Name("nas".to_owned()), "a reason")
            .expect_err("revoking oneself is not what anybody means");
        assert!(refusal.contains("this device"), "{refusal}");
    }

    /// The roster carries a reason so somebody can read it. One nobody wrote is
    /// a field filled to satisfy a format.
    #[test]
    fn a_revocation_without_a_reason_is_refused() {
        let (state, founder, _joiner) = network();
        for empty in ["", "   ", "\t"] {
            let refusal = resolve(&state, &founder, &Target::Name("laptop".to_owned()), empty)
                .expect_err("a reason is required");
            assert!(refusal.contains("needs a reason"), "{refusal}");
        }
    }

    #[test]
    fn the_signed_operation_revokes_the_device_that_was_named() {
        let (state, founder, joiner) = network();
        let expulsion = resolve(&state, &founder, &Target::Name("laptop".to_owned()), "sold")
            .expect("resolves");
        let bytes = sign(&expulsion, &founder, &state, Vec::new()).expect("signs");

        let raw = roster::sign::RawOperation::decode(&bytes).expect("decodes");
        match &raw.core().body {
            OperationBody::RevokeDevice { device, reason } => {
                assert_eq!(*device, joiner.device_id());
                assert_eq!(reason, "sold");
            }
            other => panic!("expected a revocation, got {other:?}"),
        }
    }

    /// A second member with the given name and id, beside the fixture's.
    fn with_member(state: &mut RosterState, id: DeviceId, name: &str) {
        let mut record = state.devices.values().next().expect("the fixture has members").clone();
        record.id = id;
        record.name = name.to_owned();
        state.devices.insert(id, record);
    }

    /// Two admins admitting a `laptop` while apart. This used to expel whichever
    /// sorted first.
    #[test]
    fn a_name_two_members_share_is_refused_and_both_are_listed() {
        let (mut state, founder, joiner) = network();
        let twin = DeviceId::from_bytes([0x5a; 32]);
        with_member(&mut state, twin, "laptop");

        let refusal = resolve(&state, &founder, &Target::Name("laptop".to_owned()), "lost")
            .expect_err("two devices answer to it");
        assert!(refusal.contains("nothing was signed"), "{refusal}");
        assert!(refusal.contains(&short_id(&joiner.device_id())), "{refusal}");
        assert!(refusal.contains(&short_id(&twin)), "{refusal}");
        assert!(refusal.contains("peerfectly revoke --id"), "and how to name one: {refusal}");
    }

    #[test]
    fn an_exact_id_names_exactly_that_device_whatever_its_name() {
        let (mut state, founder, joiner) = network();
        let twin = DeviceId::from_bytes([0x5a; 32]);
        with_member(&mut state, twin, "laptop");

        for typed in [short_id(&twin), short_id(&twin).replace('-', "").to_uppercase()] {
            let expulsion = resolve(&state, &founder, &Target::Id(typed.clone()), "lost")
                .unwrap_or_else(|refusal| panic!("{typed} resolves: {refusal}"));
            assert_eq!(expulsion.device, twin);
        }
        let other = resolve(&state, &founder, &Target::Id(short_id(&joiner.device_id())), "lost")
            .expect("resolves");
        assert_eq!(other.device, joiner.device_id());
    }

    #[test]
    fn part_of_an_id_is_not_an_id() {
        let (state, founder, joiner) = network();
        let whole = short_id(&joiner.device_id()).replace('-', "");
        let part = whole.get(..15).expect("sixteen digits");

        let refusal = resolve(&state, &founder, &Target::Id(part.to_owned()), "lost")
            .expect_err("fifteen digits");
        assert!(refusal.contains("is not a device id"), "{refusal}");
    }

    #[test]
    fn the_id_of_a_revoked_device_is_refused_as_already_revoked() {
        let (mut state, founder, joiner) = network();
        state.devices.remove(&joiner.device_id());
        state.revoked.insert(joiner.device_id());

        let refusal =
            resolve(&state, &founder, &Target::Id(short_id(&joiner.device_id())), "again")
                .expect_err("already revoked");
        assert!(refusal.contains("already revoked"), "{refusal}");
    }

    /// Ids agreeing in their first eight bytes cannot be told apart by a short id,
    /// so neither is chosen.
    #[test]
    fn two_members_sharing_a_short_id_are_refused() {
        let (mut state, founder, _joiner) = network();
        let mut one = [0x77u8; 32];
        let mut other = [0x77u8; 32];
        if let Some(byte) = one.get_mut(20) {
            *byte = 1;
        }
        if let Some(byte) = other.get_mut(20) {
            *byte = 2;
        }
        with_member(&mut state, DeviceId::from_bytes(one), "desk");
        with_member(&mut state, DeviceId::from_bytes(other), "tablet");

        let refusal =
            resolve(&state, &founder, &Target::Id(short_id(&DeviceId::from_bytes(one))), "lost")
                .expect_err("two devices answer to that id");
        assert!(refusal.contains("desk") && refusal.contains("tablet"), "{refusal}");
    }

    /// The pending screen is titled by when a revocation was signed.
    #[test]
    fn a_revocation_carries_the_minute_it_was_signed() {
        let (state, founder, _joiner) = network();
        let expulsion = resolve(&state, &founder, &Target::Name("laptop".to_owned()), "sold")
            .expect("resolves");
        let bytes = sign(&expulsion, &founder, &state, Vec::new()).expect("signs");
        let ts = roster::sign::RawOperation::decode(&bytes).expect("decodes").core().ts;

        assert_eq!(ts % 60_000, 0, "the minute and nothing below it");
        assert!(crate::clock::operation_time(ts).is_some(), "{ts} is a time");
        let now = crate::clock::signing_time();
        assert!(now.saturating_sub(ts) <= 60_000, "{ts} is now ({now})");
    }

    /// Nothing here judges whether the revocation is permitted. That is the
    /// roster's rule, and a second opinion would either duplicate it or
    /// contradict it.
    #[test]
    fn this_module_does_not_decide_who_may_revoke() {
        let code = crate::code_of(include_str!("revoking.rs"));
        for judgement in ["is_admin", "Role::Admin", "is_founder", "revoked.contains"] {
            assert!(
                !code.contains(judgement),
                "`{judgement}` would be the daemon deciding membership, which the roster decides"
            );
        }
    }
}

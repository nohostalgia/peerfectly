//! Admitting a device, from this side: taking its request, and bringing it the
//! network once a person has approved it.
//!
//! The daemon does this rather than the command line, for one reason: it holds
//! the roster. An operation appended to the log by another process would be
//! invisible to a running daemon until it restarted, and a device admitted into
//! a roster nobody is using is a device that cannot connect.
//!
//! # Two exchanges, with a person between them, whenever they like
//!
//! [`collect`] dials an open invite's rendezvous, takes the device's request,
//! checks the keys it presents are its own, says it was received, and ends the
//! exchange. Nothing is signed and nobody is asked: the request is kept beside
//! the invite until a person approves or rejects it.
//!
//! [`deliver`] brings an admission that has been signed to the device it names,
//! at the rendezvous or at the device's own transport key — the admin that
//! approved it, or any full member the admission reached. The device adopts
//! nothing it does not check, so a delivery proves nothing by arriving.
//!
//! # This side never listens
//!
//! [`transport_convesso::enrolment::Admitting`] dials and has no method that
//! accepts. A machine holding a roster is not reachable through the enrolment
//! protocol at all, which is the point: the exception that lets a stranger be
//! spoken to belongs on the device that has nothing to lose.

use std::time::Duration;

use enrollment::exchange::Message;
use enrollment::limits;
use identity::NodeIdentity;
use roster::sign::PublicKey;
use roster::state::RosterState;
use roster::types::{OperationBody, OperationCore};
use transport_convesso::enrolment::{Admitting, Channel};

/// Why an admission did not happen.
pub type Refusal = String;

/// The device asking to be admitted: its keys and the name it proposes, as it
/// introduced itself over an invite's exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applicant {
    /// Its signing key: its identity.
    pub signing: PublicKey,
    /// Its transport key.
    pub transport: PublicKey,
    /// Its attestation key.
    pub attestation: PublicKey,
    /// The name it proposes.
    pub name: String,
    /// Where the network's block coincides with its other networks or the
    /// subnets it is on, in its own words: unproved, and deciding nothing.
    pub conflicts: Vec<String>,
}

impl From<&enrollment::exchange::Introduction> for Applicant {
    fn from(introduction: &enrollment::exchange::Introduction) -> Self {
        Self {
            signing: introduction.signing.clone(),
            transport: introduction.transport.clone(),
            attestation: introduction.attestation.clone(),
            name: introduction.name.clone(),
            conflicts: introduction.conflicts.clone(),
        }
    }
}

/// A device already answering to the name a joining device will be admitted
/// under.
///
/// Carries the **identifier** as well as the name, because a name is not an
/// identity: the device asking to join has different keys and will have a
/// different identifier whatever it is called. A person deciding on the strength
/// of a name is shown the identity that decision falls on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Taken {
    /// The name, as the roster holds it.
    pub name: String,
    /// The device holding it.
    pub device: roster::id::DeviceId,
}

/// Dials the rendezvous an open invite's secret derives, at the relay it names,
/// and takes the request of the device waiting there.
///
/// Both proofs are checked before anything is kept: the signing key's, over
/// the request it made for **this** invite, and the transport key's, over this
/// channel. The device is then told its request was received, and the exchange
/// ends.
///
/// # Errors
///
/// When the device cannot be reached, says something other than an
/// introduction, or does not prove the keys it presents.
pub async fn collect(invite: &enrollment::Invite) -> Result<Applicant, Refusal> {
    let endpoint = Admitting::dialling().await.map_err(|cause| cause.to_string())?;
    let outcome = take_request(&endpoint, invite).await;
    endpoint.close().await;
    outcome
}

async fn take_request(
    endpoint: &Admitting,
    invite: &enrollment::Invite,
) -> Result<Applicant, Refusal> {
    let deadline = Duration::from_secs(limits::EXCHANGE_DEADLINE_SECS);
    let rendezvous = transport_convesso::enrolment::rendezvous_key(&invite.rendezvous_seed())
        .map_err(|cause| cause.to_string())?;
    let mut channel = reach(endpoint, &rendezvous, &invite.relay).await?;
    let material = channel.material().map_err(|cause| cause.to_string())?;
    let Message::Introduce(introduction) = receive(&mut channel, deadline).await? else {
        return Err("the device said something other than its request".to_owned());
    };
    introduction
        .verify(&material, &invite.network, &rendezvous)
        .map_err(|cause| cause.to_string())?;
    send(&mut channel, &Message::Received, deadline).await?;
    // Held open until the device has read it and gone, or a few seconds:
    // closed at once, the endpoint took the message with it, and the device
    // went on believing nobody had its request.
    let _gone = receive(&mut channel, RECEIVED_LINGER).await;
    Ok(Applicant::from(&introduction))
}

/// How long the exchange is held open after saying a request was received.
const RECEIVED_LINGER: Duration = Duration::from_secs(5);

/// Where a device to be given the network waits, and what it must be.
pub struct Destination<'a> {
    /// The key dialled: the invite's rendezvous key, or the device's own
    /// transport key.
    pub dialled: PublicKey,
    /// The relay it waits at: the network's.
    pub relay: &'a str,
    /// The signing key the admission names.
    pub signing: &'a PublicKey,
    /// The transport key the admission names.
    pub transport: &'a PublicKey,
}

/// What a delivery carries: the roster, as an admin delivers it.
pub struct Delivery {
    /// Every operation this device holds, the admission among them.
    pub operations: Vec<Vec<u8>>,
    /// The pieces of the batches among them.
    pub pieces: Vec<Vec<u8>>,
    /// The network's snapshot, where this device holds one.
    pub snapshot: Option<Vec<u8>>,
    /// The state the log rests on, where this roster was compacted.
    pub base: Option<enrollment::adopt::Base>,
}

/// Brings the network to the device `destination` names.
///
/// The device introduces itself first, as it does to whoever calls. Only the
/// device the admission names is given anything: its transport key — which it
/// proves over this channel — and its signing key must be the admission's.
/// Anybody else waiting at a rendezvous whose invite they read is given
/// nothing.
///
/// Returns whether the device said it adopted the network. What it says is a
/// courtesy, not evidence: the admission is signed already, and a device that
/// lied here would only be lying about itself.
///
/// # Errors
///
/// When the device cannot be reached, is not the device the admission names,
/// or the exchange fails before the roster is sent.
pub async fn deliver(destination: &Destination<'_>, delivery: &Delivery) -> Result<bool, Refusal> {
    let endpoint = Admitting::dialling().await.map_err(|cause| cause.to_string())?;
    let outcome = bring(&endpoint, destination, delivery).await;
    endpoint.close().await;
    outcome
}

async fn bring(
    endpoint: &Admitting,
    destination: &Destination<'_>,
    delivery: &Delivery,
) -> Result<bool, Refusal> {
    let deadline = Duration::from_secs(limits::EXCHANGE_DEADLINE_SECS);
    let mut channel = reach(endpoint, &destination.dialled, destination.relay).await?;
    let material = channel.material().map_err(|cause| cause.to_string())?;
    let Message::Introduce(introduction) = receive(&mut channel, deadline).await? else {
        return Err("the device said something other than an introduction".to_owned());
    };
    if introduction.transport != *destination.transport
        || introduction.signing != *destination.signing
    {
        return Err("the device that answered is not the one admitted".to_owned());
    }
    introduction
        .transport_possession
        .verify(&introduction.transport, &material)
        .map_err(|cause| cause.to_string())?;

    // Where this roster was compacted its log no longer reaches the genesis, so
    // the state beneath it goes first, in as many parts as it takes.
    if let Some(base) = &delivery.base {
        let pieces = roster::transfer::pieces_of(&base.state);
        for part in pieces.chunks(enrollment::exchange::BASE_PIECES_PER_MESSAGE) {
            let message = Message::Base { root: base.root.clone(), pieces: part.to_vec() };
            send(&mut channel, &message, deadline).await?;
        }
    }
    // A batch's operation is only its header: without its pieces the joiner
    // holds it incomplete, and whatever was signed after it — this admission,
    // where a batch came before — would wait on it.
    for part in delivery.pieces.chunks(enrollment::exchange::BATCH_PIECES_PER_MESSAGE) {
        send(&mut channel, &Message::Batch { pieces: part.to_vec() }, deadline).await?;
    }
    // The whole log, not only the admission: every device appears together,
    // and a joiner that received one operation would have a network with two
    // members and no idea about the rest. The snapshot goes with it, so the
    // device arrives able to date what it was given.
    let admission = Message::Admission {
        operations: delivery.operations.clone(),
        snapshot: delivery.snapshot.clone(),
    };
    send(&mut channel, &admission, deadline).await?;

    Ok(matches!(receive(&mut channel, deadline).await, Ok(Message::Outcome { taken: true })))
}

/// Reaches `key` at `relay`, giving it little time: a device that is not there
/// is the usual answer.
async fn reach(endpoint: &Admitting, key: &PublicKey, relay: &str) -> Result<Channel, Refusal> {
    tokio::time::timeout(crate::limits::INVITE_DIAL_PATIENCE, endpoint.reach(key, relay))
        .await
        .map_err(|_| "the device did not answer".to_owned())?
        .map_err(|cause| cause.to_string())
}

/// Decides everything an admission needs decided, and stops at its signature.
///
/// Returns the operation to be signed, and the name it admits under, which is
/// not always the name the invite gave.
///
/// # Errors
///
/// When the operation cannot be made.
pub fn admission_core(
    applicant: &Applicant,
    invited: &crate::invites::Invited,
    identity: &NodeIdentity,
    state: &RosterState,
    heads: Vec<roster::id::OperationId>,
    keeping_the_name: bool,
) -> Result<(OperationCore, String), Refusal> {
    let spec = identity_spec(applicant, invited, state, keeping_the_name)?;
    let spec_name = spec.name.clone();
    let operation = OperationCore::new(
        // The minute it was signed, on this device's clock. Nothing reads it as
        // a sequence; the roster defines it as a time for display.
        crate::clock::signing_time(),
        identity.signing_key().algorithm(),
        OperationBody::AddDevice(spec),
        heads,
        identity.signing_key().key_id(),
        state.network,
    )
    .map_err(|cause| cause.to_string())?;
    Ok((operation, spec_name))
}

/// The settings an invited device is admitted with: a `set_device` following
/// the admission, giving it its IPv4 offset and whatever else its invite chose.
///
/// The offset is the one the invite's address names in the network's block,
/// or else the lowest no member holds, so that a network's offsets stay
/// consecutive (`scalable-membership` 19.2). A block with none free admits it
/// IPv6 only.
///
/// # Errors
///
/// When the operation cannot be made, or the invite named an address that is
/// not one of the block's hosts.
pub fn settings_core(
    invited: &crate::invites::Invited,
    identity: &NodeIdentity,
    state: &RosterState,
    admission: &OperationCore,
) -> Result<Option<OperationCore>, Refusal> {
    let mode = (invited.mode != roster::leaf::Mode::Full).then_some(invited.mode);
    let groups = (!invited.groups.is_empty()).then(|| invited.groups.clone());
    let range = state.params.ipv4_range();
    let offset = match invited.ipv4 {
        Some(address) => Some(range.offset_of(address).ok_or_else(|| {
            format!(
                "the invite named {}, which is not an address of the network's block, {range}. \
                 Nothing was admitted.",
                std::net::Ipv4Addr::from(address)
            )
        })?),
        None => state.free_offsets(1),
    };
    // A later claim keeps an offset, so this one would take it from its holder
    // for good.
    if let Some(holder) =
        offset.and_then(|offset| state.devices.holding_address(offset).first().copied())
    {
        let name = state.devices.get(&holder).map(|leaf| leaf.record.name.clone());
        return Err(format!(
            "the invite named an address {} already holds. Nothing was admitted.",
            crate::control::Named::new(&holder, name)
        ));
    }
    let ipv4 = offset.map(Some);
    if mode.is_none() && groups.is_none() && ipv4.is_none() {
        return Ok(None);
    }
    let OperationBody::AddDevice(spec) = &admission.body else { return Ok(None) };
    let device = spec.device_id().map_err(|cause| cause.to_string())?;
    let change = roster::leaf::SettingsChange {
        mode,
        groups,
        ipv4,
        ..roster::leaf::SettingsChange::default()
    };
    OperationCore::new(
        crate::clock::signing_time(),
        identity.signing_key().algorithm(),
        OperationBody::SetDevice { device, change },
        vec![admission.id()],
        identity.signing_key().key_id(),
        state.network,
    )
    .map(Some)
    .map_err(|cause| cause.to_string())
}

/// What an admin is told of each device that, between `previous` and `state`,
/// lost its IPv4 offset to another given it at the same time; nothing where
/// `me` is no admin.
///
/// Two admins admitting at once both give the lowest free offset, and the
/// later claim keeps it (`roster::state`, "an address lost is lost for good").
/// The device is reached by IPv6 until an admin gives it another (`ipv4
/// give`). Signing that is a person's act, so the daemon says so rather than
/// signing it (`scalable-membership` 19.2).
///
/// Read only where the two states share a base, from the devices that differ:
/// never a walk over every member.
#[must_use]
pub fn lost_offsets(
    previous: &RosterState,
    state: &RosterState,
    me: &roster::id::DeviceId,
) -> Vec<String> {
    if !state.is_admin(me) {
        return Vec::new();
    }
    let Some(differing) = state.devices.differing(&previous.devices) else { return Vec::new() };
    let mut lost = Vec::new();
    for device in differing {
        let (Some(before), Some(now)) = (previous.devices.get(&device), state.devices.get(&device))
        else {
            continue;
        };
        let (Some(offset), None) = (before.settings.ipv4, now.settings.ipv4) else { continue };
        let Some(holder) = state.devices.holding_address(offset).first().copied() else {
            continue;
        };
        let taker = state.devices.get(&holder).map(|leaf| leaf.record.name.clone());
        lost.push(format!(
            "{} lost its IPv4 address to {}, given it at the same time by another admin; it is \
             reached by IPv6 until an admin gives it another: peerfectly ipv4 give {}",
            crate::control::Named::new(&device, Some(now.record.name.clone())),
            crate::control::Named::new(&holder, taker),
            crate::control::shown(&now.record.name),
        ));
    }
    lost
}

/// What a person is told about the name a device was admitted under, where it
/// is not the one its invite gave. Before this a device quietly became
/// `name-2` and nobody was told.
#[must_use]
pub fn renamed_note(spec_name: &str, invited_name: &str) -> Option<String> {
    (spec_name != admitted_name(invited_name)).then(|| {
        format!(
            "that name was already in use, so it was admitted as `{}`",
            crate::control::shown(spec_name)
        )
    })
}

/// The specification the admitting side writes, from the keys the device
/// presented and the record of the invite it came through.
///
/// The joining device chose none of this. It proposed a name; the name, role,
/// founder flag and capabilities are decided here, which is why its
/// introduction carries no field for any of them.
fn identity_spec(
    applicant: &Applicant,
    invited: &crate::invites::Invited,
    state: &RosterState,
    keeping_the_name: bool,
) -> Result<roster::types::DeviceSpec, Refusal> {
    let mut keys = vec![
        roster::types::KeyEntry::new(
            applicant.signing.algorithm(),
            roster::types::KeyPurpose::Signing,
            applicant.signing.as_bytes().to_vec(),
        )
        .map_err(|cause| cause.to_string())?,
        roster::types::KeyEntry::new(
            applicant.transport.algorithm(),
            roster::types::KeyPurpose::Transport,
            applicant.transport.as_bytes().to_vec(),
        )
        .map_err(|cause| cause.to_string())?,
        // The key the joining device will date its roster with. It comes from
        // the request and nowhere else, and the signing key's proof covers it.
        roster::types::KeyEntry::new(
            applicant.attestation.algorithm(),
            roster::types::KeyPurpose::Attestation,
            applicant.attestation.as_bytes().to_vec(),
        )
        .map_err(|cause| cause.to_string())?,
    ];
    keys.sort_by_key(roster::types::KeyEntry::order_key);

    // Keeping the name is a deliberate answer to a question a person was asked:
    // the device that had it is being revoked in the same act, and the name is
    // meant to carry over.
    //
    // It has to be said here rather than left to fall out. The revocation may
    // already be signed and applied by the time this runs, but the `state` this
    // reads may have been gathered before it, and altering the name against it
    // would quietly undo what the person asked for.
    //
    // An invited device takes the name its invite's record gives it, and the
    // role the admin chose when inviting; the name it proposed is a suggestion.
    let proposed = admitted_name(&invited.name);
    let name = if keeping_the_name { proposed } else { unused_name(&proposed, state) };
    roster::types::DeviceSpec::new(keys, name, invited.role, false, vec![])
        .map_err(|cause| cause.to_string())
}

/// The name a device is admitted under: the one its invite gave, made one a
/// resolver can answer.
///
/// Lowered when that is all it needs. A record written by an older build may
/// hold anything its person typed, so a name that is not a label is made into
/// the nearest one, and the admin is shown that before approving. A name with
/// nothing usable in it becomes `device`, made unique like any other.
#[must_use]
pub fn admitted_name(proposed: &str) -> String {
    crate::names::usable(proposed)
        .ok()
        .or_else(|| crate::names::made_usable(proposed))
        .unwrap_or_else(|| "device".to_owned())
}

/// The device already answering to a name, if one does.
///
/// Without regard to case: the resolver answers `Laptop` and `laptop` alike, so
/// two devices with those names are one name nobody can look up.
#[must_use]
pub fn holder_of(name: &str, state: &RosterState) -> Option<Taken> {
    state
        .devices
        .values()
        .find(|record| record.name.eq_ignore_ascii_case(name))
        .map(|record| Taken { name: record.name.clone(), device: record.id })
}

/// A name no device in the network already answers to.
///
/// Two devices with one name would make a name ambiguous, and a name is what a
/// person types. The proposal is kept where it can be.
fn unused_name(proposed: &str, state: &RosterState) -> String {
    let taken = |candidate: &str| !state.devices.named(candidate).is_empty();
    if !taken(proposed) {
        return proposed.to_owned();
    }
    for suffix in 2..100_u32 {
        let candidate = format!("{proposed}-{suffix}");
        if !taken(&candidate) {
            return candidate;
        }
    }
    proposed.to_owned()
}

/// Sends one message within the deadline.
async fn send(channel: &mut Channel, message: &Message, deadline: Duration) -> Result<(), Refusal> {
    tokio::time::timeout(deadline, channel.send(&message.encode()))
        .await
        .map_err(|_| "the exchange took too long".to_owned())?
        .map_err(|cause| cause.to_string())
}

/// Reads one message within the deadline.
async fn receive(channel: &mut Channel, deadline: Duration) -> Result<Message, Refusal> {
    let bytes = tokio::time::timeout(deadline, channel.receive())
        .await
        .map_err(|_| "the exchange took too long".to_owned())?
        .map_err(|cause| cause.to_string())?;
    Message::decode(&bytes).map_err(|cause| cause.to_string())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use roster::types::Role;

    use super::*;

    /// A device introducing itself, proposing a name.
    fn applicant(joining: &NodeIdentity, name: &str) -> Applicant {
        Applicant {
            signing: joining.signing_key().public_key(),
            transport: joining.transport_key().public_key(),
            attestation: joining.attestation_key().public_key(),
            name: name.to_owned(),
            conflicts: Vec::new(),
        }
    }

    /// What an invite's record says the device will be.
    fn invited(name: &str, role: Role) -> crate::invites::Invited {
        crate::invites::Invited {
            name: name.to_owned(),
            role,
            mode: roster::leaf::Mode::Full,
            groups: Vec::new(),
            ipv4: None,
        }
    }

    fn state_with(names: &[&str]) -> RosterState {
        let params = roster::types::NetworkParams::new(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            "example.internal",
            2_592_000,
        )
        .expect("valid");
        state_of(params, names)
    }

    fn state_of(params: roster::types::NetworkParams, names: &[&str]) -> RosterState {
        let founder = NodeIdentity::generate().expect("generates");

        let genesis = OperationCore::new(
            1,
            founder.signing_key().algorithm(),
            OperationBody::CreateNetwork {
                device: founder.device_spec("founder", Role::Admin, true, vec![]).expect("spec"),
                params,
            },
            vec![],
            founder.signing_key().key_id(),
            roster::id::NetworkId::from_bytes([0; 32]),
        )
        .expect("well-formed");
        let genesis_bytes =
            roster::sign::sign_operation(&genesis, founder.signer()).expect("signs");

        let mut roster = roster::roster::Roster::new();
        assert!(roster.offer_bytes(&genesis_bytes).is_accepted());
        let network = roster::id::NetworkId::from_bytes(*genesis.id().as_bytes());

        let mut parents = vec![genesis.id()];
        for (index, name) in names.iter().enumerate() {
            let device = NodeIdentity::generate().expect("generates");
            let add = OperationCore::new(
                u64::try_from(index).unwrap_or(0).saturating_add(2),
                founder.signing_key().algorithm(),
                OperationBody::AddDevice(
                    device.device_spec(*name, Role::Member, false, vec![]).expect("spec"),
                ),
                parents.clone(),
                founder.signing_key().key_id(),
                network,
            )
            .expect("well-formed");
            let bytes = roster::sign::sign_operation(&add, founder.signer()).expect("signs");
            assert!(roster.offer_bytes(&bytes).is_accepted());
            parents = vec![add.id()];
        }

        roster.state().expect("derives")
    }

    /// A joining device proposes a name and nothing else. What it becomes is
    /// what the invite's record says, which is why there is no field for it to
    /// ask in.
    #[test]
    fn the_invites_record_chooses_the_name_and_role() {
        let state = state_with(&[]);
        let joining = NodeIdentity::generate().expect("generates");
        let asking = applicant(&joining, "admin-please");

        let spec = identity_spec(&asking, &invited("laptop", Role::Member), &state, false)
            .expect("builds");
        assert_eq!(spec.role, Role::Member, "never an admin because it asked");
        assert!(!spec.founder);
        assert!(spec.capabilities.is_empty());
        assert_eq!(spec.name, "laptop", "the record's name, not the one proposed");

        let spec =
            identity_spec(&asking, &invited("nas", Role::Admin), &state, false).expect("builds");
        assert_eq!(spec.role, Role::Admin, "an admin because the admin invited one");
    }

    /// A record written by an older build may hold a name a resolver cannot
    /// answer; it is admitted under the nearest one, which is what the admin is
    /// shown.
    #[test]
    fn an_unusable_name_is_made_usable() {
        let state = state_with(&[]);
        let joining = NodeIdentity::generate().expect("generates");
        for (proposed, admitted) in
            [("Mario's phone", "mario-s-phone"), ("Laptop", "laptop"), ("___", "device")]
        {
            let spec = identity_spec(
                &applicant(&joining, "board"),
                &invited(proposed, Role::Member),
                &state,
                false,
            )
            .expect("builds");
            assert_eq!(spec.name, admitted, "{proposed:?}");
            assert_eq!(admitted_name(proposed), admitted, "and the admin is shown the same");
        }
    }

    /// A name is what a person types, so two devices must not share one.
    #[test]
    fn a_name_already_taken_is_made_unique() {
        let state = state_with(&["laptop"]);
        let joining = NodeIdentity::generate().expect("generates");

        let spec = identity_spec(
            &applicant(&joining, "laptop"),
            &invited("laptop", Role::Member),
            &state,
            false,
        )
        .expect("builds");
        assert_eq!(spec.name, "laptop-2");
        assert_ne!(spec.name, "laptop", "two devices answering to one name is not a network");
    }

    /// The keys in the specification are the ones the device presented, and
    /// the device id follows from the signing key.
    #[test]
    fn the_specification_carries_the_keys_the_device_presented() {
        let state = state_with(&[]);
        let joining = NodeIdentity::generate().expect("generates");

        let spec = identity_spec(
            &applicant(&joining, "laptop"),
            &invited("laptop", Role::Member),
            &state,
            false,
        )
        .expect("builds");
        assert_eq!(
            spec.device_id().expect("derives"),
            joining.device_id(),
            "the identity admitted is the identity that asked"
        );
    }

    /// A name the network already uses stops the admission for an answer. Before
    /// this the second device quietly became `laptop-2` and the admin learned of
    /// it from the device list, having confirmed a code for `laptop`.
    #[test]
    fn a_name_already_in_use_is_reported_with_the_device_holding_it() {
        let state = state_with(&["laptop"]);
        let held = state.devices.values().find(|record| record.name == "laptop").expect("held");

        let found = holder_of("laptop", &state).expect("somebody has it");

        assert_eq!("laptop", found.name);
        assert_eq!(held.id, found.device, "and the identity the decision falls on");
        assert_eq!(None, holder_of("telefono", &state), "a free name reports nothing");
    }

    /// `Laptop` and `laptop` are one name to the resolver, so one name here.
    #[test]
    fn a_name_that_differs_only_in_case_is_in_use() {
        let state = state_with(&["laptop"]);

        let found = holder_of("Laptop", &state).expect("the same name, case aside");

        assert_eq!("laptop", found.name);
        assert_eq!("Laptop-2", unused_name("Laptop", &state), "not a second `laptop`");
    }

    /// Declining to replace admits under a name no device holds — today's
    /// behaviour, now the answer to a question rather than a silent act.
    #[test]
    fn not_replacing_admits_under_a_name_nobody_holds() {
        let state = state_with(&["laptop"]);

        assert_eq!("laptop-2", unused_name("laptop", &state));
        assert_eq!("telefono", unused_name("telefono", &state), "a free name is kept");
    }

    /// Replacing keeps the name: the device that had it is revoked in the same
    /// act, and altering the name here would quietly undo what was asked for.
    #[test]
    fn replacing_keeps_the_name_that_was_asked_for() {
        let state = state_with(&["laptop"]);
        let joining = NodeIdentity::generate().expect("generates");
        let asking = applicant(&joining, "laptop");
        let record = invited("laptop", Role::Member);

        let kept = identity_spec(&asking, &record, &state, true).expect("builds");
        let renamed = identity_spec(&asking, &record, &state, false).expect("builds");

        assert_eq!("laptop", kept.name, "the name carries over");
        assert_eq!("laptop-2", renamed.name, "and without replacing it does not");
        assert_eq!(
            kept.device_id().expect("an id"),
            renamed.device_id().expect("an id"),
            "the device is the same either way: an id follows from the signing key"
        );
    }

    /// The offset an admission gives, as the `set_device` after it says.
    fn given(
        invited: &crate::invites::Invited,
        state: &RosterState,
    ) -> Result<Option<u32>, Refusal> {
        let admin = NodeIdentity::generate().expect("generates");
        let joining = NodeIdentity::generate().expect("generates");
        let (admission, _) = admission_core(
            &applicant(&joining, "board"),
            invited,
            &admin,
            state,
            Vec::new(),
            false,
        )
        .expect("builds");
        let settings = settings_core(invited, &admin, state, &admission)?.expect("settings");
        let OperationBody::SetDevice { change, .. } = settings.body else { panic!("a set_device") };
        Ok(change.ipv4.flatten().map(u32::from_be_bytes))
    }

    /// An admission gives the lowest offset no member holds: the founder holds
    /// the first host, so the first device admitted is given the second.
    #[test]
    fn an_admission_gives_the_lowest_free_offset() {
        let state = state_with(&[]);
        assert_eq!(given(&invited("board", Role::Member), &state), Ok(Some(2)));
    }

    /// An invite naming an address gives its offset; one outside the block, or
    /// held already, admits nothing.
    #[test]
    fn an_invited_address_is_given_as_its_offset_or_refused() {
        let state = state_with(&[]);
        let mut asked = invited("board", Role::Member);
        asked.ipv4 = Some([100, 64, 0, 9]);
        assert_eq!(given(&asked, &state), Ok(Some(9)));

        asked.ipv4 = Some([192, 168, 1, 9]);
        let refused = given(&asked, &state).unwrap_err();
        assert!(refused.contains("not an address of the network's block"), "{refused}");

        asked.ipv4 = Some([100, 64, 0, 1]);
        let refused = given(&asked, &state).unwrap_err();
        assert!(refused.contains("already holds") && refused.contains("founder"), "{refused}");
    }

    /// A full block admits the device IPv6 only, giving it no offset.
    #[test]
    fn a_full_block_admits_ipv6_only() {
        let params = roster::types::NetworkParams::new(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            "example.internal",
            0,
        )
        .expect("valid")
        .in_ipv4_range("10.0.0.0/28".parse().expect("a block"));
        let names: Vec<String> = (0..13).map(|n| format!("d{n}")).collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut state = state_of(params, &names);
        // The founder holds the first host; the thirteen others the rest.
        let members: Vec<_> =
            state.devices.keys().filter(|device| !state.is_founder(device)).collect();
        for (offset, device) in (2_u32..).zip(members) {
            let settings = roster::leaf::DeviceSettings {
                ipv4: Some(offset.to_be_bytes()),
                ..roster::leaf::DeviceSettings::default()
            };
            state.set_settings(device, settings);
        }
        let admin = NodeIdentity::generate().expect("generates");
        let joining = NodeIdentity::generate().expect("generates");
        let asked = invited("board", Role::Member);
        let (admission, _) = admission_core(
            &applicant(&joining, "board"),
            &asked,
            &admin,
            &state,
            Vec::new(),
            false,
        )
        .expect("builds");
        assert!(settings_core(&asked, &admin, &state, &admission).expect("made").is_none());
    }
}

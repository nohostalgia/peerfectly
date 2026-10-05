//! Admitting a device, from this side.
//!
//! The daemon does this rather than the command line, for one reason: it holds
//! the roster. An operation appended to the log by another process would be
//! invisible to a running daemon until it restarted, and a device admitted into
//! a roster nobody is using is a device that cannot connect.
//!
//! # Two steps, because a person stands between them
//!
//! `admit` opens the exchange, proves the joining device holds both of the keys
//! it presented, works out the confirmation code, and then **stops**. Nothing is
//! signed. The pending exchange waits here while the person compares two screens.
//!
//! `confirm` signs the admission and delivers the roster. `abandon` drops the
//! exchange and leaves nothing behind. If neither arrives, the exchange expires
//! on its own deadline — the safe direction, since expiring means nothing was
//! admitted.
//!
//! # This side never listens
//!
//! [`transport_iroh::enrolment::Admitting`] dials and has no method that
//! accepts. A machine holding a roster is not reachable through the enrolment
//! protocol at all, which is the point: the exception that lets a stranger be
//! spoken to belongs on the device that has nothing to lose.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use enrollment::code::{Confirmation, Side};
use enrollment::exchange::Message;
use enrollment::limits;
use enrollment::payload::Joining;
use identity::NodeIdentity;
use roster::state::RosterState;
use roster::types::{OperationBody, OperationCore, Role};
use tokio::sync::Mutex;
use transport_iroh::enrolment::{Admitting, Channel};

/// Why an admission did not happen.
pub type Refusal = String;

/// An exchange that is open and waiting for a person.
///
/// Holding one is not a decision. Nothing has been signed, the joining device is
/// a member of nothing, and dropping this leaves both machines as they were.
pub struct Pending {
    /// The open channel, kept so the roster can be delivered over it.
    ///
    /// Shared, because something has to read it while the person here is still
    /// deciding: the device being enrolled says the code matched over this same
    /// channel, and that has to arrive *before* this side's person is asked
    /// about it. A question about something that has not happened yet is one a
    /// person answers wrongly.
    channel: Arc<Mutex<Channel>>,
    /// The endpoint the channel belongs to, kept so it outlives the exchange.
    endpoint: Admitting,
    /// What the joining device said it is.
    payload: Joining,
    /// The code both screens must show.
    code: Confirmation,
    /// When this exchange stops being usable.
    expires: Instant,
    /// Whether the device being enrolled has said the code matched.
    ///
    /// Set by the task reading the channel, read by whatever asks this side's
    /// person. Nothing is signed while it is false.
    accepted: Arc<AtomicBool>,
    /// The device already answering to the name this one proposes, if there is
    /// one.
    ///
    /// Worked out when the exchange opens, against the roster this admission is
    /// being made into, so that a person is asked before anything is signed
    /// rather than told afterwards.
    taken: Option<Taken>,
}

/// A device already answering to the name a joining device proposes.
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

impl Pending {
    /// The name the joining device proposed for itself.
    #[must_use]
    pub fn proposed_name(&self) -> &str {
        &self.payload.name
    }

    /// The device already answering to that name, if there is one.
    #[must_use]
    pub const fn taken(&self) -> Option<&Taken> {
        self.taken.as_ref()
    }

    /// The joining device's signing key, in the shape a person can compare.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        crate::relay::fingerprint(self.payload.signing.as_bytes())
    }

    /// The code this exchange produced.
    #[must_use]
    pub fn code(&self) -> &Confirmation {
        &self.code
    }

    /// Whether this exchange is still usable.
    #[must_use]
    pub fn live(&self) -> bool {
        Instant::now() < self.expires
    }

    /// Whether the device being enrolled has said the code matched.
    #[must_use]
    pub fn accepted(&self) -> bool {
        self.accepted.load(Ordering::SeqCst)
    }

    /// Starts listening for that, in the background. Called by [`open`].
    ///
    /// One message, under the exchange's own deadline. A device that says
    /// nothing costs this side the deadline and no more; a device that says
    /// something other than an acceptance leaves the flag false, which reads the
    /// same to everyone: there is nothing to sign.
    fn listen(&self) {
        let channel = Arc::clone(&self.channel);
        let accepted = Arc::clone(&self.accepted);
        let deadline = Duration::from_secs(limits::EXCHANGE_DEADLINE_SECS);
        tokio::spawn(async move {
            let mut held = channel.lock().await;
            if let Ok(Message::Accepted) = receive(&mut held, deadline).await {
                accepted.store(true, Ordering::SeqCst);
            }
        });
    }
}

impl core::fmt::Debug for Pending {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pending")
            .field("proposed_name", &self.payload.name)
            .field("code", &self.code.as_str())
            .field("live", &self.live())
            .finish()
    }
}

/// Opens an exchange with a device that is waiting, and stops before signing.
///
/// # Errors
///
/// When the payload cannot be read, the device cannot be reached, or it fails to
/// prove that it holds the signing key its payload names.
pub async fn open(
    identity: &NodeIdentity,
    state: &RosterState,
    payload_text: &str,
) -> Result<Pending, Refusal> {
    let payload = Joining::from_text(payload_text).map_err(|cause| cause.to_string())?;
    refuse_a_colliding_address(&payload, state)?;
    // **Before the endpoint exists**, not merely before the exchange: building
    // it is where a relay starts to be reached.
    refuse_a_relay_the_network_does_not_use(&payload, state, crate::clock::now_ms())?;

    let endpoint = Admitting::dialling(identity, state).await.map_err(|cause| cause.to_string())?;
    // Every refusal from here on closes the endpoint it leaves behind. Dropped
    // instead, its socket stayed bound — found on a phone that, with every network
    // off, kept receiving into a queue nobody read.
    let payload_name = payload.name.clone();
    match exchange(&endpoint, &payload, identity).await {
        Ok((channel, code, expires)) => {
            let pending = Pending {
                channel: Arc::new(Mutex::new(channel)),
                endpoint,
                payload,
                code,
                expires,
                accepted: Arc::new(AtomicBool::new(false)),
                taken: holder_of(&payload_name, state),
            };
            // Listening starts here rather than being left to the caller: the
            // device being enrolled may accept while a person on this side is
            // still walking over to it, and a caller who forgot would be asking
            // about something nobody was listening for.
            pending.listen();
            Ok(pending)
        }
        Err(refusal) => {
            endpoint.close().await;
            Err(refusal)
        }
    }
}

/// Refuses a payload waiting at a relay this network does not use (F-17).
///
/// A payload is written by whoever produced it. Dialling the relay it names lets
/// that author choose a host this machine resolves and connects to — which learns
/// the admin's address, when it admits, and that it runs this product, before any
/// certificate is checked. So nothing is contacted unless the relay is the
/// network's own, or the one it is leaving: a device that began joining just
/// before a move is waiting there.
///
/// A network with no relay admits nobody. A joining device can only be reached
/// through the relay it names, and there is nothing to bind that to.
fn refuse_a_relay_the_network_does_not_use(
    payload: &Joining,
    state: &RosterState,
    now: u64,
) -> Result<(), Refusal> {
    let Some(ours) = state.params.relay.as_deref() else {
        return Err("this network has no relay, so it cannot admit anybody: a joining device can \
             only be reached through the relay it waits at, and this network has none to bind \
             that to. Give it a relay first — `peerfectly relay <address>`, or from the network's \
             screen on a phone. Nothing was contacted."
            .to_owned());
    };

    let leaving = state.params.leaving_at(now).map(|leaving| leaving.relay.as_str());
    let used = core::iter::once(ours).chain(leaving);
    if used.clone().any(|relay| crate::relay::same_relay(relay, &payload.relay)) {
        return Ok(());
    }

    let ours = used.collect::<Vec<_>>().join(" or ");
    Err(format!(
        "the device is waiting at {}, but this network uses {ours}. Start the join again on the \
         device with --relay {}. Nothing was contacted.",
        crate::control::shown(&payload.relay),
        state.params.relay.as_deref().unwrap_or_default()
    ))
}

/// Refuses a device whose IPv4 candidate another device, present or revoked,
/// already derives.
///
/// Admitted anyway, the collision would leave both devices without IPv4 —
/// including one that has held its address for a long time. This is the one
/// moment a person is present on both devices, and a joining device makes its
/// key when it starts to join, so starting again is enough.
///
/// Checked before the device is reached. The candidate depends only on the
/// signing key the payload names; a payload naming a key its sender does not
/// hold fails the possession check later whatever this says, so refusing first
/// reveals nothing and spares a dial that could only end in a refusal.
fn refuse_a_colliding_address(payload: &Joining, state: &RosterState) -> Result<(), Refusal> {
    // The name plays no part: a device's id follows from its signing key alone,
    // so which of the two names it ends up with cannot move the address.
    let joining =
        identity_spec(payload, state, false)?.device_id().map_err(|cause| cause.to_string())?;
    let range = state.params.ipv4_range();
    let candidate = tunnel::ipv4_candidate(&state.network, &joining, &range);
    let taken = state
        .devices
        .keys()
        .chain(state.revoked.iter())
        .filter(|device| **device != joining)
        .find(|device| tunnel::ipv4_candidate(&state.network, device, &range) == candidate);
    let Some(other) = taken else {
        return Ok(());
    };
    let who = match state.devices.get(other) {
        Some(record) => format!("{} [{}]", record.name, crate::control::short_id(other)),
        None => format!("a revoked device [{}]", crate::control::short_id(other)),
    };
    Err(format!(
        "this device's IPv4 address would collide with {who}; start the join again on it — a \
         new key gives a new address"
    ))
}

/// Reaches the joining device, checks its possession of the signing key it
/// names, and works out the code.
async fn exchange(
    endpoint: &Admitting,
    payload: &Joining,
    identity: &NodeIdentity,
) -> Result<(Channel, Confirmation, Instant), Refusal> {
    let deadline = Duration::from_secs(limits::EXCHANGE_DEADLINE_SECS);

    let mut channel =
        tokio::time::timeout(deadline, endpoint.reach(&payload.transport, &payload.relay))
            .await
            .map_err(|_| {
                format!(
                    "{} did not answer within {}s. Is it still waiting?",
                    payload.relay,
                    deadline.as_secs()
                )
            })?
            .map_err(|cause| cause.to_string())?;

    let material = channel.material().map_err(|cause| cause.to_string())?;

    // The channel proves the joining device holds the transport key its payload
    // names — this side dialled that key, and nobody else could answer. It says
    // nothing about the signing key, and a device's identity comes from that.
    // Without this check a payload could pair one device's identity with
    // another's transport key, and a roster keeps the first admission of a
    // device id for ever.
    let Message::Hello { possession } = receive(&mut channel, deadline).await? else {
        return Err("the device said something other than a greeting".to_owned());
    };
    possession.verify(&payload.signing, &material).map_err(|cause| cause.to_string())?;

    let joining = Side {
        signing: payload.signing.clone(),
        transport: payload.transport.clone(),
        attestation: payload.attestation.clone(),
    };
    let code = Confirmation::derive(&joining, &identity.transport_key().public_key(), &material)
        .map_err(|cause| cause.to_string())?;

    let expires = Instant::now().checked_add(deadline).unwrap_or_else(Instant::now);
    Ok((channel, code, expires))
}

/// Delivers an admission signed somewhere this process could not sign it.
///
/// The endpoint is closed whatever happens, as [`confirm`] closes it: an
/// exchange that is over must not leave a socket bound, whichever half of the
/// act ended it.
pub async fn finish_with(
    pending: Pending,
    signed: Vec<u8>,
    spec_name: String,
    log: &[Vec<u8>],
    snapshot: Option<Vec<u8>>,
) -> Result<(Vec<u8>, String), Refusal> {
    let mut pending = pending;
    let outcome = deliver_signed(&mut pending, signed, spec_name, log, snapshot).await;
    pending.endpoint.close().await;
    outcome
}

/// Signs the admission and delivers the network.
///
/// Called only after a person has compared two screens. The role is chosen here
/// and not asked for: a joining device proposes a name and nothing else.
///
/// # Errors
///
/// When the exchange has expired, the operation cannot be signed, or the roster
/// cannot be delivered.
pub async fn confirm(
    pending: Pending,
    identity: &NodeIdentity,
    state: &RosterState,
    heads: Vec<roster::id::OperationId>,
    log: &[Vec<u8>],
    snapshot: Option<Vec<u8>>,
    keeping_the_name: bool,
) -> Result<(Vec<u8>, String), Refusal> {
    let mut pending = pending;
    // Closed whatever happens: an exchange that expired, a declined lock or a
    // delivery that failed must not leave the endpoint's socket bound.
    let outcome =
        deliver(&mut pending, identity, state, heads, log, snapshot, keeping_the_name).await;
    pending.endpoint.close().await;
    outcome
}

/// Decides everything an admission needs decided, and stops at its signature.
///
/// The exchange must be live and the far side must have said the code matched —
/// both checked here, before anything is prepared, because a device that has to
/// ask somebody for a signature must not ask for one that was never going to be
/// used.
///
/// Returns the operation to be signed, and the name it admits under, which is not
/// always the name that was proposed.
pub async fn core(
    pending: &mut Pending,
    identity: &NodeIdentity,
    state: &RosterState,
    heads: Vec<roster::id::OperationId>,
    keeping_the_name: bool,
) -> Result<(OperationCore, String), Refusal> {
    if !pending.live() {
        return Err("this enrolment took too long and has expired. Start it again.".to_owned());
    }

    // Nothing is signed until the device being enrolled has said that the code a
    // person typed into it matched. That arrives over this same channel while
    // this side's person is still deciding, which is why it is listened for
    // rather than waited for here: by the time anybody answers, it has either
    // happened or it has not.
    if !pending.accepted() {
        return Err("the device being enrolled has not said the code was accepted. Type the six digits into it first; if it shows something else, start again. Nothing was signed."
            .to_owned());
    }

    let spec = identity_spec(&pending.payload, state, keeping_the_name)?;
    let spec_name = spec.name.clone();
    let operation = OperationCore::new(
        // The minute it was signed, on this device's clock. This used to be a
        // counter, on the belief that the value only had to rise; nothing reads it
        // as a sequence, the roster defines it as a time for display, and a
        // counter there rendered every admission as signed in January 1970.
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

/// Delivers an admission that has been signed, however it came to be signed.
///
/// The deadline here is per message, not for the exchange: by the time this runs
/// a person may have answered a prompt on this machine, and the device waiting to
/// be admitted is still waiting — it allows far longer for the whole thing than
/// one message is given.
async fn deliver_signed(
    pending: &mut Pending,
    signed: Vec<u8>,
    spec_name: String,
    log: &[Vec<u8>],
    snapshot: Option<Vec<u8>>,
) -> Result<(Vec<u8>, String), Refusal> {
    let deadline = Duration::from_secs(limits::EXCHANGE_DEADLINE_SECS);

    // The whole log, not only the admission: §3.1 says every device appears
    // together, and a joiner that received one operation would have a network
    // with two members and no idea about the rest.
    let mut operations = log.to_vec();
    operations.push(signed.clone());

    {
        let mut channel = pending.channel.lock().await;
        // The snapshot goes with the roster, so the device arrives able to
        // confirm what it was given. Without one it would begin having accepted
        // none — which is the state a device reaches after being out of touch too
        // long, and a device that has just joined must not look like one.
        send(&mut channel, &Message::Admission { operations, snapshot }, deadline).await?;
    }

    // What the other side says about it is a courtesy, not evidence: this side
    // has already signed, and a device that lied here would only be lying about
    // itself.
    let mut channel = pending.channel.lock().await;
    let said = match receive(&mut channel, deadline).await {
        Ok(Message::Outcome { taken: true }) => "it adopted the network".to_owned(),
        Ok(Message::Outcome { taken: false }) => {
            "it refused the network — check that the relay certificate it accepted is the one \
             this network pins"
                .to_owned()
        }
        Ok(_) | Err(_) => "it did not say whether it adopted the network".to_owned(),
    };

    // Which name it was admitted under, when that is not the one it proposed.
    // Before this a device quietly became `name-2` and nobody was told.
    let said = if spec_name != pending.payload.name {
        format!(
            "{said}. that name was already in use, so it was admitted as `{}`",
            crate::control::shown(&spec_name)
        )
    } else {
        said
    };

    Ok((signed, said))
}

/// Signs and delivers, over an exchange the caller closes.
async fn deliver(
    pending: &mut Pending,
    identity: &NodeIdentity,
    state: &RosterState,
    heads: Vec<roster::id::OperationId>,
    log: &[Vec<u8>],
    snapshot: Option<Vec<u8>>,
    keeping_the_name: bool,
) -> Result<(Vec<u8>, String), Refusal> {
    let (operation, spec_name) = core(pending, identity, state, heads, keeping_the_name).await?;
    let signed =
        identity.sign_operation(&operation).map_err(|cause| crate::control::declined(&cause))?;
    deliver_signed(pending, signed, spec_name, log, snapshot).await
}

/// Drops an exchange, leaving both machines as they were.
pub async fn abandon(pending: Pending) {
    pending.endpoint.close().await;
}

/// The specification the admitting side writes, from the keys the payload named.
///
/// The joining device chose none of this. It proposed a name; the role, the
/// founder flag and the capabilities are decided here, which is why the payload
/// carries no field for any of them.
fn identity_spec(
    payload: &Joining,
    state: &RosterState,
    keeping_the_name: bool,
) -> Result<roster::types::DeviceSpec, Refusal> {
    let mut keys = vec![
        roster::types::KeyEntry::new(
            payload.signing.algorithm(),
            roster::types::KeyPurpose::Signing,
            payload.signing.as_bytes().to_vec(),
        )
        .map_err(|cause| cause.to_string())?,
        roster::types::KeyEntry::new(
            payload.transport.algorithm(),
            roster::types::KeyPurpose::Transport,
            payload.transport.as_bytes().to_vec(),
        )
        .map_err(|cause| cause.to_string())?,
        // The key the joining device will date its roster with. It comes from
        // the payload and nowhere else, and the confirmation code covers it, so
        // what goes into the record is what both people compared.
        roster::types::KeyEntry::new(
            payload.attestation.algorithm(),
            roster::types::KeyPurpose::Attestation,
            payload.attestation.as_bytes().to_vec(),
        )
        .map_err(|cause| cause.to_string())?,
    ];
    keys.sort_by_key(roster::types::KeyEntry::order_key);

    // Keeping the name is a deliberate answer to a question a person was asked:
    // the device that had it is being revoked in the same act, and the name is
    // meant to carry over.
    //
    // It has to be said here rather than left to fall out. The revocation has
    // already been signed and applied by the time this runs, and a revoked
    // device leaves the membership entirely — so the name *is* free. But the
    // `state` this reads was gathered before any of that, and altering the name
    // against it would quietly undo what the person asked for.
    let name =
        if keeping_the_name { payload.name.clone() } else { unused_name(&payload.name, state) };
    roster::types::DeviceSpec::new(keys, name, Role::Member, false, vec![])
        .map_err(|cause| cause.to_string())
}

/// The device already answering to a name, if one does.
fn holder_of(name: &str, state: &RosterState) -> Option<Taken> {
    state
        .devices
        .values()
        .find(|record| record.name == name)
        .map(|record| Taken { name: record.name.clone(), device: record.id })
}

/// A name no device in the network already answers to.
///
/// Two devices with one name would make a name ambiguous, and a name is what a
/// person types. The proposal is kept where it can be.
fn unused_name(proposed: &str, state: &RosterState) -> String {
    let taken = |candidate: &str| state.devices.values().any(|record| record.name == candidate);
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
    use super::*;

    /// A joining device's payload, proposing a name.
    fn a_payload(name: &str) -> Joining {
        let joining = NodeIdentity::generate().expect("generates");
        Joining::of(&joining, name, "https://relay.example:443").expect("valid")
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

    /// A network on `relay`, moving from `leaving` where there is one.
    fn on_relay(relay: &str, leaving: Option<(&str, u64)>) -> RosterState {
        let base = roster::types::NetworkParams::with_relay(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            Some(leaving.map_or(relay, |(old, _)| old)),
            "example.internal",
            2_592_000,
        )
        .expect("valid");
        let params = match leaving {
            Some((_, issued)) => base.moving_to(relay, None, issued).expect("moves"),
            None => base,
        };
        state_of(params, &[])
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

    // ---- F-17: the relay a payload names ----------------------------------

    fn waiting_at(relay: &str) -> Joining {
        let joining = NodeIdentity::generate().expect("generates");
        Joining::of(&joining, "laptop", relay).expect("valid")
    }

    /// **A payload naming another relay is refused, naming both.**
    #[test]
    fn a_payload_naming_another_relay_is_refused() {
        let state = on_relay("https://ours.example:443", None);
        let refused = refuse_a_relay_the_network_does_not_use(
            &waiting_at("https://theirs.example:443"),
            &state,
            1,
        )
        .expect_err("not our relay");
        assert!(refused.contains("theirs.example"), "where it waits: {refused}");
        assert!(refused.contains("ours.example"), "and where we are: {refused}");
        assert!(refused.contains("Nothing was contacted"), "{refused}");
    }

    /// The same relay, written another way, is the same relay.
    #[test]
    fn the_same_relay_written_differently_is_admitted() {
        let state = on_relay("https://ours.example:443", None);
        assert!(
            refuse_a_relay_the_network_does_not_use(&waiting_at("https://OURS.example"), &state, 1)
                .is_ok()
        );
    }

    /// A device that began joining just before a move is waiting at the old
    /// relay: admitted during the transition, and not after it.
    #[test]
    fn the_relay_being_left_is_admitted_until_the_move_ends() {
        let issued = 1_000;
        let state = on_relay("https://new.example:443", Some(("https://old.example:443", issued)));
        let at_old = waiting_at("https://old.example:443");
        let end = issued + 2_592_000 * 1_000;

        assert!(refuse_a_relay_the_network_does_not_use(&at_old, &state, end - 1).is_ok());
        assert!(
            refuse_a_relay_the_network_does_not_use(&at_old, &state, end).is_err(),
            "the end is the rule"
        );
        assert!(
            refuse_a_relay_the_network_does_not_use(
                &waiting_at("https://new.example"),
                &state,
                end
            )
            .is_ok(),
            "and the new one always"
        );
    }

    /// A network with no relay admits nobody, and says how to give it one.
    #[test]
    fn a_network_with_no_relay_admits_nobody() {
        let refused = refuse_a_relay_the_network_does_not_use(
            &waiting_at("https://any.example:443"),
            &state_with(&[]),
            1,
        )
        .expect_err("nothing to bind to");
        assert!(refused.contains("no relay"), "{refused}");
        assert!(refused.contains("peerfectly relay"), "and how to give it one: {refused}");
    }

    /// **Nothing is contacted: the refusal comes before the endpoint exists.**
    ///
    /// Not merely before the exchange — building the endpoint is where a relay
    /// starts to be reached. Asserted on the code, because a behavioural test of
    /// "nothing was contacted" would need a network to watch.
    #[test]
    fn the_relay_is_checked_before_anything_is_built() {
        let code = crate::code_of(include_str!("admitting.rs"));
        let opening = code
            .split("pub async fn open(")
            .nth(1)
            .and_then(|rest| rest.split("\nfn ").next())
            .expect("it is declared");
        let checked =
            opening.find("refuse_a_relay_the_network_does_not_use").expect("it checks the relay");
        let built = opening.find("Admitting::dialling").expect("it builds the endpoint");
        assert!(checked < built, "the relay is checked before the endpoint is built");
    }

    /// A joining device proposes a name and nothing else. What it becomes is
    /// decided here, which is why there is no field for it to ask in.
    #[test]
    fn the_admitting_side_chooses_the_role() {
        let state = state_with(&[]);
        let joining = NodeIdentity::generate().expect("generates");
        let payload = Joining::of(&joining, "laptop", "https://relay.example:443").expect("valid");

        let spec = identity_spec(&payload, &state, false).expect("builds");
        assert_eq!(spec.role, Role::Member, "never an admin because it asked");
        assert!(!spec.founder);
        assert!(spec.capabilities.is_empty());
        assert_eq!(spec.name, "laptop");
    }

    /// A name is what a person types, so two devices must not share one.
    #[test]
    fn a_proposed_name_already_taken_is_made_unique() {
        let state = state_with(&["laptop"]);
        let joining = NodeIdentity::generate().expect("generates");
        let payload = Joining::of(&joining, "laptop", "https://relay.example:443").expect("valid");

        let spec = identity_spec(&payload, &state, false).expect("builds");
        assert_eq!(spec.name, "laptop-2");
        assert_ne!(spec.name, "laptop", "two devices answering to one name is not a network");
    }

    /// The keys in the specification are the ones the payload carried, and the
    /// device id follows from the signing key.
    #[test]
    fn the_specification_carries_the_keys_the_payload_named() {
        let state = state_with(&[]);
        let joining = NodeIdentity::generate().expect("generates");
        let payload = Joining::of(&joining, "laptop", "https://relay.example:443").expect("valid");

        let spec = identity_spec(&payload, &state, false).expect("builds");
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
        let payload = a_payload("laptop");

        let kept = identity_spec(&payload, &state, true).expect("builds");
        let renamed = identity_spec(&payload, &state, false).expect("builds");

        assert_eq!("laptop", kept.name, "the name carries over");
        assert_eq!("laptop-2", renamed.name, "and without replacing it does not");
        assert_eq!(
            kept.device_id().expect("an id"),
            renamed.device_id().expect("an id"),
            "the device is the same either way: an id follows from the signing key"
        );
    }
}

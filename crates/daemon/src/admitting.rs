//! Admitting a device, from this side.
//!
//! The daemon does this rather than the command line, for one reason: it holds
//! the roster. An operation appended to the log by another process would be
//! invisible to a running daemon until it restarted, and a device admitted into
//! a roster nobody is using is a device that cannot connect.
//!
//! # Two steps, because a person stands between them
//!
//! Dialling an invited device ([`open_invited`]) opens the exchange, proves the
//! device holds the keys it presented, works out the confirmation code, and then
//! **stops**. Nothing is signed. The pending exchange waits here while the person
//! compares two screens.
//!
//! `confirm` signs the admission and delivers the roster. `abandon` drops the
//! exchange and leaves nothing behind. If neither arrives, the exchange expires
//! on its own deadline — the safe direction, since expiring means nothing was
//! admitted.
//!
//! # This side never listens
//!
//! [`transport_convesso::enrolment::Admitting`] dials and has no method that
//! accepts. A machine holding a roster is not reachable through the enrolment
//! protocol at all, which is the point: the exception that lets a stranger be
//! spoken to belongs on the device that has nothing to lose.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use enrollment::code::{Confirmation, Side};
use enrollment::exchange::Message;
use enrollment::limits;
use identity::NodeIdentity;
use roster::state::RosterState;
use roster::types::{OperationBody, OperationCore};
use tokio::sync::Mutex;
use transport_convesso::enrolment::{Admitting, Channel};

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
    /// Boxed: on convesso it is a node of its own, larger than the rest.
    endpoint: Box<Admitting>,
    /// What the joining device said it is.
    applicant: Applicant,
    /// What the invite it came through says it will be: the name, role, mode,
    /// groups and address the admin chose when inviting.
    ///
    /// With it, the invite's secret: so the invite is marked used once the
    /// admission is signed, and not before. Boxed, being not small.
    invited: Box<(crate::invites::Invited, [u8; enrollment::invite::SECRET_LEN])>,
    /// The code both screens must show.
    code: Confirmation,
    /// When this exchange stops being usable.
    expires: Instant,
    /// Whether the device being enrolled has said the code matched.
    ///
    /// Set by the task reading the channel, read by whatever asks this side's
    /// person. Nothing is signed while it is false.
    accepted: Arc<AtomicBool>,
    /// The name the joining device will be admitted under: the one it proposed,
    /// made usable (`admitted_name`).
    name: String,
    /// The device already answering to the name this one proposes, if there is
    /// one.
    ///
    /// Worked out when the exchange opens, against the roster this admission is
    /// being made into, so that a person is asked before anything is signed
    /// rather than told afterwards.
    taken: Option<Taken>,
}

/// The device asking to be admitted: its keys and the name it proposes, as it
/// introduced itself over an invite's exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applicant {
    /// Its signing key: its identity.
    pub signing: roster::sign::PublicKey,
    /// Its transport key.
    pub transport: roster::sign::PublicKey,
    /// Its attestation key.
    pub attestation: roster::sign::PublicKey,
    /// The name it proposes.
    pub name: String,
}

impl From<&enrollment::exchange::Introduction> for Applicant {
    fn from(introduction: &enrollment::exchange::Introduction) -> Self {
        Self {
            signing: introduction.signing.clone(),
            transport: introduction.transport.clone(),
            attestation: introduction.attestation.clone(),
            name: introduction.name.clone(),
        }
    }
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
    /// The name the joining device proposed for itself, made usable: what the
    /// admin is shown, before anything is signed, and what it is admitted under.
    #[must_use]
    pub fn proposed_name(&self) -> &str {
        &self.name
    }

    /// The name its invite was issued under.
    #[must_use]
    pub fn invited_name(&self) -> &str {
        &self.invited.0.name
    }

    /// The device already answering to that name, if there is one.
    #[must_use]
    pub const fn taken(&self) -> Option<&Taken> {
        self.taken.as_ref()
    }

    /// The joining device's signing key, in the shape a person can compare.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        crate::relay::fingerprint(self.applicant.signing.as_bytes())
    }

    /// The code this exchange produced.
    #[must_use]
    pub fn code(&self) -> &Confirmation {
        &self.code
    }

    /// The secret of the invite this device came through.
    #[must_use]
    pub fn invite_secret(&self) -> &[u8; enrollment::invite::SECRET_LEN] {
        &self.invited.1
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
            .field("proposed_name", &self.applicant.name)
            .field("code", &self.code.as_str())
            .field("live", &self.live())
            .finish()
    }
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
    let (signed, said) =
        finish_with_all(pending, vec![signed], spec_name, log, &[], snapshot, None).await?;
    Ok((signed.into_iter().next().unwrap_or_default(), said))
}

/// Delivers an admission and what was signed with it — the settings an invite
/// chose — resting on `base` where this device's roster was compacted, with the
/// `pieces` of the batches it holds.
///
/// The endpoint is closed whatever happens, as [`finish_with`] closes it.
///
/// # Errors
///
/// When the exchange cannot deliver.
pub async fn finish_with_all(
    pending: Pending,
    signed: Vec<Vec<u8>>,
    spec_name: String,
    log: &[Vec<u8>],
    pieces: &[Vec<u8>],
    snapshot: Option<Vec<u8>>,
    base: Option<enrollment::adopt::Base>,
) -> Result<(Vec<Vec<u8>>, String), Refusal> {
    let mut pending = pending;
    let outcome =
        deliver_signed(&mut pending, signed, spec_name, log, pieces, snapshot, base).await;
    (*pending.endpoint).close().await;
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
    (*pending.endpoint).close().await;
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

    let spec = identity_spec(&pending.applicant, &pending.invited.0, state, keeping_the_name)?;
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
    signed: Vec<Vec<u8>>,
    spec_name: String,
    log: &[Vec<u8>],
    pieces: &[Vec<u8>],
    snapshot: Option<Vec<u8>>,
    base: Option<enrollment::adopt::Base>,
) -> Result<(Vec<Vec<u8>>, String), Refusal> {
    let deadline = Duration::from_secs(limits::EXCHANGE_DEADLINE_SECS);

    // The whole log, not only the admission: §3.1 says every device appears
    // together, and a joiner that received one operation would have a network
    // with two members and no idea about the rest.
    let mut operations = log.to_vec();
    operations.extend(signed.iter().cloned());

    {
        let mut channel = pending.channel.lock().await;
        // Where this roster was compacted its log no longer reaches the
        // genesis, so the state beneath it goes first, in as many parts as it
        // takes.
        if let Some(base) = base {
            let pieces = roster::transfer::pieces_of(&base.state);
            for part in pieces.chunks(enrollment::exchange::BASE_PIECES_PER_MESSAGE) {
                let message = Message::Base { root: base.root.clone(), pieces: part.to_vec() };
                send(&mut channel, &message, deadline).await?;
            }
        }
        // A batch's operation is only its header: without its pieces the joiner
        // holds it incomplete, and whatever was signed after it — this
        // admission, where a batch came before — would wait on it.
        for part in pieces.chunks(enrollment::exchange::BATCH_PIECES_PER_MESSAGE) {
            send(&mut channel, &Message::Batch { pieces: part.to_vec() }, deadline).await?;
        }
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
            "it refused the network: it did not find itself admitted in it".to_owned()
        }
        Ok(_) | Err(_) => "it did not say whether it adopted the network".to_owned(),
    };

    // Which name it was admitted under, when that is not the one its invite
    // gave. Before this a device quietly became `name-2` and nobody was told.
    // Not the one it proposed: the invite's name decides, and a device that
    // proposed another was not refused a name in use.
    let said = if spec_name != admitted_name(&pending.invited.0.name) {
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
    let mut signed = vec![
        identity.sign_operation(&operation).map_err(|cause| crate::control::declined(&cause))?,
    ];
    // The mode, groups and address an invite chose, where they are not the
    // default: set after the admission, in the same act.
    if let Some(settings) = settings_core(pending, identity, state, &operation)? {
        signed.push(
            identity.sign_operation(&settings).map_err(|cause| crate::control::declined(&cause))?,
        );
    }
    let (signed, said) =
        deliver_signed(pending, signed, spec_name, log, &[], snapshot, None).await?;
    Ok((signed.into_iter().next().unwrap_or_default(), said))
}

/// The settings an invited device is admitted with, where its invite chose
/// any other than the default: a `set_device` following the admission.
///
/// # Errors
///
/// When the operation cannot be made.
pub fn settings_core(
    pending: &Pending,
    identity: &NodeIdentity,
    state: &RosterState,
    admission: &OperationCore,
) -> Result<Option<OperationCore>, Refusal> {
    let invited = &pending.invited.0;
    let mode = (invited.mode != roster::leaf::Mode::Full).then_some(invited.mode);
    let groups = (!invited.groups.is_empty()).then(|| invited.groups.clone());
    let ipv4 = invited.ipv4.map(Some);
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

/// Opens the exchange with a device that came through one of this device's
/// invites: dials the rendezvous key its secret derives, at the relay it names,
/// takes the device's introduction and checks both its proofs, and works out
/// the code. Stops there, as [`open`] does.
///
/// # Errors
///
/// When the device cannot be reached, says something other than an
/// introduction, or does not prove the keys it presents.
pub async fn open_invited(
    identity: &NodeIdentity,
    state: &RosterState,
    record: &crate::invites::Record,
) -> Result<Pending, Refusal> {
    let endpoint = Admitting::dialling(identity, state).await.map_err(|cause| cause.to_string())?;
    match exchange_invited(&endpoint, &record.invite).await {
        Ok((channel, code, expires, applicant)) => {
            let name = admitted_name(&record.invited.name);
            let pending = Pending {
                channel: Arc::new(Mutex::new(channel)),
                endpoint: Box::new(endpoint),
                applicant,
                invited: Box::new((record.invited.clone(), record.invite.secret)),
                code,
                expires,
                accepted: Arc::new(AtomicBool::new(false)),
                taken: holder_of(&name, state),
                name,
            };
            pending.listen();
            Ok(pending)
        }
        Err(refusal) => {
            endpoint.close().await;
            Err(refusal)
        }
    }
}

/// Reaches an invited device at its rendezvous key and takes its introduction.
async fn exchange_invited(
    endpoint: &Admitting,
    invite: &enrollment::Invite,
) -> Result<(Channel, Confirmation, Instant, Applicant), Refusal> {
    let deadline = Duration::from_secs(limits::EXCHANGE_DEADLINE_SECS);
    let key = transport_convesso::enrolment::rendezvous_key(&invite.rendezvous_seed())
        .map_err(|cause| cause.to_string())?;
    // Reaching it is what is tried every few seconds, and given little time: a
    // device that is not there is the usual answer. Once reached, its
    // introduction may wait on a person — the possession it proves is signed by
    // a key that a passphrase or a TPM may guard — and has the exchange's own
    // deadline, as every step after it does.
    let mut channel = tokio::time::timeout(
        crate::limits::INVITE_DIAL_PATIENCE,
        endpoint.reach(&key, &invite.relay),
    )
    .await
    .map_err(|_| "the invited device did not answer".to_owned())?
    .map_err(|cause| cause.to_string())?;
    let material = channel.material().map_err(|cause| cause.to_string())?;
    let Message::Introduce(introduction) = receive(&mut channel, deadline).await? else {
        return Err("the device said something other than an introduction".to_owned());
    };
    introduction.verify(&material).map_err(|cause| cause.to_string())?;
    let joining = Side {
        signing: introduction.signing.clone(),
        transport: introduction.transport.clone(),
        attestation: introduction.attestation.clone(),
    };
    let code = Confirmation::derive(&joining, &channel.own(), &material)
        .map_err(|cause| cause.to_string())?;
    let expires = Instant::now().checked_add(deadline).unwrap_or_else(Instant::now);
    Ok((channel, code, expires, Applicant::from(&introduction)))
}

/// Drops an exchange, leaving both machines as they were.
pub async fn abandon(pending: Pending) {
    (*pending.endpoint).close().await;
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
        // the introduction and nowhere else, and the confirmation code covers it, so
        // what goes into the record is what both people compared.
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
    // It has to be said here rather than left to fall out. The revocation has
    // already been signed and applied by the time this runs, and a revoked
    // device leaves the membership entirely — so the name *is* free. But the
    // `state` this reads was gathered before any of that, and altering the name
    // against it would quietly undo what the person asked for.
    // An invited device takes the name its invite's record gives it, and the
    // role the admin chose when inviting; the name it proposed is a suggestion.
    let proposed = admitted_name(&invited.name);
    let name = if keeping_the_name { proposed } else { unused_name(&proposed, state) };
    roster::types::DeviceSpec::new(keys, name, invited.role, false, vec![])
        .map_err(|cause| cause.to_string())
}

/// The name a joining device is admitted under: the one it proposed, made one a
/// resolver can answer.
///
/// Lowered when that is all it needs. An older client may propose anything its
/// person typed, and nobody on this side can be asked to retype it, so a name
/// that is not a label is made into the nearest one, and the admin is shown that
/// before signing. A name with nothing usable in it becomes `device`, made unique
/// like any other.
fn admitted_name(proposed: &str) -> String {
    crate::names::usable(proposed)
        .ok()
        .or_else(|| crate::names::made_usable(proposed))
        .unwrap_or_else(|| "device".to_owned())
}

/// The device already answering to a name, if one does.
///
/// Without regard to case: the resolver answers `Laptop` and `laptop` alike, so
/// two devices with those names are one name nobody can look up.
fn holder_of(name: &str, state: &RosterState) -> Option<Taken> {
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
    let taken = |candidate: &str| {
        state.devices.values().any(|record| record.name.eq_ignore_ascii_case(candidate))
    };
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
}

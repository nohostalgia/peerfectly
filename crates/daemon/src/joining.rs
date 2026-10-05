//! Waiting to be given a network.
//!
//! This runs where there is no daemon, because there cannot be one: the daemon
//! reads a roster and stops without one. A device here has keys and nothing
//! else.
//!
//! # A relay address is the whole bootstrap
//!
//! A device with no network is unreachable in both directions — it registers at
//! no relay, so nobody can dial it, and it cannot announce on the local network
//! either, because announcements are sealed with a network identifier it does
//! not have. A person types a relay address, and that is enough: an endpoint
//! registers at a relay by its own key and knows nothing about any roster.
//!
//! Then the device shows what it is and waits. The admin comes to it, because
//! dialling needs the peer's transport key and the payload is what carries it.
//!
//! # What is accepted, and what that is worth
//!
//! While waiting, this accepts an exchange from a peer no roster names — there
//! is no roster with which to name anyone. It grants that peer nothing. What
//! arrives is verified afterwards: the network must admit this device's own
//! keys, be signed by an admin, and pin the relay certificate this device had to
//! accept on sight. And a person compares six digits before any of it is
//! believed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use enrollment::code::{Confirmation, Side};
use enrollment::exchange::{Message, Possession};
use enrollment::payload::Joining;
use enrollment::{adopt, limits};
use identity::NodeIdentity;
use transport_iroh::enrolment::{Channel, Waiting};

use crate::state::{Log, Paths};

/// Why a join did not happen.
///
/// A message rather than a variant, for the reason [`crate::relay::Refusal`] is:
/// each one ends the command, and the person needs the sentence.
pub type Refusal = String;

/// How a person answers the question this asks.
///
/// Taken as a trait so the wait can be driven by a test without a terminal. The
/// person is the security control here, not a detail of the interface: nothing
/// in this module may proceed on its own.
///
/// # These are called off the runtime
///
/// Every method here may block for as long as a person takes, and the QUIC
/// connection this enrolment runs over needs the runtime to keep driving it
/// meanwhile. So they are called on a blocking thread — an implementation may
/// read from a terminal without thinking about it.
///
/// Found the hard way: reading a code from standard input on the runtime's own
/// thread stalled the connection, and the exchange died while the person was
/// typing.
pub trait Person: Send + Sync + 'static {
    /// Shows the payload a person must carry to the admin.
    fn show_payload(&self, text: &str, scannable: &str);

    /// Asks for the code the admin is displaying.
    ///
    /// Returning `None` abandons the enrolment.
    fn code_shown_by_the_admin(&self, ours: &Confirmation) -> Option<String>;

    /// Has a signing key that is not reachable from here prove it is held.
    ///
    /// Only reached when [`identity::SigningKey::answers_here`] is false, which
    /// is a machine whose key store answers only in the session of the person who
    /// owns it. Everywhere else the proof is signed on the spot and this is never
    /// called, which is why it has a default: a surface that cannot ask says so
    /// by not answering, and the join ends saying what it needed.
    ///
    /// Returning `None` ends the join. Nothing is written either way.
    fn signs_the_proof(&self, request: &identity::detached::SigningRequest) -> Option<Vec<u8>> {
        let _ = request;
        None
    }

    /// Says what happened, as it happens.
    fn note(&self, message: &str);

    /// Says that an exchange was refused, and why.
    ///
    /// Separate from [`Self::note`] because it is not commentary: it is the
    /// answer to the person who just typed six digits. The wait itself goes on —
    /// somebody who mistyped tries again — so nothing else will report it, and a
    /// person left waiting for an outcome that is not coming reads it as the
    /// device having frozen.
    fn exchange_refused(&self, refusal: &str) {
        let _ = refusal;
    }

    /// Whether the person has abandoned the join. Asked while it waits, so the
    /// endpoint it opened is closed rather than dropped.
    fn abandoned(&self) -> bool {
        false
    }
}

/// What a join driven by the daemon has reached.
///
/// A join is a conversation with two pauses in it: one while a person carries
/// the payload to an admin, and one while they compare six digits. The control
/// channel is one request and one answer, so the daemon holds where the
/// conversation has got to and the command line asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// Registering at the relay. Nothing to show yet.
    Registering,
    /// Waiting for an admin, with the payload a person carries to one.
    Waiting {
        /// The payload as text.
        payload: String,
        /// The same payload, drawn.
        scannable: String,
    },
    /// An admin has arrived and is showing a code for a person to type here.
    ///
    /// What this device derived is not carried: a person must read the digits
    /// off the admin's screen, and a client that could show them its own would
    /// be offering the wrong screen to read.
    Confirming {
        /// The payload, still, in case the person is looking at it.
        payload: String,
    },
    /// The proof of possession is prepared and needs a signature from a key this
    /// process cannot reach.
    ///
    /// Nothing has been written and nothing has been sent: what is waiting is the
    /// one thing a device must do to show the identity it presented is its own.
    Signing {
        /// The payload, still, in case the person is looking at it.
        payload: String,
        /// The bytes to be signed, and what they will become.
        request: identity::detached::SigningRequest,
    },
    /// The network was adopted.
    Joined {
        /// The suffix every name in it sits under.
        suffix: String,
        /// How many devices it has, this one included.
        devices: usize,
        /// Whether the relay this device used was confirmed by the network.
        relay_confirmed: bool,
    },
    /// It ended without a network, and why.
    Failed(String),
}

/// A person reached through the control channel rather than a terminal.
///
/// The daemon holds the join; the command line asks what it has got to and hands
/// back the code a person typed. This is the bridge: it records progress where
/// the service can read it, and blocks on the confirmation the way the terminal
/// version blocks on stdin.
///
/// Every method here runs on the blocking pool, off the runtime — `joining` calls
/// them through `spawn_blocking` for exactly that reason. Blocking the reactor
/// inside an enrolment is how a test once hung for forty-three minutes.
pub struct AcrossTheChannel {
    /// The last exchange refusal, shared with [`Underway`].
    refused: Arc<std::sync::Mutex<Option<String>>>,
    /// Where the join has got to, for the service to read.
    progress: Arc<std::sync::Mutex<Progress>>,
    /// The code a person typed, once they have.
    ///
    /// A `std::sync` channel rather than a tokio one because the waiting happens
    /// on the blocking pool. With a timeout, so a join nobody confirms ends
    /// rather than holding a thread for as long as the daemon runs.
    confirmed: std::sync::Mutex<std::sync::mpsc::Receiver<String>>,
    /// The signature over the proof of possession, once somebody has made it.
    ///
    /// A second channel rather than a second use of the first: the two are
    /// answers to different questions, and a join that muddled them would take
    /// six typed digits for a signature.
    proved: std::sync::Mutex<std::sync::mpsc::Receiver<Vec<u8>>>,
    /// Set when the person abandons the join.
    abandoned: Arc<std::sync::atomic::AtomicBool>,
}

impl AcrossTheChannel {
    /// A person, and the handle the service confirms through.
    #[must_use]
    pub fn new() -> (Arc<Self>, Underway) {
        let (sender, receiver) = std::sync::mpsc::channel();
        let (proves, proved) = std::sync::mpsc::channel();
        let progress = Arc::new(std::sync::Mutex::new(Progress::Registering));
        let abandoned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let refused = Arc::new(std::sync::Mutex::new(None));
        let person = Arc::new(Self {
            refused: Arc::clone(&refused),
            progress: Arc::clone(&progress),
            confirmed: std::sync::Mutex::new(receiver),
            proved: std::sync::Mutex::new(proved),
            abandoned: Arc::clone(&abandoned),
        });
        (person, Underway { refused, progress, confirm: sender, prove: proves, abandoned })
    }

    /// Records where the join has got to.
    pub(crate) fn reached(&self, progress: Progress) {
        if let Ok(mut held) = self.progress.lock() {
            *held = progress;
        }
    }

    /// Records how the join ended.
    ///
    /// The join's own result, rather than the running commentary: what a person
    /// needs is whether they have a network, and if not, why not.
    pub fn finished(&self, outcome: Result<Joined, Refusal>) {
        self.reached(match outcome {
            Ok(joined) => Progress::Joined {
                suffix: joined.suffix,
                devices: joined.devices,
                relay_confirmed: joined.relay_confirmed,
            },
            Err(refusal) => Progress::Failed(refusal),
        });
    }

    /// What it has got to.
    fn now(&self) -> Progress {
        self.progress.lock().map_or(Progress::Registering, |held| held.clone())
    }
}

/// The service's half: what a join has reached, and how to confirm it.
pub struct Underway {
    /// The last exchange refusal, if one has happened.
    ///
    /// A refused exchange leaves the wait open, so there is no failure to
    /// report — but there is a person who has just typed six digits and needs
    /// to know they were wrong.
    refused: Arc<std::sync::Mutex<Option<String>>>,
    /// Where the join has got to.
    progress: Arc<std::sync::Mutex<Progress>>,
    /// Hands a person's code to the join.
    confirm: std::sync::mpsc::Sender<String>,
    /// Hands the join a signature over its proof of possession.
    prove: std::sync::mpsc::Sender<Vec<u8>>,
    /// Tells the join the person has left it.
    abandoned: Arc<std::sync::atomic::AtomicBool>,
}

impl Underway {
    /// Where the join has got to.
    #[must_use]
    pub fn progress(&self) -> Progress {
        self.progress.lock().map_or(Progress::Registering, |held| held.clone())
    }

    /// Hands the join the code a person typed.
    ///
    /// Returns whether anything was listening: a join that has already ended is
    /// not confirmed, it is over.
    pub fn confirm(&self, code: &str) -> bool {
        self.confirm.send(code.to_owned()).is_ok()
    }

    /// Hands the join a signature over its proof of possession.
    ///
    /// Returns whether anything was listening, as [`Self::confirm`] does.
    pub fn proved(&self, signature: Vec<u8>) -> bool {
        self.prove.send(signature).is_ok()
    }

    /// What this join is waiting to have signed, if it is waiting for that.
    #[must_use]
    pub fn wants_signing(&self) -> Option<identity::detached::SigningRequest> {
        match self.progress() {
            Progress::Signing { request, .. } => Some(request),
            _ => None,
        }
    }

    /// The last exchange refusal, taken.
    ///
    /// Taken rather than read, because it answers one person once: a refusal
    /// left lying about would answer the *next* attempt with the last attempt's
    /// reason.
    #[must_use]
    pub fn refusal(&self) -> Option<String> {
        self.refused.lock().ok().and_then(|mut held| held.take())
    }

    /// Tells the join to stop waiting and close what it opened.
    pub fn abandon(&self) {
        self.abandoned.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Person for AcrossTheChannel {
    fn abandoned(&self) -> bool {
        self.abandoned.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn show_payload(&self, text: &str, scannable: &str) {
        self.reached(Progress::Waiting {
            payload: text.to_owned(),
            scannable: scannable.to_owned(),
        });
    }

    fn code_shown_by_the_admin(&self, ours: &Confirmation) -> Option<String> {
        let payload = match self.now() {
            Progress::Waiting { payload, .. } | Progress::Confirming { payload, .. } => payload,
            _ => String::new(),
        };
        // The code this device derived is deliberately **not** carried here.
        // Progress is what a client is shown, and a client that could show the
        // code would be inviting the person to read it from this screen rather
        // than from the admin's — which is the screen an attacker who dialled
        // first controls.
        let _ = ours;
        self.reached(Progress::Confirming { payload });

        // Bounded, because an unbounded wait here holds a thread from the
        // blocking pool for as long as the daemon runs, on a join nobody is
        // coming back to. The bound is the same one the whole wait has.
        let held = self.confirmed.lock().ok()?;
        held.recv_timeout(Duration::from_secs(limits::WAIT_SECS)).ok()
    }

    fn signs_the_proof(&self, request: &identity::detached::SigningRequest) -> Option<Vec<u8>> {
        let payload = match self.now() {
            Progress::Waiting { payload, .. } | Progress::Confirming { payload, .. } => payload,
            _ => String::new(),
        };
        self.reached(Progress::Signing { payload, request: request.clone() });

        // Bounded, for the reason the code's wait is bounded: an unbounded wait
        // holds a thread from the blocking pool for as long as the daemon runs,
        // on a join nobody is coming back to.
        let held = self.proved.lock().ok()?;
        held.recv_timeout(Duration::from_secs(limits::WAIT_SECS)).ok()
    }

    fn note(&self, message: &str) {
        // A note is not progress. The one that matters — why a join ended — is
        // recorded by the service from the join's own result.
        let _ = message;
    }

    fn exchange_refused(&self, refusal: &str) {
        // Kept so the service can answer the person at once, instead of polling
        // for an outcome that a continuing wait will never produce.
        if let Ok(mut held) = self.refused.lock() {
            *held = Some(refusal.to_owned());
        }
    }
}

/// What a completed join produced.
#[derive(Debug, Clone)]
pub struct Joined {
    /// The name of the network's suffix, for telling the person what to do next.
    pub suffix: String,
    /// How many devices the network has, this one included.
    pub devices: usize,
    /// Whether the relay this device used was confirmed by the network.
    pub relay_confirmed: bool,
}

/// Waits to be admitted, and adopts the network if everything checks out.
///
/// # Errors
///
/// When this machine already holds a network, when the relay cannot be reached,
/// when the wait ends without an admission, or when what arrived could not be
/// believed.
pub async fn join(
    paths: &Paths,
    relay: &str,
    name: &str,
    person: Arc<dyn Person>,
) -> Result<Joined, Refusal> {
    join_with(paths, relay, name, person, &crate::keys::PlatformKeys).await
}

/// Joins with keys from `keys`.
///
/// # Errors
///
/// As [`join`], and when the keys decline to prove possession.
pub async fn join_with(
    paths: &Paths,
    relay: &str,
    name: &str,
    person: Arc<dyn Person>,
    keys: &dyn crate::keys::Keys,
) -> Result<Joined, Refusal> {
    paths.create().map_err(|cause| cause.to_string())?;

    let log = Log::at(paths.roster());
    if !log.read().map_err(|cause| cause.to_string())?.is_empty() {
        return Err(format!(
            "this machine already holds a network. Joining another would abandon it, so it is \
             refused.\nTo start over deliberately, remove {} first.",
            paths.roster().display()
        ));
    }

    let identity = keys.identity(paths).map_err(|cause| cause.to_string())?;
    let waiting = Waiting::listen(&identity, relay).await.map_err(|cause| cause.to_string())?;

    // Everything after listening runs inside one future, so that however it ends
    // — a relay that does not answer, a wait that runs out, a person abandoning
    // it — the endpoint is closed. Dropped instead, its socket stayed bound.
    let work = async {
        note(&person, "registering at the relay...").await;
        tokio::time::timeout(Duration::from_secs(30), waiting.online())
            .await
            .map_err(|_| format!("{relay} did not answer within thirty seconds"))?;

        if let Some(certificate) = waiting.accepted_on_sight() {
            note(
                &person,
                &format!(
                    "
the relay's certificate was accepted on sight — nothing vouches for it yet:
                       SHA-256  {}
the network you join must pin this same certificate, or it will be refused.",
                    crate::relay::fingerprint(&certificate)
                ),
            )
            .await;
        }

        let payload =
            Joining::of(&identity, name, waiting.relay()).map_err(|cause| cause.to_string())?;
        show(&person, payload.to_text()).await;

        wait_for_admission(&waiting, &identity, &person).await
    };
    let outcome = tokio::select! {
        outcome = work => outcome,
        () = until_abandoned(&person) => Err("the join was abandoned; nothing was written".to_owned()),
    };
    waiting.close().await;

    let Delivered { operations, snapshot, adopted } = outcome?;
    for operation in &operations {
        log.append(operation).map_err(|cause| cause.to_string())?;
    }

    keep_delivered_snapshot(paths, &operations, snapshot.as_deref());

    Ok(Joined {
        suffix: adopted.state.params.suffix.clone(),
        devices: adopted.state.devices.len(),
        relay_confirmed: adopted.relay_confirmed,
    })
}

/// Checks a delivered snapshot against the operations it came with, and keeps it.
///
/// **A snapshot that does not check costs the roster nothing.** The operations
/// prove the membership and have already been written; the snapshot only dates
/// it. Refusing the whole delivery over one would throw away a membership a
/// person has just confirmed on two screens, in order to punish a field that is
/// allowed to be missing entirely.
///
/// What a device without one gets is a roster it cannot yet confirm — the same
/// state as one that has been out of touch too long. That is worth saying rather
/// than hiding, and the daemon says it as soon as the network is reported.
fn keep_delivered_snapshot(paths: &Paths, operations: &[Vec<u8>], snapshot: Option<&[u8]>) {
    let Some(bytes) = snapshot else { return };

    // Checked by the roster's own rules — signed by a device these operations
    // name as an admin, over heads they contain — and never because of who sent
    // it. The same roster the operations derive to is what does the checking.
    let mut roster = roster::roster::Roster::with_clock(Box::new(crate::state::WallClock));
    for operation in operations {
        let _admitted = roster.offer_bytes(operation);
    }
    if !roster.offer_snapshot(bytes).is_accepted() {
        return;
    }
    let _kept = crate::state::write_snapshot(paths, bytes, crate::state::wall_seconds());
}

/// One wait: several exchanges, one at a time, each with its own deadline.
/// Returns once the person has abandoned the join.
async fn until_abandoned(person: &Arc<dyn Person>) {
    while !person.abandoned() {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_admission(
    waiting: &Waiting,
    identity: &NodeIdentity,
    person: &Arc<dyn Person>,
) -> Result<Delivered, Refusal> {
    let started = Instant::now();
    let whole = Duration::from_secs(limits::WAIT_SECS);
    let each = Duration::from_secs(limits::EXCHANGE_DEADLINE_SECS);

    for attempt in 1..=limits::ATTEMPTS_PER_WAIT {
        let left = whole.checked_sub(started.elapsed()).unwrap_or_default();
        if left.is_zero() {
            return Err(format!(
                "nobody admitted this device within {} minutes. Nothing was written; run the \
                 command again when the other machine is ready.",
                whole.as_secs().saturating_div(60)
            ));
        }

        // One exchange at a time, because two would mean two codes on one
        // screen. Each with a deadline of its own, because the payload is
        // public: without one, anybody who had seen it could open an exchange,
        // say nothing, and hold the only slot for the whole wait.
        let Ok(accepted) = tokio::time::timeout(left.min(each), waiting.accept()).await else {
            continue;
        };
        let Ok(channel) = accepted else { continue };

        match one_exchange(channel, identity, person, each).await {
            Ok(admitted) => return Ok(admitted),
            Err(refusal) => {
                // A failed exchange does not end the wait: a person who mistyped
                // a code, or who was talking to the wrong machine, tries again.
                // They are told, though — that is what `exchange_refused` is
                // for, and the wait carrying on is not a reason to say nothing.
                refused(person, &refusal).await;
                note(person, &format!("attempt {attempt}: {refusal}")).await;
            }
        }
    }

    Err(format!(
        "this wait entertained {} attempts and none of them worked out. Nothing was written.",
        limits::ATTEMPTS_PER_WAIT
    ))
}

/// One exchange, from the channel opening to a network being believed.
async fn one_exchange(
    mut channel: Channel,
    identity: &NodeIdentity,
    person: &Arc<dyn Person>,
    deadline: Duration,
) -> Result<Delivered, Refusal> {
    let material = channel.material().map_err(|cause| cause.to_string())?;
    let peer = channel.peer().map_err(|cause| cause.to_string())?;

    // The channel proves the peer holds its transport key. This proves the same
    // about ours, which the channel says nothing about — and a device's identity
    // comes from its signing key, so without it a payload could pair our
    // identity with somebody else's transport key.
    let possession = if identity.signing_key().answers_here() {
        Possession::prove_detached(identity, &material).map_err(|cause| match cause {
            enrollment::Error::NotProved(custody) => crate::control::declined(&custody),
            other => other.to_string(),
        })?
    } else {
        // The key is somewhere this process cannot reach — a machine key store
        // that answers only in the session of the person who owns it. So the
        // challenge is prepared here and somebody else signs it, and what comes
        // back is checked against the key this device is presenting before it is
        // sent. A device proving possession with a signature it did not verify
        // would be vouching for whatever answered.
        let request = Possession::request(&identity.signing_key().public_key(), &material)
            .map_err(|cause| cause.to_string())?;
        let signature = proved(person, &request)
            .await
            .ok_or_else(|| "nothing signed the proof that this device holds its own signing key. Nothing was written.".to_owned())?;
        // `from_bytes` decides nothing, and says so. So the check is here, where
        // a reader can see it: a device that sent a proof it had not verified
        // would be vouching for whatever answered.
        let proof = Possession::from_bytes(signature);
        proof.verify(&identity.signing_key().public_key(), &material).map_err(|_| {
            "what signed the proof does not hold this device's signing key. Nothing was sent."
                .to_owned()
        })?;
        proof
    };
    send(&mut channel, &Message::Hello { possession }, deadline).await?;

    let ours = Side {
        signing: identity.signing_key().public_key(),
        transport: identity.transport_key().public_key(),
        attestation: identity.attestation_key().public_key(),
    };
    // The admitting side's signing key is not known here and does not need to
    // be: the code binds this device's three keys, the admitting side's
    // transport key — which the channel authenticated — and the channel itself.
    // The admin computes the same value from what its own role knows.
    let code = Confirmation::derive(&ours, &peer, &material).map_err(|cause| cause.to_string())?;

    let Some(entered) = ask(person, code.clone()).await else {
        return Err("abandoned; nothing was written".to_owned());
    };
    if !code.matches(&entered) {
        return Err("that is not the code this exchange produced. Either it was mistyped, or the \
                    machine that answered is not the one showing you that code"
            .to_owned());
    }

    // Said before the admission is waited for, and only once a person has
    // compared: it is what tells the other side that somebody did. It carries
    // nothing — the digits stay on this device, and both sides already derived
    // the same code from the channel.
    send(&mut channel, &Message::Accepted, deadline).await?;

    let Message::Admission { operations, snapshot } = receive(&mut channel, deadline).await? else {
        return Err("the other machine said something other than an admission".to_owned());
    };

    // Delivery proves nothing. What arrived must admit this device's own keys,
    // be signed by an admin, and pin the relay certificate already accepted.
    let adopted = adopt::adopt(&operations, identity, None).map_err(|cause| cause.to_string());
    let taken = adopted.is_ok();
    let _ = send(&mut channel, &Message::Outcome { taken }, deadline).await;

    Ok(Delivered { operations, snapshot, adopted: adopted? })
}

/// What an exchange delivered, once it has been checked.
pub struct Delivered {
    /// The operations, exactly as they arrived.
    pub operations: Vec<Vec<u8>>,
    /// The network's snapshot, where the admitting side sent one.
    ///
    /// Unverified here: it is checked against the operations beside it, and a
    /// snapshot that does not check is dropped without costing the roster
    /// anything. The membership is what the operations prove; the snapshot only
    /// dates it.
    pub snapshot: Option<Vec<u8>>,
    /// The state the operations derive to.
    pub adopted: adopt::Adopted,
}

/// Asks the person for the code, without stalling the connection.
///
/// The exchange is a live QUIC connection and the runtime has to keep driving it
/// while somebody reads a number off another screen and types it in. Doing this
/// on the runtime's own thread killed the connection mid-question.
async fn ask(person: &Arc<dyn Person>, ours: Confirmation) -> Option<String> {
    let person = Arc::clone(person);
    tokio::task::spawn_blocking(move || person.code_shown_by_the_admin(&ours)).await.ok().flatten()
}

/// Has somebody sign the proof, off the runtime for the same reason.
async fn proved(
    person: &Arc<dyn Person>,
    request: &identity::detached::SigningRequest,
) -> Option<Vec<u8>> {
    let person = Arc::clone(person);
    let request = request.clone();
    tokio::task::spawn_blocking(move || person.signs_the_proof(&request)).await.ok().flatten()
}

/// Shows the payload, off the runtime for the same reason.
async fn show(person: &Arc<dyn Person>, text: String) {
    let person = Arc::clone(person);
    let _ = tokio::task::spawn_blocking(move || {
        let drawn = scannable(&text);
        person.show_payload(&text, &drawn);
    })
    .await;
}

/// Says something to the person, off the runtime for the same reason.
async fn refused(person: &Arc<dyn Person>, refusal: &str) {
    let person = Arc::clone(person);
    let refusal = refusal.to_owned();
    let _ = tokio::task::spawn_blocking(move || person.exchange_refused(&refusal)).await;
}

async fn note(person: &Arc<dyn Person>, message: &str) {
    let person = Arc::clone(person);
    let message = message.to_owned();
    let _ = tokio::task::spawn_blocking(move || person.note(&message)).await;
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

/// The payload as a code a camera can read.
///
/// A rendering of the same bytes the text form carries, never a second format.
/// A failure here costs the scannable form and not the enrolment, so it reports
/// itself in place rather than ending anything.
#[must_use]
pub fn scannable(text: &str) -> String {
    use qrcode::QrCode;
    use qrcode::render::unicode;

    match QrCode::new(text.as_bytes()) {
        Ok(code) => code.render::<unicode::Dense1x2>().quiet_zone(true).build(),
        Err(cause) => format!("(the payload could not be drawn as a code: {cause})"),
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// A person who is not there.
    struct Nobody;

    impl Person for Nobody {
        fn show_payload(&self, _text: &str, _scannable: &str) {}
        fn code_shown_by_the_admin(&self, _ours: &Confirmation) -> Option<String> {
            None
        }
        fn note(&self, _message: &str) {}
    }

    /// The two forms carry one payload. A scannable code that said something
    /// else would be a second format wearing one name.
    #[test]
    fn the_scannable_form_carries_the_text_form() {
        let identity = NodeIdentity::generate().expect("generates");
        let payload =
            Joining::of(&identity, "laptop", "https://relay.example:443").expect("within bounds");

        let text = payload.to_text();
        let drawn = scannable(&text);
        assert!(!drawn.contains("could not be drawn"), "{drawn}");
        assert!(drawn.lines().count() > 8, "a code has to be big enough to scan: {drawn}");
    }

    /// Joining a second network from a machine that already has one would
    /// abandon the first. Refused, and it says how to do it on purpose.
    #[tokio::test]
    async fn joining_from_a_machine_that_already_has_a_network_is_refused() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());
        paths.create().expect("creates");

        crate::founding::found(
            &paths,
            &crate::founding::Founding {
                name: "nas".to_owned(),
                suffix: "peerfectly.internal".to_owned(),
                relay: None,
                rendezvous: None,
                certificate: None,
                ipv4_range: None,
            },
        )
        .expect("founds");

        let refusal = join(&paths, "https://relay.example:443", "laptop", Arc::new(Nobody))
            .await
            .expect_err("already has a network");
        assert!(refusal.contains("already holds a network"), "{refusal}");
        assert!(refusal.contains("remove"), "{refusal}");
    }

    /// The bounds are the ones the format crate states, not a second set.
    #[test]
    fn the_wait_uses_the_bounds_the_format_states() {
        assert_eq!(limits::WAIT_SECS, 600);
        assert_eq!(limits::EXCHANGE_DEADLINE_SECS, 60);
        assert_eq!(limits::ATTEMPTS_PER_WAIT, 10);
    }

    /// A network with one admin, its log, and a snapshot over it — what an
    /// admitting side delivers.
    fn delivered() -> (Vec<Vec<u8>>, Vec<u8>) {
        let founder = identity::NodeIdentity::generate().expect("generates");
        let params = roster::types::NetworkParams::new(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            "example.internal",
            2_592_000,
        )
        .expect("valid");
        let genesis = roster::types::OperationCore::new(
            1,
            founder.signing_key().algorithm(),
            roster::types::OperationBody::CreateNetwork {
                device: founder
                    .device_spec("nas", roster::types::Role::Admin, true, vec![])
                    .expect("spec"),
                params,
            },
            vec![],
            founder.signing_key().key_id(),
            roster::id::NetworkId::from_bytes([0; 32]),
        )
        .expect("well-formed");
        let bytes = founder.sign_operation(&genesis).expect("signs");

        let mut roster = roster::roster::Roster::new();
        assert!(roster.offer_bytes(&bytes).is_accepted());
        let snapshot = crate::snapshots::sign_over_heads(&roster, &founder).expect("signs");
        (vec![bytes], snapshot)
    }

    /// The ordinary case: what came with the roster is checked and kept.
    #[test]
    fn a_delivered_snapshot_that_checks_is_kept() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());
        paths.create().expect("creates");
        let (operations, snapshot) = delivered();

        keep_delivered_snapshot(&paths, &operations, Some(&snapshot));

        let (kept, _at) = crate::state::read_snapshot(&paths).expect("it was kept");
        assert_eq!(snapshot, kept, "byte for byte, as it arrived");
    }

    /// A snapshot that does not check costs the roster nothing. The operations
    /// prove the membership and are already written; this only dates it, and it
    /// was allowed to be missing altogether.
    #[test]
    fn a_delivered_snapshot_that_does_not_check_is_dropped_and_nothing_else_is() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());
        paths.create().expect("creates");
        let (operations, mut snapshot) = delivered();
        let last = snapshot.len().saturating_sub(1);
        if let Some(byte) = snapshot.get_mut(last) {
            *byte ^= 0xff;
        }

        keep_delivered_snapshot(&paths, &operations, Some(&snapshot));

        assert!(crate::state::read_snapshot(&paths).is_none(), "nothing was kept");
        // And the membership is untouched: this function writes one file and
        // reads nothing else, so what it declined to write is all it affected.
        assert!(!paths.snapshot().exists(), "and no half-written one is left behind");
    }

    /// An admitting side that sends none — an older build, or one holding no
    /// snapshot — leaves the joiner a member with nothing yet to measure from.
    #[test]
    fn a_delivery_carrying_no_snapshot_leaves_the_joiner_a_member() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());
        paths.create().expect("creates");
        let (operations, _snapshot) = delivered();

        keep_delivered_snapshot(&paths, &operations, None);

        assert!(crate::state::read_snapshot(&paths).is_none(), "there was none to keep");
    }
}

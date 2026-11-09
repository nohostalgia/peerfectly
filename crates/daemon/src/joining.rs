//! Waiting to be given a network.
//!
//! A device here has keys and nothing else: no roster, so nobody it could
//! name, and no network id to announce under. An admin's invite is the whole
//! bootstrap: it names the network's relay and a secret, and the device
//! registers at that relay under the rendezvous key the secret derives.
//!
//! # Asynchronous, and it lasts until it ends
//!
//! Nobody has to be present when anybody else is. The device waits — at the
//! rendezvous, and under its own new transport key — for as long as its join
//! lasts, which is until it is admitted or a person cancels it. Every exchange
//! is opened by the other side:
//!
//! - the admin's daemon dials the rendezvous while the invite is open, takes
//!   the device's **request**, and says it was received. A person approves it
//!   there later, whenever they choose;
//! - once it is approved, the admin's daemon, or any full member the admission
//!   reached, dials the device and **delivers** the network.
//!
//! The join is kept on disk ([`crate::joins`]) and resumed after a restart.
//!
//! # What is accepted, and what that is worth
//!
//! While waiting, this accepts an exchange from a peer no roster names — there
//! is no roster with which to name anyone. It grants that peer nothing. What
//! arrives is verified: the network must be the one the invite names, admit
//! this device's own keys, and be signed by an admin. Anything else costs one
//! refused exchange, and the join goes on.

use std::sync::Arc;
use std::time::Duration;

use enrollment::exchange::{Message, Possession};
use enrollment::{adopt, limits};
use identity::NodeIdentity;
use tokio::sync::watch;
use transport_convesso::enrolment::{Channel, Waiting};

use crate::state::{Log, Paths};

/// Why a join did not happen.
///
/// A message rather than a variant, for the reason [`crate::relay::Refusal`] is:
/// each one is shown to a person, and the person needs the sentence.
pub type Refusal = String;

/// How long a join rests after an exchange, whatever came of it: so a peer
/// opening exchanges over and over costs the device little, and never ends the
/// join.
pub const PACE: Duration = Duration::from_secs(2);

/// What a join has reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// Registering at the relay. Nothing to show yet.
    Registering,
    /// Registered, waiting for the admin's daemon to take the request.
    Waiting,
    /// The admin's daemon has the request, and a person there decides.
    Requested {
        /// When it said so, in seconds since the epoch.
        at: u64,
    },
    /// The network was adopted.
    Joined {
        /// The suffix every name in it sits under.
        suffix: String,
        /// How many devices it has, this one included.
        devices: usize,
    },
    /// It ended without a network, and why.
    Failed(String),
}

/// What a running join shares with the service: where it has got to, what last
/// went wrong, and how to end it.
pub struct Underway {
    progress: Arc<std::sync::Mutex<Progress>>,
    refused: Arc<std::sync::Mutex<Option<String>>>,
    cancel: watch::Sender<bool>,
}

/// The join's half of [`Underway`].
#[derive(Clone)]
pub struct Reporting {
    progress: Arc<std::sync::Mutex<Progress>>,
    refused: Arc<std::sync::Mutex<Option<String>>>,
    cancelled: watch::Receiver<bool>,
}

impl Underway {
    /// A join's shared state, starting at `progress`, and the join's half of it.
    #[must_use]
    pub fn new(progress: Progress) -> (Self, Reporting) {
        let progress = Arc::new(std::sync::Mutex::new(progress));
        let refused = Arc::new(std::sync::Mutex::new(None));
        let (cancel, cancelled) = watch::channel(false);
        let reporting =
            Reporting { progress: Arc::clone(&progress), refused: Arc::clone(&refused), cancelled };
        (Self { progress, refused, cancel }, reporting)
    }

    /// Where the join has got to.
    #[must_use]
    pub fn progress(&self) -> Progress {
        self.progress.lock().map_or(Progress::Registering, |held| held.clone())
    }

    /// What the last exchange that did not work out said, if one has not.
    ///
    /// Not a failure: the join goes on after it. It is what a person waiting
    /// is shown when nothing seems to happen.
    #[must_use]
    pub fn last_refusal(&self) -> Option<String> {
        self.refused.lock().ok().and_then(|held| held.clone())
    }

    /// Ends the join: it stops waiting and closes what it opened.
    pub fn cancel(&self) {
        let _ = self.cancel.send(true);
    }
}

impl Reporting {
    /// Records where the join has got to.
    pub fn reached(&self, progress: Progress) {
        if let Ok(mut held) = self.progress.lock() {
            *held = progress;
        }
    }

    fn refused(&self, refusal: &str) {
        if let Ok(mut held) = self.refused.lock() {
            *held = Some(refusal.to_owned());
        }
    }

    fn registered(&self) {
        if let Ok(mut held) = self.progress.lock()
            && *held == Progress::Registering
        {
            *held = Progress::Waiting;
        }
    }

    /// Returns once the join is cancelled.
    async fn until_cancelled(&self) {
        let mut cancelled = self.cancelled.clone();
        let _ = cancelled.wait_for(|cancelled| *cancelled).await;
    }
}

/// What a completed join produced.
#[derive(Debug, Clone)]
pub struct Joined {
    /// The name of the network's suffix, for telling the person what to do next.
    pub suffix: String,
    /// How many devices the network has, this one included.
    pub devices: usize,
}

/// The fingerprint of a device's signing key, as both screens show it: twenty
/// hexadecimal characters of its SHA-256, in groups of four.
///
/// Derived from the key and from nothing a channel chose, so nobody can make
/// another key show the same without searching 2^80 of them.
#[must_use]
pub fn fingerprint(signing: &roster::sign::PublicKey) -> String {
    use sha2::{Digest as _, Sha256};

    let digest = Sha256::digest(signing.as_bytes());
    let hex: String = digest.iter().take(10).map(|byte| format!("{byte:02X}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|group| String::from_utf8_lossy(group).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// What the signing key signs for a join from `invite`: the invite answered,
/// and the other two keys this device brings.
///
/// # Errors
///
/// When the invite's secret derives no key.
pub fn request_material(
    invite: &enrollment::Invite,
    identity: &NodeIdentity,
) -> Result<Vec<u8>, Refusal> {
    let rendezvous = transport_convesso::enrolment::rendezvous_key(&invite.rendezvous_seed())
        .map_err(|cause| cause.to_string())?;
    Ok(enrollment::request_material(
        &invite.network,
        &rendezvous,
        &identity.transport_key().public_key(),
        &identity.attestation_key().public_key(),
    ))
}

/// Proves, here, that this device holds its signing key: once, when the join
/// begins, because the key may be one only a person can unlock.
///
/// # Errors
///
/// When the key will not sign — a person declined it.
pub fn prove_here(
    invite: &enrollment::Invite,
    identity: &NodeIdentity,
) -> Result<Possession, Refusal> {
    let material = request_material(invite, identity)?;
    Possession::prove_detached(identity, &material).map_err(|cause| match cause {
        enrollment::Error::NotProved(custody) => crate::control::declined(&custody),
        other => other.to_string(),
    })
}

/// The signature somebody else must make where the key is out of this
/// process's reach.
///
/// # Errors
///
/// When the invite's secret derives no key.
pub fn proof_request(
    invite: &enrollment::Invite,
    identity: &NodeIdentity,
) -> Result<identity::detached::SigningRequest, Refusal> {
    let material = request_material(invite, identity)?;
    Possession::request(&identity.signing_key().public_key(), &material)
        .map_err(|cause| cause.to_string())
}

/// The proof `signature` makes, once it is checked against this device's key.
///
/// A device that sent a proof it had not verified would be vouching for
/// whatever answered.
///
/// # Errors
///
/// When it does not verify.
pub fn proof_from(
    invite: &enrollment::Invite,
    identity: &NodeIdentity,
    signature: Vec<u8>,
) -> Result<Possession, Refusal> {
    let material = request_material(invite, identity)?;
    let proof = Possession::from_bytes(signature);
    proof.verify(&identity.signing_key().public_key(), &material).map_err(|_| {
        "what signed the proof does not hold this device's signing key. Nothing was sent."
            .to_owned()
    })?;
    Ok(proof)
}

/// Runs a join until it ends: admitted, or cancelled.
///
/// Registers at the invite's relay under the rendezvous key and under this
/// device's own transport key, and answers every exchange either brings, one at
/// a time. A refused exchange is recorded and the join goes on. `kept` is
/// called with the moment the admin's daemon said it has the request, so it is
/// kept across a restart.
///
/// # Errors
///
/// When the invite does not read, the relay cannot be used, a network already
/// stands here, or the join was cancelled.
pub async fn run(
    paths: &Paths,
    join: &crate::joins::Join,
    identity: &NodeIdentity,
    reporting: &Reporting,
    kept: impl Fn(u64) + Send + Sync,
) -> Result<Joined, Refusal> {
    let invite = enrollment::Invite::from_text(&join.invite).map_err(|cause| cause.to_string())?;
    if !Log::at(paths.roster()).read().map_err(|cause| cause.to_string())?.is_empty() {
        // A delivery that was written, and a stop before the network was taken
        // on: what is here is checked as a delivery is.
        return delivered_before(paths, &invite, identity);
    }
    let proof = roster::hex::decode(&join.proof)
        .map(Possession::from_bytes)
        .ok_or_else(|| "the join holds no proof of its signing key".to_owned())?;
    if let Some(at) = join.requested_at {
        reporting.reached(Progress::Requested { at });
    }

    let rendezvous = Waiting::at_rendezvous(&invite.rendezvous_seed(), &invite.relay)
        .await
        .map_err(|cause| cause.to_string())?;
    let own = match Waiting::under_own_key(identity, &invite.relay).await {
        Ok(own) => own,
        Err(cause) => {
            rendezvous.close().await;
            return Err(cause.to_string());
        }
    };

    let work = async {
        let online = async {
            tokio::join!(rendezvous.online(), own.online());
            reporting.registered();
        };
        let exchanges = async {
            loop {
                let accepted = tokio::select! {
                    accepted = rendezvous.accept() => accepted,
                    accepted = own.accept() => accepted,
                };
                let Ok(channel) = accepted else {
                    tokio::time::sleep(PACE).await;
                    continue;
                };
                match one_exchange(channel, identity, &proof, &invite, &join.name, &join.conflicts)
                    .await
                {
                    Ok(Exchanged::Received) => {
                        let at = crate::state::wall_seconds();
                        reporting.reached(Progress::Requested { at });
                        kept(at);
                    }
                    Ok(Exchanged::Delivered(delivered)) => return delivered,
                    Err(refusal) => reporting.refused(&refusal),
                }
                tokio::time::sleep(PACE).await;
            }
        };
        let ((), delivered) = tokio::join!(online, exchanges);
        delivered
    };
    let outcome = tokio::select! {
        delivered = work => Ok(delivered),
        () = reporting.until_cancelled() => Err("the join was cancelled; nothing was written".to_owned()),
    };
    rendezvous.close().await;
    own.close().await;
    let delivered = outcome?;
    keep_delivered(paths, delivered)
}

/// What an exchange came to.
enum Exchanged {
    /// The admin's daemon has the request.
    Received,
    /// The network, checked.
    Delivered(Box<Delivered>),
}

/// Writes a delivery that was checked: the base first, so a log that does not
/// reach the genesis is never left without the state beneath it.
fn keep_delivered(paths: &Paths, delivered: Box<Delivered>) -> Result<Joined, Refusal> {
    let Delivered { operations, pieces, snapshot, adopted, base } = *delivered;
    if let Some((root, state)) = &adopted.base {
        // The store is opened for the write and closed after it: the node that
        // carries the network opens it next.
        let store = crate::state::open_base_store(paths).map_err(|cause| cause.to_string())?;
        crate::state::write_base(paths, &store, root, state).map_err(|cause| cause.to_string())?;
        drop(store);
    }
    let log = Log::at(paths.roster());
    for operation in &operations {
        log.append(operation).map_err(|cause| cause.to_string())?;
    }
    // Beside the log, as the node keeps them: replayed after it at every start.
    let kept = Log::at(paths.pieces());
    for piece in &pieces {
        kept.append(piece).map_err(|cause| cause.to_string())?;
    }
    keep_delivered_snapshot(paths, base, &operations, &pieces, snapshot.as_deref());
    Ok(Joined { suffix: adopted.state.params.suffix.clone(), devices: adopted.state.devices.len() })
}

/// A join resumed over a log it had already written: believed only if that log
/// is the invited network and admits this device, as a delivery is.
fn delivered_before(
    paths: &Paths,
    invite: &enrollment::Invite,
    identity: &NodeIdentity,
) -> Result<Joined, Refusal> {
    let mut roster = roster::roster::Roster::new();
    for operation in Log::at(paths.roster()).read().map_err(|cause| cause.to_string())? {
        roster.offer_bytes(&operation);
    }
    let state = roster.state().map_err(|_| {
        "the network this join wrote does not read. Cancel the join and join again.".to_owned()
    })?;
    if state.network != invite.network || !state.devices.contains_key(&identity.device_id()) {
        return Err("what is written here is not the invited network admitting this device. \
                    Cancel the join and join again."
            .to_owned());
    }
    Ok(Joined { suffix: state.params.suffix.clone(), devices: state.devices.len() })
}

/// One exchange, from the channel opening to the request received or a network
/// believed.
async fn one_exchange(
    mut channel: Channel,
    identity: &NodeIdentity,
    proof: &Possession,
    invite: &enrollment::Invite,
    name: &str,
    conflicts: &[String],
) -> Result<Exchanged, Refusal> {
    let deadline = Duration::from_secs(limits::EXCHANGE_DEADLINE_SECS);
    let material = channel.material().map_err(|cause| cause.to_string())?;

    // The channel proves the peer holds its key. These prove the same about
    // this device's: the transport key over this channel, the signing key over
    // the request — made once, when the join began. Without them an
    // introduction could pair this device's identity with somebody else's
    // transport key.
    let transport_possession = Possession::prove(identity.transport_key().signer(), &material)
        .map_err(|cause| cause.to_string())?;
    let introduction = enrollment::exchange::Introduction {
        signing: identity.signing_key().public_key(),
        transport: identity.transport_key().public_key(),
        attestation: identity.attestation_key().public_key(),
        name: name.to_owned(),
        possession: proof.clone(),
        transport_possession,
        conflicts: conflicts.to_vec(),
    };
    send(&mut channel, &Message::Introduce(introduction), deadline).await?;

    // The request received, and nothing more; or the state the admitting
    // side's roster rests on, where it was compacted, and the pieces of its
    // batches, in as many parts as they take; then the admission.
    let mut assembling: Option<(Vec<u8>, roster::transfer::StateAssembler)> = None;
    let mut parts = 0_usize;
    let mut pieces: Vec<Vec<u8>> = Vec::new();
    let mut batch_parts = 0_usize;
    let (operations, snapshot) = loop {
        match receive(&mut channel, deadline).await? {
            Message::Received if parts == 0 && batch_parts == 0 => {
                return Ok(Exchanged::Received);
            }
            Message::Batch { pieces: part } => {
                batch_parts = batch_parts.saturating_add(1);
                if batch_parts > MOST_BATCH_PARTS {
                    return Err("the other machine sent more of its batches than any network has"
                        .to_owned());
                }
                pieces.extend(part);
            }
            Message::Base { root, pieces } => {
                parts = parts.saturating_add(1);
                if parts > MOST_BASE_PARTS {
                    return Err(
                        "the other machine sent more of a base than any network has".to_owned()
                    );
                }
                let assembler = match &mut assembling {
                    Some((held, assembler)) if *held == root => assembler,
                    Some(_) => {
                        return Err(
                            "the other machine sent parts of two different bases".to_owned()
                        );
                    }
                    None => {
                        let raw = roster::snapshot::RawSnapshot::decode(&root)
                            .map_err(|cause| cause.to_string())?;
                        let assembler = roster::transfer::StateAssembler::new(
                            raw.body().network,
                            raw.body().root,
                            roster_sync::limits::MAX_STATE_DEVICES,
                        );
                        &mut assembling.insert((root, assembler)).1
                    }
                };
                for piece in &pieces {
                    assembler.add(piece).map_err(|cause| cause.to_string())?;
                }
            }
            Message::Admission { operations, snapshot } => break (operations, snapshot),
            _ => return Err("the other machine said something out of turn".to_owned()),
        }
    };
    let base = match assembling {
        Some((root, assembler)) => {
            assembler.finish().map(|state| Some(adopt::Base { root, state })).map_err(|cause| {
                format!("the state the network was delivered resting on does not hold: {cause}")
            })
        }
        None => Ok(None),
    };

    // Delivery proves nothing. What arrived must admit this device's own keys,
    // and be signed by an admin — and a base it rests on must make its root.
    let adopted = base.clone().and_then(|base| {
        adopt::adopt_on(base, &operations, &pieces, identity).map_err(|cause| cause.to_string())
    });
    // Only the network the invite named. Somebody who learned the secret and
    // dialled first could deliver a roster of another network, with this device
    // in it: the device adopts nothing, and says so.
    let adopted = match adopted {
        Ok(adopted) if adopted.state.network != invite.network => {
            Err("the network delivered is not the one the invite names: whoever dialled is not a \
             member of the invited network. Nothing was written."
                .to_owned())
        }
        other => other,
    };
    let taken = adopted.is_ok();
    let _ = send(&mut channel, &Message::Outcome { taken }, deadline).await;
    // Held open until the other side has read it and gone, or a few seconds:
    // closed at once, the endpoints took the answer with them.
    let _gone = receive(&mut channel, ANSWER_LINGER).await;

    Ok(Exchanged::Delivered(Box::new(Delivered {
        operations,
        pieces,
        snapshot,
        adopted: adopted?,
        base: base?,
    })))
}

/// How long an exchange is held open after its last answer.
const ANSWER_LINGER: Duration = Duration::from_secs(5);

/// How many parts of a base a join takes at most: more than the largest state
/// a network may hold is cut into.
const MOST_BASE_PARTS: usize = 4096;

/// How many parts of the batches' pieces a join takes at most: room for every
/// batch the roster holds incomplete at once, whole, several times over.
const MOST_BATCH_PARTS: usize = 4096;

/// What an exchange delivered, once it has been checked.
pub struct Delivered {
    /// The operations, exactly as they arrived.
    pub operations: Vec<Vec<u8>>,
    /// The pieces of the batches among them, exactly as they arrived.
    pub pieces: Vec<Vec<u8>>,
    /// The network's snapshot, where the admitting side sent one.
    ///
    /// Unverified here: it is checked against the operations beside it, and a
    /// snapshot that does not check is dropped without costing the roster
    /// anything. The membership is what the operations prove; the snapshot only
    /// dates it.
    pub snapshot: Option<Vec<u8>>,
    /// The state the operations derive to.
    pub adopted: adopt::Adopted,
    /// The root and state the operations rest on, where the admitting side
    /// had compacted.
    pub base: Option<adopt::Base>,
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

/// Checks a delivered snapshot against the operations it came with, and keeps it.
///
/// **A snapshot that does not check costs the roster nothing.** The operations
/// prove the membership and have already been written; the snapshot only dates
/// it. Refusing the whole delivery over one would throw away a membership an
/// admin has just approved, in order to punish a field that is allowed to be
/// missing entirely.
///
/// What a device without one gets is a roster it cannot yet confirm — the same
/// state as one that has been out of touch too long. That is worth saying rather
/// than hiding, and the daemon says it as soon as the network is reported.
fn keep_delivered_snapshot(
    paths: &Paths,
    base: Option<adopt::Base>,
    operations: &[Vec<u8>],
    pieces: &[Vec<u8>],
    snapshot: Option<&[u8]>,
) {
    let Some(bytes) = snapshot else { return };

    // Checked by the roster's own rules — signed by a device these operations
    // name as an admin, over heads they contain — and never because of who sent
    // it. The same roster the operations derive to is what does the checking.
    let mut roster = roster::roster::Roster::with_clock(Box::new(crate::state::WallClock));
    if adopt::fill(&mut roster, base, operations, pieces).is_err() {
        return;
    }
    if !roster.offer_snapshot(bytes).is_accepted() {
        return;
    }
    let _kept = crate::state::write_snapshot(paths, bytes, crate::state::wall_seconds());
}

/// An invite as a code a camera can read.
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
        Err(cause) => format!("(the invite could not be drawn as a code: {cause})"),
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// The two forms carry one invite. A scannable code that said something
    /// else would be a second format wearing one name.
    #[test]
    fn the_scannable_form_carries_the_text_form() {
        let invite = enrollment::Invite::issue(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a@relay.example:443",
            roster::id::NetworkId::from_bytes([7; 32]),
            roster::types::Ipv4Range::DEFAULT,
        )
        .expect("issues");

        let text = invite.to_text();
        let drawn = scannable(&text);
        assert!(!drawn.contains("could not be drawn"), "{drawn}");
        assert!(drawn.lines().count() > 8, "a code has to be big enough to scan: {drawn}");
    }

    /// Twenty hexadecimal characters, in groups a person reads aloud, from the
    /// key and nothing else.
    #[test]
    fn a_fingerprint_is_twenty_characters_of_the_key() {
        let one = identity::NodeIdentity::generate().expect("generates");
        let other = identity::NodeIdentity::generate().expect("generates");
        let shown = fingerprint(&one.signing_key().public_key());
        assert_eq!(shown.len(), 24, "five groups of four, and four dashes: {shown}");
        assert_eq!(shown.chars().filter(char::is_ascii_hexdigit).count(), 20, "{shown}");
        assert_eq!(shown, fingerprint(&one.signing_key().public_key()), "the same key, the same");
        assert_ne!(shown, fingerprint(&other.signing_key().public_key()));
    }

    fn invite() -> enrollment::Invite {
        enrollment::Invite::issue(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a@relay.example:443",
            roster::id::NetworkId::from_bytes([7; 32]),
            roster::types::Ipv4Range::DEFAULT,
        )
        .expect("issues")
    }

    /// The proof made once, at the join, is the one an admin checks against
    /// the invite; one made by another key, or for another invite, is refused.
    #[test]
    fn the_signing_keys_proof_names_the_invite_and_the_other_keys() {
        let device = identity::NodeIdentity::generate().expect("generates");
        let answered = invite();
        let proof = prove_here(&answered, &device).expect("signs here");
        let material = request_material(&answered, &device).expect("derives");
        proof.verify(&device.signing_key().public_key(), &material).expect("verifies");
        assert!(
            proof
                .verify(
                    &device.signing_key().public_key(),
                    &request_material(&invite(), &device).expect("derives")
                )
                .is_err(),
            "not for another invite"
        );

        let request = proof_request(&answered, &device).expect("prepares");
        let elsewhere = identity::NodeIdentity::generate().expect("generates");
        let signed = elsewhere.signer().sign(request.message()).expect("signs");
        assert!(proof_from(&answered, &device, signed).is_err(), "another key proves nothing");
        let signed = device.signer().sign(request.message()).expect("signs");
        assert!(proof_from(&answered, &device, signed).is_ok());
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

        keep_delivered_snapshot(&paths, None, &operations, &[], Some(&snapshot));

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

        keep_delivered_snapshot(&paths, None, &operations, &[], Some(&snapshot));

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

        keep_delivered_snapshot(&paths, None, &operations, &[], None);

        assert!(crate::state::read_snapshot(&paths).is_none(), "there was none to keep");
    }
}

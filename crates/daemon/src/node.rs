//! The node, assembled.
//!
//! Seven crates, each deliberately missing the same thing. `roster-sync` has no
//! loop, `rendezvous` no publish policy, `local-discovery` no schedule,
//! `transport-iroh` no opinion about when to connect, `tunnel` no device. Every
//! one of them wrote "the daemon owns this". This is where they are joined.
//!
//! It is in the core, over [`transport::Transport`], so the whole assembly runs
//! against the in-process transport with no network, no adapter and no
//! privileges — the same trick that let `roster-sync` be finished before there
//! was a real transport to carry it.
//!
//! # A failure in one part is not a failure of the node
//!
//! The rendezvous is unreachable on a train. Multicast is filtered on most
//! corporate Wi-Fi. A peer hangs up mid-sync. None of these is a reason to stop
//! carrying packets on the sessions that are working, and a node that treated
//! them that way would be least available exactly when a person most wanted it.
//!
//! So each part reports its failures through [`Node::record`] and the rest carries
//! on. What is not acceptable is failing *silently*: a subsystem that has been
//! dead for a day while the daemon looked healthy is worse than one that stopped
//! the node, because nobody went looking.
//!
//! # There is no transport while the tunnel is down
//!
//! Section 2.6c: with the network off, the daemon sends nothing to the
//! rendezvous, the relay, or any other infrastructure. Not "sends little" — a
//! person with a packet capture must see nothing.
//!
//! A transport bound for the life of the process cannot honour that. Binding one
//! contacts the relay immediately, so a daemon that held one would be talking to
//! infrastructure while its owner believed the network was off — which is the
//! promise the whole product is sold on.
//!
//! So the transport is started when the tunnel comes up and dropped when it goes
//! down. With it absent there is nothing to send *through*, which is a stronger
//! guarantee than a flag somebody has to check.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::SystemTime;

use identity::NodeIdentity;
use roster::id::{DeviceId, OperationId};
use roster::state::RosterState;
use roster_sync::Syncer;
use tokio::sync::{Mutex, watch};
use transport::session::{Session, Transport};
use tunnel::Ipv4Holdings;

use crate::channel::{Channel, frame, unframe};
use crate::confirmations::{Confirmations, Confirmed};
use crate::contacts::{ContactRecord, LastContacts};
use crate::gateway::{Departure, Gateway};
use crate::router::Router;
use crate::schedule::Schedule;
use crate::state::Log;

/// Something that went wrong in one part of the node.
///
/// Every one is logged. The latest is also kept, so `status` can say a network
/// has a problem **now**; the history is the log's.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Fault {
    /// Which part.
    ///
    /// Owned rather than borrowed because a report crosses the control channel,
    /// and a borrowed name cannot be read back on the far side. `record` still
    /// takes a `&'static str`, so the set of subsystems stays closed.
    pub subsystem: String,
    /// What it said.
    pub cause: String,
    /// When it last happened, by the wall clock.
    ///
    /// For display and for [`PROBLEM_LASTS`] only. It decides nothing about who
    /// may do what, which is why a wall clock is acceptable here.
    pub at: std::time::SystemTime,
}

/// Whether something recorded is a problem, or only an event.
///
/// **Chosen where it is recorded**, by whoever knows what it means: the same
/// subsystem holds both, so nothing could decide it afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// About one peer or one packet, or an ordinary coming and going: a peer
    /// switching off, a session ending. Logged, and never shown as a problem.
    Event,
    /// This device cannot do its part, or something is wrong with its standing
    /// or with a peer's behaviour. Logged, and the network's current problem.
    Problem,
}

/// How long the latest fault stays a network's current problem.
///
/// Most failures have no matching success to clear them — a refused relay
/// connection is not followed by an event saying the relay is fine — so a
/// problem ages out instead. One that keeps happening is recorded again, which
/// renews it.
pub const PROBLEM_LASTS: std::time::Duration = std::time::Duration::from_secs(10 * 60);

impl Fault {
    /// Whether this is still the network's current problem at `now`.
    ///
    /// A clock that went backwards reads as current: showing a problem a little
    /// longer is the cheaper mistake.
    #[must_use]
    pub fn current(&self, now: std::time::SystemTime) -> bool {
        now.duration_since(self.at).map_or(true, |since| since < PROBLEM_LASTS)
    }
}

/// A device that has not confirmed holding everything authored here.
///
/// Named rather than counted. "Two operations are outstanding" tells a person
/// that something is wrong and nothing about what to do; "the laptop has not got
/// the revocation" tells them which machine is still admitting the device they
/// expelled. It also survives a dishonest member: one that claims to hold what
/// it discards removes its own row from this list and nobody else's.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Lagging {
    /// The device, as the roster names it.
    pub name: String,
    /// How many operations authored here it has not confirmed holding.
    pub operations: usize,
    /// Whether a session with it is open right now.
    ///
    /// The difference between "wait for it to appear" and "it is here and has
    /// not taken this", which are not the same situation and do not have the
    /// same remedy.
    pub connected: bool,
}

/// The assembled node.
pub struct Node {
    /// This device's keys.
    identity: Arc<NodeIdentity>,
    /// Roster reconciliation.
    syncer: Mutex<Syncer>,
    /// Whether this network's roster can be confirmed, and who the admins are.
    ///
    /// Cached, and read on the path that carries every packet. Taking the
    /// syncer's lock there would put every packet behind a reconciliation, and
    /// deriving the roster per packet would pay for an answer that changes at
    /// most once a reconciliation.
    ///
    /// Recomputed where the roster changes and on the daemon's recurring pass,
    /// so a roster that goes stale between two passes is acted on at the next
    /// one. The window is measured in days; the pass runs in seconds.
    carrying: watch::Sender<Arc<Option<Refusing>>>,
    /// The connectivity layer, while the tunnel is up.
    ///
    /// Absent while down, so §2.6c holds by construction: there is nothing to
    /// reach infrastructure *with*.
    transport: Mutex<Option<Arc<dyn Transport>>>,
    /// Woken when the transport is replaced while the tunnel is up.
    ///
    /// The loop accepting sessions is parked inside the old transport's
    /// `accept`, which returns only when something arrives there. Without this
    /// it would keep accepting on a transport nobody dials any more.
    replaced: tokio::sync::Notify,
    /// The packet path.
    gateway: Arc<Gateway>,
    /// Overlay address to session.
    router: Mutex<Router>,
    /// The IPv4 holdings the roster implies, as last enforced.
    ///
    /// Watched by whatever installs routes and answers names, so a device
    /// admitted or revoked while up changes them without a restart. Sent only
    /// from `enforce_roster`, and only when the holdings actually changed.
    holdings: watch::Sender<Arc<Ipv4Holdings>>,
    /// The peers withheld on this device, and why, as the service last decided.
    ///
    /// Decided outside the node, because it depends on this device's other
    /// networks and interfaces; kept here, because the resolver and the report
    /// already read the node. Empty while down: nothing is routed, so nothing is
    /// withheld from a route.
    withheld: std::sync::Mutex<Arc<BTreeMap<DeviceId, crate::conflicts::Conflict>>>,
    /// Live sessions, by the device they belong to.
    sessions: Mutex<BTreeMap<DeviceId, Arc<dyn Session>>>,
    /// Devices whose session has refused a packet because the far end does not
    /// accept packets, so it is recorded once per session rather than once per
    /// packet.
    refusing_packets: Mutex<BTreeSet<DeviceId>>,
    /// The latest problem, and where.
    fault: Mutex<Option<Fault>>,
    /// The latest event, kept only so that a repeat is not logged again.
    event: Mutex<Option<Fault>>,
    /// The network this node carries, as its directory is named, for the log.
    called: String,
    /// The operation log the roster is rebuilt from.
    log: Log,
    /// The intervals this node runs on.
    schedule: Schedule,
    /// Which devices have been observed to hold which operations.
    ///
    /// §2.6c: with the network down the daemon reaches no infrastructure, so an
    /// administrative act taken then has nowhere to go yet. What matters is not
    /// that it waits — the CRDT is built for that — but that nobody is told it
    /// arrived. A person who has revoked a device and been shown nothing thinks
    /// the revocation has taken effect.
    ///
    /// So the question is answered from evidence rather than from a queue: an
    /// operation authored here is outstanding toward every member whose own offer
    /// has never named it. There is no list to lose across a restart, and no
    /// event that empties it without a peer having said anything.
    confirmed: Mutex<Confirmed>,
    /// Where that record is kept between runs.
    confirmations: Confirmations,
    /// The last minute each device spoke on a session with this one.
    ///
    /// Written from two places — a session opening, and roster traffic arriving
    /// on one — and read only for the report. `contacts`' own test lists the
    /// functions here that must never read it.
    contacts: Mutex<LastContacts>,
    /// Where that is kept between runs.
    contact_record: ContactRecord,
}

impl Node {
    /// Assembles a node.
    #[must_use]
    pub fn new(
        identity: Arc<NodeIdentity>,
        syncer: Syncer,
        gateway: Arc<Gateway>,
        router: Router,
        log: Log,
        schedule: Schedule,
    ) -> Self {
        let confirmations = Confirmations::beside(log.path());

        // A record that cannot be read is treated as an empty one, which reports
        // every operation authored here as outstanding toward every member. The
        // two failure directions are not symmetrical: over-reporting costs a
        // person a look at a device that is already fine, and under-reporting
        // costs them a revocation they believe is in force and is not. The
        // failure is recorded rather than swallowed, so the over-reporting has a
        // stated reason next to it.
        let (confirmed, failure) = match confirmations.load() {
            Ok(confirmed) => (confirmed, None),
            Err(cause) => (Confirmed::default(), Some(cause.to_string())),
        };

        // Losing this one misleads nobody: every device reads as having no
        // contact recorded, which is what this device now knows.
        let contact_record = ContactRecord::beside(log.path());
        let (contacts, lost) = contact_record.load();

        // Every network's directory is named after its label, and the log sits
        // in it. Read off the path rather than passed in, so that naming a node
        // for the log is not another argument every caller has to get right.
        let called = log
            .path()
            .parent()
            .and_then(|directory| directory.file_name())
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned());

        // Each is logged; the last is kept as the latest.
        let mut latest = None;
        for cause in failure.into_iter().chain(lost.map(|cause| cause.to_string())) {
            tracing::warn!(
                network = %called,
                subsystem = "state",
                cause = %crate::logging::scrubbed(&cause),
                "fault"
            );
            latest = Some(Fault { subsystem: "state".to_owned(), cause, at: SystemTime::now() });
        }

        // The holdings the roster already implies, so the gateway and router
        // agree with it from the start rather than from the first change.
        let holdings = syncer
            .roster()
            .state()
            .map_or_else(|_| Ipv4Holdings::default(), |state| Ipv4Holdings::of_state(&state));
        let mut router = router;
        router.set_holdings(holdings.clone());
        gateway.set_holdings(holdings.clone());

        Self {
            identity,
            syncer: Mutex::new(syncer),
            carrying: watch::Sender::new(Arc::new(None)),
            transport: Mutex::new(None),
            replaced: tokio::sync::Notify::new(),
            gateway,
            router: Mutex::new(router),
            holdings: watch::Sender::new(Arc::new(holdings)),
            withheld: std::sync::Mutex::new(Arc::new(BTreeMap::new())),
            sessions: Mutex::new(BTreeMap::new()),
            refusing_packets: Mutex::new(BTreeSet::new()),
            fault: Mutex::new(latest),
            event: Mutex::new(None),
            called,
            log,
            schedule,
            confirmed: Mutex::new(confirmed),
            confirmations,
            contacts: Mutex::new(contacts),
            contact_record,
        }
    }

    /// The node this device's stored operations describe, if they describe a
    /// network at all.
    ///
    /// `Ok(None)` is the ordinary state of a device nobody has founded or joined
    /// yet: it has an identity and an empty log, and there is no prefix, no
    /// address and no suffix to build anything from. That is not a failure, and
    /// treating it as one is what used to stop the daemon from running at all —
    /// which in turn forced founding and joining into a separate process.
    ///
    /// Operations are replayed through the same validation the network path uses,
    /// so a tampered file is refused rather than trusted for having been on the
    /// local disk.
    ///
    /// # Errors
    ///
    /// When the log cannot be read, or when it describes a network whose
    /// parameters are unusable.
    /// `restored` is the snapshot this network last accepted and when, as
    /// [`crate::state::read_snapshot`] returns it, and `attested` is the same for
    /// its attestation. Both are checked here exactly as one off the wire would
    /// be; what they buy is the date, and for the attestation that date is the
    /// whole of freshness — without it, restarting would be the way out of a
    /// stale roster.
    pub fn from_log(
        identity: Arc<NodeIdentity>,
        log: crate::state::Log,
        restored: Option<(Vec<u8>, u64)>,
        attested: Option<(Vec<u8>, u64)>,
    ) -> crate::Result<Option<Arc<Self>>> {
        // On the wall clock, not the roster's default: freshness has to outlive
        // this process, and the default counts from the moment it started.
        let mut roster = roster::roster::Roster::with_clock(Box::new(crate::state::WallClock));
        let held = log.read()?;
        // Why the first operation this build refuses was refused. A log written
        // by a build whose rules were looser — before network suffixes and
        // prefixes were bounded, say — reads as a device that holds a network
        // and cannot use it. Saying so beats "no network here": the log is on
        // the disk, and a person who founded that network needs to know that it
        // is the parameters and not their identity that this build will not have.
        let mut refusal = None;
        for operation in &held {
            let admission = roster.offer_bytes(operation);
            if let (None, Some(reason)) = (&refusal, admission.refusal()) {
                refusal = Some(reason.to_string());
            }
        }

        // After the operations, because verifying a snapshot means deriving what
        // it covers from operations this node holds. Before anything is served,
        // because a node that answered a peer while undated would answer from a
        // roster it has not yet decided whether to trust.
        if let Some((bytes, received_at)) = restored {
            let _restored = roster.restore_snapshot(&bytes, received_at);
        }
        if let Some((bytes, received_at)) = attested {
            let _restored = roster.restore_attestation(&bytes, received_at);
        }

        let Ok(state) = roster.state() else {
            return match refusal {
                Some(cause) if !held.is_empty() => Err(crate::error::Error::Parameters { cause }),
                // An empty log is a device nobody has founded or joined yet, and
                // a log that derives nothing without a refusal is one still
                // waiting for the operations its own name.
                _ => Ok(None),
            };
        };

        let prefix = tunnel::Prefix::from_parameter(&state.params.ula)?;
        // Taken before the identity is handed over: the tunnel judges a packet's
        // destination against this device, and this is the one place that knows
        // which device that is.
        let own = identity.device_id();

        // No adapter and no transport are made here. Both are things a person has
        // to ask for, and both talk to something the moment they exist. `up`
        // makes them; `down` drops them.
        Ok(Some(Arc::new(Self::new(
            identity,
            Syncer::new(roster),
            Arc::new(crate::gateway::Gateway::new(tunnel::Tunnel::new(prefix, own))),
            crate::router::Router::new(prefix),
            log,
            crate::schedule::Schedule::provisional(),
        ))))
    }

    /// This device's own identity.
    #[must_use]
    pub fn identity(&self) -> &Arc<NodeIdentity> {
        &self.identity
    }

    /// The packet path.
    #[must_use]
    pub fn gateway(&self) -> &Arc<Gateway> {
        &self.gateway
    }

    /// The IPv4 holdings, as last enforced, and every later change to them.
    #[must_use]
    pub fn ipv4_holdings(&self) -> watch::Receiver<Arc<Ipv4Holdings>> {
        self.holdings.subscribe()
    }

    /// The IPv4 holdings, as last enforced.
    #[must_use]
    pub fn current_ipv4_holdings(&self) -> Arc<Ipv4Holdings> {
        Arc::clone(&self.holdings.borrow())
    }

    /// What a resolver answers `A` with, as things stand.
    #[must_use]
    pub fn ipv4_view(&self) -> crate::wire::Ipv4View {
        crate::wire::Ipv4View { holdings: self.current_ipv4_holdings(), withheld: self.withheld() }
    }

    /// The peers withheld on this device, and why.
    #[must_use]
    pub fn withheld(&self) -> Arc<BTreeMap<DeviceId, crate::conflicts::Conflict>> {
        self.withheld
            .lock()
            .map_or_else(|poisoned| Arc::clone(poisoned.get_ref()), |held| Arc::clone(&held))
    }

    /// Records which peers are withheld on this device.
    pub fn set_withheld(&self, withheld: BTreeMap<DeviceId, crate::conflicts::Conflict>) {
        let withheld = Arc::new(withheld);
        match self.withheld.lock() {
            Ok(mut held) => *held = withheld,
            Err(poisoned) => *poisoned.into_inner() = withheld,
        }
    }

    /// The connectivity layer, while the tunnel is up.
    ///
    /// `None` while it is down, and that is not a state to wait out: §2.6c means
    /// there is nothing to reach infrastructure with, so a loop that needs one
    /// ends rather than spinning until one appears.
    pub async fn transport(&self) -> Option<Arc<dyn Transport>> {
        self.transport.lock().await.clone()
    }

    /// Takes a started transport, which is what makes the node reachable.
    pub async fn started(&self, transport: Arc<dyn Transport>) {
        *self.transport.lock().await = Some(transport);
    }

    /// Puts a new transport in place of the running one, without the tunnel
    /// going down.
    ///
    /// For a relay that moved: the adapter, the routes and the names are left
    /// alone, and only the connectivity is rebuilt. The sessions on the old
    /// transport are closed — they are carried by it — and the loops that dial
    /// open new ones on this one. The loop accepting sessions is woken so it
    /// moves across rather than waiting on a transport nobody uses.
    ///
    /// A node that is down is not given one: §2.6c gives a down network no
    /// licence to reach a relay, moving or not.
    pub async fn replace_transport(&self, transport: Arc<dyn Transport>) {
        {
            let mut held = self.transport.lock().await;
            if held.is_none() {
                return;
            }
            *held = Some(transport);
        }
        self.close_sessions().await;
        // `notify_one`, not `notify_waiters`: if the loop is between two waits
        // the permit is kept for it, rather than lost while it parks on the old
        // transport.
        self.replaced.notify_one();
    }

    /// Closes every session, leaving the transport.
    async fn close_sessions(&self) {
        let sessions: Vec<Arc<dyn Session>> =
            self.sessions.lock().await.values().map(Arc::clone).collect();
        for session in sessions {
            let _closed = session.close().await;
        }
        self.sessions.lock().await.clear();
    }

    /// Drops the transport and every session on it.
    ///
    /// After this the node reaches no infrastructure, which is §2.6c's whole
    /// requirement — obtained by having nothing to reach it with.
    pub async fn stopped(&self) {
        self.transport.lock().await.take();
        self.close_sessions().await;

        // Nothing about propagation is touched here. Taking the tunnel down ends
        // sessions and drops the transport; it says nothing about whether an
        // operation reached anybody, and for a while this line cleared the queue
        // as though it did — so `peerfectly down` after signing a revocation reported
        // that nothing was waiting.
    }

    /// The roster's current heads, for an operation authored here.
    pub async fn heads(&self) -> Vec<roster::id::OperationId> {
        self.syncer.lock().await.roster().heads()
    }

    /// Where the roster stands now: its heads, and the snapshot it holds.
    ///
    /// Taken when a batch is prepared and compared when its signatures come
    /// back. A batch is built over the roster as it was; if another admin's
    /// operation or snapshot arrived while a person was deciding, what they
    /// authorised is no longer what it would do, and it is not applied.
    pub async fn moment(&self) -> crate::signing::Moment {
        let syncer = self.syncer.lock().await;
        let roster = syncer.roster();
        crate::signing::Moment {
            heads: roster.heads(),
            snapshot: roster.snapshot().map(|held| held.body().seq),
        }
    }

    /// What these operations would make of this roster, before any is signed.
    ///
    /// # Errors
    ///
    /// When they cannot be placed in the roster's graph.
    pub async fn preview(
        &self,
        cores: &[roster::types::OperationCore],
    ) -> roster::Result<roster::roster::Preview> {
        self.syncer.lock().await.roster().preview(cores)
    }

    /// Whether the node has a transport.
    pub async fn is_reachable(&self) -> bool {
        self.transport.lock().await.is_some()
    }

    /// The intervals this node runs on.
    #[must_use]
    pub const fn schedule(&self) -> Schedule {
        self.schedule
    }

    /// The latest problem, however long ago.
    pub async fn fault(&self) -> Option<Fault> {
        self.fault.lock().await.clone()
    }

    /// The network's current problem at `now`: the latest fault, if recent.
    pub async fn problem(&self, now: SystemTime) -> Option<Fault> {
        self.fault().await.filter(|fault| fault.current(now))
    }

    /// The latest event, however long ago. For tests and diagnostics: it is
    /// never in the report.
    pub async fn event(&self) -> Option<Fault> {
        self.event.lock().await.clone()
    }

    /// Records a failure without stopping anything.
    ///
    /// Logged either way; a problem is also kept as the latest, which is what the
    /// report shows. **A repeat of the latest of its kind is not logged again**:
    /// a dial that fails every minute, or a packet a second for a device that is
    /// off, would bury everything else in the log. A repeated problem renews
    /// when it happened, which keeps it the current problem.
    pub async fn record(&self, severity: Severity, subsystem: &'static str, cause: impl ToString) {
        let cause = cause.to_string();
        let at = SystemTime::now();
        let mut latest = match severity {
            Severity::Problem => self.fault.lock().await,
            Severity::Event => self.event.lock().await,
        };

        if let Some(same) =
            latest.as_mut().filter(|one| one.subsystem == subsystem && one.cause == cause)
        {
            same.at = at;
            return;
        }

        match severity {
            Severity::Problem => tracing::warn!(
                network = %self.called,
                subsystem,
                cause = %crate::logging::scrubbed(&cause),
                "fault"
            ),
            Severity::Event => tracing::info!(
                network = %self.called,
                subsystem,
                cause = %crate::logging::scrubbed(&cause),
                "event"
            ),
        }
        *latest = Some(Fault { subsystem: subsystem.to_owned(), cause, at });
    }

    /// Devices this node has evidence of having signed two histories.
    ///
    /// Read from the roster each time, never remembered: an accusation that
    /// outlived the evidence for it would be a claim to be believed, and the
    /// roster releases one once a revocation has settled the question.
    pub async fn equivocations(&self) -> Vec<roster::roster::Equivocation> {
        self.syncer.lock().await.roster().equivocations()
    }

    /// The roster's current derived state.
    ///
    /// # Errors
    ///
    /// When the roster cannot derive a state, which means the operations held do
    /// not describe a network.
    pub async fn state(&self) -> roster::Result<RosterState> {
        self.syncer.lock().await.roster().state()
    }

    /// Restores a snapshot this network accepted before, with the time it was
    /// accepted at.
    ///
    /// Checked again exactly as one off the wire is — a stored snapshot is bytes
    /// off a disk, and handing them back proves nothing. Only the moment it
    /// counts as having arrived differs, and that is the whole point: re-offering
    /// it would date it from now, and a device could then leave a stale roster by
    /// restarting.
    pub async fn restore_snapshot(&self, bytes: &[u8], received_at: u64) -> bool {
        self.syncer.lock().await.roster_mut().restore_snapshot(bytes, received_at).is_accepted()
    }

    /// Writes a snapshot beside the log, exactly as it arrived, dated now.
    ///
    /// **The bytes are the caller's, not the roster's.** Asking the roster for
    /// what it holds would hand back a structure it decoded and re-assembled, and
    /// `DESIGN.md` §0 forbids a store writing anything but what was signed — the
    /// same rule, and the same reason, as the operations written above.
    ///
    /// Dated now because this is called where a snapshot arrives. One restored
    /// from disk arrives through no caller and keeps the date it already has.
    pub(crate) async fn keep_snapshot(&self, bytes: &[u8]) {
        let Some(paths) = self.paths() else { return };
        if let Err(cause) =
            crate::state::write_snapshot(&paths, bytes, crate::state::wall_seconds())
        {
            self.record(Severity::Problem, "state", cause).await;
        }
    }

    /// Where this node's network is kept, taken from its log.
    fn paths(&self) -> Option<crate::state::Paths> {
        self.log.path().parent().map(crate::state::Paths::under)
    }

    /// Signs a fresh snapshot where this device administers the network and the
    /// one it holds is old enough to be worth replacing.
    ///
    /// Called where the daemon already does its recurring work, and on the way
    /// up. A snapshot is not an operation — it enters no log, is never a parent
    /// and takes no part in merge — so signing one on a timer raises none of the
    /// questions a daemon signing *operations* on a timer would.
    ///
    /// Silent when there is nothing to do, which is the ordinary case: a member's
    /// daemon reaches the first check and stops, without touching a key.
    pub(crate) async fn attest_unattended(&self) {
        // On a phone the signing key lives in the keystore, and every signature
        // asks for the lock. A daemon that reached for it on a timer would raise
        // a prompt out of nowhere, repeatedly, for something a person did not ask
        // for — a worse product than a roster that is a few days older than it
        // could be. So an admin whose key is held elsewhere attests only where a
        // person is already there: at founding, and after an admin act.
        if self.identity.signing_key().custodian().is_some() {
            return;
        }
        self.attest_now().await;
    }

    /// Dates this node's roster and tells every session, where it is an admin.
    ///
    /// The thing `attest_unattended` above cannot do. That one signs a snapshot,
    /// which needs the key a phone's keystore holds, so it gives up when a
    /// custodian has it — and a network whose only admin was a phone then stayed
    /// current only while somebody kept opening the app. An attestation is
    /// signed by a key that asks nobody, so there is no such case here.
    ///
    /// Called on the recurring pass and wherever this node's heads change.
    /// Silent when there is nothing to do, which is the ordinary case: a
    /// member's node reaches the first check and stops without touching a key.
    pub(crate) async fn keep_fresh(&self) {
        let now = crate::state::wall_seconds();
        let signed = {
            let syncer = self.syncer.lock().await;
            if !crate::attesting::due(syncer.roster(), &self.identity, now) {
                return;
            }
            crate::attesting::sign_over_heads(syncer.roster(), &self.identity)
        };
        self.spread_attestation(signed).await;
    }

    /// The same, without asking whether the period has passed.
    ///
    /// For a change of heads, which is an event rather than elapsed time. A
    /// revocation reaching an open session at once is the case this exists for:
    /// waiting out the period would leave every peer dating its roster from
    /// before the revocation it most needs to know about.
    /// Public so an integration test can drive it, as `attest_now` and the
    /// recurring pass drive it in the daemon.
    pub async fn attest_change(&self) {
        let signed = {
            let syncer = self.syncer.lock().await;
            if !crate::attesting::may_attest(syncer.roster(), &self.identity) {
                return;
            }
            crate::attesting::sign_over_heads(syncer.roster(), &self.identity)
        };
        self.spread_attestation(signed).await;
    }

    /// Accepts an attestation this node signed, keeps it, and sends it on.
    async fn spread_attestation(&self, signed: Result<Vec<u8>, String>) {
        let bytes = match signed {
            Ok(bytes) => bytes,
            // Recorded so that a network which never gets one has a reason a
            // person can read, and not treated as the network being broken: a
            // network whose attestations fail goes stale and says so.
            Err(cause) => {
                self.record(Severity::Event, "attestation", cause).await;
                return;
            }
        };
        if !self.syncer.lock().await.roster_mut().offer_attestation(&bytes).is_accepted() {
            self.record(
                Severity::Problem,
                "attestation",
                "this device signed one its own roster refused",
            )
            .await;
            return;
        }
        self.keep_attestation(&bytes).await;
        self.reconsider_carrying().await;

        // To every session, and to every session's own copy: an attestation says
        // what *this* node knew, so each admin sends its own rather than passing
        // on another's.
        let message = roster_sync::message::Message::Attestation(bytes);
        let peers: Vec<DeviceId> = self.sessions.lock().await.keys().copied().collect();
        for peer in peers {
            self.send_to(peer, Channel::Roster, &message.encode()).await;
        }
    }

    /// Keeps an attestation beside the log, with the moment it arrived.
    ///
    /// Without this, freshness would last as long as the process: an attestation
    /// is not an operation and is not in the log, so a node that replayed its log
    /// would hold none — and one that re-accepted its own on start would date it
    /// from the start, which would make restarting the way out of a stale roster.
    pub(crate) async fn keep_attestation(&self, bytes: &[u8]) {
        let Some(paths) = self.paths() else { return };
        if let Err(cause) =
            crate::state::write_attestation(&paths, bytes, crate::state::wall_seconds())
        {
            self.record(Severity::Problem, "state", cause).await;
        }
    }

    /// The snapshot a batch should end with, once `cores` are in — when one will
    /// be owed and this node cannot sign it itself.
    ///
    /// `None` when the snapshot held will still describe the roster closely
    /// enough, when the act leaves this device no admin, or when the key signs
    /// here — in which case [`Self::attest_now`] signs one as the act lands, and
    /// there is nothing to ask for.
    ///
    /// Built over a preview, so it is prepared **with** the operations rather
    /// than after them: the whole act is shown to a person, and signed, at once.
    pub async fn snapshot_after(
        &self,
        cores: &[roster::types::OperationCore],
    ) -> Option<identity::detached::SigningRequest> {
        if self.identity.signing_key().answers_here() {
            return None;
        }
        let syncer = self.syncer.lock().await;
        let body = crate::snapshots::after(
            syncer.roster(),
            cores,
            &self.identity,
            crate::state::wall_seconds(),
        )
        .ok()??;
        Some(identity::detached::prepare_snapshot(&body, &self.identity.signing_key().public_key()))
    }

    /// The same, where a person is present and has just signed something.
    ///
    /// The one path that may ask a custodian for a signature: founding, and the
    /// moments after an admission or a revocation, where the prompt arrives while
    /// a person is looking at the screen that caused it.
    pub(crate) async fn attest_now(&self) {
        let now = crate::state::wall_seconds();
        // A key this process cannot reach cannot sign here at all, and recording
        // that as a fault every time would put a fault line where a requirement
        // belongs. The asking happens where an answer has somewhere to come back
        // to; see `snapshot_after`.
        if !self.identity.signing_key().answers_here() {
            return;
        }
        let signed = {
            let syncer = self.syncer.lock().await;
            if !crate::snapshots::due(syncer.roster(), &self.identity, now) {
                return;
            }
            crate::snapshots::sign_over_heads(syncer.roster(), &self.identity)
        };
        let bytes = match signed {
            Ok(bytes) => bytes,
            // A person declining the lock is an ordinary outcome, and the next
            // pass asks again. Recorded so that a network that never gets one has
            // a reason a person can read.
            Err(cause) => {
                self.record(Severity::Event, "snapshot", cause).await;
                return;
            }
        };
        if !self.syncer.lock().await.roster_mut().offer_snapshot(&bytes).is_accepted() {
            self.record(
                Severity::Problem,
                "snapshot",
                "this device signed one its own roster refused",
            )
            .await;
            return;
        }
        self.keep_snapshot(&bytes).await;
        self.reconsider_carrying().await;
    }

    /// Works out what this device will carry, and keeps it for the packet path.
    ///
    /// Called where the roster changes and on the recurring pass. Cheap to read
    /// afterwards, which is the point: the answer is the same for every packet
    /// until one of those happens.
    pub(crate) async fn reconsider_carrying(&self) {
        let rule = {
            let mut syncer = self.syncer.lock().await;
            crate::snapshots::cautious(syncer.roster_mut()).and_then(|why| {
                syncer
                    .roster()
                    .state()
                    .ok()
                    .map(|state| Refusing { why, admins: crate::snapshots::admins_of(&state) })
            })
        };
        self.carrying.send_replace(Arc::new(rule));
    }

    /// Whether a packet to or from this peer is carried, and why not when it is
    /// not.
    ///
    /// **This is what bounds the revocation window.** A device that has not been
    /// able to confirm its roster for longer than the network allows stops
    /// carrying traffic for a membership it can no longer confirm, rather than
    /// carrying it for ever. A revoked device that no honest peer will talk to
    /// arrives at this on its own, which is the case no amount of delivery can
    /// fix.
    ///
    /// **Sessions are not refused, only traffic.** A device in this state has to
    /// be able to catch up, and what it needs may be carried by any member that
    /// has met an administrator more recently — not only by an administrator
    /// itself. Refusing the session would refuse the cure along with the disease.
    fn refuses_traffic_with(&self, peer: &DeviceId) -> Option<String> {
        let held = Arc::clone(&self.carrying.borrow());
        let refusing = held.as_ref().as_ref()?;
        if refusing.admins.contains(peer) {
            return None;
        }
        Some(format!(
            "{peer:?} is not an administrator of that network, and {}",
            refusing.why.because()
        ))
    }

    /// Why this device cannot confirm this network's roster, if it cannot.
    pub async fn cautious(&self) -> Option<crate::snapshots::Cautious> {
        crate::snapshots::cautious(self.syncer.lock().await.roster_mut())
    }

    /// How current this device believes this network's roster to be.
    /// Why this device cannot confirm this network's roster, as the report says
    /// it.
    pub async fn unconfirmed(&self) -> Option<crate::control::Unconfirmed> {
        self.cautious().await.map(|why| match why {
            crate::snapshots::Cautious::Stale => crate::control::Unconfirmed::Stale,
            crate::snapshots::Cautious::NeverAttested => crate::control::Unconfirmed::NeverAttested,
            crate::snapshots::Cautious::ClockMoved => crate::control::Unconfirmed::ClockMoved,
        })
    }

    /// How current this device believes this network's roster to be.
    pub async fn freshness(&self) -> roster::roster::Freshness {
        self.syncer.lock().await.roster_mut().freshness()
    }

    /// Registers an established session and greets the peer.
    ///
    /// The greeting is the offer `roster-sync` defines: reconciliation starts on
    /// contact rather than on a timer, because a node that has been away needs
    /// to catch up now and not in a minute.
    pub async fn opened(&self, session: Box<dyn Session>) -> Arc<dyn Session> {
        let session: Arc<dyn Session> = Arc::from(session);
        let peer = session.peer();

        self.router.lock().await.opened(peer);
        self.sessions.lock().await.insert(peer, Arc::clone(&session));
        self.note_contact(peer).await;
        self.date_for(peer).await;

        session
    }

    /// Sends this node's current attestation to a peer whose session has just
    /// opened, where this node is an admin and holds one.
    ///
    /// **Found on two real devices.** A device that has just joined holds no
    /// attestation: the admission delivers the roster and the snapshot, and the
    /// admin's own attestation was sent to its open sessions at a moment when
    /// the joiner had none. Without this the new member would wait out the whole
    /// period — up to twelve hours — reading as never attested, which is the
    /// state a device reaches after being out of touch far too long. A device
    /// that has just joined must not look like one.
    ///
    /// It is not only about joining. Any device that was off, or out of reach,
    /// gets one the moment it is reachable again, rather than at the admin's
    /// next period.
    ///
    /// Nothing is signed here: what is sent is the attestation this node already
    /// holds. Signing on every session opening would be a key use per
    /// reconnection, which is the shape of thing this design avoids.
    async fn date_for(&self, peer: DeviceId) {
        {
            let syncer = self.syncer.lock().await;
            if !crate::attesting::may_attest(syncer.roster(), &self.identity) {
                return;
            }
        }
        // The bytes as they were signed, off the disk, rather than a re-encoding
        // of the decoded form the roster holds. Re-encoding a decoded structure
        // is how two implementations come to disagree about what a signature
        // covers; the same rule the store already follows for operations.
        let Some(paths) = self.paths() else { return };
        let Some((bytes, _at)) = crate::state::read_attestation(&paths) else { return };
        let message = roster_sync::message::Message::Attestation(bytes);
        self.send_to(peer, Channel::Roster, &message.encode()).await;
    }

    /// Records that a device spoke on an authenticated session, now.
    ///
    /// Called only from [`Self::opened`] and from roster traffic arriving, and
    /// both are reached only through a session the transport established after
    /// checking the peer against the roster. An announcement does not come here,
    /// and neither does an enrolment exchange: the first is readable by every
    /// device ever revoked, and the second is with a device that is a member of
    /// nothing.
    ///
    /// Not called when a session ends. An ending is noticed some time after the
    /// peer stopped speaking, and recording it would put the last contact after
    /// the last word.
    async fn note_contact(&self, peer: DeviceId) {
        let changed = self.contacts.lock().await.touch(peer, crate::clock::minute_now());
        if changed {
            self.save_contacts().await;
        }
    }

    /// Writes the contact record, recording a failure rather than raising it.
    async fn save_contacts(&self) {
        let snapshot = self.contacts.lock().await.clone();
        if let Err(cause) = self.contact_record.save(&snapshot) {
            self.record(Severity::Problem, "state", cause).await;
        }
    }

    /// When this device last had a session with `device` that spoke.
    pub async fn last_contact(&self, device: &DeviceId) -> crate::control::Contact {
        crate::describing::contact(&*self.contacts.lock().await, device)
    }

    /// Sends the offer that starts reconciliation.
    ///
    /// **Deliberately not part of [`Self::opened`].** Registering a session and
    /// writing to it are different acts, and doing both before anything reads is
    /// a deadlock: two nodes that greet each other simultaneously each block on a
    /// send the other will not read until it has finished its own.
    ///
    /// That is exactly what happened. Every part was tested; the test drove them
    /// in an order no two real nodes would agree on.
    ///
    /// # Nothing is drained here
    ///
    /// This used to also push a queue of operations authored while no session was
    /// open, and empty it as it did — so a send that failed was recorded as a
    /// delivery. It is not needed: both sides greet on contact, so the peer's own
    /// offer arrives and is answered with everything that offer did not name,
    /// which includes whatever was authored while the tunnel was down.
    pub async fn greet(&self, peer: DeviceId) {
        let greeting = self.syncer.lock().await.greeting().encode();
        self.send_to(peer, Channel::Roster, &greeting).await;
    }

    /// Serves one session until it ends.
    ///
    /// **The loop that was missing.** `opened` registers a session and greets the
    /// peer; without something reading from it afterwards, a node accepts a
    /// connection and then ignores everything the far end says. Every method
    /// below it was tested — by a test that called them in order itself.
    pub async fn serve(self: Arc<Self>, session: Box<dyn Session>) {
        let session = self.opened(session).await;
        let peer = session.peer();

        // Greeting runs beside the reading, never before it. A node that writes
        // before it reads deadlocks against a peer doing the same, and both
        // sides greet on contact by design.
        let greeter = Arc::clone(&self);
        tokio::spawn(async move { greeter.greet(peer).await });

        // Packets are read beside payloads, never in the same `select!`: a payload
        // receive reads a length and then a body, and dropping it half-way would
        // lose the stream's framing. And a packet must not wait for a payload.
        let packets = {
            let node = Arc::clone(&self);
            let session = Arc::clone(&session);
            tokio::spawn(async move {
                while let Ok(packet) = session.recv_packet().await {
                    node.received_packet(peer, &packet).await;
                }
            })
        };

        loop {
            match session.recv().await {
                Ok(payload) => self.received(peer, &payload).await,
                Err(cause) => {
                    // A session ending is ordinary — a peer switching off, a
                    // network changing. Recorded rather than ignored, because a
                    // node that quietly stops hearing from everyone looks
                    // healthy.
                    self.record(Severity::Event, "session", format!("{peer:?}: {cause}")).await;
                    self.closed(&peer).await;
                    packets.abort();
                    return;
                }
            }
        }
    }

    /// Accepts sessions for as long as the transport lasts, serving each.
    pub async fn accept_forever(self: Arc<Self>) {
        loop {
            let transport = self.transport.lock().await.clone();
            let Some(transport) = transport else { return };

            let accepted = tokio::select! {
                accepted = transport.accept() => accepted,
                // Replaced under us: start again on the one now in place. Not a
                // fault — the old transport is being retired on purpose.
                () = self.replaced.notified() => continue,
            };
            match accepted {
                Ok(session) => {
                    tokio::spawn(Arc::clone(&self).serve(session));
                }
                Err(cause) => {
                    self.record(Severity::Problem, "transport", cause).await;
                    return;
                }
            }
        }
    }

    /// Carries packets from the machine for as long as the tunnel lasts.
    pub async fn carry_forever(self: Arc<Self>) {
        loop {
            match self.carry_one().await {
                Ok(_) => {}
                // No device means the tunnel went down: stop, rather than spin.
                Err(crate::Error::NotUp) => return,
                Err(cause) => {
                    self.record(Severity::Problem, "tunnel", cause).await;
                    return;
                }
            }
        }
    }

    /// Opens a session with every roster peer this node has none with.
    ///
    /// Dialling by transport key alone: the relay is a signed network parameter,
    /// so every device already knows where every other device's relay is, and no
    /// directory has to be asked where a peer is.
    pub async fn dial_missing(self: &Arc<Self>) {
        self.dial(&|_| true).await;
    }

    /// Opens a session with every roster peer matching `wanted` that has none.
    async fn dial(self: &Arc<Self>, wanted: &(dyn Fn(&DeviceId) -> bool + Sync)) {
        let Ok(state) = self.state().await else { return };
        let me = self.identity.device_id();

        for record in state.devices.values() {
            if record.id == me || !wanted(&record.id) || self.has_session(&record.id).await {
                continue;
            }

            let Some(key) = transport_key_of(record) else {
                self.record(
                    Severity::Event,
                    "roster",
                    format!("{:?} declares no transport key", record.id),
                )
                .await;
                continue;
            };
            if let Err(cause) = self.connect(&key).await {
                // Unreachable right now is the ordinary state of a device that is
                // switched off. Recorded, and tried again on the next tick.
                self.record(Severity::Event, "transport", format!("{}: {cause}", record.name))
                    .await;
            }
        }
    }
}

/// What a device refuses to carry while it cannot confirm its roster.
///
/// Both halves are needed on the packet path and neither is cheap to work out
/// there, so they are worked out together and kept.
#[derive(Debug, Clone)]
struct Refusing {
    /// Why the roster cannot be confirmed.
    why: crate::snapshots::Cautious,
    /// The devices the roster names as administrators.
    ///
    /// The exception that keeps this from being absorbing: an administrator is
    /// what signs the attestation that ends the condition, so traffic to one
    /// keeps flowing.
    admins: std::collections::BTreeSet<DeviceId>,
}

/// A device's transport key, as the roster declares it.
/// The operations `me` signed, as the roster holds them.
///
/// Propagation is only this device's business for what this device authored. An
/// operation somebody else signed and this node merely relayed is their concern to
/// be told about, and counting it here would report a person's own network back
/// at them as a backlog.
fn authored_by<'a>(
    roster: &'a roster::roster::Roster,
    state: &RosterState,
    me: &DeviceId,
) -> Vec<&'a roster::sign::VerifiedOperation> {
    roster
        .dag()
        .operations()
        .iter()
        .filter(|operation| {
            state.device_for_key(&operation.core().author).is_some_and(|record| record.id == *me)
        })
        .collect()
}

fn transport_key_of(record: &roster::types::DeviceRecord) -> Option<roster::sign::PublicKey> {
    let entry =
        record.keys.iter().find(|entry| entry.purpose == roster::types::KeyPurpose::Transport)?;
    roster::sign::PublicKey::new(entry.alg, entry.value.clone()).ok()
}

impl Node {
    /// Makes the roster's current truth real: hands the new state to the layers
    /// that decide from it, and closes sessions with devices it no longer names.
    ///
    /// Run after every change to the roster, so a revocation takes effect on the
    /// sessions that already exist rather than only on the next one. Without
    /// this, revoking a device would leave it connected — the transport checks
    /// membership when a session is *established*, and a session established
    /// before the revocation was never checked against it.
    ///
    /// **This is the one place that speaks.** Every path that changes the roster
    /// this node owns ends here — an operation signed on this device, and
    /// operations arriving from a peer — and there are no others: the `Syncer` is
    /// private to this module and nothing outside it holds one. Adoption happens
    /// before there is a node at all, and reaches this through the log the daemon
    /// loads at startup. Telling each of those sites to notify the layers below
    /// would mean a fourth site added later reintroduces exactly the bug this
    /// closes, in exactly the way it appeared: silently, with every piece looking
    /// correct on its own.
    ///
    /// The roster is read fresh each time; nothing here caches who is a member.
    pub async fn enforce_roster(&self) {
        let Ok(state) = self.state().await else {
            // Operations that do not describe a network cannot say who is out of
            // it either. Leaving sessions alone is the conservative reading.
            return;
        };

        // The transport decides membership from state it is given, and this node
        // is what gives it. Before this existed, the transport kept authorising
        // against whatever it held when the tunnel came up: a device admitted
        // since read as a non-member **in both directions**, and a device revoked
        // since kept its session. Both were observed between two real machines,
        // minutes after a person had enrolled one into the other's network.
        //
        // It goes first, so the connection is gone before the session map that
        // names it is tidied below.
        let transport = self.transport.lock().await.clone();
        if let Some(transport) = transport {
            transport.update_state(state.clone()).await;
        }

        // Addresses follow membership in the same place. A device admitted
        // since the tunnel came up becomes routable at its IPv4 address now, and
        // a device revoked stops being so, rather than at the next restart.
        let holdings = Ipv4Holdings::of_state(&state);
        self.gateway.set_holdings(holdings.clone());
        self.router.lock().await.set_holdings(holdings.clone());
        self.holdings.send_if_modified(|current| {
            if **current == holdings {
                false
            } else {
                *current = Arc::new(holdings);
                true
            }
        });

        self.forget_departed(&state).await;
        self.reconsider_carrying().await;

        // If *this* device has been removed, every session goes — not only the
        // ones with departed peers, because there are none: the peers are all
        // still members and this node is not.
        //
        // This is not a security control. The other side enforces the revocation
        // whatever this node does, and a compromised one would not cooperate. It
        // is correctness for an honest node: continuing to reconcile a roster it
        // has been removed from, and to hold sessions into a network it has left,
        // is a node acting on an authority it no longer has.
        let removed = !state.devices.contains_key(&self.identity.device_id());

        let gone: Vec<DeviceId> = self
            .sessions
            .lock()
            .await
            .keys()
            .filter(|peer| removed || !state.devices.contains_key(peer))
            .copied()
            .collect();

        for peer in gone {
            let session = self.sessions.lock().await.get(&peer).map(Arc::clone);
            if let Some(session) = session {
                let _closed = session.close().await;
            }
            self.closed(&peer).await;
            // This device leaving the roster is its standing, and a problem; a
            // peer leaving it is that peer's, and an event.
            let (severity, why) = if removed {
                (
                    Severity::Problem,
                    format!("this device is no longer in the roster; session with {peer:?} closed"),
                )
            } else {
                (Severity::Event, format!("{peer:?} is no longer in the roster; session closed"))
            };
            self.record(severity, "roster", why).await;
        }
    }

    /// Drops what is kept about devices that are no longer there to keep it for.
    ///
    /// Confirmations for devices that have left. Not a tidy-up for its own sake:
    /// an operation cannot be outstanding toward somebody who is no longer a
    /// member, so keeping their pairs would grow the record against devices that
    /// no longer exist and report against them too.
    ///
    /// Last contact is kept for revoked devices as well as members. When a stolen
    /// laptop last spoke to this device is exactly what a person wants to know,
    /// and it cannot change once the device is revoked: its session is closed
    /// here and refused afterwards.
    async fn forget_departed(&self, state: &RosterState) {
        let members: BTreeSet<DeviceId> = state.devices.keys().copied().collect();
        if self.confirmed.lock().await.retain_members(&members) {
            self.persist_confirmations().await;
        }

        let kept: BTreeSet<DeviceId> = members.union(&state.revoked).copied().collect();
        let changed = self.contacts.lock().await.retain(&kept);
        if changed {
            self.save_contacts().await;
        }
    }

    /// Forgets a session that has ended.
    pub async fn closed(&self, peer: &DeviceId) {
        self.router.lock().await.closed(peer);
        self.sessions.lock().await.remove(peer);
        self.refusing_packets.lock().await.remove(peer);
    }

    /// How many sessions are live.
    pub async fn session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// Whether there is a session with a device right now.
    ///
    /// A live fact, not a remembered one. With the tunnel down there are no
    /// sessions and this is false for everyone, which is the truth.
    pub async fn has_session(&self, peer: &DeviceId) -> bool {
        self.sessions.lock().await.contains_key(peer)
    }

    /// Whether the session with `peer` is direct or through the relay, as the
    /// transport says now.
    ///
    /// `None` with no session, no transport, or a transport that cannot tell.
    pub async fn path_to(&self, peer: &DeviceId) -> Option<transport::Path> {
        if !self.has_session(peer).await {
            return None;
        }
        let transport = self.transport.lock().await.clone()?;
        transport.path_to(peer).await
    }

    /// Handles one payload from a peer.
    ///
    /// The dispatch point for both protocols. A payload whose channel this build
    /// does not know is recorded and dropped, never guessed at.
    pub async fn received(&self, peer: DeviceId, payload: &[u8]) {
        let Some((channel, body)) = unframe(payload) else {
            self.record(
                Severity::Event,
                "session",
                format!("a payload from {peer:?} named no known channel"),
            )
            .await;
            return;
        };

        match channel {
            Channel::Roster => self.received_roster(peer, body).await,
        }
    }

    /// Roster bytes from a peer.
    async fn received_roster(&self, peer: DeviceId, body: &[u8]) {
        // The peer spoke. Roster traffic and not packets: the re-offer arrives
        // every minute from both sides, which is the granularity kept, and a lock
        // taken per packet would be paid on the path that carries everything.
        self.note_contact(peer).await;

        let reception = self.syncer.lock().await.receive(peer, body);

        // Persist exactly what was admitted, as it arrived. Deriving the bytes
        // back from the roster would re-serialize a decoded structure, which
        // `DESIGN.md` §0 forbids for the reason that it is how two implementations
        // quietly disagree about what was signed.
        //
        // This loop used to walk `replies` — what this node is about to *send* to
        // the peer, which is by definition what it already holds. So nothing
        // learned from a peer was ever written down: a device applied a
        // revocation, closed the session it revoked, and forgot it at the next
        // restart. And this node's own operations were appended again on every
        // reconciliation, without bound.
        for operation in &reception.accepted {
            if let Err(cause) = self.log.append(operation) {
                self.record(Severity::Problem, "state", cause).await;
            }
        }

        // A snapshot is not an operation, so the loop above never sees one: it is
        // not in `accepted` and it does not go in the log. Kept beside the log
        // instead, with the moment it arrived, because that moment is what
        // freshness is measured from and it does not survive this process
        // otherwise.
        if let Some(snapshot) = &reception.snapshot {
            self.keep_snapshot(snapshot).await;
        }

        // Neither is an attestation an operation. This is the one that decides
        // freshness, so a fresher one is exactly what ends a cautious state, and
        // it is reconsidered the moment one arrives rather than at the next pass.
        if let Some(attestation) = &reception.attestation {
            self.keep_attestation(attestation).await;
            self.reconsider_carrying().await;
        }

        for refusal in &reception.refusals {
            self.record(
                Severity::Event,
                "roster-sync",
                format!("{:?}: {}", refusal.operation, refusal.reason),
            )
            .await;
        }

        // The peer said, in its own offer, what it holds. That statement is the
        // only thing that makes an operation authored here stop being outstanding
        // toward it.
        if let Some(held) = reception.held {
            self.record_confirmations(held).await;
        }

        for message in reception.replies {
            self.send_to(peer, Channel::Roster, &message.encode()).await;
        }
        if let Some(forward) = reception.forward {
            self.send_to_others(peer, Channel::Roster, &forward.encode()).await;
        }

        // A revocation that arrived from a peer takes effect here, on the
        // sessions already open, and not at some later reconnection.
        self.enforce_roster().await;
    }

    /// A packet from a peer, as the session's packet channel delivered it.
    pub async fn received_packet(&self, peer: DeviceId, body: &[u8]) {
        if let Some(refusal) = self.refuses_traffic_with(&peer) {
            self.record(Severity::Event, "tunnel", refusal).await;
            return;
        }
        match self.gateway.inbound(peer, body).await {
            Ok(verdict) => {
                if !verdict.is_accepted() {
                    // Reported, always. A rule that fires silently is a rule
                    // nobody can trust, and a member spoofing addresses is the
                    // thing an operator most needs to be able to find.
                    //
                    // No exemption here, deliberately — unlike `carry_one`,
                    // which excuses this machine's own link-local and multicast
                    // chatter on the way out. That chatter is constant and
                    // unavoidable; an inbound packet addressed somewhere else
                    // had to pass the sender's own outbound rule to arrive, so
                    // it is not the same kind of event. It is a peer running
                    // something other than this product, or an attack.
                    self.record(Severity::Problem, "tunnel", verdict.to_string()).await;
                }
            }
            Err(cause) => self.record(Severity::Problem, "tunnel", cause).await,
        }
    }

    /// Takes one packet from the machine and sends it where it belongs.
    ///
    /// # Errors
    ///
    /// When the device cannot be read.
    pub async fn carry_one(&self) -> crate::Result<Departure> {
        // The packet first, holding nothing. Waiting for the machine to send
        // something takes as long as it takes, and a lock held across that wait
        // is held for the same time — which deadlocked every new session against
        // an idle read.
        let packet = self.gateway.take().await?;

        let departure = {
            let router = self.router.lock().await;
            self.gateway.route(&packet, &router)
        };

        match &departure {
            Departure::To { device, packet } => {
                self.send_packet_to(*device, packet).await;
            }
            // A machine sends link-local, multicast and IPv4 chatter on every
            // adapter it has. The tunnel refusing it is §2.6 working, not a
            // fault, and recording each one buries the failures that matter.
            Departure::Refused(tunnel::Outbound::DestinationOffNetwork { .. })
            | Departure::Refused(tunnel::Outbound::UnknownVersion { .. }) => {}
            Departure::Refused(refusal) => self.record(Severity::Event, "tunnel", refusal).await,
            Departure::Unreachable { destination } => {
                self.record(Severity::Event, "tunnel", format!("no session for {destination}"))
                    .await;
            }
            Departure::TooLarge { len, limit } => {
                self.record(
                    Severity::Event,
                    "tunnel",
                    format!("{len} bytes is past the link's {limit}"),
                )
                .await;
            }
        }
        Ok(departure)
    }

    /// Admits an operation authored here, and spreads it.
    ///
    /// # Errors
    ///
    /// When the roster refuses it.
    pub async fn admit_without_activating(&self, bytes: &[u8]) -> crate::Result<()> {
        // Written before it is spread. An operation a peer has and this node
        // forgets at the next restart is worse than one that was refused: it
        // takes effect, disappears, and nobody is told.
        self.log.append(bytes)?;

        let forward = self
            .syncer
            .lock()
            .await
            .admit_local(bytes)
            .map_err(|cause| crate::Error::Refused { cause: cause.to_string() })?;

        if let Some(message) = forward {
            // Sent to whoever is here, and nothing is recorded for it. A write to
            // a session the far end never reads looks, from this side, exactly
            // like one it did; what settles it is that peer's own offer naming
            // the operation, which the recurring reconciliation will fetch.
            let peers: Vec<DeviceId> = self.sessions.lock().await.keys().copied().collect();
            let encoded = message.encode();
            for peer in peers {
                self.send_to(peer, Channel::Roster, &encoded).await;
            }
        }

        // Including a revocation authored here: it must stop the session it
        // revokes, not merely be sent to it.
        self.enforce_roster().await;

        // The heads moved, so this node's word about what it knows is out of
        // date the moment it finishes saying it. A revocation is the case this
        // exists for: waiting out the period would leave every peer dating its
        // roster from before the one thing it most needs to know.
        self.attest_change().await;
        Ok(())
    }

    /// Which members have not confirmed holding what was authored here.
    ///
    /// The thing a person most needs to see and is least likely to ask for. It is
    /// derived rather than stored: the log says what this device authored, the
    /// roster says who the members are, and the confirmation record says which of
    /// them has said, in its own offer, that it holds each one. Nothing here can
    /// be emptied by an event that is not a peer speaking.
    pub async fn outstanding(&self) -> Vec<Lagging> {
        self.lagging().await.into_iter().map(|(_, device)| device).collect()
    }

    /// How much is owed to members this node holds no session with.
    ///
    /// The work pressing exists to finish, as a single number, because that is
    /// what [`crate::schedule::Pressing`] paces against. Members already
    /// connected are excluded: a session is open, the recurring reconciliation
    /// will carry it, and dialling would achieve nothing.
    pub async fn owed(&self) -> usize {
        self.lagging()
            .await
            .iter()
            .filter(|(_, device)| !device.connected)
            .fold(0usize, |total, (_, device)| total.saturating_add(device.operations))
    }

    /// Members with no open session that are owed something signed here.
    pub async fn pressed(&self) -> Vec<DeviceId> {
        self.lagging()
            .await
            .into_iter()
            .filter_map(|(id, device)| (!device.connected).then_some(id))
            .collect()
    }

    /// Opens a session with each of the given devices, if one is not open.
    ///
    /// Scoped deliberately: a member that has confirmed everything this device
    /// signed is not contacted for it, so the cost of pressing is bounded by
    /// what is actually being waited for rather than by the size of the network.
    pub async fn press(self: &Arc<Self>) {
        let wanted: BTreeSet<DeviceId> = self.pressed().await.into_iter().collect();
        if wanted.is_empty() {
            return;
        }
        self.dial(&|device| wanted.contains(device)).await;
    }

    /// Every member, with what it has not confirmed and whether it is connected.
    async fn lagging(&self) -> Vec<(DeviceId, Lagging)> {
        let me = self.identity.device_id();

        // Confirmations and sessions first, then the roster, held while counting.
        // Nothing anywhere holds the roster while waiting for either of these, so
        // taking them in this order cannot deadlock — and the roster's operations
        // are read where they are rather than copied, on a tick that runs every
        // few seconds while anything is owed.
        let confirmed = self.confirmed.lock().await;
        let connected: BTreeSet<DeviceId> = self.sessions.lock().await.keys().copied().collect();
        let syncer = self.syncer.lock().await;
        let roster = syncer.roster();
        let Ok(state) = roster.state() else { return Vec::new() };
        let mine: Vec<&roster::sign::VerifiedOperation> = authored_by(roster, &state, &me);
        if mine.is_empty() {
            return Vec::new();
        }

        let mut lagging = Vec::new();
        for record in state.devices.values() {
            if record.id == me {
                continue;
            }
            // The same rule the report uses, so pressing and the report cannot
            // disagree about who an operation is owed to.
            let missing = mine
                .iter()
                .filter(|operation| crate::describing::owed_to(operation, &record.id))
                .filter(|operation| !confirmed.holds(&record.id, &operation.id()))
                .count();
            if missing > 0 {
                lagging.push((
                    record.id,
                    Lagging {
                        name: record.name.clone(),
                        operations: missing,
                        connected: connected.contains(&record.id),
                    },
                ));
            }
        }
        lagging
    }

    /// Everything the report says about membership, gathered in one pass.
    ///
    /// Built while the roster is borrowed, not from a copy of it. On a desktop a
    /// person asks for the report by hand; on a phone the interface refreshes it
    /// while it is visible, and a copy of every operation per refresh is the
    /// roster's size allocated every two seconds.
    ///
    /// The small things are read first and the roster held last, and nothing
    /// awaits while it is held.
    pub(crate) async fn membership(&self, state: &RosterState) -> crate::describing::Membership {
        let me = self.identity.device_id();
        let confirmed = self.confirmed.lock().await;
        let connected: BTreeSet<DeviceId> = self.sessions.lock().await.keys().copied().collect();
        let contacts = self.contacts.lock().await.clone();

        let syncer = self.syncer.lock().await;
        let roster = syncer.roster();
        let dag = roster.dag();

        // What the roster counts, not everything that verified. The graph keeps
        // operations its rules disregarded, and a name or a reason from one of
        // those is a claim the roster itself refused.
        let valid: Vec<&roster::sign::VerifiedOperation> = roster::state::derive_with_verdicts(dag)
            .map_or_else(
                |_| Vec::new(),
                |(_, verdicts)| {
                    dag.operations()
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| verdicts.is_valid(*index))
                        .map(|(_, operation)| operation)
                        .collect()
                },
            );
        let directory = crate::describing::Directory::of(state, &valid);
        let accused = crate::describing::accused(&directory, roster);
        let revoked = crate::describing::revoked(&directory, state, &valid, &contacts);
        let authored = authored_by(roster, state, &me);
        let (waiting, waiting_unlisted) = crate::describing::waiting(
            &directory, state, &authored, &me, &confirmed, &connected, &contacts,
        );
        drop(syncer);

        crate::describing::Membership {
            directory,
            revoked,
            accused,
            waiting,
            waiting_unlisted,
            contacts,
        }
    }

    /// Records what a peer's own offer said it holds.
    ///
    /// Monotone by construction — see `confirmations` — and written through to
    /// disk only when something was new, so an idle pair of nodes re-offering
    /// every minute does not rewrite the file every minute.
    async fn record_confirmations(&self, held: roster_sync::Held) {
        let ids = self.confirmable(&held).await;
        if ids.is_empty() {
            return;
        }

        let changed = self.confirmed.lock().await.confirm(held.peer, ids);
        if changed {
            self.persist_confirmations().await;
        }
    }

    /// The subset of a peer's claim that may be believed.
    ///
    /// A device may not confirm the operation that revokes it. It is the one
    /// party with a motive to claim a revocation is delivered, and the report
    /// this feeds is what a person reads before deciding a stolen laptop is dealt
    /// with. Its session is in fact closed by `enforce_roster` before it could
    /// offer anything — but that is the order of two blocks in one function, and
    /// this should not rest on it.
    async fn confirmable(&self, held: &roster_sync::Held) -> Vec<OperationId> {
        let syncer = self.syncer.lock().await;
        held.ids
            .iter()
            .filter(|id| {
                !syncer.roster().dag().operations().iter().any(|operation| {
                    operation.id() == **id
                        && matches!(
                            operation.body(),
                            roster::types::OperationBody::RevokeDevice { device, .. }
                                if *device == held.peer
                        )
                })
            })
            .copied()
            .collect()
    }

    /// Writes the confirmation record, recording a failure rather than raising it.
    async fn persist_confirmations(&self) {
        let confirmed = self.confirmed.lock().await.clone();
        if let Err(cause) = self.confirmations.save(&confirmed) {
            self.record(Severity::Problem, "state", cause).await;
        }
    }

    /// Offers this node's heads to every peer.
    ///
    /// The tick behind reconciliation-on-contact: two nodes that stay connected
    /// for hours still notice a revocation made elsewhere.
    pub async fn offer_to_everyone(&self) {
        let offer = self.syncer.lock().await.greeting().encode();
        let peers: Vec<DeviceId> = self.sessions.lock().await.keys().copied().collect();
        for peer in peers {
            self.send_to(peer, Channel::Roster, &offer).await;
        }
    }

    /// Sends to one peer, recording rather than propagating a failure.
    async fn send_to(&self, peer: DeviceId, channel: Channel, payload: &[u8]) {
        let session = self.sessions.lock().await.get(&peer).map(Arc::clone);
        let Some(session) = session else {
            self.record(Severity::Event, "session", format!("no session for {peer:?}")).await;
            return;
        };
        if let Err(cause) = session.send(&frame(channel, payload)).await {
            self.record(Severity::Event, "session", cause).await;
        }
    }

    /// Sends a tunnel packet on a peer's session, best effort.
    async fn send_packet_to(&self, peer: DeviceId, packet: &[u8]) {
        // In both directions. A device that drops what reaches it and still sends
        // would be holding everyone else to a limit it does not keep itself.
        if let Some(refusal) = self.refuses_traffic_with(&peer) {
            self.record(Severity::Event, "tunnel", refusal).await;
            return;
        }
        let session = self.sessions.lock().await.get(&peer).map(Arc::clone);
        let Some(session) = session else {
            self.record(Severity::Event, "session", format!("no session for {peer:?}")).await;
            return;
        };
        match session.send_packet(packet).await {
            Ok(()) => {}
            // Once per session: a peer on an older build refuses every packet,
            // and a line per packet would bury everything else.
            Err(transport::Error::PacketsNotAccepted) => {
                if self.refusing_packets.lock().await.insert(peer) {
                    self.record(
                        Severity::Event,
                        "session",
                        format!("{peer:?}: {}", transport::Error::PacketsNotAccepted),
                    )
                    .await;
                }
            }
            Err(cause) => self.record(Severity::Event, "session", cause).await,
        }
    }

    /// Sends to every peer but one.
    async fn send_to_others(&self, except: DeviceId, channel: Channel, payload: &[u8]) {
        let peers: Vec<DeviceId> =
            self.sessions.lock().await.keys().copied().filter(|peer| *peer != except).collect();
        for peer in peers {
            self.send_to(peer, channel, payload).await;
        }
    }

    /// Opens a session with a peer named by its transport key.
    ///
    /// # Errors
    ///
    /// When the peer cannot be reached, or the roster does not name it.
    pub async fn connect(self: &Arc<Self>, peer: &roster::sign::PublicKey) -> crate::Result<()> {
        let transport = self.transport.lock().await.clone().ok_or(crate::Error::NotUp)?;

        let session = transport
            .connect(peer)
            .await
            .map_err(|cause| crate::Error::Unreachable { cause: cause.to_string() })?;

        tokio::spawn(Arc::clone(self).serve(session));
        Ok(())
    }

    /// Waits for a peer to open a session with this node.
    ///
    /// # Errors
    ///
    /// When the tunnel is down, or the transport fails.
    pub async fn accept(self: &Arc<Self>) -> crate::Result<()> {
        let transport = self.transport.lock().await.clone().ok_or(crate::Error::NotUp)?;

        let session = transport
            .accept()
            .await
            .map_err(|cause| crate::Error::Refused { cause: cause.to_string() })?;

        tokio::spawn(Arc::clone(self).serve(session));
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    /// **A fault is the current problem for ten minutes, and then it is not.**
    /// The log still has it; the report says what is wrong now.
    #[test]
    fn a_fault_is_a_problem_for_ten_minutes() {
        use std::time::{Duration, SystemTime};

        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_757_000_000);
        let fault = super::Fault { subsystem: "relay".to_owned(), cause: "refused".to_owned(), at };

        assert!(fault.current(at + Duration::from_secs(9 * 60)), "nine minutes on, still current");
        assert!(!fault.current(at + Duration::from_secs(11 * 60)), "eleven on, it has aged out");
        assert!(fault.current(at - Duration::from_secs(60)), "a clock gone backwards shows it");
    }

    /// §2.6c by construction: with the tunnel down there is no transport, so
    /// there is nothing to reach infrastructure with.
    #[test]
    fn the_transport_exists_only_while_the_tunnel_is_up() {
        let code = crate::code_of(include_str!("node.rs"));

        assert!(
            code.contains("transport: Mutex<Option<Arc<dyn Transport>>>"),
            "a transport held for the life of the process talks to the relay while down"
        );
        assert!(code.contains("pub async fn stopped"), "and it must be droppable");
    }

    /// Every part reports into one place, and none of them can stop the others
    /// by returning an error the caller must propagate.
    #[test]
    fn a_subsystem_failure_is_recorded_rather_than_propagated() {
        let code = crate::code_of(include_str!("node.rs"));

        assert!(code.contains("self.record("), "failures are recorded");
        for silent in ["let _ = session.send", "unwrap_or_default()", ".ok();"] {
            assert!(
                !code.contains(silent),
                "`{silent}` would swallow a failure instead of recording it"
            );
        }
    }

    /// The node assembles; it does not decide membership. That is the roster's,
    /// and a second answer here would be consulted far more often than the
    /// signed one.
    #[test]
    fn the_node_decides_nothing_about_membership() {
        let code = crate::code_of(include_str!("node.rs"));
        for forbidden in ["is_member", "permitted", "allowed", "is_admin", "Role"] {
            assert!(!code.contains(forbidden), "`{forbidden}` is the roster's to decide");
        }
    }

    /// Operations are stored as they arrived, never re-encoded from a decoded
    /// structure — `DESIGN.md` §0's rule, which a store is the easiest place to
    /// break quietly.
    ///
    /// The earlier version of this test asserted only that the call existed, and
    /// passed for as long as the append sat in the wrong loop: it walked the
    /// messages being sent to the peer rather than the ones just taken in, so
    /// nothing learned from a peer reached the disk. A string being present says
    /// nothing about what feeds it, which is why the behavioural test in
    /// `tests/propagation.rs` is the one that catches it — this only pins the
    /// source of the bytes.
    #[test]
    fn operations_are_persisted_as_they_arrived() {
        let code = crate::code_of(include_str!("node.rs"));
        assert!(
            code.contains("for operation in &reception.accepted"),
            "what is written is what was admitted, not what is being sent"
        );
        assert!(code.contains("self.log.append(operation)"), "the bytes that arrived");
        assert!(!code.contains("to_bytes()"), "nothing is re-serialized on the way to disk");
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod borrowing {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use identity::NodeIdentity;
    use roster::id::{DeviceId, NetworkId};
    use roster::roster::Roster;
    use roster::sign::{VerifiedOperation, sign_operation};
    use roster::types::{NetworkParams, OperationBody, OperationCore, Role};
    use roster_sync::Syncer;
    use tunnel::{Prefix, Tunnel as Rules};

    use super::Node;
    use crate::confirmations::Confirmed;
    use crate::contacts::LastContacts;
    use crate::gateway::Gateway;
    use crate::router::Router;
    use crate::schedule::Schedule;
    use crate::state::Log;

    /// How many operations the equivalence is checked over.
    ///
    /// Not a thousand, which is what the task first asked for. Offering a history
    /// one operation at a time costs more than cubic time in the roster today —
    /// each offer re-derives the whole state to find its author's key — and a
    /// thousand takes over five minutes in release, far longer in a debug test.
    /// Recorded in the change's design as a risk with its measurements.
    const OPERATIONS: usize = 120;

    /// A roster signed by one founder: admissions, and a revocation of every
    /// tenth device admitted.
    fn a_history(founder: &NodeIdentity) -> Roster {
        let params =
            NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "home.internal", 2_592_000)
                .unwrap();
        let genesis = OperationCore::new(
            1_757_000_040_000,
            founder.signing_key().algorithm(),
            OperationBody::CreateNetwork {
                device: founder.device_spec("nas", Role::Admin, true, vec![]).unwrap(),
                params,
            },
            vec![],
            founder.signing_key().key_id(),
            NetworkId::from_bytes([0; 32]),
        )
        .unwrap();
        let network = NetworkId::from_bytes(*genesis.id().as_bytes());
        let mut roster = Roster::new();
        assert!(
            roster.offer_bytes(&sign_operation(&genesis, founder.signer()).unwrap()).is_accepted()
        );

        let mut parent = genesis.id();
        let mut admitted = Vec::new();
        let mut count = 1usize;
        let mut minute = 1u64;
        while count < OPERATIONS {
            minute = minute.saturating_add(1);
            let body = if count.is_multiple_of(10) && !admitted.is_empty() {
                let device: DeviceId = admitted.remove(0);
                OperationBody::RevokeDevice { device, reason: format!("lost {count}") }
            } else {
                let joiner = NodeIdentity::generate().unwrap();
                admitted.push(joiner.device_id());
                OperationBody::AddDevice(
                    joiner.device_spec(format!("d{count}"), Role::Member, false, vec![]).unwrap(),
                )
            };
            let core = OperationCore::new(
                1_757_000_040_000_u64.saturating_add(minute.saturating_mul(60_000)),
                founder.signing_key().algorithm(),
                body,
                vec![parent],
                founder.signing_key().key_id(),
                network,
            )
            .unwrap();
            parent = core.id();
            assert!(
                roster.offer_bytes(&sign_operation(&core, founder.signer()).unwrap()).is_accepted()
            );
            count = count.saturating_add(1);
        }
        assert_eq!(roster.dag().len(), OPERATIONS);
        roster
    }

    /// Borrowing changes nothing about what the report says.
    ///
    /// The reference is the way the report was built before: from copies of the
    /// valid operations and of what this device authored. The node now builds it
    /// from the roster in place, and the two must be the same report.
    #[tokio::test]
    async fn the_report_built_in_place_is_the_report_built_from_copies() {
        let founder = Arc::new(NodeIdentity::generate().unwrap());
        let roster = a_history(&founder);

        // The reference, from copies.
        let state = roster.state().unwrap();
        let (_, verdicts) = roster::state::derive_with_verdicts(roster.dag()).unwrap();
        let valid: Vec<VerifiedOperation> = roster
            .dag()
            .operations()
            .iter()
            .enumerate()
            .filter(|(index, _)| verdicts.is_valid(*index))
            .map(|(_, operation)| operation.clone())
            .collect();
        let valid: Vec<&VerifiedOperation> = valid.iter().collect();
        let mine: Vec<VerifiedOperation> = roster.dag().operations().to_vec();
        let mine: Vec<&VerifiedOperation> = mine.iter().collect();
        let directory = crate::describing::Directory::of(&state, &valid);
        let expected_accused = crate::describing::accused(&directory, &roster);
        let expected_revoked =
            crate::describing::revoked(&directory, &state, &valid, &LastContacts::default());
        let expected_waiting = crate::describing::waiting(
            &directory,
            &state,
            &mine,
            &founder.device_id(),
            &Confirmed::default(),
            &BTreeSet::new(),
            &LastContacts::default(),
        );

        // The node, in place.
        let scratch = tempfile::tempdir().unwrap();
        let prefix = Prefix::from_parameter(&state.params.ula).unwrap();
        let node = Node::new(
            Arc::clone(&founder),
            Syncer::new(roster),
            Arc::new(Gateway::new(Rules::new(prefix, founder.device_id()))),
            Router::new(prefix),
            Log::at(scratch.path().join("roster.log")),
            Schedule::provisional(),
        );
        let membership = node.membership(&state).await;

        assert_eq!(membership.accused, expected_accused);
        assert_eq!(membership.revoked, expected_revoked);
        assert_eq!((membership.waiting, membership.waiting_unlisted), expected_waiting);
        assert!(
            expected_revoked.len() >= 10,
            "the fixture really does revoke: {}",
            expected_revoked.len()
        );
    }

    /// The node's own sources copy no operation to build the report or to pace.
    #[test]
    fn no_operation_is_copied_to_report_or_to_pace() {
        let code = crate::code_of(include_str!("node.rs"));
        for function in ["pub(crate) async fn membership(", "async fn lagging("] {
            let (_, rest) = code.split_once(function).unwrap();
            let body = rest.split("\nasync fn ").next().unwrap_or(rest);
            let body = body.split("\npub(crate) async fn ").next().unwrap_or(body);
            for copy in [".cloned()", ".to_vec()", "to_owned()", "::from("] {
                assert!(!body.contains(copy), "`{function}` copies with `{copy}`");
            }
            // Two clones are legitimate and small: the contact record and a
            // device's name. Anything else cloned here is the roster, copied.
            for line in body.lines().filter(|line| line.contains("clone()")) {
                assert!(
                    line.contains("contacts.lock()") || line.contains("name.clone()"),
                    "`{function}` clones something that is not a name or the contacts: {line}"
                );
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod replacing {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use identity::NodeIdentity;
    use roster::id::NetworkId;
    use roster::roster::Roster;
    use roster::sign::sign_operation;
    use roster::types::{NetworkParams, OperationBody, OperationCore, Role};
    use roster_sync::Syncer;
    use transport::Transport;
    use tunnel::{Prefix, Tunnel as Rules};

    use super::Node;
    use crate::gateway::Gateway;
    use crate::router::Router;
    use crate::schedule::Schedule;
    use crate::state::Log;

    /// A transport whose `accept` waits for ever, and counts that it was asked.
    #[derive(Default)]
    struct Parked {
        asked: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Transport for Parked {
        async fn connect(
            &self,
            _peer: &roster::sign::PublicKey,
        ) -> transport::Result<Box<dyn transport::Session>> {
            core::future::pending().await
        }

        async fn accept(&self) -> transport::Result<Box<dyn transport::Session>> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            core::future::pending().await
        }
    }

    fn a_node() -> (Arc<Node>, tempfile::TempDir) {
        let founder = Arc::new(NodeIdentity::generate().unwrap());
        let params =
            NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "casa.internal", 600).unwrap();
        let genesis = OperationCore::new(
            1,
            founder.signing_key().algorithm(),
            OperationBody::CreateNetwork {
                device: founder.device_spec("founder", Role::Admin, true, vec![]).unwrap(),
                params,
            },
            vec![],
            founder.signing_key().key_id(),
            NetworkId::from_bytes([0; 32]),
        )
        .unwrap();
        let mut roster = Roster::new();
        assert!(
            roster.offer_bytes(&sign_operation(&genesis, founder.signer()).unwrap()).is_accepted()
        );
        let prefix = Prefix::from_parameter(&roster.state().unwrap().params.ula).unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let node = Arc::new(Node::new(
            Arc::clone(&founder),
            Syncer::new(roster),
            Arc::new(Gateway::new(Rules::new(prefix, founder.device_id()))),
            Router::new(prefix),
            Log::at(scratch.path().join("roster.log")),
            Schedule::provisional(),
        ));
        (node, scratch)
    }

    async fn until(what: impl Fn() -> bool) {
        tokio::time::timeout(core::time::Duration::from_secs(5), async {
            while !what() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("it happened");
    }

    /// **After a relay moves, sessions are accepted on the new transport.**
    ///
    /// The accepting loop is parked inside the old transport's `accept`, which
    /// returns only when something arrives there. Without being woken it would
    /// go on accepting on a transport nobody dials any more — and that would
    /// look like a node that works, with nobody able to reach it.
    #[tokio::test]
    async fn the_accepting_loop_moves_to_the_new_transport() {
        let (node, _scratch) = a_node();
        let old = Arc::new(Parked::default());
        let new = Arc::new(Parked::default());

        node.started(Arc::clone(&old) as Arc<dyn Transport>).await;
        let accepting = tokio::spawn(Arc::clone(&node).accept_forever());
        until(|| old.asked.load(Ordering::SeqCst) == 1).await;

        node.replace_transport(Arc::clone(&new) as Arc<dyn Transport>).await;
        until(|| new.asked.load(Ordering::SeqCst) == 1).await;

        assert!(node.fault().await.is_none(), "retiring a transport is not a fault");
        accepting.abort();
    }

    /// A node that is down is not given a transport by a relay moving.
    #[tokio::test]
    async fn a_down_node_is_not_given_a_transport() {
        let (node, _scratch) = a_node();
        node.replace_transport(Arc::new(Parked::default()) as Arc<dyn Transport>).await;
        assert!(!node.is_reachable().await, "§2.6c: nothing to reach a relay with");
    }
}

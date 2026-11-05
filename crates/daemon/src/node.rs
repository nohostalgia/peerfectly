//! The node, assembled.
//!
//! Several crates, each deliberately missing the same thing. `roster-sync` has
//! no loop, `local-discovery` no schedule, the transport no opinion about when
//! to connect, `tunnel` no device. Every
//! one of them wrote "the daemon owns this". This is where they are joined.
//!
//! It is in the core, over [`transport::Transport`], so the whole assembly runs
//! against the in-process transport with no network, no adapter and no
//! privileges — the same trick that let `roster-sync` be finished before there
//! was a real transport to carry it.
//!
//! # A failure in one part is not a failure of the node
//!
//! The relay is unreachable on a train. Multicast is filtered on most
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
//! Section 2.6c: with the network off, the daemon sends nothing to the relay,
//! or to any other infrastructure. Not "sends little" — a
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
use roster::id::DeviceId;
use roster::state::RosterState;
use roster_sync::Syncer;
use tokio::sync::{Mutex, watch};
use transport::session::{Session, Transport};
use tunnel::Ipv4Holdings;

use crate::channel::{Channel, frame, unframe};
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

/// A light member and its upkeep, as `light_node::engine` runs them: shared
/// by the node and the transport's judging, which only ever lock it briefly
/// and never across an await.
type Light = Arc<std::sync::Mutex<light_node::engine::Engine>>;

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
    /// The state the holdings and the router were last made to follow: what
    /// the next change is measured from, so that a change costs what changed.
    enforced: Mutex<Option<RosterState>>,
    /// This device's neighbour choices, and the state they are of: followed
    /// through a roster's changes rather than read from every member again.
    choices: std::sync::Mutex<Option<(RosterState, crate::neighbours::Choices)>>,
    /// The peers withheld on this device, and why, as the service last decided.
    ///
    /// Decided outside the node, because it depends on this device's other
    /// networks and interfaces; kept here, because the resolver and the report
    /// already read the node. Empty while down: nothing is routed, so nothing is
    /// withheld from a route.
    withheld: std::sync::Mutex<Arc<Vec<crate::conflicts::Hole>>>,
    /// Live sessions, by the device they belong to.
    sessions: Mutex<BTreeMap<DeviceId, Arc<dyn Session>>>,
    /// Which way each live session was opened, and when, by the same key.
    openings: std::sync::Mutex<BTreeMap<DeviceId, (Opening, tokio::time::Instant)>>,
    /// Dials in flight, by the peer's transport key, each with where its
    /// outcome will be told. A second caller waits for that outcome rather than
    /// dialling again: two dials to one peer at once opened two sessions in
    /// the same direction, and the two sides kept different ones
    /// (`convesso-reach` 5.4).
    dialling: std::sync::Mutex<InFlight>,
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
    /// What this device holds where it is a light member here: in place of a
    /// roster, whose syncer then stays empty.
    light: std::sync::RwLock<Option<Light>>,
    /// Set when this node changed mode — full to light or light to full — so
    /// the service builds it again from what it now keeps.
    switched: std::sync::atomic::AtomicBool,
    /// Set while a light member that became full fetches the state it rests on.
    becoming_full: std::sync::atomic::AtomicBool,
    /// Wakes the light member's upkeep, to carry out what its engine asks.
    upkeep: Arc<tokio::sync::Notify>,
    /// Held while what a light member's engine asks is carried out, so that
    /// its outputs are acted on in the order it gave them.
    driving: Mutex<()>,
    /// When this node was built: the light member's engine counts time from
    /// it.
    born: tokio::time::Instant,
    /// Held while the log is written: appended to, or rewritten after a
    /// compaction, so that a rewrite never drops an operation appended while it
    /// was being made.
    log_guard: Mutex<()>,
    /// What keeps this network's checkpoint current, once the service has set
    /// one. Absent in a node nobody carries.
    keeper: std::sync::OnceLock<Arc<crate::checkpoint::Keeper>>,
    /// The store this network's base is kept in, once a base is: opened by
    /// this node and held while it lives, since a store is opened by one owner
    /// at a time.
    base: std::sync::Mutex<Option<Arc<member_store::Store>>>,
    /// Whether a base that failed a check has been reported.
    base_told: std::sync::atomic::AtomicBool,
    /// The intervals this node runs on.
    schedule: Schedule,
    /// The last minute each device spoke on a session with this one.
    ///
    /// Written from two places — a session opening, and roster traffic arriving
    /// on one — and read only for the report. `contacts`' own test lists the
    /// functions here that must never read it.
    contacts: Mutex<LastContacts>,
    /// Where that is kept between runs.
    contact_record: ContactRecord,
    /// The members that chose this device as a neighbour and said so, checked
    /// against the roster. Pushed to as the device's own choices are.
    in_neighbours: Mutex<BTreeSet<DeviceId>>,
    /// Packets waiting for a member whose session is being opened.
    ///
    /// A session is opened by the first packet that needs it. What arrives while
    /// it opens waits here, in order, up to [`crate::limits::MAX_WAITING_PACKETS`],
    /// and is sent once it is open — by whichever side opened it.
    waiting: Mutex<BTreeMap<DeviceId, Waiting>>,
    /// When each open session last carried something — a packet or a roster
    /// message, in either direction.
    ///
    /// Keep-alives do not count: they are what an idle session costs, not use of
    /// it. A plain lock, because it is touched for every packet, and an
    /// asynchronous one there would be paid on the path that carries everything.
    activity: std::sync::Mutex<BTreeMap<DeviceId, tokio::time::Instant>>,
    /// Neighbours that did not answer, and until when each is left alone.
    unanswered: std::sync::Mutex<BTreeMap<DeviceId, Rest>>,
    /// Members a packet failed to open a session to, and until when packets for
    /// them are dropped rather than opening another attempt.
    ///
    /// Without it, something that keeps sending to a member that is switched off
    /// opens an attempt the moment the last one fails, for as long as it keeps
    /// sending, and each attempt retries a handshake on every path for half a
    /// minute.
    unreached: std::sync::Mutex<BTreeMap<DeviceId, Rest>>,
    /// Raised when something new was admitted that the neighbours should have.
    ///
    /// One permit, however often it is raised: [`Self::spread_forever`] waits
    /// out a short pause and then makes one round of contact for everything
    /// admitted meanwhile, so an admin signing five acts at once costs one round.
    spreading: tokio::sync::Notify,
    /// When this node last caught up with its neighbours because a session was
    /// refused for want of a member it may simply not have heard of yet.
    caught_up: std::sync::Mutex<Option<tokio::time::Instant>>,
}

/// How long a neighbour that did not answer is left alone.
#[derive(Debug, Clone, Copy)]
struct Rest {
    /// The next wait, doubled at every failure.
    interval: std::time::Duration,
    /// Not tried before this.
    until: tokio::time::Instant,
}

/// Packets waiting for one member's session.
#[derive(Debug, Default)]
struct Waiting {
    /// In the order they arrived.
    packets: std::collections::VecDeque<Vec<u8>>,
    /// Their total size, for the byte bound.
    bytes: usize,
    /// How many arrived beyond the bound and were dropped.
    dropped: usize,
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
        // Losing this one misleads nobody: every device reads as having no
        // contact recorded, which is what this device now knows.
        let contact_record = ContactRecord::beside(log.path());
        let (contacts, lost) = contact_record.load();

        // The members that chose this one, kept beside the log. A record that
        // cannot be read is an empty one: they are learned again on contact.
        let in_neighbours = match log.path().parent() {
            Some(directory) => {
                crate::state::read_in_neighbours(&crate::state::Paths::under(directory))
            }
            // A log with no directory keeps nothing beside it: there is nothing
            // to have lost.
            None => BTreeSet::new(),
        };

        // Every network's directory is named after its label, and the log sits
        // in it. Read off the path rather than passed in, so that naming a node
        // for the log is not another argument every caller has to get right.
        let called = log
            .path()
            .parent()
            .and_then(|directory| directory.file_name())
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned());

        // Logged, and kept as the latest.
        let latest = lost.map(|cause| {
            let cause = cause.to_string();
            tracing::warn!(
                network = %called,
                subsystem = "state",
                cause = %crate::logging::scrubbed(&cause),
                "fault"
            );
            Fault { subsystem: "state".to_owned(), cause, at: SystemTime::now() }
        });

        // The holdings the roster already implies, so the gateway and router
        // agree with it from the start rather than from the first change.
        // A roster that derives nothing yet holds no addresses: not a failure
        // to record, the state of a network still being joined.
        #[allow(
            clippy::manual_ok_err,
            reason = "spelled out: a test here forbids the form that swallows failures"
        )]
        let initial = match syncer.roster().state() {
            Ok(state) => Some(state),
            Err(_) => None,
        };
        let holdings = initial.as_ref().map_or_else(Ipv4Holdings::default, Ipv4Holdings::of_state);
        let mut router = router;
        router.set_holdings(holdings.clone());
        if let Some(state) = &initial {
            router.follow_state(state, &identity.device_id());
        }
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
            enforced: Mutex::new(initial),
            choices: std::sync::Mutex::new(None),
            withheld: std::sync::Mutex::new(Arc::new(Vec::new())),
            sessions: Mutex::new(BTreeMap::new()),
            openings: std::sync::Mutex::new(BTreeMap::new()),
            dialling: std::sync::Mutex::new(BTreeMap::new()),
            refusing_packets: Mutex::new(BTreeSet::new()),
            fault: Mutex::new(latest),
            event: Mutex::new(None),
            called,
            log,
            light: std::sync::RwLock::new(None),
            switched: std::sync::atomic::AtomicBool::new(false),
            becoming_full: std::sync::atomic::AtomicBool::new(false),
            upkeep: Arc::new(tokio::sync::Notify::new()),
            driving: Mutex::new(()),
            born: tokio::time::Instant::now(),
            log_guard: Mutex::new(()),
            keeper: std::sync::OnceLock::new(),
            base: std::sync::Mutex::new(None),
            base_told: std::sync::atomic::AtomicBool::new(false),
            schedule,
            contacts: Mutex::new(contacts),
            contact_record,
            in_neighbours: Mutex::new(in_neighbours),
            waiting: Mutex::new(BTreeMap::new()),
            activity: std::sync::Mutex::new(BTreeMap::new()),
            unanswered: std::sync::Mutex::new(BTreeMap::new()),
            unreached: std::sync::Mutex::new(BTreeMap::new()),
            spreading: tokio::sync::Notify::new(),
            caught_up: std::sync::Mutex::new(None),
        }
    }

    /// How long a device refused as not a member waits before trying again.
    pub const NEWCOMER_RETRY: std::time::Duration = std::time::Duration::from_secs(5);

    /// How many times it tries again before giving up on this attempt.
    pub const NEWCOMER_ATTEMPTS: usize = 3;

    /// The least time between two catch-ups caused by refusals.
    pub const CATCH_UP_AT_MOST: std::time::Duration = std::time::Duration::from_secs(60);

    /// Reconciles with the neighbours because a refusal suggests this roster
    /// is behind — at most once every [`Self::CATCH_UP_AT_MOST`].
    ///
    /// The refusal may be right: a stranger is a stranger. It may also be a
    /// device admitted moments ago whose admission has not reached this one yet,
    /// and the neighbours are where it would come from. Bounded, so that a stream
    /// of strangers costs at most one round of contact a minute; and nothing is
    /// accepted from the refused device, which gets nothing it could not get by
    /// waiting.
    fn catch_up(self: &Arc<Self>) {
        let now = tokio::time::Instant::now();
        let due = self.caught_up.lock().is_ok_and(|mut last| {
            let due =
                last.is_none_or(|at| now.saturating_duration_since(at) >= Self::CATCH_UP_AT_MOST);
            if due {
                *last = Some(now);
            }
            due
        });
        if due {
            let node = Arc::clone(self);
            tokio::spawn(async move { node.reconcile_with_neighbours().await });
        }
    }

    /// Notes that a session carried something now.
    fn active(&self, peer: DeviceId) {
        if let Ok(mut activity) = self.activity.lock() {
            activity.insert(peer, tokio::time::Instant::now());
        }
    }

    /// Closes every session that has carried nothing for `idle`, but those
    /// [`held_open`] keeps.
    ///
    /// Not a fault and not recorded: it is the ordinary end of a session nothing
    /// is using, and the next packet that needs one opens it again.
    pub async fn close_idle(&self, idle: std::time::Duration) {
        let now = tokio::time::Instant::now();
        let stale: Vec<DeviceId> = self.activity.lock().map_or_else(
            |_| Vec::new(),
            |activity| {
                activity
                    .iter()
                    .filter(|(_, last)| now.saturating_duration_since(**last) >= idle)
                    .map(|(peer, _)| *peer)
                    .collect()
            },
        );
        if held_open(self.is_light(), false) {
            return;
        }
        let stale: Vec<DeviceId> = {
            let syncer = self.syncer.lock().await;
            let roster = syncer.roster();
            stale
                .into_iter()
                .filter(|peer| {
                    let peer_light = roster.mode_of(peer) == Some(roster::leaf::Mode::Light);
                    !held_open(false, peer_light)
                })
                .collect()
        };
        for peer in stale {
            tracing::info!(network = %self.called, ?peer, "closing a session nothing used");
            let session = self.sessions.lock().await.get(&peer).map(Arc::clone);
            self.closed(&peer).await;
            if let Some(session) = session {
                let _closing = session.close().await;
            }
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
        dating: Option<(Vec<u8>, u64)>,
    ) -> crate::Result<Option<Arc<Self>>> {
        // On the wall clock, not the roster's default: freshness has to outlive
        // this process, and the default counts from the moment it started.
        let mut roster = roster::roster::Roster::with_clock(Box::new(crate::state::WallClock));
        // So that, with other admins in the network, this device's own
        // attestations do not keep its own roster fresh.
        roster.set_own_device(identity.device_id());
        // The batches' layers on disk, emptied and filled again as the log is
        // replayed: a fleet's boards are not held in memory, and nothing the
        // file held before this start is relied on (`member_store::Layers`).
        // Where it cannot be opened, the layers stay in memory.
        if let Some(paths) = log.path().parent().map(crate::state::Paths::under)
            && let Ok(layers) = crate::state::open_layers(&paths)
            && layers.clear().is_ok()
        {
            roster.keep_layers_in(layers);
        }
        let held = log.read()?;
        // A log that was compacted rests on a base: the root beneath its window
        // and the state that root commits to. Only the operations that follow
        // the base's heads are offered; the rest of the log, where a rewrite
        // was cut short, is what the base already covers.
        let paths = log.path().parent().map(crate::state::Paths::under);
        let store = paths
            .as_ref()
            .filter(|paths| paths.base_snapshot().exists())
            .map(crate::state::open_base_store)
            .transpose()?;
        let held = match (&paths, &store) {
            (Some(paths), Some(store)) => match resting_on_base(&mut roster, paths, store, held) {
                Ok(after) => after,
                // A base that does not check out holds nothing to rest on, and
                // a log beneath a base derives nothing without one: said as
                // what it is.
                Err(_) => {
                    return Err(crate::error::Error::State {
                        path: paths.base_store(),
                        cause: CHANGED_OUTSIDE.to_owned(),
                    });
                }
            },
            _ => held,
        };
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
        // The pieces of the batches among them, now that their headers are
        // held: a batch takes effect only once they are all in, so the state
        // a snapshot below is checked against needs them first.
        if let Some(paths) = log.path().parent().map(crate::state::Paths::under) {
            for piece in crate::state::Log::at(paths.pieces()).read()? {
                let _taken = roster.offer_piece(&piece);
            }
        }

        // After the operations, because verifying a snapshot means deriving what
        // it covers from operations this node holds. Before anything is served,
        // because a node that answered a peer while undated would answer from a
        // roster it has not yet decided whether to trust.
        if let Some((bytes, received_at)) = restored {
            let _restored = roster.restore_snapshot(&bytes, received_at);
        }
        // The one that dated this roster first, then the one held: the held one
        // has the higher sequence, and where it is this device's own it is
        // relayed and continued but dates nothing, which leaves the first's date
        // standing.
        if let Some((bytes, received_at)) = &dating
            && attested.as_ref().is_none_or(|(held, _)| held != bytes)
        {
            let _restored = roster.restore_attestation(bytes, *received_at);
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
        let node = Self::new(
            identity,
            Syncer::new(roster),
            Arc::new(crate::gateway::Gateway::new(tunnel::Tunnel::new(prefix, own))),
            crate::router::Router::new(prefix),
            log,
            crate::schedule::Schedule::provisional(),
        );
        if let Ok(mut held) = node.base.lock() {
            *held = store;
        }
        Ok(Some(Arc::new(node)))
    }

    /// A node for a network this device is a light member of: it holds no
    /// roster, and runs on the light member kept beside its identity.
    ///
    /// `None` where no light member is kept there.
    ///
    /// # Errors
    ///
    /// When the parameters the member holds are unusable.
    pub fn from_light(
        identity: Arc<NodeIdentity>,
        paths: &crate::state::Paths,
    ) -> crate::Result<Option<Arc<Self>>> {
        let Some(member) = crate::state::read_light(paths) else { return Ok(None) };
        let state = member.state();
        let prefix = tunnel::Prefix::from_parameter(&state.params.ula)?;
        let own = identity.device_id();
        let node = Self::new(
            identity,
            Syncer::new(roster::roster::Roster::new()),
            Arc::new(crate::gateway::Gateway::new(tunnel::Tunnel::new(prefix, own))),
            crate::router::Router::new(prefix),
            // Never written: a light member holds no operations.
            Log::at(paths.roster()),
            crate::schedule::Schedule::provisional(),
        );
        node.set_light(Some(Arc::new(std::sync::Mutex::new(light_node::engine::Engine::new(
            member,
        )))));
        Ok(Some(Arc::new(node)))
    }

    /// Keeps this network's checkpoint current from now on.
    pub fn keep_with(&self, keeper: Arc<crate::checkpoint::Keeper>) {
        let _already = self.keeper.set(keeper);
    }

    /// What keeps this network's checkpoint, if anything does.
    #[must_use]
    pub fn keeper(&self) -> Option<&Arc<crate::checkpoint::Keeper>> {
        self.keeper.get()
    }

    /// The root the roster's base rests on, where it was compacted.
    pub async fn base_root(&self) -> Option<crate::checkpoint::Hash> {
        let syncer = self.syncer.lock().await;
        syncer.roster().dag().base_snapshot().map(|snapshot| snapshot.body().root)
    }

    /// Reads a node nobody else holds yet: `None` while something else does.
    ///
    /// For checking a node just assembled against its checkpoint, where
    /// nothing else can be holding it and the caller cannot wait.
    pub fn with_roster_now<T>(&self, read: impl FnOnce(&roster::roster::Roster) -> T) -> Option<T> {
        self.syncer.try_lock().ok().map(|syncer| read(syncer.roster()))
    }

    /// The store this network's base is kept in, opened the first time a base
    /// is written and kept open from then on.
    fn base_store(&self) -> Option<Arc<member_store::Store>> {
        let mut held = self.base.lock().ok()?;
        if let Some(store) = held.as_ref() {
            return Some(Arc::clone(store));
        }
        let store = crate::state::open_base_store(&self.paths()?).ok()?;
        *held = Some(Arc::clone(&store));
        Some(store)
    }

    /// Whether the store this network's base is kept in answered something
    /// that did not check out: it was changed by someone other than this
    /// daemon, and nothing it holds is to be believed.
    #[must_use]
    pub fn base_tampered(&self) -> bool {
        self.base
            .lock()
            .ok()
            .and_then(|held| held.as_ref().map(|store| store.tampered()))
            .unwrap_or(false)
    }

    /// Whether the base store failed a check, recording it the first time it
    /// is seen.
    pub async fn base_tampered_told(&self) -> bool {
        if !self.base_tampered() {
            return false;
        }
        if !self.base_told.swap(true, std::sync::atomic::Ordering::SeqCst) {
            self.record(
                Severity::Problem,
                "state",
                "the store this network's base is kept in was changed outside this daemon:                  what it holds is not believed, and joining the network again fetches it                  from peers",
            )
            .await;
        }
        true
    }

    /// The base this roster rests on: the root beneath its window and the
    /// state it commits to.
    pub async fn base(
        &self,
    ) -> Option<(roster::snapshot::SignedSnapshot, roster::state::RosterState)> {
        let syncer = self.syncer.lock().await;
        let dag = syncer.roster().dag();
        Some((dag.base_snapshot()?.clone(), dag.base_state()?.clone()))
    }

    /// Writes `state` as the base, and rests the roster on what the store then
    /// holds rather than on the copy in memory.
    fn write_base_and_rest(
        &self,
        paths: &crate::state::Paths,
        snapshot: &roster::snapshot::SignedSnapshot,
        state: &roster::state::RosterState,
    ) -> crate::Result<Option<roster::state::RosterState>> {
        let store = self.base_store().ok_or_else(|| crate::error::Error::State {
            path: paths.base_store(),
            cause: "the base store would not open".to_owned(),
        })?;
        crate::state::write_base(paths, &store, snapshot, state)?;
        Ok(store.state().ok().flatten().filter(|stored| stored.root() == state.root()))
    }

    /// Whether the roster holds `operation`.
    pub async fn holds_operation(&self, operation: &roster::id::OperationId) -> bool {
        self.syncer.lock().await.roster().dag().contains(operation)
    }

    /// When `operation` was signed, in milliseconds since the epoch on its
    /// author's clock, where it admits one device and the roster still holds
    /// it. Not for a batch: its boards reach the network themselves, and
    /// nobody dials them (found in the testbed, 18.1: two thousand boards
    /// dialled at once kept a daemon's every thread busy).
    pub async fn admitted_alone_at(&self, operation: &roster::id::OperationId) -> Option<u64> {
        let syncer = self.syncer.lock().await;
        let dag = syncer.roster().dag();
        dag.position(operation)
            .and_then(|index| dag.operation(index))
            .filter(|held| matches!(held.core().body, roster::types::OperationBody::AddDevice(_)))
            .map(|held| held.core().ts)
    }

    /// The devices admitted alone, each by an `add_device` the roster still
    /// holds signed at `since` or after, in milliseconds since the epoch on its
    /// author's clock: the newcomers there may be, read from the operations
    /// held rather than from every member. Not a batch's boards (as
    /// [`Self::admitted_alone_at`]).
    pub async fn admitted_alone_since(
        &self,
        since: u64,
    ) -> Vec<(DeviceId, roster::id::OperationId)> {
        let syncer = self.syncer.lock().await;
        syncer
            .roster()
            .dag()
            .operations()
            .iter()
            .filter(|operation| operation.core().ts >= since)
            .filter_map(|operation| match &operation.core().body {
                roster::types::OperationBody::AddDevice(spec) => {
                    spec.device_id().ok().map(|device| (device, operation.id()))
                }
                _ => None,
            })
            .collect()
    }

    /// The neighbours this device could choose in `state`: which new members
    /// it brings the network to.
    pub(crate) fn choices(&self, state: &RosterState) -> Option<crate::neighbours::Choices> {
        self.choices_in(state)
    }

    /// The network a light member's node belongs to.
    #[must_use]
    pub fn light_network(&self) -> Option<roster::id::NetworkId> {
        self.light().and_then(|light| light.lock().ok().map(|light| light.member().network()))
    }

    /// Names a base about to be written in the checkpoint first. Whether the
    /// write may go ahead: a base the checkpoint does not name would keep the
    /// network from being carried at the next start.
    fn before_writing_base(&self, root: crate::checkpoint::Hash) -> bool {
        self.keeper.get().is_none_or(|keeper| keeper.allow_base(Some(root)).is_ok())
    }

    /// The same, for what a light member keeps.
    fn before_writing_light(&self, member: &roster::member::LightMember) -> bool {
        let hash = crate::checkpoint::light_hash(member);
        self.keeper.get().is_none_or(|keeper| keeper.allow_light(hash).is_ok())
    }

    /// Says a write named beforehand has landed.
    fn landed(&self) {
        if let Some(keeper) = self.keeper.get() {
            keeper.landed();
        }
    }

    /// The same, for what a light member keeps: and that it is what the
    /// checkpoint vouches for from now on, whatever the file is made to hold.
    fn light_landed(&self, member: &roster::member::LightMember) {
        if let Some(keeper) = self.keeper.get() {
            keeper.holds_light(crate::checkpoint::light_hash(member));
            keeper.landed();
        }
    }

    /// The light member this node runs on, if it is one now.
    fn light(&self) -> Option<Light> {
        self.light.read().map_or(None, |held| held.clone())
    }

    /// A copy of the light member this node runs on, if it is one now.
    fn light_member(&self) -> Option<roster::member::LightMember> {
        self.light().and_then(|light| light.lock().ok().map(|light| light.member().clone()))
    }

    /// Milliseconds since this node was built: the light member's engine's
    /// clock.
    fn now_ms(&self) -> u64 {
        u64::try_from(self.born.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Gives the light member's engine something that happened, and carries
    /// out what it asks in return. Nothing where this node is not light.
    async fn tell_light(&self, event: impl FnOnce(&mut light_node::engine::Engine, u64)) {
        let Some(light) = self.light() else { return };
        let now = self.now_ms();
        if let Ok(mut engine) = light.lock() {
            event(&mut engine, now);
        }
        self.drive_light().await;
    }

    /// Carries out what the light member's engine asks, in its order: sends
    /// its questions, keeps the member before acting on what follows, judges
    /// the sessions again, follows the state.
    async fn drive_light(&self) {
        let _driving = self.driving.lock().await;
        loop {
            let Some(light) = self.light() else { return };
            let next = light.lock().ok().and_then(|mut engine| engine.poll_output());
            let Some(output) = next else { return };
            match output {
                light_node::engine::Output::Send { peer, channel, body } => {
                    self.send_to(peer, channel, &body).await;
                }
                light_node::engine::Output::Keep => {
                    if let Some(member) = self.light_member() {
                        self.keep_light(&member).await;
                    }
                }
                light_node::engine::Output::Renewed => {
                    self.refresh_evidence().await;
                    // Its leaf may now say it is full.
                    let _asked = self.begin_full().await;
                }
                light_node::engine::Output::Reconsider => {
                    let transport = self.transport.lock().await.clone();
                    if let Some(transport) = transport {
                        transport.reconsider();
                    }
                }
                light_node::engine::Output::StateChanged => self.enforce_roster().await,
                // The upkeep sleeps until the earliest deadline anyway, and
                // nothing here asks the engine to find a member.
                light_node::engine::Output::WakeAt(_)
                | light_node::engine::Output::Found { .. } => {}
            }
        }
    }

    /// Makes this node a light member's, or a full member's.
    fn set_light(&self, member: Option<Light>) {
        if let Ok(mut held) = self.light.write() {
            *held = member;
        }
    }

    /// Whether this node changed mode since it was built: the service then
    /// builds it again, from what it now keeps.
    #[must_use]
    pub fn mode_switched(&self) -> bool {
        self.switched.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Becomes a light member, where the root this node holds says it is one:
    /// its leaf, its proof and that root are kept as a light member, and the
    /// roster and everything beside it is dropped.
    ///
    /// Returns whether it switched.
    async fn become_light_if_named(&self) -> bool {
        let me = self.identity.device_id();
        let recent = self.seen_lately().await;
        let member = {
            let syncer = self.syncer.lock().await;
            let roster = syncer.roster();
            let Some(evidence) = roster.evidence_for(&me) else { return false };
            if evidence.leaf.settings.mode != roster::leaf::Mode::Light {
                return false;
            }
            let Ok(state) = roster.state() else { return false };
            let Ok(mut member) = roster::member::LightMember::new(
                evidence,
                state.params,
                roster::member::DEFAULT_BUDGET,
            ) else {
                return false;
            };
            // A way out besides the admin that admitted it, chosen while the
            // whole roster is still here to choose from.
            for evidence in crate::lookup::handed_evidence(roster, &me, &|device| recent(device)) {
                let _kept = member.learn(&evidence);
            }
            member
        };
        let Some(paths) = self.paths() else { return false };
        if !self.before_writing_light(&member) {
            self.record(
                Severity::Problem,
                "state",
                "the checkpoint could not name the light member",
            )
            .await;
            return false;
        }
        if let Err(cause) = crate::state::write_light(&paths, &member) {
            self.record(Severity::Problem, "state", cause).await;
            return false;
        }
        self.light_landed(&member);
        {
            let _guard = self.log_guard.lock().await;
            if let Ok(mut held) = self.base.lock() {
                *held = None;
            }
            // The layers too, where nothing holds them open any more; one still
            // open is emptied at the next start anyway.
            for kept in [
                paths.roster(),
                paths.pieces(),
                paths.base_snapshot(),
                paths.base_store(),
                paths.layers(),
            ] {
                let _removed = std::fs::remove_file(kept);
            }
        }
        self.set_light(Some(Arc::new(std::sync::Mutex::new(light_node::engine::Engine::new(
            member,
        )))));
        self.switched.store(true, std::sync::atomic::Ordering::SeqCst);
        true
    }

    /// Starts becoming a full member, where this light member's own leaf says
    /// it is one: it asks its contact for the state behind its root, through
    /// the syncer, which rests on it once it is whole and checked. Returns the
    /// message sent, for a caller that carries it itself.
    async fn begin_full(&self) -> Option<roster_sync::message::Message> {
        let member = self.light_member()?;
        let (evidence, contact) = (member.evidence(), member.contact());
        let shown = roster::membership::Evidence::from_bytes(&evidence).ok()?;
        if shown.leaf.settings.mode != roster::leaf::Mode::Full {
            return None;
        }
        self.becoming_full.store(true, std::sync::atomic::Ordering::SeqCst);
        let root = roster_sync::message::Message::Snapshot(shown.root).encode();
        let reception = self.syncer.lock().await.receive(contact, &root);
        let request = reception
            .replies
            .into_iter()
            .find(|reply| matches!(reply, roster_sync::message::Message::StateRequest(_)))?;
        self.send_to(contact, Channel::Roster, &request.encode()).await;
        Some(request)
    }

    /// Finishes becoming a full member once the state is whole and kept: the
    /// light member is dropped, and the service builds the node again.
    async fn finish_full(&self) {
        if !self.becoming_full.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        if let Some(paths) = self.paths() {
            let _removed = std::fs::remove_file(paths.light());
        }
        self.set_light(None);
        self.switched.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// What this device shows of its membership without the root, as bytes: for
    /// an announcement. Empty where it holds no root.
    pub async fn shown(&self) -> Vec<u8> {
        if let Some(light) = self.light() {
            return light.lock().map_or_else(|_| Vec::new(), |light| light.member().shown());
        }
        crate::snapshots::shown_of(self.syncer.lock().await.roster(), &self.identity.device_id())
    }

    /// Learns a member from what it showed in an announcement signed with
    /// `key`, as a light member does: the leaf must name that key for the
    /// transport purpose, and its proof hold against a root this member
    /// remembers. Whether it was learned.
    pub async fn learn_shown(&self, key: &roster::sign::PublicKey, shown: &[u8]) -> bool {
        let Some(member) = self.light() else { return false };
        let Ok(compact) = roster::membership::Shown::from_bytes(shown) else { return false };
        let names_key = compact.leaf.record.keys.iter().any(|entry| {
            entry.purpose == roster::types::KeyPurpose::Transport && entry.value == key.as_bytes()
        });
        if !names_key {
            return false;
        }
        let kept = member.lock().ok().and_then(|mut light| {
            light.member_mut().learn_shown(shown).ok()?;
            Some(light.member().clone())
        });
        let Some(kept) = kept else { return false };
        self.keep_light(&kept).await;
        self.enforce_roster().await;
        true
    }

    /// Whether this node is a light member's.
    #[must_use]
    pub fn is_light(&self) -> bool {
        self.light().is_some()
    }

    /// What a light member's transport starts with: the compact evidence it
    /// shows, and how it judges the compact evidence its peers show. `None`
    /// for a full member.
    ///
    /// A peer is believed against a root this member remembers, and nothing
    /// else: a root it does not is caught up to first, as the session opens
    /// ([`Self::catching_up`]). It used to be shown with the evidence, and a
    /// root one step ahead adopted here; it was most of what opening a session
    /// cost, for a root the member nearly always held already
    /// (`daemon::simulator`).
    #[must_use]
    pub fn light_binding(&self) -> Option<(Vec<u8>, transport_convesso::node::Judge)> {
        let light = self.light()?;
        let shown = light.lock().ok()?.member().shown();
        let judging = Arc::clone(&light);
        let judge: transport_convesso::node::Judge =
            Arc::new(move |shown| judging.lock().is_ok_and(|light| light.judge(shown)));
        Some((shown, judge))
    }

    /// How a light member catches up while a session opens, on a root its
    /// peer's evidence rests on that it knows nothing of: it asks that peer
    /// for the roots after its own, takes them, and judges the evidence again.
    /// `None` for a full member.
    ///
    /// Without it, a member that missed roots refused every member holding
    /// them, and had nobody left to ask (testbed, 18.1).
    #[must_use]
    pub fn catching_up(&self) -> Option<transport::session::CatchingUp> {
        let light = self.light()?;
        let asking = Arc::clone(&light);
        let behind: transport::session::Behind =
            Arc::new(move |shown: &[u8]| asking.lock().ok()?.behind(shown));
        let upkeep = Arc::clone(&self.upkeep);
        let born = self.born;
        let take: transport::session::TakeRoots = Arc::new(move |shown: &[u8], roots: &[u8]| {
            let now = u64::try_from(born.elapsed().as_millis()).unwrap_or(u64::MAX);
            let taken = light.lock().is_ok_and(|mut light| light.take_roots(shown, roots, now));
            if taken {
                // Kept, and what it stands on asked, by the upkeep.
                upkeep.notify_one();
            }
            taken
        });
        Some(transport::session::CatchingUp { behind, take })
    }

    /// Reads the roster, as a full member holds it: `None` for a light node,
    /// which holds none.
    pub async fn read_roster<T>(
        &self,
        read: impl FnOnce(&roster::roster::Roster) -> T,
    ) -> Option<T> {
        if self.is_light() {
            return None;
        }
        Some(read(self.syncer.lock().await.roster()))
    }

    /// What a full member answers a light member that cannot place its root:
    /// the roots it took after the one named, as many as the room its answer
    /// has, which is what the asking peer takes.
    pub fn roots_source(self: &Arc<Self>) -> transport::session::RootsAfter {
        let node = Arc::downgrade(self);
        Arc::new(move |since: [u8; 32], room: usize| {
            let node = node.clone();
            Box::pin(async move {
                let Some(node) = node.upgrade() else { return Vec::new() };
                let roots = node.syncer.lock().await.roster().roots_after(&since);
                crate::lookup::encode_roots_within(&roots, room)
            })
        })
    }

    /// Takes roster traffic as a light member does: roots, and nothing else.
    ///
    /// An adopted root is kept, and every open session judged again under it,
    /// so a peer it revokes is cut off now (`light_node::engine`).
    async fn received_light(&self, peer: DeviceId, body: &[u8]) {
        let Ok(roster_sync::message::Message::Snapshot(bytes)) =
            roster_sync::message::Message::decode(body)
        else {
            return;
        };
        self.tell_light(|engine, now| engine.root_pushed(peer, &bytes, now)).await;
    }

    /// Answers a lookup, as a full member: the evidence of the member asked
    /// for, against the root this node holds, or nothing.
    pub async fn answer_lookup(&self, query: &crate::lookup::Query) -> Vec<u8> {
        if self.is_light() {
            return Vec::new();
        }
        if let crate::lookup::Query::Footing(asker, held) = query {
            let recent = self.seen_lately().await;
            let syncer = self.syncer.lock().await;
            return crate::lookup::footing_of(syncer.roster(), asker, held.as_ref(), &|device| {
                recent(device)
            });
        }
        let syncer = self.syncer.lock().await;
        if let crate::lookup::Query::RootsAfter(since) = query {
            // Within what every peer takes: a microcontroller asks this too.
            return crate::lookup::encode_roots_within(
                &syncer.roster().roots_after(since),
                crate::lookup::MAX_ROOTS_ANSWER,
            );
        }
        let Ok(state) = syncer.roster().state() else { return Vec::new() };
        crate::lookup::resolve(&state, query)
            .map_or_else(Vec::new, |device| crate::snapshots::evidence_of(syncer.roster(), &device))
    }

    /// Lookup traffic from a peer: a question to answer, or, for a light
    /// member, an answer its engine awaits.
    async fn received_lookup(&self, peer: DeviceId, body: &[u8]) {
        if self.is_light() {
            self.tell_light(|engine, now| engine.lookup(peer, body, now)).await;
            return;
        }
        if let Some(crate::lookup::Message::Request { id, query }) =
            crate::lookup::Message::decode(body)
        {
            let evidence = self.answer_lookup(&query).await;
            let answer = crate::lookup::Message::Answer { id, evidence };
            self.send_to(peer, Channel::Lookup, &answer.encode()).await;
        }
    }

    /// Which devices this one was in contact with lately, or is: what a full
    /// member hands a light member first.
    async fn seen_lately(&self) -> impl Fn(&DeviceId) -> bool + use<> {
        let me = self.identity.device_id();
        let now = crate::clock::minute_now();
        let contacts = self.contacts.lock().await.clone();
        move |device: &DeviceId| {
            *device == me
                || contacts.minute(device).is_some_and(|minute| {
                    now.saturating_sub(minute) <= crate::limits::HANDED_SEEN_WITHIN_MINUTES
                })
        }
    }

    /// How many lookups, renewals and chain requests this node ever asked.
    #[must_use]
    pub fn asked(&self) -> u32 {
        self.light().and_then(|light| light.lock().ok().map(|light| light.asked())).unwrap_or(0)
    }

    /// Keeps a light member beside the identity.
    async fn keep_light(&self, member: &roster::member::LightMember) {
        let Some(paths) = self.paths() else { return };
        if !self.before_writing_light(member) {
            self.record(
                Severity::Problem,
                "state",
                "the checkpoint could not name the light member",
            )
            .await;
            return;
        }
        match crate::state::write_light(&paths, member) {
            Ok(()) => self.light_landed(member),
            Err(cause) => self.record(Severity::Problem, "state", cause).await,
        }
    }

    /// A light member's upkeep, for as long as the node runs: it carries out
    /// what its engine asks, and tells it the time when a question it asked
    /// is due. The engine renews its proof and fetches roots it missed when,
    /// and only when, an event says it owes them — a root naming it, a root it
    /// could not place, a peer telling it so, a start after a gap. Never on a
    /// clock: a quiet network costs nothing.
    pub async fn keep_up_forever(self: Arc<Self>) {
        // A start: the proof may have aged while this device was off.
        self.tell_light(|engine, now| engine.start(now)).await;
        loop {
            let Some(light) = self.light() else { return };
            let due = light.lock().ok().and_then(|engine| engine.next_deadline());
            let due =
                due.and_then(|due| self.born.checked_add(std::time::Duration::from_millis(due)));
            match due {
                Some(at) => {
                    tokio::select! {
                        () = self.upkeep.notified() => {}
                        () = tokio::time::sleep_until(at) => {}
                    }
                }
                None => self.upkeep.notified().await,
            }
            self.tell_light(|engine, now| engine.tick(now)).await;
        }
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

    /// The holes in this network's block on this device: a peer whose address
    /// falls in one is withheld here, and why.
    #[must_use]
    pub fn withheld(&self) -> Arc<Vec<crate::conflicts::Hole>> {
        self.withheld
            .lock()
            .map_or_else(|poisoned| Arc::clone(poisoned.get_ref()), |held| Arc::clone(&held))
    }

    /// Records the holes in this network's block on this device.
    pub fn set_withheld(&self, withheld: Vec<crate::conflicts::Hole>) {
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
        // The root it holds may already say it is light: a device invited as
        // light is delivered the root over its own admission, and nothing
        // arrives after to make it look again. Left full, it was answered with
        // roots it could not derive and never sent the operations behind them,
        // so it stayed behind for good — found in the testbed (18.1).
        if !self.is_light() {
            let _switched = self.become_light_if_named().await;
        }
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

    /// Where an urgent act against `target` — a revocation — should hang, and
    /// what of the target's it would void.
    ///
    /// The clock picks parents here and orders nothing: it says only which
    /// batches are recent enough that a peer may still be fetching their
    /// pieces, and a revocation naming one would wait there with it.
    pub async fn urgent_anchor(&self, target: &DeviceId) -> roster::roster::UrgentAnchor {
        self.syncer.lock().await.roster().urgent_anchor(target, crate::clock::now_ms())
    }

    /// How many operations the roster's graph holds: the recent window, once
    /// it has compacted, rather than the whole history.
    pub async fn held_operations(&self) -> usize {
        self.syncer.lock().await.roster().dag().len()
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
            snapshot: roster.snapshot().map(|held| held.body().generation),
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
        if let Some(light) = &self.light() {
            return light
                .lock()
                .map(|light| light.member().state())
                .map_err(|_| roster::Error::InvalidValue("the light member is unreadable"));
        }
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

    /// Tells the transport what this device shows a peer as a session opens:
    /// its leaf, and its proof against the root it holds with that root's
    /// hash. A light peer, holding no roster, judges this device by that
    /// alone, and catches up to a root it does not know.
    async fn refresh_evidence(&self) {
        let evidence = match &self.light() {
            Some(light) => light.lock().map_or_else(|_| Vec::new(), |light| light.member().shown()),
            None => crate::snapshots::shown_of(
                self.syncer.lock().await.roster(),
                &self.identity.device_id(),
            ),
        };
        let transport = self.transport.lock().await.clone();
        if let Some(transport) = transport {
            transport.update_evidence(evidence);
        }
    }

    /// Appends batch pieces to the pieces log, under the log's guard.
    async fn keep_pieces(&self, pieces: &[Vec<u8>]) -> crate::Result<()> {
        let Some(paths) = self.paths() else { return Ok(()) };
        let log = crate::state::Log::at(paths.pieces());
        let _guard = self.log_guard.lock().await;
        for piece in pieces {
            log.append(piece)?;
        }
        Ok(())
    }

    /// Admits the pieces of a batch authored here, and spreads them.
    ///
    /// Its header first, through [`Self::admit_without_activating`]: a piece is
    /// taken only once its header is held. Kept before they are spread, as an
    /// operation is.
    ///
    /// # Errors
    ///
    /// When the roster refuses a piece, or the pieces cannot be kept.
    pub async fn admit_pieces(&self, pieces: &[Vec<u8>]) -> crate::Result<()> {
        self.keep_pieces(pieces).await?;
        let messages = self
            .syncer
            .lock()
            .await
            .admit_local_pieces(pieces)
            .map_err(|cause| crate::Error::Refused { cause: cause.to_string() })?;
        let peers: Vec<DeviceId> = self.sessions.lock().await.keys().copied().collect();
        for message in messages {
            for peer in &peers {
                self.send_roster(*peer, message.clone()).await;
            }
        }
        self.spread_soon();
        self.enforce_roster().await;
        Ok(())
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
        // A root is signed with the attestation key, which asks nobody, so the
        // recurring pass may publish one wherever an act it did not see coming —
        // one that arrived from another admin's branch — left the state moved.
        self.attest_now().await;
        // Roots from other admins arrive through sync; whatever window they
        // close is compacted here.
        self.compact_and_keep().await;
    }

    /// Compacts beneath the newest root the roster may compact against, and
    /// keeps the result: the base it now rests on, and a log that no longer
    /// carries what the base covers.
    ///
    /// The base is written first, so a log without the operations beneath it
    /// is never left without it. The log is rewritten from what is on disk,
    /// minus exactly what compaction discarded, under the log's guard: an
    /// operation appended while this ran, admitted or not yet, stays.
    pub(crate) async fn compact_and_keep(&self) {
        let Some(paths) = self.paths() else { return };
        let (discarded, snapshot, state, batches) = {
            let mut syncer = self.syncer.lock().await;
            let roster = syncer.roster_mut();
            let before: std::collections::BTreeSet<roster::id::OperationId> =
                roster.dag().operations().iter().map(roster::sign::VerifiedOperation::id).collect();
            if !matches!(roster.compact(), Ok(discarded) if discarded > 0) {
                return;
            }
            let after: std::collections::BTreeSet<roster::id::OperationId> =
                roster.dag().operations().iter().map(roster::sign::VerifiedOperation::id).collect();
            let dag = roster.dag();
            let (Some(snapshot), Some(state)) = (dag.base_snapshot(), dag.base_state()) else {
                return;
            };
            let discarded: std::collections::BTreeSet<roster::id::OperationId> =
                before.difference(&after).copied().collect();
            // The batches whose pieces are still worth keeping: those still in
            // the window, whole or waiting. One beneath the base is in its state.
            let batches: std::collections::BTreeSet<roster::id::OperationId> = roster
                .whole_batches()
                .into_iter()
                .chain(roster.waiting_headers().into_iter().map(|(batch, _)| batch))
                .collect();
            (discarded, snapshot.clone(), state.clone(), batches)
        };

        let _guard = self.log_guard.lock().await;
        if !self.before_writing_base(snapshot.body().root) {
            self.record(Severity::Problem, "state", "the checkpoint could not name the new base")
                .await;
            return;
        }
        match self.write_base_and_rest(&paths, &snapshot, &state) {
            Ok(stored) => {
                if let Some(stored) = stored {
                    let _rested = self.syncer.lock().await.roster_mut().replace_base_state(stored);
                }
            }
            Err(cause) => {
                self.record(Severity::Problem, "state", cause).await;
                return;
            }
        }
        let kept = match self.log.read() {
            Ok(held) => held
                .into_iter()
                .filter(|bytes| {
                    roster::sign::RawOperation::decode(bytes)
                        .map_or(true, |raw| !discarded.contains(&raw.id()))
                })
                .collect::<Vec<_>>(),
            Err(cause) => {
                self.record(Severity::Problem, "state", cause).await;
                return;
            }
        };
        if let Err(cause) = self.log.rewrite(&kept) {
            self.record(Severity::Problem, "state", cause).await;
        }
        // The new base is in place: the one it replaced may leave the checkpoint.
        self.landed();
        let pieces = crate::state::Log::at(paths.pieces());
        let kept = match pieces.read() {
            Ok(held) => held
                .into_iter()
                .filter(|piece| {
                    roster::batch::BatchPiece::batch_of(piece)
                        .is_ok_and(|batch| batches.contains(&batch))
                })
                .collect::<Vec<_>>(),
            Err(cause) => {
                self.record(Severity::Problem, "state", cause).await;
                return;
            }
        };
        if let Err(cause) = pieces.rewrite(&kept) {
            self.record(Severity::Problem, "state", cause).await;
        }
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

        // To every session. The members that receive it relay it onward: it
        // carries the time it was signed, so it reads as old as it is wherever
        // it arrives.
        let message = roster_sync::message::Message::Attestation(bytes);
        let peers: Vec<DeviceId> = self.sessions.lock().await.keys().copied().collect();
        for peer in peers {
            self.send_roster(peer, message.clone()).await;
        }
        // An admin on a phone gives it to its neighbours, and they relay it: it
        // never has to meet every member.
        self.spread_soon();
    }

    /// Keeps an attestation beside the log, with the moment it arrived.
    ///
    /// Without this, freshness would last as long as the process: an attestation
    /// is not an operation and is not in the log, so a node that replayed its log
    /// would hold none — and one that re-accepted its own on start would date it
    /// from the start, which would make restarting the way out of a stale roster.
    ///
    /// Dated as the roster dated it — its receipt, moved back by the age it
    /// already had — and not by the clock at the moment of writing, which would
    /// make one relayed a week late look new again after a restart.
    pub(crate) async fn keep_attestation(&self, bytes: &[u8]) {
        let Some(paths) = self.paths() else { return };
        let (dated, since) = {
            let syncer = self.syncer.lock().await;
            (syncer.roster().attestation_received_at(), syncer.roster().freshness_since())
        };
        let at = dated.unwrap_or_else(crate::state::wall_seconds);
        if let Err(cause) = crate::state::write_attestation(&paths, bytes, at) {
            self.record(Severity::Problem, "state", cause).await;
        }
        // Where this one is also what freshness is now measured from, it is kept
        // a second time as the one that dates the roster, so that holding this
        // device's own attestation later does not lose it across a restart.
        if since.is_some()
            && since == dated
            && let Err(cause) = crate::state::write_dating_attestation(&paths, bytes, at)
        {
            self.record(Severity::Problem, "state", cause).await;
        }
    }

    /// Publishes the root of this node's state, where it is an admin and the
    /// state has moved since the root it holds.
    ///
    /// Called right after an act takes effect here, and on the recurring pass.
    /// Signed with the attestation key, which asks nobody: a root carries no
    /// decision of its own, and every full member checks it by deriving. Sent to
    /// every open session at once, so a light member hears of a revocation as
    /// soon as the admin's daemon does.
    pub(crate) async fn attest_now(&self) {
        let signed = {
            let syncer = self.syncer.lock().await;
            if !crate::snapshots::owed(syncer.roster(), &self.identity) {
                return;
            }
            crate::snapshots::sign_over_heads(syncer.roster(), &self.identity)
        };
        let bytes = match signed {
            Ok(bytes) => bytes,
            // Recorded so that a network that never gets one has a reason a
            // person can read.
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
        self.refresh_evidence().await;
        self.reconsider_carrying().await;
        self.compact_and_keep().await;

        let message = roster_sync::message::Message::Snapshot(bytes);
        let peers: Vec<DeviceId> = self.sessions.lock().await.keys().copied().collect();
        for peer in peers {
            self.send_roster(peer, message.clone()).await;
        }
        self.spread_soon();
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
    ///
    /// `None` when the session is not the one kept: it was closed, and there is
    /// nothing to serve.
    pub async fn opened(
        &self,
        session: Box<dyn Session>,
        opening: Opening,
    ) -> Option<Arc<dyn Session>> {
        let session: Arc<dyn Session> = Arc::from(session);
        let peer = session.peer();

        let replaced = {
            let mut sessions = self.sessions.lock().await;
            // **Two devices that dial each other keep the same session.** Each
            // holds two, opened in opposite directions, and "keep the newer" is
            // not the same session on both sides: each closed the one the other
            // kept, and both were left with none (`convesso-reach` 9.2). Between
            // opposite directions, both keep the one the lower id dialled.
            //
            // Only while two dials can still be crossing. A peer with the higher
            // id dials only when it holds no session with this device, so a dial
            // from it past that window means it lost the one held here, whose
            // close never arrived: kept, every dial it made was closed in favour
            // of a session it no longer had, and nothing it pushed got through
            // until this device restarted (found in the testbed, 18.1, between an
            // admin and its anchor).
            let held = self.openings.lock().ok().and_then(|openings| openings.get(&peer).copied());
            let crossing = held.is_some_and(|(held, at)| {
                held != opening && at.elapsed() < crate::limits::CROSSING_DIALS
            });
            if sessions.contains_key(&peer) && crossing && !self.keeps(opening, &peer) {
                drop(sessions);
                let _closing = session.close().await;
                return None;
            }
            let replaced = sessions.insert(peer, Arc::clone(&session));
            if let Ok(mut openings) = self.openings.lock() {
                openings.insert(peer, (opening, tokio::time::Instant::now()));
            }
            replaced
        };
        self.router.lock().await.opened(peer);
        // The one replaced is closed, not merely dropped from the table. Dropped,
        // it stayed open in the transport, since its own reader holds it, and
        // kept both its paths alive at rest for good (Linux
        // `VERIFICATION.md`, step 35).
        if let Some(old) = replaced.filter(|old| !Arc::ptr_eq(old, &session)) {
            let _closing = old.close().await;
        }
        self.active(peer);
        self.note_contact(peer).await;
        self.date_for(peer).await;

        Some(session)
    }

    /// Whether, of two sessions with `peer` opened in opposite directions, the
    /// one opened `opening` is kept: the one the device with the lower id
    /// dialled, so both sides keep the same.
    fn keeps(&self, opening: Opening, peer: &DeviceId) -> bool {
        let dialled_by_the_lower = self.identity.device_id() < *peer;
        match opening {
            Opening::Dialled => dialled_by_the_lower,
            Opening::Accepted => !dialled_by_the_lower,
        }
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
        self.send_roster(peer, message).await;
    }

    /// Sends a roster message to a peer, as that peer is to receive it.
    ///
    /// Every roster send goes through here, so a light member is never sent
    /// an operation, a piece or an offer of them, whichever path produced it;
    /// see [`roster_sync::Syncer::for_peer`].
    async fn send_roster(&self, peer: DeviceId, message: roster_sync::message::Message) {
        // A light member offers nothing: full members push roots to it.
        if self.is_light() {
            return;
        }
        let shaped = self.syncer.lock().await.for_peer(&peer, message);
        if let Some(message) = shaped {
            self.send_to(peer, Channel::Roster, &message.encode()).await;
        }
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
        let (greeting, neighbour) = {
            let syncer = self.syncer.lock().await;
            let neighbour = syncer.roster().state().is_ok_and(|state| {
                self.choices_in(&state).is_some_and(|choices| choices.could_choose(&peer))
            });
            (syncer.greeting(), neighbour)
        };
        self.send_roster(peer, greeting).await;
        // Where this device could have chosen the peer, it says so, so that the
        // peer pushes to it too. The peer checks the same rule before believing it.
        if neighbour {
            self.claim_neighbour(peer).await;
        }
    }

    /// Serves one session until it ends.
    ///
    /// **The loop that was missing.** `opened` registers a session and greets the
    /// peer; without something reading from it afterwards, a node accepts a
    /// connection and then ignores everything the far end says. Every method
    /// below it was tested — by a test that called them in order itself.
    pub async fn serve(self: Arc<Self>, session: Box<dyn Session>, opening: Opening) {
        let Some(session) = self.opened(session, opening).await else { return };
        self.serving(session).await;
    }

    /// Serves a session [`Self::opened`] registered, until it ends.
    async fn serving(self: Arc<Self>, session: Arc<dyn Session>) {
        let peer = session.peer();

        // What waited for this session is sent first, in the order it arrived,
        // whichever side opened it.
        self.release_waiting(peer).await;

        // Greeting runs beside the reading, never before it. A node that writes
        // before it reads deadlocks against a peer doing the same, and both
        // sides greet on contact by design.
        let greeter = Arc::clone(&self);
        tokio::spawn(async move { greeter.greet(peer).await });

        // A light member asks the first member it meets after starting what it
        // stands on: the parameters may have moved while it was off. Asked by
        // the upkeep, never here, where the answer would wait behind this.
        self.tell_light(|engine, now| engine.session_opened(peer, now)).await;

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
                    self.ended(&session).await;
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
                    tokio::spawn(Arc::clone(&self).serve(session, Opening::Accepted));
                }
                // A device this roster does not name. Possibly a newcomer this
                // node has not heard of yet, so it catches up; never a reason to
                // stop accepting everyone else.
                Err(transport::Error::NotAMember) => {
                    self.record(
                        Severity::Event,
                        "transport",
                        "a session from a device this roster does not name was refused",
                    )
                    .await;
                    self.catch_up();
                }
                // One connection that failed. It used to end this loop, and with it
                // every session this device would accept until it restarted: one
                // stranger, or one handshake that did not finish, was enough. The
                // loop ends only when the transport is taken away, above.
                Err(cause) => {
                    self.record(Severity::Event, "transport", cause).await;
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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

    /// The neighbours this device chooses now, skipping those that have not
    /// answered and are not yet due to be tried again.
    async fn chosen_neighbours(&self) -> Vec<DeviceId> {
        let Ok(state) = self.state().await else { return Vec::new() };
        // A light member chooses no neighbours: it keeps in touch with its
        // anchors it knows and, failing them, the admin whose root it holds.
        if let Some(member) = self.light_member() {
            let anchors: Vec<DeviceId> =
                crate::seeking::anchors_for(&member.device(), &member.params().anchors)
                    .into_iter()
                    .filter(|anchor| state.devices.contains_key(anchor))
                    .collect();
            let kept = member.known_fulls();
            let order = crate::seeking::first_start_order(
                &anchors,
                Some(member.contact()),
                &kept,
                &[],
                &[],
            );
            return order.into_iter().filter(|device| *device != member.device()).take(2).collect();
        }
        let Some(choices) = self.choices_in(&state) else {
            // Light by its own state and not yet by a root it holds — invited as
            // light, say, and up a moment after the root that makes it so went
            // out. It chooses no neighbours as a light member would, and keeps
            // in touch with the full members it would be handed, so that the
            // root reaches it.
            let me = self.identity.device_id();
            let light = state
                .devices
                .get(&me)
                .is_some_and(|leaf| leaf.settings.mode == roster::leaf::Mode::Light);
            if !light {
                return Vec::new();
            }
            let recent = self.seen_lately().await;
            let full = |device: &DeviceId| {
                state
                    .devices
                    .get(device)
                    .is_some_and(|leaf| leaf.settings.mode == roster::leaf::Mode::Full)
            };
            let anchors: Vec<DeviceId> =
                state.params.anchors.iter().filter(|anchor| full(anchor)).copied().collect();
            let fulls: Vec<DeviceId> = if anchors.is_empty() {
                state
                    .devices
                    .iter()
                    .filter(|(_, leaf)| leaf.settings.mode == roster::leaf::Mode::Full)
                    .map(|(device, _)| device)
                    .collect()
            } else {
                Vec::new()
            };
            return crate::seeking::handed(&me, &anchors, &fulls, &|device| recent(device));
        };
        let now = tokio::time::Instant::now();
        let resting: BTreeSet<DeviceId> = self.unanswered.lock().map_or_else(
            |_| BTreeSet::new(),
            |unanswered| {
                unanswered
                    .iter()
                    .filter(|(_, rest)| rest.until > now)
                    .map(|(device, _)| *device)
                    .collect()
            },
        );
        choices.choose(&state, &|device| resting.contains(device))
    }

    /// This device's neighbour choices in `state`: those kept, followed to it.
    /// `None` where this device is not a full member there.
    fn choices_in(&self, state: &RosterState) -> Option<crate::neighbours::Choices> {
        let mut kept = self.choices.lock().ok()?;
        let next = match kept.as_ref() {
            Some((previous, choices)) if previous.root() == state.root() => {
                return Some(choices.clone());
            }
            Some((previous, choices)) => choices.updated(previous, state),
            None => crate::neighbours::Choices::of(state, &self.identity.device_id()),
        };
        *kept = next.clone().map(|choices| (state.clone(), choices));
        next
    }

    /// Tries the members this device holds no session with, because a person
    /// asked about them.
    ///
    /// In parallel, at most `at_most` of them, each given `within` to answer. A
    /// member that answers has a session afterwards, and is reported reachable
    /// with the path it used; one that does not is reported by its last contact.
    pub async fn probe(self: &Arc<Self>, within: std::time::Duration, at_most: usize) {
        let Ok(state) = self.state().await else { return };
        let me = self.identity.device_id();
        let mut keys = Vec::new();
        for record in state.devices.values() {
            if keys.len() >= at_most {
                break;
            }
            if record.id == me
                || state.revoked.contains(&record.id)
                || self.has_session(&record.id).await
            {
                continue;
            }
            if let Some(key) = transport_key_of(&record) {
                keys.push((record.id, key));
            }
        }
        let attempts: Vec<_> = keys
            .into_iter()
            .map(|(device, key)| {
                let node = Arc::clone(self);
                tokio::spawn(async move {
                    // A session that opened registers on its own task; it is
                    // waited for here, within the same bound, so the report
                    // built next sees it.
                    let _answered = tokio::time::timeout(within, async {
                        if node.connect(&key).await.is_ok() {
                            while !node.has_session(&device).await {
                                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                            }
                        }
                    })
                    .await;
                })
            })
            .collect();
        for attempt in attempts {
            let _finished = attempt.await;
        }
    }

    /// The periodic safety net, and the contact a device makes on its way up.
    ///
    /// Every open session, and every neighbour this device chose, is sent the
    /// digest of what it holds; a neighbour with no open session is contacted for
    /// it. Where the digests agree that is the whole exchange. A neighbour that
    /// does not answer is rested — a minute, then twice as long each time, up to
    /// six hours — and its slot moves to the next member meanwhile.
    ///
    /// Nobody else is contacted: a member that is merely in the roster is never
    /// dialled for being there.
    pub async fn reconcile_with_neighbours(self: &Arc<Self>) {
        tracing::info!(network = %self.called, "reconciling with the neighbours");
        self.offer_to_everyone().await;
        // Only the neighbours this device chose: those that chose it run the same
        // check toward it.
        self.contact_neighbours(false).await;
    }

    /// How long to wait after an admission before contacting the neighbours, so
    /// that a burst of admissions makes one round of contact.
    pub const SPREAD_PAUSE: std::time::Duration = std::time::Duration::from_secs(2);

    /// Says that something new was admitted and the neighbours should have it.
    fn spread_soon(&self) {
        self.spreading.notify_one();
    }

    /// Contacts the neighbours after every admission, a short pause after the
    /// first of a burst, for as long as the node runs.
    ///
    /// Contact is all a push to a neighbour with no open session needs: the
    /// session greets with a digest on opening, and whatever the neighbour lacks
    /// follows. Neighbours with a session open were sent the operation already.
    pub async fn spread_forever(self: Arc<Self>) {
        loop {
            self.spreading.notified().await;
            tokio::time::sleep(Self::SPREAD_PAUSE).await;
            tracing::info!(network = %self.called, "spreading to the neighbours");
            self.contact_neighbours(true).await;
        }
    }

    /// Opens contact with every neighbour that has no session: the three this
    /// device chose and, where `mutual`, those that chose it.
    async fn contact_neighbours(self: &Arc<Self>, mutual: bool) {
        // A roster that derives nothing has no members to be neighbours with, and
        // saying why is the business of whatever asks for the state to show it.
        let Ok(state) = self.state().await else { return };
        let mut neighbours: BTreeSet<DeviceId> =
            self.chosen_neighbours().await.into_iter().collect();
        if mutual {
            neighbours.extend(self.in_neighbours().await);
        }
        for device in neighbours {
            if self.has_session(&device).await || state.revoked.contains(&device) {
                continue;
            }
            let Some(key) = state.devices.get(&device).and_then(|leaf| transport_key_of(&leaf))
            else {
                continue;
            };
            // The session greets on opening, and says it comes from a neighbour.
            match self.connect(&key).await {
                Ok(()) => {
                    if let Ok(mut unanswered) = self.unanswered.lock() {
                        unanswered.remove(&device);
                    }
                }
                Err(cause) => {
                    self.rest(device);
                    self.record(Severity::Event, "neighbours", format!("{device:?}: {cause}"))
                        .await;
                }
            }
        }
    }

    /// Rests a neighbour that did not answer: twice as long as last time, from a
    /// minute up to six hours.
    pub(crate) fn rest(&self, device: DeviceId) {
        const FIRST: std::time::Duration = std::time::Duration::from_secs(60);
        const LONGEST: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);
        let Ok(mut unanswered) = self.unanswered.lock() else { return };
        let now = tokio::time::Instant::now();
        let entry = unanswered.entry(device).or_insert(Rest { interval: FIRST, until: now });
        entry.until = now.checked_add(entry.interval).unwrap_or(now);
        entry.interval = entry.interval.saturating_mul(2).min(LONGEST);
    }
}

/// Whether a session between this device and a peer stays open however long
/// it carries nothing: where either is a light member.
///
/// A session nothing uses costs nothing on the wire: convesso lets its keys
/// expire and forgets it, and this binding's session outlives that, reopened
/// by the next frame either side sends. Kept open, it is how a light member
/// hears of a new root the moment a full member takes it, pushed as anything
/// new is; closed, it heard only when it next came asking, once an hour,
/// which cost every light member a session opened and evidence shown both ways
/// each hour, whether the network had changed or not (`daemon::simulator`).
/// Between full members nothing changes: they are pushed to as neighbours.
#[must_use]
pub(crate) const fn held_open(this_light: bool, peer_light: bool) -> bool {
    this_light || peer_light
}

/// Dials in flight, by the peer's transport key, each with where its outcome
/// will be told.
type InFlight = BTreeMap<Vec<u8>, watch::Receiver<Option<crate::Result<()>>>>;

/// The dial in flight to one peer, taken out of the table when it ends,
/// however it ends: one abandoned half-way would otherwise hold every later
/// dial to that peer waiting for ever.
struct Leading<'a> {
    dialling: &'a std::sync::Mutex<InFlight>,
    key: Vec<u8>,
}

impl Drop for Leading<'_> {
    fn drop(&mut self) {
        if let Ok(mut dialling) = self.dialling.lock() {
            dialling.remove(&self.key);
        }
    }
}

/// Which way a session was opened, as seen from this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opening {
    /// This node dialled.
    Dialled,
    /// The peer dialled, and this node accepted.
    Accepted,
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

/// The UDP source port of an IPv4 or IPv6 packet, where it is one.
///
/// IPv6 extension headers are not walked: a packet carrying them is not UDP as
/// far as this is concerned, and is treated as the machine's own traffic, which
/// is the direction that costs nothing but an attempt.
fn udp_source_port(packet: &[u8]) -> Option<u16> {
    const UDP: u8 = 17;
    let version = packet.first()? >> 4;
    let offset = match version {
        4 => {
            if *packet.get(9)? != UDP {
                return None;
            }
            usize::from(packet.first()? & 0x0f).checked_mul(4)?
        }
        6 => {
            if *packet.get(6)? != UDP {
                return None;
            }
            40
        }
        _ => return None,
    };
    let high = *packet.get(offset)?;
    let low = *packet.get(offset.checked_add(1)?)?;
    Some(u16::from_be_bytes([high, low]))
}

/// A device's transport key, as the roster declares it.
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
        self.refresh_evidence().await;
        if !self.is_light() && self.become_light_if_named().await {
            return;
        }

        // Addresses follow membership in the same place. A device admitted
        // since the tunnel came up becomes routable at its IPv4 address now, and
        // a device revoked stops being so, rather than at the next restart.
        // Held until the holdings are sent: what the next change is measured
        // from and what the holdings say must be the same state's.
        let mut enforced = self.enforced.lock().await;
        let previous = enforced.replace(state.clone());
        let holdings = match &previous {
            Some(previous) => self.holdings.borrow().updated(previous, &state),
            None => Ipv4Holdings::of_state(&state),
        };
        self.gateway.set_holdings(holdings.clone());
        {
            let mut router = self.router.lock().await;
            router.set_holdings(holdings.clone());
            router.follow_state(&state, &self.identity.device_id());
        }
        self.holdings.send_if_modified(|current| {
            if **current == holdings {
                false
            } else {
                *current = Arc::new(holdings);
                true
            }
        });
        drop(enforced);
        if let Some(previous) = &previous {
            self.tell_lost_offsets(previous, &state).await;
        }

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

    /// Tells an admin of each device that lost its IPv4 offset to another
    /// given it at the same time (`admitting::lost_offsets`).
    async fn tell_lost_offsets(&self, previous: &RosterState, state: &RosterState) {
        let me = self.identity.device_id();
        for said in crate::admitting::lost_offsets(previous, state, &me) {
            self.record(Severity::Event, "ipv4", said).await;
        }
    }

    /// Drops what is kept about devices that are no longer there to keep it for.
    ///
    /// Last contact is kept for revoked devices as well as members. When a stolen
    /// laptop last spoke to this device is exactly what a person wants to know,
    /// and it cannot change once the device is revoked: its session is closed
    /// here and refused afterwards.
    async fn forget_departed(&self, state: &RosterState) {
        // Asked of the state for each device held, rather than by listing every
        // member: what is held is what this device spoke to, a few at most.
        let member = |device: &DeviceId| state.devices.contains_key(device);
        let kept = |device: &DeviceId| member(device) || state.revoked.contains(device);
        let changed = self.contacts.lock().await.retain(kept);
        if changed {
            self.save_contacts().await;
        }
    }

    /// Forgets a session that has ended — only if it is still the one held.
    ///
    /// A session closed for being idle ends on its own task a moment later. By
    /// then the next packet may have opened a new one to the same device, and
    /// forgetting by device would forget the new one in its place. Sessions are
    /// opened on demand, so that is the ordinary sequence, not a corner case.
    async fn ended(&self, session: &Arc<dyn Session>) {
        let peer = session.peer();
        let current =
            self.sessions.lock().await.get(&peer).is_some_and(|held| Arc::ptr_eq(held, session));
        if current {
            self.closed(&peer).await;
        }
    }

    /// Forgets the session held with a device, whichever one it is.
    pub async fn closed(&self, peer: &DeviceId) {
        if let Some(light) = self.light()
            && let Ok(mut engine) = light.lock()
        {
            engine.session_closed(peer);
        }
        self.router.lock().await.closed(peer);
        self.sessions.lock().await.remove(peer);
        if let Ok(mut openings) = self.openings.lock() {
            openings.remove(peer);
        }
        if let Ok(mut activity) = self.activity.lock() {
            activity.remove(peer);
        }
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

    /// The devices this node has a session with now: few, whatever the
    /// network's size.
    pub async fn session_peers(&self) -> Vec<DeviceId> {
        self.sessions.lock().await.keys().copied().collect()
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
        self.active(peer);
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
            Channel::Neighbour => self.received_neighbour_claim(peer).await,
            Channel::Lookup => self.received_lookup(peer, body).await,
        }
    }

    /// The members that chose this device as a neighbour, as far as it knows.
    pub async fn in_neighbours(&self) -> BTreeSet<DeviceId> {
        self.in_neighbours.lock().await.clone()
    }

    /// Tells a peer this device contacted it as one of its neighbours.
    pub async fn claim_neighbour(&self, peer: DeviceId) {
        self.send_to(peer, Channel::Neighbour, &[]).await;
    }

    /// A peer says it chose this device as a neighbour.
    ///
    /// Believed only where the roster says it could have: anyone could claim it,
    /// and a member believed on its word alone could make itself everybody's
    /// neighbour. Kept beside the log once believed, so a restart still pushes
    /// to it.
    async fn received_neighbour_claim(&self, peer: DeviceId) {
        let holds = {
            let syncer = self.syncer.lock().await;
            syncer.roster().state().is_ok_and(|state| {
                crate::neighbours::claim_holds_in(&state, &peer, &self.identity.device_id())
            })
        };
        if !holds {
            self.record(
                Severity::Event,
                "neighbours",
                format!("{peer:?} claimed to be a neighbour, and the roster says it could not be"),
            )
            .await;
            return;
        }
        let snapshot = {
            let mut held = self.in_neighbours.lock().await;
            if !held.insert(peer) {
                return;
            }
            held.clone()
        };
        if let Some(paths) = self.paths()
            && let Err(cause) = crate::state::write_in_neighbours(&paths, &snapshot)
        {
            self.record(Severity::Problem, "state", cause).await;
        }
    }

    /// Roster bytes from a peer.
    async fn received_roster(&self, peer: DeviceId, body: &[u8]) {
        // The peer spoke. Roster traffic and not packets: the re-offer arrives
        // every minute from both sides, which is the granularity kept, and a lock
        // taken per packet would be paid on the path that carries everything.
        self.note_contact(peer).await;

        if self.is_light() && !self.becoming_full.load(std::sync::atomic::Ordering::SeqCst) {
            self.received_light(peer, body).await;
            return;
        }
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
        let based = reception.base.is_some();
        // A base obtained from a peer, before the heads it rests on are logged:
        // replayed, the log rests on it, as on one this node compacted to.
        if let Some((snapshot, state)) = &reception.base
            && let Some(paths) = self.paths()
        {
            let written = if self.before_writing_base(snapshot.body().root) {
                let _guard = self.log_guard.lock().await;
                self.write_base_and_rest(&paths, snapshot, state)
            } else {
                Err(crate::error::Error::State {
                    path: paths.base_store(),
                    cause: "the checkpoint could not name the base".to_owned(),
                })
            };
            match written {
                Ok(stored) => {
                    self.landed();
                    if let Some(stored) = stored {
                        let _rested =
                            self.syncer.lock().await.roster_mut().replace_base_state(stored);
                    }
                }
                Err(cause) => self.record(Severity::Problem, "state", cause).await,
            }
        }
        for operation in &reception.accepted {
            let appended = {
                let _guard = self.log_guard.lock().await;
                self.log.append(operation)
            };
            if let Err(cause) = appended {
                self.record(Severity::Problem, "state", cause).await;
            }
        }
        if based {
            self.finish_full().await;
        }
        // And the batch pieces taken, beside the log: a batch's entries live
        // in them, and a restart without them would leave its header waiting.
        if !reception.pieces.is_empty()
            && let Err(cause) = self.keep_pieces(&reception.pieces).await
        {
            self.record(Severity::Problem, "state", cause).await;
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

        for message in reception.replies {
            self.send_roster(peer, message).await;
        }
        if let Some(forward) = reception.forward {
            let others: Vec<DeviceId> =
                self.sessions.lock().await.keys().copied().filter(|other| *other != peer).collect();
            for other in others {
                self.send_roster(other, forward.clone()).await;
            }
            self.spread_soon();
        }

        // A revocation that arrived from a peer takes effect here, on the
        // sessions already open, and not at some later reconnection.
        self.enforce_roster().await;
    }

    /// A packet from a peer, as the session's packet channel delivered it.
    pub async fn received_packet(&self, peer: DeviceId, body: &[u8]) {
        self.active(peer);
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
    pub async fn carry_one(self: &Arc<Self>) -> crate::Result<Departure> {
        // The packet first, holding nothing. Waiting for the machine to send
        // something takes as long as it takes, and a lock held across that wait
        // is held for the same time — which deadlocked every new session against
        // an idle read.
        let packet = self.gateway.take().await?;

        // The transport's own probe of an address a member advertised inside its
        // tunnel. Never carried, session or not: through a session it would keep
        // that session busy for ever, so it would never close for being idle, and
        // without one it would open one. The path selector refuses such a path
        // anyway.
        if self.is_own_transports(&packet).await {
            return Ok(Departure::Refused(tunnel::Outbound::DestinationOffNetwork {
                destination: tunnel::destination_of(&packet)
                    .unwrap_or(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
            }));
        }

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
                // A member with no session: the packet waits, and the first one
                // to wait opens the session. An address no member holds has
                // nowhere to go.
                let member = self.router.lock().await.member_at(*destination);
                match member {
                    // A member a packet failed to reach moments ago: dropped
                    // until the rest is over, not another attempt.
                    Some(device) if self.resting_after_failure(&device) => {}
                    Some(device) => {
                        if self.hold_for(device, packet.clone()).await {
                            tokio::spawn(Arc::clone(self).open_for_waiting(device));
                        }
                    }
                    None => {
                        self.record(
                            Severity::Event,
                            "tunnel",
                            format!("no member at {destination}"),
                        )
                        .await;
                    }
                }
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

    /// Puts a packet in a member's waiting queue, and says whether it is the
    /// first, so that the caller opens the session exactly once.
    ///
    /// Beyond the bound the packet is dropped and counted, never queued: a member
    /// that does not answer holds no more than the bound however much is sent.
    async fn hold_for(&self, device: DeviceId, packet: Vec<u8>) -> bool {
        let mut waiting = self.waiting.lock().await;
        let first = !waiting.contains_key(&device);
        let queue = waiting.entry(device).or_default();
        let fits = queue.packets.len() < crate::limits::MAX_WAITING_PACKETS
            && queue.bytes.saturating_add(packet.len()) <= crate::limits::MAX_WAITING_BYTES;
        if fits {
            queue.bytes = queue.bytes.saturating_add(packet.len());
            queue.packets.push_back(packet);
        } else {
            queue.dropped = queue.dropped.saturating_add(1);
        }
        first
    }

    /// Opens a session for the packets waiting for `device`.
    ///
    /// The session, once open, sends them itself (see [`Self::serve`]). A dial
    /// that fails drops them, and the failure is recorded once for the attempt,
    /// not once for every packet that was waiting.
    async fn open_for_waiting(self: Arc<Self>, device: DeviceId) {
        let key = {
            let syncer = self.syncer.lock().await;
            syncer.roster().state().ok().and_then(|state| {
                state.devices.get(&device).and_then(|leaf| transport_key_of(&leaf))
            })
        };
        let outcome = match key {
            Some(key) => self.connect(&key).await,
            None => Err(crate::Error::Unreachable {
                cause: "the roster declares no transport key for it".to_owned(),
            }),
        };
        if let Err(cause) = outcome {
            self.rest_after_failure(device);
            let dropped = self.waiting.lock().await.remove(&device);
            let count =
                dropped.map_or(0, |queue| queue.packets.len().saturating_add(queue.dropped));
            self.record(
                Severity::Event,
                "tunnel",
                format!("{count} packets for {device:?} were dropped: {cause}"),
            )
            .await;
        }
    }

    /// Whether a packet is the transport's own: UDP from a port it sends from.
    async fn is_own_transports(&self, packet: &[u8]) -> bool {
        let Some(source) = udp_source_port(packet) else { return false };
        let Some(transport) = self.transport().await else { return false };
        transport.own_ports().contains(&source)
    }

    /// Whether packets for `device` are being dropped after a failed attempt.
    pub(crate) fn resting_after_failure(&self, device: &DeviceId) -> bool {
        let now = tokio::time::Instant::now();
        self.unreached
            .lock()
            .is_ok_and(|unreached| unreached.get(device).is_some_and(|rest| rest.until > now))
    }

    /// The first rest after a failed on-demand attempt, and the longest.
    pub const UNREACHED_FIRST: std::time::Duration = std::time::Duration::from_secs(30);
    /// See [`Self::UNREACHED_FIRST`].
    pub const UNREACHED_LONGEST: std::time::Duration = std::time::Duration::from_secs(10 * 60);

    /// Ends whatever rest `device` is on, because it has just announced itself
    /// on the local network: there is news about where it is, and a rest earned
    /// before it says nothing about now.
    ///
    /// **Dials nothing.** The next packet for it, or the next round of
    /// neighbours, tries it again: sessions stay on demand. A member that
    /// announces itself and still cannot be reached costs one attempt an
    /// announcement, which on a quiet network is one a minute.
    pub fn announced(&self, device: DeviceId) {
        if let Ok(mut unreached) = self.unreached.lock() {
            unreached.remove(&device);
        }
        if let Ok(mut unanswered) = self.unanswered.lock() {
            unanswered.remove(&device);
        }
    }

    /// Rests a member a packet failed to reach: half a minute, then twice as long
    /// each time, up to ten minutes. A session opening ends it, and so does the
    /// member announcing itself ([`Self::announced`]).
    pub(crate) fn rest_after_failure(&self, device: DeviceId) {
        let Ok(mut unreached) = self.unreached.lock() else { return };
        let now = tokio::time::Instant::now();
        let entry =
            unreached.entry(device).or_insert(Rest { interval: Self::UNREACHED_FIRST, until: now });
        entry.until = now.checked_add(entry.interval).unwrap_or(now);
        entry.interval = entry.interval.saturating_mul(2).min(Self::UNREACHED_LONGEST);
    }

    /// Sends what waited for a session that has just opened, in order.
    async fn release_waiting(&self, peer: DeviceId) {
        // Reached: whatever rest it was on is over.
        if let Ok(mut unreached) = self.unreached.lock() {
            unreached.remove(&peer);
        }
        let Some(queue) = self.waiting.lock().await.remove(&peer) else { return };
        for packet in queue.packets {
            self.send_packet_to(peer, &packet).await;
        }
        if queue.dropped > 0 {
            self.record(
                Severity::Event,
                "tunnel",
                format!(
                    "{} packets for {peer:?} arrived while its session opened and did not fit",
                    queue.dropped
                ),
            )
            .await;
        }
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
        {
            let _guard = self.log_guard.lock().await;
            self.log.append(bytes)?;
        }

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
            for peer in peers {
                self.send_roster(peer, message.clone()).await;
            }
            // And the neighbours with no session, which is every operation and
            // not only a revocation: one is rare, so pushing it costs something
            // only when it happens.
            self.spread_soon();
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
        drop(syncer);

        crate::describing::Membership { directory, revoked, accused, contacts }
    }

    /// Sends this node's digest to every open session.
    ///
    /// Part of [`Self::reconcile_with_neighbours`]: two nodes that stay connected
    /// for hours still notice a revocation made elsewhere, at the cost of a few
    /// dozen bytes each way when they already agree.
    pub async fn offer_to_everyone(&self) {
        let offer = self.syncer.lock().await.greeting();
        let peers: Vec<DeviceId> = self.sessions.lock().await.keys().copied().collect();
        for peer in peers {
            self.send_roster(peer, offer.clone()).await;
        }
    }

    /// Sends to one peer, recording rather than propagating a failure.
    async fn send_to(&self, peer: DeviceId, channel: Channel, payload: &[u8]) {
        let session = self.sessions.lock().await.get(&peer).map(Arc::clone);
        let Some(session) = session else {
            self.record(Severity::Event, "session", format!("no session for {peer:?}")).await;
            return;
        };
        match session.send(&frame(channel, payload)).await {
            Ok(()) => self.active(peer),
            Err(cause) => self.record(Severity::Event, "session", cause).await,
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
            Ok(()) => self.active(peer),
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

    /// Opens a session with a peer named by its transport key.
    ///
    /// # Errors
    ///
    /// When the peer cannot be reached, or the roster does not name it.
    ///
    /// Refused as not a member — this device may have been admitted moments ago,
    /// and the peer not have heard yet — it tries again after
    /// [`Self::NEWCOMER_RETRY`], up to [`Self::NEWCOMER_ATTEMPTS`] times, while
    /// the peer catches up with its own neighbours. Over a real connection the
    /// refusal can arrive as the peer closing it, so that is retried the same way.
    ///
    /// **One dial to a peer at a time.** A caller that finds one in flight waits
    /// for its outcome and is told the same. The session a dial opens is
    /// registered before the dial is done, so a caller that comes after it
    /// finds the session.
    pub async fn connect(self: &Arc<Self>, peer: &roster::sign::PublicKey) -> crate::Result<()> {
        let key = peer.as_bytes().to_vec();
        loop {
            let turn = {
                let Ok(mut dialling) = self.dialling.lock() else {
                    return self.dial_once(peer).await;
                };
                match dialling.get(&key) {
                    Some(in_flight) => Err(in_flight.clone()),
                    None => {
                        let (tell, told) = watch::channel(None);
                        dialling.insert(key.clone(), told);
                        Ok(tell)
                    }
                }
            };
            match turn {
                Ok(tell) => {
                    let _leading = Leading { dialling: &self.dialling, key: key.clone() };
                    let outcome = self.dial_once(peer).await;
                    tell.send_replace(Some(outcome.clone()));
                    return outcome;
                }
                Err(mut in_flight) => {
                    // A dial abandoned before it finished told nothing: this
                    // caller dials itself.
                    if let Ok(told) = in_flight.wait_for(Option::is_some).await
                        && let Some(outcome) = told.clone()
                    {
                        return outcome;
                    }
                }
            }
        }
    }

    /// Dials a peer once, retrying only a refusal from a peer that may be behind.
    async fn dial_once(self: &Arc<Self>, peer: &roster::sign::PublicKey) -> crate::Result<()> {
        // Retried only toward a device this roster names: then a refusal means
        // the other side is the one behind. A device this side does not know
        // either is a stranger to both, and insisting would only delay saying so.
        let known = self.state().await.is_ok_and(|state| {
            state
                .device_for_key_of_purpose(&peer.key_id(), roster::types::KeyPurpose::Transport)
                .is_some_and(|record| !state.revoked.contains(&record.id))
        });
        let mut attempt = 0usize;
        loop {
            let transport = self.transport.lock().await.clone().ok_or(crate::Error::NotUp)?;
            match transport.connect(peer).await {
                Ok(session) => {
                    if let Some(session) = self.opened(session, Opening::Dialled).await {
                        tokio::spawn(Arc::clone(self).serving(session));
                    }
                    return Ok(());
                }
                Err(refusal @ (transport::Error::NotAMember | transport::Error::ClosedByPeer))
                    if known && attempt < Self::NEWCOMER_ATTEMPTS =>
                {
                    // It may be this side that is behind, about the peer.
                    if matches!(refusal, transport::Error::NotAMember) {
                        self.catch_up();
                        // A light member refused as a stranger: the peer does not
                        // believe its proof any more, which is the peer asking
                        // it to renew.
                        // Told, and left to the upkeep: this dial may be one the
                        // upkeep itself is making, which would wait on itself.
                        if let Some(light) = self.light() {
                            let now = self.now_ms();
                            if let Ok(mut engine) = light.lock() {
                                engine.refused_as_a_stranger(now);
                            }
                            self.upkeep.notify_one();
                        }
                    }
                    attempt = attempt.saturating_add(1);
                    tokio::time::sleep(Self::NEWCOMER_RETRY).await;
                }
                Err(cause) => return Err(crate::Error::Unreachable { cause: cause.to_string() }),
            }
        }
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

        tokio::spawn(Arc::clone(self).serve(session, Opening::Accepted));
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

    /// **Nobody is dialled for being in the roster.** A session is opened for
    /// one of four reasons, and each is a function here: a packet that needs one,
    /// a neighbour, an operation still owed to a member, a person asking about a
    /// member. A fifth caller of `connect` is a fifth reason, and has to be added
    /// here on purpose — which is the point: the minute-by-minute dialling of
    /// every member was one line in a loop, and it cost gigabytes a month.
    #[test]
    fn only_four_reasons_open_a_session() {
        const REASONS: &[&str] = &["open_for_waiting", "contact_neighbours", "dial", "probe"];
        let code = crate::code_of(include_str!("node.rs"));
        let mut callers = std::collections::BTreeSet::new();
        for (at, _) in code.match_indices("self.connect(&") {
            let before = code.get(..at).unwrap_or_default();
            let start = before.rfind("fn ").expect("inside a function");
            let name: String = code
                .get(start + 3..)
                .unwrap_or_default()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            callers.insert(name);
        }
        for caller in &callers {
            assert!(
                REASONS.contains(&caller.as_str()),
                "`{caller}` opens sessions, and is not one of the reasons a session is opened"
            );
        }
        assert!(!code.contains("fn dial_missing"), "dialling every member is gone");
    }

    /// The UDP source port is read from both families, and nothing else is
    /// taken for UDP.
    #[test]
    fn a_packets_udp_source_port_is_read() {
        let mut v4 = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0];
        v4.extend_from_slice(&[100, 64, 0, 1, 100, 64, 0, 2]);
        v4.extend_from_slice(&[0xda, 0x8c, 0, 53, 0, 8, 0, 0]);
        assert_eq!(super::udp_source_port(&v4), Some(0xda8c));

        let mut v6 = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
        v6.extend_from_slice(&[0u8; 32]);
        v6.extend_from_slice(&[0x12, 0x34, 0, 53, 0, 8, 0, 0]);
        assert_eq!(super::udp_source_port(&v6), Some(0x1234));

        let mut tcp = v4.clone();
        if let Some(protocol) = tcp.get_mut(9) {
            *protocol = 6;
        }
        assert_eq!(super::udp_source_port(&tcp), None, "TCP is not UDP");
        assert_eq!(super::udp_source_port(&[]), None);
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
    use std::sync::Arc;

    use identity::NodeIdentity;
    use roster::id::{DeviceId, NetworkId};
    use roster::roster::Roster;
    use roster::sign::{VerifiedOperation, sign_operation};
    use roster::types::{NetworkParams, OperationBody, OperationCore, Role};
    use roster_sync::Syncer;
    use tunnel::{Prefix, Tunnel as Rules};

    use super::Node;
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
        let mut roster = Roster::with_clock(Box::new(crate::state::WallClock));
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
        let directory = crate::describing::Directory::of(&state, &valid);
        let expected_accused = crate::describing::accused(&directory, &roster);
        let expected_revoked =
            crate::describing::revoked(&directory, &state, &valid, &LastContacts::default());

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
        assert!(
            expected_revoked.len() >= 10,
            "the fixture really does revoke: {}",
            expected_revoked.len()
        );
    }

    /// The node's own sources copy no operation to build the report.
    #[test]
    fn no_operation_is_copied_to_build_the_report() {
        let code = crate::code_of(include_str!("node.rs"));
        for function in ["pub(crate) async fn membership("] {
            let (_, rest) = code.split_once(function).unwrap();
            let body = rest.split("\nasync fn ").next().unwrap_or(rest);
            let body = body.split("\npub(crate) async fn ").next().unwrap_or(body);
            let body = body.split("\npub async fn ").next().unwrap_or(body);
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
    /// A node of a large network, founded by `founder`, with its log in `dir`.
    fn a_node_of(
        founder: &Arc<NodeIdentity>,
        dir: &std::path::Path,
    ) -> (Node, roster::state::RosterState) {
        let roster = a_history(founder);
        let state = roster.state().unwrap();
        let prefix = Prefix::from_parameter(&state.params.ula).unwrap();
        let node = Node::new(
            Arc::clone(founder),
            Syncer::new(roster),
            Arc::new(Gateway::new(Rules::new(prefix, founder.device_id()))),
            Router::new(prefix),
            Log::at(dir.join("roster.log")),
            Schedule::provisional(),
        );
        (node, state)
    }

    /// A member's claim to have chosen this device as a neighbour, where the
    /// roster says it could have, is kept — and kept across a restart, so the
    /// device still pushes to it.
    #[tokio::test]
    async fn a_valid_neighbour_claim_is_kept_across_a_restart() {
        let founder = Arc::new(NodeIdentity::generate().unwrap());
        let scratch = tempfile::tempdir().unwrap();
        let (node, state) = a_node_of(&founder, scratch.path());
        let members = crate::neighbours::members_of(&state);
        let me = founder.device_id();
        let claimant = members
            .iter()
            .map(|member| member.device)
            .find(|device| {
                *device != me
                    && crate::neighbours::claim_holds(&state.network, device, &me, &members)
            })
            .expect("some member could have chosen the founder");

        node.received(claimant, &crate::channel::frame(crate::channel::Channel::Neighbour, &[]))
            .await;
        assert!(node.in_neighbours().await.contains(&claimant));

        drop(node);
        let (restarted, _) = a_node_of(&founder, scratch.path());
        assert!(restarted.in_neighbours().await.contains(&claimant), "kept beside the log");
    }

    /// A claim the roster says could not be true is ignored: otherwise any member
    /// could make itself everybody's neighbour.
    #[tokio::test]
    async fn a_false_neighbour_claim_is_ignored() {
        let founder = Arc::new(NodeIdentity::generate().unwrap());
        let scratch = tempfile::tempdir().unwrap();
        let (node, state) = a_node_of(&founder, scratch.path());
        let members = crate::neighbours::members_of(&state);
        let me = founder.device_id();
        let liar = members
            .iter()
            .map(|member| member.device)
            .find(|device| {
                *device != me
                    && !crate::neighbours::claim_holds(&state.network, device, &me, &members)
            })
            .expect("most members could not have chosen the founder");

        node.received(liar, &crate::channel::frame(crate::channel::Channel::Neighbour, &[])).await;
        assert!(!node.in_neighbours().await.contains(&liar));
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

    /// A transport whose dials wait until released and then fail, counting
    /// them.
    #[derive(Default)]
    struct Held {
        dialled: AtomicUsize,
        release: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl Transport for Held {
        async fn connect(
            &self,
            _peer: &roster::sign::PublicKey,
        ) -> transport::Result<Box<dyn transport::Session>> {
            self.dialled.fetch_add(1, Ordering::SeqCst);
            self.release.notified().await;
            Err(transport::Error::PeerUnreachable { cause: None })
        }

        async fn accept(&self) -> transport::Result<Box<dyn transport::Session>> {
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
        let mut roster = Roster::with_clock(Box::new(crate::state::WallClock));
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

    /// **Two dials to one peer at once are one dial, and both callers are told
    /// its outcome.** Two in flight opened two sessions in the same direction,
    /// and the two sides kept different ones (`convesso-reach` 5.4).
    #[tokio::test]
    async fn two_dials_to_one_peer_at_once_are_one() {
        let (node, _scratch) = a_node();
        let held = Arc::new(Held::default());
        node.started(Arc::clone(&held) as Arc<dyn Transport>).await;
        let peer = NodeIdentity::generate().unwrap().transport_key().public_key();
        let dial = || {
            let (node, peer) = (Arc::clone(&node), peer.clone());
            tokio::spawn(async move { node.connect(&peer).await })
        };

        let (one, other) = (dial(), dial());
        until(|| held.dialled.load(Ordering::SeqCst) == 1).await;
        tokio::time::sleep(core::time::Duration::from_millis(100)).await;
        held.release.notify_waiters();
        let (one, other) = (one.await.unwrap(), other.await.unwrap());

        assert_eq!(held.dialled.load(Ordering::SeqCst), 1, "one dial reached the transport");
        assert!(one.is_err(), "the dial failed");
        assert_eq!(one, other, "and both callers are told so");
    }

    /// A dial abandoned half-way holds no later dial to the same peer waiting.
    #[tokio::test]
    async fn a_dial_abandoned_half_way_holds_up_no_later_one() {
        let (node, _scratch) = a_node();
        let held = Arc::new(Held::default());
        node.started(Arc::clone(&held) as Arc<dyn Transport>).await;
        let peer = NodeIdentity::generate().unwrap().transport_key().public_key();
        let dial = || {
            let (node, peer) = (Arc::clone(&node), peer.clone());
            tokio::spawn(async move { node.connect(&peer).await })
        };

        let abandoned = dial();
        until(|| held.dialled.load(Ordering::SeqCst) == 1).await;
        abandoned.abort();
        let _aborted = abandoned.await;

        let later = dial();
        until(|| held.dialled.load(Ordering::SeqCst) == 2).await;
        held.release.notify_waiters();
        assert!(later.await.unwrap().is_err(), "the later dial ran to its own end");
    }

    /// A node that is down is not given a transport by a relay moving.
    #[tokio::test]
    async fn a_down_node_is_not_given_a_transport() {
        let (node, _scratch) = a_node();
        node.replace_transport(Arc::new(Parked::default()) as Arc<dyn Transport>).await;
        assert!(!node.is_reachable().await, "§2.6c: nothing to reach a relay with");
    }
}

/// What tests read of a node's rests. Here, after everything else, because
/// the guards that read this file's code stop at the first test attribute.
#[cfg(test)]
impl Node {
    /// Whether `device` is rested as a neighbour that did not answer.
    pub(crate) fn resting_as_a_neighbour(&self, device: &DeviceId) -> bool {
        self.unanswered.lock().is_ok_and(|unanswered| unanswered.contains_key(device))
    }
}

/// Rests `roster` on the base kept beside the log, where there is one, and
/// returns the operations still to offer: those that follow the base's heads.
///
/// Where there is no base, or it does not check out, the roster is left empty
/// and the whole log is returned, to be replayed as it always was.
/// What a base that does not check out is said to be.
pub const CHANGED_OUTSIDE: &str = "the base store does not check out against its signed root: it was changed outside      this daemon";

/// Up to how many devices a base store is checked whole before the log rests
/// on it: a few seconds at most.
const CHECKED_BEFORE_RESTING: usize = 50_000;

fn resting_on_base(
    roster: &mut roster::roster::Roster,
    paths: &crate::state::Paths,
    store: &Arc<member_store::Store>,
    held: Vec<Vec<u8>>,
) -> Result<Vec<Vec<u8>>, Vec<Vec<u8>>> {
    let Some((snapshot, state)) = crate::state::read_base(paths, store) else { return Err(held) };
    let Ok(raw) = roster::snapshot::RawSnapshot::decode(&snapshot) else { return Err(held) };
    // Checked whole: against the root it holds, which `rest_on` then holds to
    // the signed one. Before anything rests on it, where that is quick; in the
    // background otherwise, a million devices taking minutes — meanwhile every
    // leaf read is checked against the signed root as it is read, so what the
    // store could do is hide a device, never add one. A store failing either
    // says so through `Node::base_tampered`.
    if roster::members::MemberStore::count(&**store) <= CHECKED_BEFORE_RESTING {
        if store.verify(&state.devices.root()).is_err() {
            return Err(held);
        }
    } else {
        let checking = Arc::clone(store);
        let _checker = std::thread::Builder::new()
            .name("base check".to_owned())
            .spawn(move || checking.verify_held());
    }
    let heads: std::collections::BTreeSet<roster::id::OperationId> =
        raw.body().heads.iter().copied().collect();
    let decoded: Vec<(Vec<u8>, roster::id::OperationId, Vec<roster::id::OperationId>)> = held
        .iter()
        .filter_map(|bytes| {
            let operation = roster::sign::RawOperation::decode(bytes).ok()?;
            Some((bytes.clone(), operation.id(), operation.core().parents.clone()))
        })
        .collect();
    let head_bytes: Vec<Vec<u8>> = decoded
        .iter()
        .filter(|(_, id, _)| heads.contains(id))
        .map(|(bytes, _, _)| bytes.clone())
        .collect();
    // The root it is checked against is the signed one: a store holding a
    // whole other state, consistent with itself, stops here.
    if roster.rest_on(&snapshot, state, &head_bytes).is_err() {
        return Err(held);
    }
    // In the log's order, which is the order they were admitted: an operation
    // follows the base when every parent is a head or follows it.
    let mut known = heads;
    let mut after = Vec::new();
    for (bytes, id, parents) in decoded {
        if known.contains(&id) {
            continue;
        }
        if parents.iter().all(|parent| known.contains(parent)) {
            known.insert(id);
            after.push(bytes);
        }
    }
    Ok(after)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod batches {
    use std::sync::Arc;

    use identity::NodeIdentity;
    use roster::batch::{BatchEntry, BatchHeader, pieces_of};
    use roster::id::NetworkId;
    use roster::leaf::Mode;
    use roster::sign::sign_operation;
    use roster::types::{NetworkParams, OperationBody, OperationCore, Role};

    use super::Node;
    use crate::state::{Log, Paths};

    /// A network founded by `founder`, its genesis written to `paths`.
    fn founded(founder: &NodeIdentity, paths: &Paths) -> NetworkId {
        let params =
            NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 2_592_000)
                .unwrap();
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
        Log::at(paths.roster())
            .append(&sign_operation(&genesis, founder.signer()).unwrap())
            .unwrap();
        NetworkId::from_bytes(*genesis.id().as_bytes())
    }

    fn started(founder: &Arc<NodeIdentity>, paths: &Paths) -> Arc<Node> {
        Node::from_log(Arc::clone(founder), Log::at(paths.roster()), None, None, None)
            .unwrap()
            .unwrap()
    }

    /// A batch admitted here is whole again after a restart: its pieces were
    /// kept beside the log, and replayed once the header was.
    #[tokio::test]
    async fn a_batch_survives_a_restart() {
        let founder = Arc::new(NodeIdentity::generate().unwrap());
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path());
        let network = founded(&founder, &paths);
        let node = started(&founder, &paths);

        let entries: Vec<BatchEntry> = (0..150)
            .map(|index| {
                let board = NodeIdentity::generate().unwrap();
                let spec = board.device_spec("board", Role::Member, false, vec![]).unwrap();
                BatchEntry {
                    keys: spec.keys,
                    name: format!("board-{index}"),
                    serial: Vec::new(),
                    ipv4: None,
                }
            })
            .collect();
        let header =
            BatchHeader::for_entries(&entries, Mode::Light, Vec::new(), None, "lot").unwrap();
        let core = OperationCore::new(
            crate::clock::signing_time(),
            founder.signing_key().algorithm(),
            OperationBody::AdmitBatch(header),
            node.heads().await,
            founder.signing_key().key_id(),
            network,
        )
        .unwrap();
        let batch = core.id();
        node.admit_without_activating(&sign_operation(&core, founder.signer()).unwrap())
            .await
            .unwrap();
        node.admit_pieces(&pieces_of(&batch, &entries).unwrap()).await.unwrap();
        assert_eq!(node.state().await.unwrap().devices.len(), 151);

        drop(node);
        let restarted = started(&founder, &paths);
        assert_eq!(restarted.state().await.unwrap().devices.len(), 151, "whole after a restart");
        assert!(Log::at(paths.pieces()).read().unwrap().len() > 1);
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod light {
    use std::sync::Arc;

    use identity::NodeIdentity;
    use roster::id::NetworkId;
    use roster::member::{DEFAULT_BUDGET, LightMember};
    use roster::roster::Roster;
    use roster::sign::sign_operation;
    use roster::types::{NetworkParams, OperationBody, OperationCore, Role};

    use super::Node;
    use crate::state::Paths;

    /// A founder's roster of the founder and `member`, with a root over it.
    fn founded(founder: &NodeIdentity, member: &NodeIdentity) -> (Roster, NetworkId) {
        let params =
            NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "example.internal", 2_592_000)
                .unwrap();
        let sign = |body, parents, network| {
            let core = OperationCore::new(
                1,
                founder.signing_key().algorithm(),
                body,
                parents,
                founder.signing_key().key_id(),
                network,
            )
            .unwrap();
            (core.id(), sign_operation(&core, founder.signer()).unwrap())
        };
        let (genesis, genesis_bytes) = sign(
            OperationBody::CreateNetwork {
                device: founder.device_spec("nas", Role::Admin, true, vec![]).unwrap(),
                params,
            },
            vec![],
            NetworkId::from_bytes([0; 32]),
        );
        let network = NetworkId::from_bytes(*genesis.as_bytes());
        let (_, added) = sign(
            OperationBody::AddDevice(
                member.device_spec("sensor", Role::Member, false, vec![]).unwrap(),
            ),
            vec![genesis],
            network,
        );
        let mut roster = Roster::new();
        assert!(roster.offer_bytes(&genesis_bytes).is_accepted());
        assert!(roster.offer_bytes(&added).is_accepted());
        let root = crate::snapshots::sign_over_heads(&roster, founder).unwrap();
        assert!(roster.offer_snapshot(&root).is_accepted());
        (roster, network)
    }

    /// A full member on the root the light member holds is believed by its
    /// compact evidence. One that took the next root is not believed on its
    /// word, since only the root's hash is shown: the light member catches up
    /// from the chain, and then believes it.
    #[tokio::test]
    async fn a_peer_on_a_root_not_held_is_believed_once_caught_up() {
        let founder = NodeIdentity::generate().unwrap();
        let sensor = Arc::new(NodeIdentity::generate().unwrap());
        let (mut roster, network) = founded(&founder, &sensor);
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path());
        let member = LightMember::new(
            roster.evidence_for(&sensor.device_id()).unwrap(),
            roster.state().unwrap().params,
            DEFAULT_BUDGET,
        )
        .unwrap();
        crate::state::write_light(&paths, &member).unwrap();
        let node = Node::from_light(Arc::clone(&sensor), &paths).unwrap().expect("a light member");
        let (_, judge) = node.light_binding().unwrap();
        let catching = node.catching_up().expect("a light member catches up");
        let held = member.current().unwrap();

        let admit = |roster: &mut Roster, name: &str, ts: u64| {
            let device = NodeIdentity::generate().unwrap();
            let core = OperationCore::new(
                ts,
                founder.signing_key().algorithm(),
                OperationBody::AddDevice(
                    device.device_spec(name, Role::Member, false, vec![]).unwrap(),
                ),
                roster.heads(),
                founder.signing_key().key_id(),
                network,
            )
            .unwrap();
            assert!(
                roster.offer_bytes(&sign_operation(&core, founder.signer()).unwrap()).is_accepted()
            );
            let root = crate::snapshots::sign_over_heads(roster, &founder).unwrap();
            assert!(roster.offer_snapshot(&root).is_accepted());
        };
        let shown =
            |roster: &Roster| roster.evidence_for(&founder.device_id()).unwrap().shown().unwrap();

        assert!(judge(&shown(&roster)), "on the root it holds, believed");

        admit(&mut roster, "tv", 2);
        let next = shown(&roster);
        assert!(!judge(&next), "on the next root, not taken on a peer's word");
        assert_eq!((catching.behind)(&next.to_bytes()), Some(held), "it asks after its own");
        let answer = crate::lookup::encode_roots_within(
            &roster.roots_after(&held),
            transport_convesso::frame::MAX_ROOTS,
        );
        assert!((catching.take)(&next.to_bytes(), &answer), "the chain is taken");
        assert!(judge(&next), "and the peer believed");
        assert_eq!(node.light().unwrap().lock().unwrap().member().current(), Some(next.against));
    }

    /// Two roots behind, a light member asks the peer for the roots after its
    /// own as the session opens, takes them, and believes the peer: what the
    /// testbed found missing (18.1), where a member that missed roots refused
    /// every member holding them.
    #[tokio::test]
    async fn a_member_two_roots_behind_catches_up_from_the_peer() {
        let founder = NodeIdentity::generate().unwrap();
        let sensor = Arc::new(NodeIdentity::generate().unwrap());
        let (mut roster, network) = founded(&founder, &sensor);
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path());
        let member = LightMember::new(
            roster.evidence_for(&sensor.device_id()).unwrap(),
            roster.state().unwrap().params,
            DEFAULT_BUDGET,
        )
        .unwrap();
        crate::state::write_light(&paths, &member).unwrap();
        let node = Node::from_light(Arc::clone(&sensor), &paths).unwrap().expect("a light member");
        let (_, judge) = node.light_binding().unwrap();
        let catching = node.catching_up().expect("a light member catches up");
        let held = member.current().unwrap();

        for (name, ts) in [("tv", 2), ("radio", 3)] {
            let device = NodeIdentity::generate().unwrap();
            let core = OperationCore::new(
                ts,
                founder.signing_key().algorithm(),
                OperationBody::AddDevice(
                    device.device_spec(name, Role::Member, false, vec![]).unwrap(),
                ),
                roster.heads(),
                founder.signing_key().key_id(),
                network,
            )
            .unwrap();
            assert!(
                roster.offer_bytes(&sign_operation(&core, founder.signer()).unwrap()).is_accepted()
            );
            let root = crate::snapshots::sign_over_heads(&roster, &founder).unwrap();
            assert!(roster.offer_snapshot(&root).is_accepted());
        }
        let far = roster.evidence_for(&founder.device_id()).unwrap().shown().unwrap();
        let shown = far.to_bytes();

        assert!(!judge(&far), "not placed, not believed");
        assert_eq!((catching.behind)(&shown), Some(held), "it asks after the root it holds");

        // What a full member answers, as `Node::roots_source` builds it.
        let answer = crate::lookup::encode_roots_within(
            &roster.roots_after(&held),
            transport_convesso::frame::MAX_ROOTS,
        );
        assert!((catching.take)(&shown, &answer), "the chain is taken");
        assert!(judge(&far), "and the peer believed");
        assert_eq!((catching.behind)(&shown), None, "nothing more to ask");
        assert_eq!(node.light().unwrap().lock().unwrap().member().current(), Some(far.against));
        assert!(
            !(catching.take)(&shown, b"not roots"),
            "nothing is taken from bytes that are not roots"
        );
    }

    /// What a light member keeps, changed behind the running daemon, is not
    /// what the next checkpoint vouches for; what the daemon writes after is.
    #[tokio::test]
    async fn a_light_member_planted_while_the_daemon_runs_is_not_vouched_for() {
        let founder = NodeIdentity::generate().unwrap();
        let sensor = Arc::new(NodeIdentity::generate().unwrap());
        let (roster, _) = founded(&founder, &sensor);
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path().join("casa"));
        paths.create().unwrap();
        let member = LightMember::new(
            roster.evidence_for(&sensor.device_id()).unwrap(),
            roster.state().unwrap().params,
            DEFAULT_BUDGET,
        )
        .unwrap();
        crate::state::write_light(&paths, &member).unwrap();
        let node = Node::from_light(Arc::clone(&sensor), &paths).unwrap().expect("a light member");
        let (machine, _) = crate::checkpoint::SoftwareKey::at(scratch.path()).unwrap();
        let keeper =
            Arc::new(crate::checkpoint::Keeper::new(Arc::new(machine), paths.clone(), None));
        let started = crate::checkpoint::file_hash(&paths.light()).unwrap();
        // As the service does at start, once the file was checked.
        keeper.holds_light(started);
        node.keep_with(Arc::clone(&keeper));
        let vouched = || {
            let (machine, _) = crate::checkpoint::SoftwareKey::at(scratch.path()).unwrap();
            crate::checkpoint::read(&paths, &machine).unwrap().unwrap()
        };

        std::fs::write(paths.light(), b"planted").unwrap();
        let planted = crate::checkpoint::file_hash(&paths.light()).unwrap();
        let values = crate::checkpoint::Values::of(&node, &paths, "casa").await.unwrap();
        keeper.keep(values, true).unwrap();
        assert!(!vouched().allows_light(&planted), "the planted file is not named");
        assert!(vouched().allows_light(&started), "what the daemon holds is");

        // A root taken is written by the daemon, and that is what is named.
        let mut later = roster;
        let extra = NodeIdentity::generate().unwrap();
        let core = OperationCore::new(
            2,
            founder.signing_key().algorithm(),
            OperationBody::AddDevice(extra.device_spec("tv", Role::Member, false, vec![]).unwrap()),
            later.heads(),
            founder.signing_key().key_id(),
            later.state().unwrap().network,
        )
        .unwrap();
        assert!(later.offer_bytes(&sign_operation(&core, founder.signer()).unwrap()).is_accepted());
        let second = crate::snapshots::sign_over_heads(&later, &founder).unwrap();
        let message = roster_sync::message::Message::Snapshot(second).encode();
        node.received_roster(founder.device_id(), &message).await;
        let written = crate::checkpoint::file_hash(&paths.light()).unwrap();
        assert_ne!(written, planted, "the daemon wrote over it");
        let values = crate::checkpoint::Values::of(&node, &paths, "casa").await.unwrap();
        keeper.keep(values, true).unwrap();
        assert!(vouched().allows_light(&written), "what it wrote is named");
        assert!(!vouched().allows_light(&started), "and what it replaced is gone");
    }

    #[tokio::test]
    async fn a_light_daemon_runs_with_no_roster_file() {
        let founder = NodeIdentity::generate().unwrap();
        let sensor = Arc::new(NodeIdentity::generate().unwrap());
        let (roster, _) = founded(&founder, &sensor);
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path());
        let member = LightMember::new(
            roster.evidence_for(&sensor.device_id()).unwrap(),
            roster.state().unwrap().params,
            DEFAULT_BUDGET,
        )
        .unwrap();
        crate::state::write_light(&paths, &member).unwrap();

        let node = Node::from_light(Arc::clone(&sensor), &paths).unwrap().expect("a light member");
        assert!(node.is_light());
        let state = node.state().await.unwrap();
        assert!(state.devices.contains_key(&sensor.device_id()), "it knows itself");
        assert!(node.light_binding().is_some(), "and what to show and judge by");

        // A root arriving from a full member is taken, and kept beside the
        // identity; no roster is ever written.
        let mut later = roster;
        let extra = NodeIdentity::generate().unwrap();
        let heads = later.heads();
        let core = OperationCore::new(
            2,
            founder.signing_key().algorithm(),
            OperationBody::AddDevice(extra.device_spec("tv", Role::Member, false, vec![]).unwrap()),
            heads,
            founder.signing_key().key_id(),
            later.state().unwrap().network,
        )
        .unwrap();
        assert!(later.offer_bytes(&sign_operation(&core, founder.signer()).unwrap()).is_accepted());
        let second = crate::snapshots::sign_over_heads(&later, &founder).unwrap();
        let before = std::fs::read(paths.light()).unwrap();
        let taken = roster::snapshot::RawSnapshot::decode(&second).unwrap().body().root;
        let message = roster_sync::message::Message::Snapshot(second).encode();
        node.received_roster(founder.device_id(), &message).await;

        assert_ne!(std::fs::read(paths.light()).unwrap(), before, "the new root is kept");
        assert!(!paths.roster().exists(), "and there is no roster file");
        let restarted = Node::from_light(sensor, &paths).unwrap().unwrap();
        assert_eq!(
            restarted.light().unwrap().lock().unwrap().member().current(),
            Some(taken),
            "restarted, it holds the root it took"
        );
    }

    #[tokio::test]
    async fn a_full_node_answers_a_lookup_with_evidence_a_light_member_believes() {
        let founder = Arc::new(NodeIdentity::generate().unwrap());
        let sensor = NodeIdentity::generate().unwrap();
        let (roster, _) = founded(&founder, &sensor);
        let mut member = LightMember::new(
            roster.evidence_for(&founder.device_id()).unwrap(),
            roster.state().unwrap().params,
            DEFAULT_BUDGET,
        )
        .unwrap();
        let state = roster.state().unwrap();
        let prefix = tunnel::Prefix::from_parameter(&state.params.ula).unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let full = Node::new(
            Arc::clone(&founder),
            roster_sync::Syncer::new(roster),
            Arc::new(crate::gateway::Gateway::new(tunnel::Tunnel::new(
                prefix,
                founder.device_id(),
            ))),
            crate::router::Router::new(prefix),
            crate::state::Log::at(scratch.path().join("roster.log")),
            crate::schedule::Schedule::provisional(),
        );

        let query = crate::lookup::Query::Name("sensor".to_owned());
        let evidence = full.answer_lookup(&query).await;
        assert_eq!(
            crate::lookup::take_answer(&mut member, &query, &evidence),
            Ok(sensor.device_id())
        );
        let nobody = crate::lookup::Query::Name("nobody".to_owned());
        assert!(full.answer_lookup(&nobody).await.is_empty(), "nothing known is said as nothing");
    }

    /// A light member's upkeep owes nothing on a clock: a month with no root
    /// published and nothing asked of it, and it asks nothing.
    #[tokio::test(start_paused = true)]
    async fn a_quiet_network_costs_a_light_member_nothing_for_a_month() {
        let founder = NodeIdentity::generate().unwrap();
        let sensor = Arc::new(NodeIdentity::generate().unwrap());
        let (roster, _) = founded(&founder, &sensor);
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path());
        let member = LightMember::new(
            roster.evidence_for(&sensor.device_id()).unwrap(),
            roster.state().unwrap().params,
            DEFAULT_BUDGET,
        )
        .unwrap();
        crate::state::write_light(&paths, &member).unwrap();
        let node = Node::from_light(Arc::clone(&sensor), &paths).unwrap().unwrap();
        let upkeep = tokio::spawn(Arc::clone(&node).keep_up_forever());

        for _ in 0..30 {
            tokio::time::advance(std::time::Duration::from_secs(24 * 60 * 60)).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(node.asked(), 0, "nothing renewed, nothing fetched, in a month");

        // A root naming the member is what makes it renew.
        let mut later = roster;
        let rename = OperationCore::new(
            3,
            founder.signing_key().algorithm(),
            OperationBody::Rename { device: sensor.device_id(), name: "probe".into() },
            later.heads(),
            founder.signing_key().key_id(),
            later.state().unwrap().network,
        )
        .unwrap();
        assert!(
            later.offer_bytes(&sign_operation(&rename, founder.signer()).unwrap()).is_accepted()
        );
        let named = crate::snapshots::sign_over_heads(&later, &founder).unwrap();
        node.received_roster(
            founder.device_id(),
            &roster_sync::message::Message::Snapshot(named).encode(),
        )
        .await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(node.asked() > 0, "named in a delta, it asks for a renewed proof");
        upkeep.abort();
    }

    /// Sets a device's mode, signed by the founder, over the roster's heads.
    fn set_mode(
        roster: &mut Roster,
        founder: &NodeIdentity,
        device: roster::id::DeviceId,
        mode: roster::leaf::Mode,
        ts: u64,
    ) {
        let core = OperationCore::new(
            ts,
            founder.signing_key().algorithm(),
            OperationBody::SetDevice {
                device,
                change: roster::leaf::SettingsChange {
                    mode: Some(mode),
                    ..roster::leaf::SettingsChange::default()
                },
            },
            roster.heads(),
            founder.signing_key().key_id(),
            roster.state().unwrap().network,
        )
        .unwrap();
        assert!(
            roster.offer_bytes(&sign_operation(&core, founder.signer()).unwrap()).is_accepted()
        );
        let root = crate::snapshots::sign_over_heads(roster, founder).unwrap();
        assert!(roster.offer_snapshot(&root).is_accepted());
    }

    #[tokio::test]
    async fn a_full_member_made_light_drops_its_roster_and_keeps_its_leaf() {
        let founder = NodeIdentity::generate().unwrap();
        let sensor = Arc::new(NodeIdentity::generate().unwrap());
        let (mut roster, _) = founded(&founder, &sensor);
        set_mode(&mut roster, &founder, sensor.device_id(), roster::leaf::Mode::Light, 5);
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path());
        let log = crate::state::Log::at(paths.roster());
        for bytes in roster.retained_operations() {
            log.append(&bytes).unwrap();
        }
        let state = roster.state().unwrap();
        let prefix = tunnel::Prefix::from_parameter(&state.params.ula).unwrap();
        let node = Node::new(
            Arc::clone(&sensor),
            roster_sync::Syncer::new(roster),
            Arc::new(crate::gateway::Gateway::new(tunnel::Tunnel::new(prefix, sensor.device_id()))),
            crate::router::Router::new(prefix),
            log,
            crate::schedule::Schedule::provisional(),
        );
        assert!(!node.is_light());

        node.enforce_roster().await;

        assert!(node.is_light() && node.mode_switched());
        assert!(!paths.roster().exists(), "the roster is dropped");
        assert!(paths.light().exists(), "and the light member kept");
        assert!(node.state().await.unwrap().devices.contains_key(&sensor.device_id()));
    }

    /// A member its state already makes light, and no root it holds yet,
    /// keeps in touch with full members until that root reaches it.
    #[tokio::test]
    async fn a_member_light_by_its_state_alone_keeps_in_touch_with_full_members() {
        let founder = NodeIdentity::generate().unwrap();
        let sensor = Arc::new(NodeIdentity::generate().unwrap());
        let (mut roster, network) = founded(&founder, &sensor);
        // Made light by an operation, with no root over it.
        let core = OperationCore::new(
            5,
            founder.signing_key().algorithm(),
            OperationBody::SetDevice {
                device: sensor.device_id(),
                change: roster::leaf::SettingsChange {
                    mode: Some(roster::leaf::Mode::Light),
                    ..roster::leaf::SettingsChange::default()
                },
            },
            roster.heads(),
            founder.signing_key().key_id(),
            network,
        )
        .unwrap();
        assert!(
            roster.offer_bytes(&sign_operation(&core, founder.signer()).unwrap()).is_accepted()
        );
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path());
        let log = crate::state::Log::at(paths.roster());
        let state = roster.state().unwrap();
        let prefix = tunnel::Prefix::from_parameter(&state.params.ula).unwrap();
        let node = Node::new(
            Arc::clone(&sensor),
            roster_sync::Syncer::new(roster),
            Arc::new(crate::gateway::Gateway::new(tunnel::Tunnel::new(prefix, sensor.device_id()))),
            crate::router::Router::new(prefix),
            log,
            crate::schedule::Schedule::provisional(),
        );
        assert!(!node.is_light(), "no root makes it light yet");
        assert_eq!(node.chosen_neighbours().await, vec![founder.device_id()]);
    }

    /// Made light, a member keeps a way out besides the admin that admitted
    /// it: full members chosen from the roster it still held.
    #[tokio::test]
    async fn a_member_made_light_keeps_full_members_besides_its_admitter() {
        let founder = NodeIdentity::generate().unwrap();
        let sensor = Arc::new(NodeIdentity::generate().unwrap());
        let laptop = NodeIdentity::generate().unwrap();
        let (mut roster, network) = founded(&founder, &sensor);
        let core = OperationCore::new(
            3,
            founder.signing_key().algorithm(),
            OperationBody::AddDevice(
                laptop.device_spec("laptop", Role::Member, false, vec![]).unwrap(),
            ),
            roster.heads(),
            founder.signing_key().key_id(),
            network,
        )
        .unwrap();
        assert!(
            roster.offer_bytes(&sign_operation(&core, founder.signer()).unwrap()).is_accepted()
        );
        set_mode(&mut roster, &founder, sensor.device_id(), roster::leaf::Mode::Light, 5);
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path());
        let log = crate::state::Log::at(paths.roster());
        for bytes in roster.retained_operations() {
            log.append(&bytes).unwrap();
        }
        let state = roster.state().unwrap();
        let prefix = tunnel::Prefix::from_parameter(&state.params.ula).unwrap();
        let node = Node::new(
            Arc::clone(&sensor),
            roster_sync::Syncer::new(roster),
            Arc::new(crate::gateway::Gateway::new(tunnel::Tunnel::new(prefix, sensor.device_id()))),
            crate::router::Router::new(prefix),
            log,
            crate::schedule::Schedule::provisional(),
        );

        node.enforce_roster().await;

        assert!(node.is_light());
        let member = node.light().unwrap();
        let kept = member.lock().unwrap().member().known_fulls();
        assert_eq!(kept, vec![laptop.device_id()], "the laptop, besides the admin");
        assert!(node.chosen_neighbours().await.contains(&laptop.device_id()), "and turns to it");
    }

    #[tokio::test]
    async fn a_light_member_made_full_rests_on_the_state_it_fetched() {
        let founder = Arc::new(NodeIdentity::generate().unwrap());
        let sensor = Arc::new(NodeIdentity::generate().unwrap());
        let (mut roster, _) = founded(&founder, &sensor);
        set_mode(&mut roster, &founder, sensor.device_id(), roster::leaf::Mode::Light, 5);
        let scratch = tempfile::tempdir().unwrap();
        let paths = Paths::under(scratch.path());
        let member = LightMember::new(
            roster.evidence_for(&sensor.device_id()).unwrap(),
            roster.state().unwrap().params,
            DEFAULT_BUDGET,
        )
        .unwrap();
        crate::state::write_light(&paths, &member).unwrap();
        let node = Node::from_light(Arc::clone(&sensor), &paths).unwrap().unwrap();

        // The admin makes it full; the root says so, and its proof is renewed.
        set_mode(&mut roster, &founder, sensor.device_id(), roster::leaf::Mode::Full, 6);
        let latest = roster.snapshot().unwrap().to_bytes();
        {
            let held = node.light().unwrap();
            let mut held = held.lock().unwrap();
            held.member_mut().offer_root(&latest).unwrap();
            held.member_mut().renew(roster.evidence_for(&sensor.device_id()).unwrap()).unwrap();
        }
        let request = node.begin_full().await.expect("it asks for the state");

        // The full member answers; the light member rests on what it is given.
        let mut full = roster_sync::Syncer::new(roster);
        let answers = full.receive(sensor.device_id(), &request.encode()).replies;
        assert!(!answers.is_empty());
        for answer in answers {
            node.received_roster(founder.device_id(), &answer.encode()).await;
        }

        assert!(!node.is_light() && node.mode_switched(), "it is full now");
        assert!(!paths.light().exists(), "the light member is dropped");
        assert!(paths.base_store().exists(), "and the state it rests on kept");
        assert_eq!(
            node.state().await.unwrap().root(),
            full.roster().snapshot().unwrap().body().root,
            "it holds the state the root commits to"
        );
    }
}

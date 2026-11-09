//! A network at scale, in one process (`scalable-membership` 16).
//!
//! Full members run what a full member's daemon runs: the roster and its sync,
//! the neighbours the daemon chooses, and the same rule for what is passed on —
//! every open session but the one it came from, shaped for a light peer by
//! `Syncer::for_peer`. Light members hold what a light member holds, and meet
//! full members as the daemon has them meet: each keeps in touch with two, its
//! anchors first (`Node::chosen_neighbours`), opens its sessions with them
//! when it comes online (the reconciliation tick reaches a peer without one),
//! and keeps them open however long they carry nothing (`node::held_open`).
//! As a session opens each side shows its evidence; the light member takes
//! the root it is shown, or asks the chain to it (`BEHIND`, `ROOTS`). A root
//! taken later is pushed to it on the session already open, as anything new
//! is; on taking one it asks what it stands on, and renews its proof when a
//! delta names it. Nothing else of a daemon is here: no tunnel, no transport,
//! no tasks, and no convesso: a session's handshakes, and the new ones after
//! convesso forgets a session nothing used, are not counted.
//!
//! Messages travel over an in-memory queue, one hop a tick, so a tick is the
//! latency of one message and propagation is counted in hops. Every byte sent
//! and received is counted, per node.
//!
//! It drives the components the daemon drives, rather than a model of them: a
//! number it reports is what those components do, and a defect it finds is in
//! them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use identity::NodeIdentity;
use light_node::engine::{Engine, LOOKUP_PATIENCE_MS, Output};
use roster::batch::{BatchEntry, BatchHeader, pieces_of};
use roster::id::{DeviceId, NetworkId, OperationId};
use roster::leaf::Mode;
use roster::member::{DEFAULT_BUDGET, LightMember};
use roster::roster::Roster;
use roster::sign::sign_operation;
use roster::types::{NetworkParams, OperationBody, OperationCore, Role};
use roster_sync::Syncer;
use roster_sync::message::Message;

/// A node of the simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum At {
    Full(usize),
    Light(usize),
}

/// What travels between two nodes.
enum Carried {
    /// A roster-sync message, as the daemon sends it on the roster channel.
    Roster(Vec<u8>),
    /// A lookup message, as the daemon sends it on the lookup channel: a light
    /// member's engine asking (roots after its own, its footing, its proof
    /// again), or a full member answering.
    Lookup(Vec<u8>),
    /// What one side shows the other as a session opens: its compact
    /// evidence, in `OPEN` or `ACCEPT`.
    Shown(Vec<u8>),
    /// A light member that cannot place the root it was shown, as `BEHIND`.
    Behind([u8; 32]),
    /// The roots `BEHIND` asked for, as `ROOTS`.
    Roots(Vec<u8>),
}

impl Carried {
    /// What it costs on the wire, near enough: its payload, and the frame's
    /// framing where it is one of the transport's.
    fn bytes(&self) -> u64 {
        let length = match self {
            Self::Roster(bytes) | Self::Lookup(bytes) | Self::Roots(bytes) => bytes.len(),
            Self::Shown(bytes) => bytes.len().saturating_add(10),
            Self::Behind(_) => 32 + 9,
        };
        u64::try_from(length).unwrap_or(u64::MAX)
    }
}

struct Envelope {
    from: At,
    to: At,
    carried: Carried,
}

struct Full {
    id: DeviceId,
    syncer: Syncer,
    /// The full members it holds a session with: those it chose and those that
    /// chose it.
    neighbours: Vec<usize>,
    /// The light members that keep in touch with it.
    serves: Vec<usize>,
    sent: u64,
    received: u64,
}

struct Light {
    /// Its member and upkeep, run by the engine the daemon runs.
    engine: Engine,
    online: bool,
    /// The full members it keeps in touch with.
    kept: Vec<usize>,
    /// Whether its sessions with them are open: from when it comes online
    /// until it goes off.
    in_session: bool,
    renewed: u64,
    sent: u64,
    received: u64,
}

/// What one phase cost.
#[derive(Debug, Clone, Default)]
pub(crate) struct Phase {
    /// Ticks until every full member held what the phase made, and every light
    /// member online the root that followed.
    pub(crate) ticks: u64,
    /// Bytes each full member sent and received, on average and at most.
    pub(crate) full_bytes: (u64, u64),
    /// The same for each light member.
    pub(crate) light_bytes: (u64, u64),
    /// Proofs renewed in the phase.
    pub(crate) renewals: u64,
    /// Whether what the phase waited for happened at all.
    pub(crate) reached: bool,
}

impl core::fmt::Display for Phase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} hops{}; per full member {} B on average, {} B at most; per light member {} B on average, {} B at most; {} renewals",
            self.ticks,
            if self.reached { "" } else { ", never reached" },
            self.full_bytes.0,
            self.full_bytes.1,
            self.light_bytes.0,
            self.light_bytes.1,
            self.renewals,
        )
    }
}

/// What a full member answers a lookup question, as `Node::answer_lookup`:
/// the footing, the roots after one, or a member's evidence.
fn full_answers(full: &Full, question: &[u8]) -> Option<Vec<u8>> {
    let Some(crate::lookup::Message::Request { id, query }) =
        crate::lookup::Message::decode(question)
    else {
        return None;
    };
    let roster = full.syncer.roster();
    let evidence = match &query {
        crate::lookup::Query::Footing(asker, held) => {
            crate::lookup::footing_of(roster, asker, held.as_ref(), &|_| true)
        }
        crate::lookup::Query::RootsAfter(since) => crate::lookup::encode_roots_within(
            &roster.roots_after(since),
            crate::lookup::MAX_ROOTS_ANSWER,
        ),
        other => roster
            .state()
            .ok()
            .and_then(|state| crate::lookup::resolve(&state, other))
            .map_or_else(Vec::new, |device| crate::snapshots::evidence_of(roster, &device)),
    };
    Some(crate::lookup::Message::Answer { id, evidence }.encode())
}

/// A network of full and light members.
pub(crate) struct Simulation {
    founder: Arc<NodeIdentity>,
    network: NetworkId,
    fulls: Vec<Full>,
    lights: Vec<Light>,
    light_index: BTreeMap<DeviceId, usize>,
    queue: Vec<Envelope>,
    clock: u64,
    /// The light members' engines' clock, in milliseconds: a hop a tenth of a
    /// second, so a question whose answer was lost is given up within fifty.
    now: u64,
}

/// How many full members a light member keeps in touch with, as
/// `Node::chosen_neighbours` keeps.
const KEPT: usize = 2;

/// A plausible signing time, rising by a minute with each act.
const EPOCH_MS: u64 = 1_760_000_000_000;

impl Simulation {
    /// A network founded on full member 0, with `fulls` full members in all, the
    /// first `anchors` of them its anchors. No light member yet.
    pub(crate) fn founded(fulls: usize, anchors: usize) -> Self {
        let founder = Arc::new(NodeIdentity::generate().expect("generates"));
        let others: Vec<NodeIdentity> =
            (1..fulls).map(|_| NodeIdentity::generate().expect("generates")).collect();
        let params = NetworkParams::new(vec![0xfd, 0, 0, 0, 0, 0, 0, 0], "sim.internal", 2_592_000)
            .expect("parameters");
        let mut log: Vec<Vec<u8>> = Vec::new();
        let mut roster = Roster::new();
        let mut clock = EPOCH_MS;
        let mut sign = |roster: &mut Roster, body: OperationBody, network: NetworkId| {
            clock = clock.saturating_add(60_000);
            let core = OperationCore::new(
                clock,
                founder.signing_key().algorithm(),
                body,
                roster.heads(),
                founder.signing_key().key_id(),
                network,
            )
            .expect("an operation");
            let bytes = sign_operation(&core, founder.signer()).expect("signs");
            let admission = roster.offer_bytes(&bytes);
            assert!(admission.is_accepted(), "the founder's own act: {admission:?}");
            (core.id(), bytes)
        };

        let (genesis, bytes) = sign(
            &mut roster,
            OperationBody::CreateNetwork {
                device: founder.device_spec("full-0", Role::Admin, true, vec![]).expect("spec"),
                params,
            },
            NetworkId::from_bytes([0; 32]),
        );
        log.push(bytes);
        let network = NetworkId::from_bytes(*genesis.as_bytes());
        for (index, identity) in (1_usize..).zip(&others) {
            let spec = identity
                .device_spec(format!("full-{index}"), Role::Member, false, vec![])
                .expect("spec");
            log.push(sign(&mut roster, OperationBody::AddDevice(spec), network).1);
        }
        let ids: Vec<DeviceId> = std::iter::once(founder.device_id())
            .chain(others.iter().map(NodeIdentity::device_id))
            .collect();
        let mut with_anchors = roster.state().expect("derives").params;
        with_anchors.anchors = ids.iter().take(anchors).copied().collect();
        with_anchors.anchors.sort_unstable();
        log.push(sign(&mut roster, OperationBody::SetNetwork(with_anchors), network).1);
        let root = crate::snapshots::sign_over_heads(&roster, &founder).expect("a root");
        log.push(root);

        let fulls = ids
            .iter()
            .map(|id| {
                let mut held = Roster::new();
                let (root, operations) = log.split_last().expect("a log");
                for operation in operations {
                    assert!(held.offer_bytes(operation).is_accepted());
                }
                assert!(held.offer_snapshot(root).is_accepted());
                Full {
                    id: *id,
                    syncer: Syncer::new(held),
                    neighbours: Vec::new(),
                    serves: Vec::new(),
                    sent: 0,
                    received: 0,
                }
            })
            .collect();
        let mut simulation = Self {
            founder,
            network,
            fulls,
            lights: Vec::new(),
            light_index: BTreeMap::new(),
            queue: Vec::new(),
            clock,
            now: 0,
        };
        simulation.choose_neighbours();
        simulation
    }

    /// Every full member's neighbours, as the daemon chooses them, made mutual
    /// as the daemon's sessions are.
    fn choose_neighbours(&mut self) {
        let state = self.founder_roster().state().expect("derives");
        let index: BTreeMap<DeviceId, usize> =
            self.fulls.iter().enumerate().map(|(at, full)| (full.id, at)).collect();
        let mut edges: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); self.fulls.len()];
        for (at, full) in self.fulls.iter().enumerate() {
            let choices = crate::neighbours::Choices::of(&state, &full.id).expect("full");
            for chosen in choices.choose(&state, &|_| false) {
                if let Some(other) = index.get(&chosen) {
                    if let Some(set) = edges.get_mut(at) {
                        set.insert(*other);
                    }
                    if let Some(set) = edges.get_mut(*other) {
                        set.insert(at);
                    }
                }
            }
        }
        for (full, set) in self.fulls.iter_mut().zip(edges) {
            full.neighbours = set.into_iter().collect();
        }
    }

    fn founder_roster(&self) -> &Roster {
        self.fulls.first().expect("a founder").syncer.roster()
    }

    /// Admits `count` light members in batches signed by the founder, and
    /// runs until every full member holds it. Then the founder publishes the
    /// root over it, and `running` of the boards are provisioned from that
    /// root, as a board is at the station, and run: what the phase returns is
    /// the batch's spreading.
    ///
    /// The rest are members the full members hold and serve nobody for: a
    /// sample stands for them where running them all would not fit, a full
    /// member's traffic with light members growing with how many it serves.
    pub(crate) fn admit_light_batch(&mut self, count: usize, running: usize) -> Phase {
        let entries: Vec<BatchEntry> = (0..count)
            .map(|index| {
                let board = NodeIdentity::generate().expect("generates");
                let spec = board
                    .device_spec(format!("board-{index}"), Role::Member, false, vec![])
                    .expect("spec");
                BatchEntry {
                    keys: spec.keys,
                    name: spec.name,
                    serial: format!("SN{index}").into_bytes(),
                    ipv4: None,
                }
            })
            .collect();
        let before = self.counters();
        // In as many batches as the limit on one needs, each signed after the
        // last is held, as an admin admits a fleet larger than one batch.
        let most = usize::try_from(roster::limits::MAX_BATCH_ENTRIES).unwrap_or(usize::MAX);
        let mut out = Vec::new();
        for chunk in entries.chunks(most) {
            // Each lot given the lowest run of the block free, in device order,
            // as an admin's daemon gives one (`batches::prepared`).
            let mut lot = chunk.to_vec();
            lot.sort_by_key(|entry| entry.device_id().ok());
            let count = u32::try_from(lot.len()).expect("a batch's size");
            let first = self
                .fulls
                .first()
                .and_then(|founder| founder.syncer.roster().state().ok())
                .and_then(|state| state.free_offsets(count))
                .expect("room in the block");
            let run = roster::batch::OffsetRun::new(first, count).expect("a run");
            for (entry, offset) in lot.iter_mut().zip(run.offsets()) {
                entry.ipv4 = Some(offset);
            }
            let lot = lot.as_slice();
            let header = BatchHeader::for_entries(lot, Mode::Light, Vec::new(), Some(run), "sim")
                .expect("a header");
            let (batch, header) = self.founder_signs(OperationBody::AdmitBatch(header));
            let pieces = pieces_of(&batch, lot).expect("pieces");
            let founder = self.fulls.first_mut().expect("a founder");
            if let Some(message) = founder.syncer.admit_local(&header).expect("its own header") {
                out.push(message);
            }
            out.extend(founder.syncer.admit_local_pieces(&pieces).expect("its own pieces"));
        }
        for message in out {
            self.spread(0, None, &message);
        }
        let expected = self.fulls.len().saturating_add(count);
        let ticks = self.run_until(|simulation| {
            simulation.fulls.iter().all(|full| {
                full.syncer.roster().state().is_ok_and(|state| state.devices.len() == expected)
            })
        });
        let phase = self.phase_since(&before, ticks);

        self.publish_root();
        let _settled = self.run_until(|_| false);
        self.provision_lights(running);
        phase
    }

    /// `running` boards of the batch, provisioned from the founder's current
    /// root and handed their anchors.
    fn provision_lights(&mut self, running: usize) {
        let roster = self.founder_roster();
        let state = roster.state().expect("derives");
        let index: BTreeMap<DeviceId, usize> =
            self.fulls.iter().enumerate().map(|(at, full)| (full.id, at)).collect();
        let boards: Vec<DeviceId> = state
            .devices
            .iter()
            .filter(|(id, _)| !index.contains_key(id) && !self.light_index.contains_key(id))
            .map(|(id, _)| id)
            .take(running)
            .collect();
        let mut lights = Vec::new();
        for board in boards {
            let evidence = roster.evidence_for(&board).expect("a board's evidence");
            let member =
                LightMember::new(evidence, state.params.clone(), DEFAULT_BUDGET).expect("a member");
            // Two, its anchors first, as `Node::chosen_neighbours` keeps.
            let kept: Vec<usize> = crate::seeking::anchors_for(&board, &state.params.anchors)
                .iter()
                .filter_map(|anchor| index.get(anchor).copied())
                .take(KEPT)
                .collect();
            lights.push((board, member, kept));
        }
        for (board, member, kept) in lights {
            let at = self.lights.len();
            let engine = Engine::new(member);
            for full in &kept {
                if let Some(full) = self.fulls.get_mut(*full) {
                    full.serves.push(at);
                }
            }
            self.lights.push(Light {
                engine,
                online: true,
                kept,
                in_session: false,
                renewed: 0,
                sent: 0,
                received: 0,
            });
            self.light_index.insert(board, at);
        }
    }

    /// The founder signs `body` over its heads, and holds it.
    fn founder_signs(&mut self, body: OperationBody) -> (OperationId, Vec<u8>) {
        self.clock = self.clock.saturating_add(60_000);
        let roster = self.founder_roster();
        let core = OperationCore::new(
            self.clock,
            self.founder.signing_key().algorithm(),
            body,
            roster.heads(),
            self.founder.signing_key().key_id(),
            self.network,
        )
        .expect("an operation");
        let bytes = sign_operation(&core, self.founder.signer()).expect("signs");
        (core.id(), bytes)
    }

    /// The founder publishes a root over what it holds, as an admin's daemon
    /// does after every act.
    fn publish_root(&mut self) -> Vec<u8> {
        let root = crate::snapshots::sign_over_heads(self.founder_roster(), &self.founder)
            .expect("a root");
        let founder = self.fulls.first_mut().expect("a founder");
        assert!(founder.syncer.roster_mut().offer_snapshot(&root).is_accepted(), "its own root");
        self.spread(0, None, &Message::Snapshot(root.clone()));
        root
    }

    /// An admin's act and the root after it: the founder revokes `revoked` and
    /// renames `renamed`, two of the light members, then publishes. Runs until
    /// every full member holds both, and every light member online the root,
    /// pushed on its sessions. The revoked one is out, its sessions closed.
    pub(crate) fn revoke_and_rename(&mut self, revoked: usize, renamed: usize) -> Phase {
        let device = |at: usize, lights: &[Light]| {
            lights.get(at).map(|light| light.engine.member().device()).expect("a light member")
        };
        let gone = device(revoked, &self.lights);
        let changed = device(renamed, &self.lights);
        self.switch_off(&[revoked]);
        let before = self.counters();
        let mut signed = Vec::new();
        for body in [
            OperationBody::RevokeDevice { device: gone, reason: "lost".to_owned() },
            OperationBody::Rename { device: changed, name: format!("renamed-{renamed}") },
        ] {
            let (id, bytes) = self.founder_signs(body);
            let founder = self.fulls.first_mut().expect("a founder");
            if let Some(message) = founder.syncer.admit_local(&bytes).expect("its own act") {
                self.spread(0, None, &message);
            }
            signed.push(id);
        }
        let _root = self.publish_root();
        let ticks = self.run_until(|simulation| {
            simulation
                .fulls
                .iter()
                .all(|full| signed.iter().all(|id| full.syncer.roster().dag().contains(id)))
                && simulation.lights_hold_the_root()
        });
        self.phase_since(&before, ticks)
    }

    /// An admin's rename of light member `renamed`, and the root after it:
    /// runs until every full member holds it, and every light member online
    /// the root.
    pub(crate) fn rename(&mut self, renamed: usize) -> Phase {
        let device = self
            .lights
            .get(renamed)
            .map(|light| light.engine.member().device())
            .expect("a light member");
        let before = self.counters();
        self.clock = self.clock.saturating_add(1);
        let (id, bytes) = self.founder_signs(OperationBody::Rename {
            device,
            name: format!("renamed-{renamed}-{}", self.clock % 1_000),
        });
        let founder = self.fulls.first_mut().expect("a founder");
        if let Some(message) = founder.syncer.admit_local(&bytes).expect("its own act") {
            self.spread(0, None, &message);
        }
        let _root = self.publish_root();
        let ticks = self.run_until(|simulation| {
            simulation.fulls.iter().all(|full| full.syncer.roster().dag().contains(&id))
                && simulation.lights_hold_the_root()
        });
        self.phase_since(&before, ticks)
    }

    /// Takes light members offline, their sessions gone, so roots published
    /// meanwhile do not reach them.
    pub(crate) fn switch_off(&mut self, lights: &[usize]) {
        let ids: Vec<DeviceId> = self.fulls.iter().map(|full| full.id).collect();
        for at in lights {
            if let Some(light) = self.lights.get_mut(*at) {
                light.online = false;
                light.in_session = false;
                for full in &light.kept {
                    if let Some(id) = ids.get(*full) {
                        light.engine.session_closed(id);
                    }
                }
            }
        }
    }

    /// Brings light members back: they meet their full members at the next
    /// [`Self::hour`].
    pub(crate) fn switch_on(&mut self, lights: &[usize]) {
        // Off long enough for whatever it asked to be given up.
        self.now = self.now.saturating_add(LOOKUP_PATIENCE_MS);
        for at in lights {
            if let Some(light) = self.lights.get_mut(*at) {
                light.online = true;
                light.engine.tick(self.now);
            }
            self.carry_out(*at);
        }
    }

    /// One hour of the reconciliation tick: every light member online without
    /// its sessions opens them with the full members it keeps, each side
    /// showing its evidence, and catches up from what it is shown. The
    /// sessions stay open. Runs until every light member online holds the
    /// founder's root.
    pub(crate) fn hour(&mut self) -> Phase {
        let before = self.counters();
        let shown: Vec<Vec<u8>> = self
            .fulls
            .iter()
            .map(|full| crate::snapshots::shown_of(full.syncer.roster(), &full.id))
            .collect();
        for at in 0..self.lights.len() {
            let Some(light) = self.lights.get_mut(at) else { continue };
            if !light.online || light.in_session {
                continue;
            }
            light.in_session = true;
            let own = light.engine.member().shown();
            // The first full member met after a start is asked what the light
            // member stands on, as `Node::serving` tells the engine.
            for full in &light.kept {
                if let Some(id) = self.fulls.get(*full).map(|full| full.id) {
                    light.engine.session_opened(id, self.now);
                }
            }
            for full in light.kept.clone() {
                self.queue.push(Envelope {
                    from: At::Light(at),
                    to: At::Full(full),
                    carried: Carried::Shown(own.clone()),
                });
                let theirs = shown.get(full).cloned().unwrap_or_default();
                self.queue.push(Envelope {
                    from: At::Full(full),
                    to: At::Light(at),
                    carried: Carried::Shown(theirs),
                });
            }
            self.carry_out(at);
        }
        let ticks = self.run_until(Self::lights_hold_the_root);
        self.phase_since(&before, ticks)
    }

    /// Whether every light member online holds the founder's root.
    fn lights_hold_the_root(&self) -> bool {
        let root = self.founder_roster().snapshot().map(|held| held.body().root);
        self.lights.iter().all(|light| !light.online || light.engine.member().current() == root)
    }

    /// What a light member keeps, as it writes it: its memory, near enough.
    pub(crate) fn light_memory(&self) -> (u64, u64) {
        let sizes: Vec<u64> = self
            .lights
            .iter()
            .map(|light| u64::try_from(light.engine.member().to_bytes().len()).unwrap_or(u64::MAX))
            .collect();
        spread_of(&sizes)
    }

    /// How many full and light members there are.
    pub(crate) fn size(&self) -> (usize, usize) {
        (self.fulls.len(), self.lights.len())
    }

    /// The light members' current roots, counted.
    pub(crate) fn light_roots(&self) -> BTreeMap<Option<[u8; 32]>, usize> {
        let mut counted = BTreeMap::new();
        for light in &self.lights {
            let held = counted.entry(light.engine.member().current()).or_insert(0_usize);
            *held = held.saturating_add(1);
        }
        counted
    }

    // ---- the network ------------------------------------------------------

    /// Sends `message` from full member `from` to every session but `except`:
    /// its neighbours, and the light members it serves that are in session.
    fn spread(&mut self, from: usize, except: Option<At>, message: &Message) {
        let Some(full) = self.fulls.get(from) else { return };
        let lights = &self.lights;
        let targets: Vec<At> = full
            .neighbours
            .iter()
            .map(|other| At::Full(*other))
            .chain(
                full.serves
                    .iter()
                    .filter(|light| lights.get(**light).is_some_and(|light| light.in_session))
                    .map(|light| At::Light(*light)),
            )
            .filter(|to| Some(*to) != except)
            .collect();
        for to in targets {
            self.send_roster(from, to, message);
        }
    }

    /// Sends a roster message from a full member, shaped for its receiver.
    fn send_roster(&mut self, from: usize, to: At, message: &Message) {
        let Some(full) = self.fulls.get(from) else { return };
        let peer = match to {
            At::Full(other) => self.fulls.get(other).map(|other| other.id),
            At::Light(light) => self.lights.get(light).map(|light| light.engine.member().device()),
        };
        let Some(peer) = peer else { return };
        if let Some(shaped) = full.syncer.for_peer(&peer, message.clone()) {
            self.queue.push(Envelope {
                from: At::Full(from),
                to,
                carried: Carried::Roster(shaped.encode()),
            });
        }
    }

    /// Delivers what was sent until nothing is left in flight. Returns the
    /// ticks it took for `done` to hold, and whether it ever did.
    fn run_until(&mut self, done: impl Fn(&Self) -> bool) -> (u64, bool) {
        let mut ticks = 0_u64;
        let mut reached = done(self).then_some(0);
        while !self.queue.is_empty() {
            ticks = ticks.saturating_add(1);
            self.now = self.now.saturating_add(100);
            let now: Vec<Envelope> = std::mem::take(&mut self.queue);
            for envelope in now {
                self.deliver(envelope);
            }
            // What an engine gave up on, past its deadline.
            for at in 0..self.lights.len() {
                let late = self.lights.get(at).is_some_and(|light| {
                    light.online && light.engine.next_deadline().is_some_and(|due| due <= self.now)
                });
                if late {
                    if let Some(light) = self.lights.get_mut(at) {
                        light.engine.tick(self.now);
                    }
                    self.carry_out(at);
                }
            }
            if reached.is_none() && done(self) {
                reached = Some(ticks);
            }
        }
        reached.map_or((ticks, false), |at| (at, true))
    }

    fn deliver(&mut self, envelope: Envelope) {
        let Envelope { from, to, carried } = envelope;
        if let At::Light(at) = to
            && !self.lights.get(at).is_some_and(|light| light.online)
        {
            return;
        }
        let bytes = carried.bytes();
        self.count(from, bytes, true);
        self.count(to, bytes, false);
        match (to, carried) {
            (At::Full(at), Carried::Roster(payload)) => self.full_receives(at, from, &payload),
            (At::Full(at), Carried::Lookup(question)) => {
                let answer = self.fulls.get(at).and_then(|full| full_answers(full, &question));
                if let Some(answer) = answer {
                    self.queue.push(Envelope {
                        from: to,
                        to: from,
                        carried: Carried::Lookup(answer),
                    });
                }
            }
            (At::Full(at), Carried::Behind(since)) => {
                // As `Node::roots_source` answers it: within one frame.
                let roots = self
                    .fulls
                    .get(at)
                    .map(|full| full.syncer.roster().roots_after(&since))
                    .unwrap_or_default();
                let answer = crate::lookup::encode_roots_within(
                    &roots,
                    transport_convesso::frame::MAX_ROOTS,
                );
                self.queue.push(Envelope { from: to, to: from, carried: Carried::Roots(answer) });
            }
            (At::Light(at), carried) => self.light_receives(at, from, carried),
            (At::Full(_), Carried::Shown(_) | Carried::Roots(_)) => {}
        }
    }

    fn full_receives(&mut self, at: usize, from: At, payload: &[u8]) {
        let peer = match from {
            At::Full(other) => self.fulls.get(other).map(|other| other.id),
            At::Light(light) => self.lights.get(light).map(|light| light.engine.member().device()),
        };
        let (Some(peer), Some(full)) = (peer, self.fulls.get_mut(at)) else { return };
        let reception = full.syncer.receive(peer, payload);
        for reply in reception.replies {
            self.send_roster(at, from, &reply);
        }
        if let Some(forward) = reception.forward {
            self.spread(at, Some(from), &forward);
        }
    }

    /// What a light member receives, given to its engine as the daemon gives
    /// it; then what the engine asks, carried out.
    fn light_receives(&mut self, at: usize, from: At, carried: Carried) {
        let At::Full(full) = from else { return };
        let Some(peer) = self.fulls.get(full).map(|full| full.id) else { return };
        let now = self.now;
        let Some(light) = self.lights.get_mut(at) else { return };
        match carried {
            Carried::Roster(payload) => {
                let Ok(Message::Snapshot(root)) = Message::decode(&payload) else { return };
                light.engine.root_pushed(peer, &root, now);
            }
            Carried::Lookup(answer) => light.engine.lookup(peer, &answer, now),
            Carried::Shown(shown) => {
                // As the light member's transport judges it as a session opens:
                // believed against a root it remembers, or the chain asked.
                let Ok(compact) = roster::membership::Shown::from_bytes(&shown) else { return };
                if light.engine.judge(&compact) {
                    return;
                }
                if let Some(current) = light.engine.behind(&shown) {
                    self.queue.push(Envelope {
                        from: At::Light(at),
                        to: from,
                        carried: Carried::Behind(current),
                    });
                }
                return;
            }
            Carried::Roots(roots) => {
                let shown = self
                    .fulls
                    .get(full)
                    .map(|full| crate::snapshots::shown_of(full.syncer.roster(), &full.id))
                    .unwrap_or_default();
                let Some(light) = self.lights.get_mut(at) else { return };
                let _taken = light.engine.take_roots(&shown, &roots, now);
            }
            Carried::Behind(_) => return,
        }
        self.carry_out(at);
    }

    /// Carries out what light member `at`'s engine asks: its questions sent to
    /// the full members it names, its renewals counted.
    fn carry_out(&mut self, at: usize) {
        loop {
            let Some(output) = self.lights.get_mut(at).and_then(|light| light.engine.poll_output())
            else {
                return;
            };
            match output {
                Output::Send { peer, body, .. } => {
                    if let Some(full) = self.fulls.iter().position(|full| full.id == peer) {
                        self.queue.push(Envelope {
                            from: At::Light(at),
                            to: At::Full(full),
                            carried: Carried::Lookup(body),
                        });
                    }
                }
                Output::Renewed => {
                    if let Some(light) = self.lights.get_mut(at) {
                        light.renewed = light.renewed.saturating_add(1);
                    }
                }
                Output::Keep
                | Output::Reconsider
                | Output::StateChanged
                | Output::WakeAt(_)
                | Output::Found { .. } => {}
            }
        }
    }

    // ---- counting --------------------------------------------------------

    fn count(&mut self, at: At, bytes: u64, sending: bool) {
        let (sent, received) = match at {
            At::Full(at) => match self.fulls.get_mut(at) {
                Some(full) => (&mut full.sent, &mut full.received),
                None => return,
            },
            At::Light(at) => match self.lights.get_mut(at) {
                Some(light) => (&mut light.sent, &mut light.received),
                None => return,
            },
        };
        let counter = if sending { sent } else { received };
        *counter = counter.saturating_add(bytes);
    }

    fn counters(&self) -> Counters {
        Counters {
            fulls: self.fulls.iter().map(|full| full.sent.saturating_add(full.received)).collect(),
            lights: self
                .lights
                .iter()
                .map(|light| light.sent.saturating_add(light.received))
                .collect(),
            renewed: self.lights.iter().map(|light| light.renewed).sum(),
        }
    }

    fn phase_since(&self, before: &Counters, (ticks, reached): (u64, bool)) -> Phase {
        let now = self.counters();
        let full_bytes: Vec<u64> = now
            .fulls
            .iter()
            .enumerate()
            .map(|(at, total)| total.saturating_sub(before.fulls.get(at).copied().unwrap_or(0)))
            .collect();
        let light_bytes: Vec<u64> = now
            .lights
            .iter()
            .enumerate()
            .map(|(at, total)| total.saturating_sub(before.lights.get(at).copied().unwrap_or(0)))
            .collect();
        Phase {
            ticks,
            full_bytes: spread_of(&full_bytes),
            light_bytes: spread_of(&light_bytes),
            renewals: now.renewed.saturating_sub(before.renewed),
            reached,
        }
    }
}

struct Counters {
    fulls: Vec<u64>,
    lights: Vec<u64>,
    renewed: u64,
}

/// The average and the largest of `values`.
fn spread_of(values: &[u64]) -> (u64, u64) {
    let count = u64::try_from(values.len()).unwrap_or(u64::MAX).max(1);
    let total: u64 = values.iter().fold(0_u64, |sum, value| sum.saturating_add(*value));
    (total.checked_div(count).unwrap_or(0), values.iter().copied().max().unwrap_or(0))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// A network at scale, run by hand when a measurement is wanted and never
    /// in CI: at a size given in `PEERFECTLY_SIM_LIGHTS` (and
    /// `PEERFECTLY_SIM_FULLS`, `PEERFECTLY_SIM_ANCHORS`), ten thousand light
    /// members behind a dozen full ones by default. `PEERFECTLY_SIM_RUNNING`
    /// runs only that many of the light members, every one by default: the
    /// full members hold them all, and serve the sample. A batch reaches every
    /// full member, the root after an act every light member, and a light
    /// member that was off catches up as its anchors greet it; what each
    /// phase cost is printed for the record.
    #[test]
    #[ignore = "a measurement, run by hand: cargo test -p daemon --lib simulator -- --ignored --nocapture"]
    fn measure() {
        let read = |name: &str, default: usize| {
            std::env::var(name).ok().and_then(|value| value.parse().ok()).unwrap_or(default)
        };
        let lights = read("PEERFECTLY_SIM_LIGHTS", 10_000);
        run(
            lights,
            read("PEERFECTLY_SIM_RUNNING", lights).min(lights),
            read("PEERFECTLY_SIM_FULLS", 12),
            read("PEERFECTLY_SIM_ANCHORS", 4),
        );
    }

    fn run(admitted: usize, lights: usize, fulls: usize, anchors: usize) {
        let started = std::time::Instant::now();
        let mut simulation = Simulation::founded(fulls, anchors);
        let batch = simulation.admit_light_batch(admitted, lights);
        assert!(batch.reached, "the batch reaches every full member: {batch:?}");
        assert_eq!(simulation.size(), (fulls, lights));
        println!(
            "batch of {admitted}, {lights} of them run: {batch}  ({:?} so far)",
            started.elapsed()
        );

        // Sessions opened after a start ask each light member's footing whole,
        // as the daemon does of the first full member it meets.
        let first = simulation.hour();
        println!("sessions opened, after a start: {first}");
        assert!(first.reached, "every light member holds the root: {first:?}");
        let quiet = simulation.hour();
        println!("an hour with nothing new: {quiet}");
        assert!(quiet.reached, "and still does: {quiet:?}");

        let act = simulation.revoke_and_rename(0, 1);
        println!("revoke and rename, to everyone: {act}  ({:?} so far)", started.elapsed());
        assert!(act.reached, "every member has it, the light ones pushed the root: {act:?}");
        assert_eq!(act.renewals, 1, "the renamed member renews its proof, once");
        let next = simulation.hour();
        println!("the hour after it: {next}");
        assert!(next.reached, "and keeps it: {next:?}");

        // A tenth of the light members off across two acts, then back.
        let off: Vec<usize> = (2..lights).step_by(10).collect();
        simulation.switch_off(&off);
        assert!(simulation.rename(3).reached);
        assert!(simulation.hour().reached);
        assert!(simulation.rename(4).reached);
        simulation.switch_on(&off);
        let back = simulation.hour();
        println!("{} back after two roots: {back}", off.len());
        assert!(back.reached, "each catches up from the full members it keeps: {back:?}");
        println!("roots held: {:?}", simulation.light_roots().values().collect::<Vec<_>>());

        let memory = simulation.light_memory();
        println!("light memory (bytes kept, average and largest): {memory:?}");
        println!("in {:?}", started.elapsed());
    }
}

//! A network at scale, in one process (`scalable-membership` 16).
//!
//! Full members run what a full member's daemon runs: the roster and its sync,
//! the neighbours the daemon chooses, and the same rule for what is passed on —
//! every open session but the one it came from, shaped for a light peer by
//! `Syncer::for_peer`. Light members hold what a light member holds, and meet
//! full members as the daemon has them meet: each keeps in touch with two, its
//! anchors first (`Node::chosen_neighbours`), opens its sessions with them
//! once an hour (the reconciliation tick), and is left alone once they have
//! carried nothing for a while (`close_idle`). As a session opens each side
//! shows its evidence; the light member takes the root it is shown, or asks
//! the chain to it (`BEHIND`, `ROOTS`), then asks what it stands on, and renews
//! its proof when a delta names it. Nothing else of a daemon is here: no
//! tunnel, no transport, no tasks.
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
    /// A light member asking for the roots after the one it holds.
    RootsAfter([u8; 32]),
    /// The roots asked for.
    Roots(Vec<u8>),
    /// A light member asking for its own leaf and proof again.
    Renew,
    /// The evidence asked for.
    Evidence(Vec<u8>),
    /// What one side shows the other as a session opens: its compact
    /// evidence, in `OPEN` or `ACCEPT`.
    Shown(Vec<u8>),
    /// A light member that cannot place the root it was shown, as `BEHIND`.
    Behind([u8; 32]),
    /// A light member asking what it stands on, after taking a root, with the
    /// digest of the footing it last took.
    Footing(Option<[u8; 32]>),
    /// What it stands on, as a footing answer carries it.
    Footed(Vec<u8>),
}

impl Carried {
    /// What it costs on the wire, near enough: its payload, and the lookup
    /// message's framing where it is one.
    fn bytes(&self) -> u64 {
        let length = match self {
            Self::Roster(bytes)
            | Self::Roots(bytes)
            | Self::Evidence(bytes)
            | Self::Footed(bytes) => bytes.len(),
            Self::Shown(bytes) => bytes.len().saturating_add(10),
            Self::RootsAfter(_) => 32 + 6,
            Self::Footing(held) => {
                if held.is_some() {
                    64 + 6
                } else {
                    32 + 6
                }
            }
            Self::Behind(_) => 32 + 9,
            Self::Renew => 16 + 6,
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
    member: LightMember,
    online: bool,
    /// The full members it keeps in touch with.
    kept: Vec<usize>,
    /// Whether its sessions with them are open now.
    in_session: bool,
    /// The digest of the footing it last took.
    footing: Option<[u8; 32]>,
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

/// A network of full and light members.
pub(crate) struct Simulation {
    founder: Arc<NodeIdentity>,
    network: NetworkId,
    fulls: Vec<Full>,
    lights: Vec<Light>,
    light_index: BTreeMap<DeviceId, usize>,
    queue: Vec<Envelope>,
    clock: u64,
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
    /// root over it, and each board is provisioned from that root, as a board
    /// is at the station: what the phase returns is the batch's spreading.
    pub(crate) fn admit_light_batch(&mut self, count: usize) -> Phase {
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
        for lot in entries.chunks(most) {
            let header = BatchHeader::for_entries(lot, Mode::Light, Vec::new(), None, "sim")
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
        self.provision_lights();
        phase
    }

    /// Every board of the batch, provisioned from the founder's current root
    /// and handed its anchors.
    fn provision_lights(&mut self) {
        let roster = self.founder_roster();
        let state = roster.state().expect("derives");
        let index: BTreeMap<DeviceId, usize> =
            self.fulls.iter().enumerate().map(|(at, full)| (full.id, at)).collect();
        let boards: Vec<DeviceId> = state
            .devices
            .iter()
            .filter(|(id, _)| !index.contains_key(id) && !self.light_index.contains_key(id))
            .map(|(id, _)| id)
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
            for full in &kept {
                if let Some(full) = self.fulls.get_mut(*full) {
                    full.serves.push(at);
                }
            }
            self.lights.push(Light {
                member,
                online: true,
                kept,
                in_session: false,
                footing: None,
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
    /// every full member holds both; light members, with no session open, take
    /// the root at their next [`Self::hour`]. The revoked one is out.
    pub(crate) fn revoke_and_rename(&mut self, revoked: usize, renamed: usize) -> Phase {
        let device = |at: usize, lights: &[Light]| {
            lights.get(at).map(|light| light.member.device()).expect("a light member")
        };
        let gone = device(revoked, &self.lights);
        let changed = device(renamed, &self.lights);
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
        });
        if let Some(light) = self.lights.get_mut(revoked) {
            light.online = false;
        }
        self.phase_since(&before, ticks)
    }

    /// An admin's rename of light member `renamed`, and the root after it:
    /// runs until every full member holds it.
    pub(crate) fn rename(&mut self, renamed: usize) -> Phase {
        let device =
            self.lights.get(renamed).map(|light| light.member.device()).expect("a light member");
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
        });
        self.phase_since(&before, ticks)
    }

    /// Takes light members offline, so roots published meanwhile do not reach
    /// them.
    pub(crate) fn switch_off(&mut self, lights: &[usize]) {
        for at in lights {
            if let Some(light) = self.lights.get_mut(*at) {
                light.online = false;
            }
        }
    }

    /// Brings light members back: they meet their full members at the next
    /// [`Self::hour`].
    pub(crate) fn switch_on(&mut self, lights: &[usize]) {
        for at in lights {
            if let Some(light) = self.lights.get_mut(*at) {
                light.online = true;
            }
        }
    }

    /// One hour of the reconciliation tick: every light member online opens
    /// its sessions with the full members it keeps, each side showing its
    /// evidence, and catches up from what it is shown. The sessions close
    /// after, as idle ones do. Runs until every light member online holds
    /// the founder's root.
    pub(crate) fn hour(&mut self) -> Phase {
        let before = self.counters();
        let shown: Vec<Vec<u8>> = self
            .fulls
            .iter()
            .map(|full| crate::snapshots::shown_of(full.syncer.roster(), &full.id))
            .collect();
        for at in 0..self.lights.len() {
            let Some(light) = self.lights.get_mut(at) else { continue };
            if !light.online {
                continue;
            }
            light.in_session = true;
            let own = light.member.shown();
            // The first full member met after a start is asked what the light
            // member stands on, as `Node::serving` asks it (`footing_due`).
            if light.footing.is_none()
                && let Some(first) = light.kept.first()
            {
                self.queue.push(Envelope {
                    from: At::Light(at),
                    to: At::Full(*first),
                    carried: Carried::Footing(None),
                });
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
        }
        let root = self.founder_roster().snapshot().map(|held| held.body().root);
        let ticks = self.run_until(|simulation| {
            simulation.lights.iter().all(|light| !light.online || light.member.current() == root)
        });
        for light in &mut self.lights {
            light.in_session = false;
        }
        self.phase_since(&before, ticks)
    }

    /// What a light member keeps, as it writes it: its memory, near enough.
    pub(crate) fn light_memory(&self) -> (u64, u64) {
        let sizes: Vec<u64> = self
            .lights
            .iter()
            .map(|light| u64::try_from(light.member.to_bytes().len()).unwrap_or(u64::MAX))
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
            let held = counted.entry(light.member.current()).or_insert(0_usize);
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
            At::Light(light) => self.lights.get(light).map(|light| light.member.device()),
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
        let mut reached = None;
        while !self.queue.is_empty() {
            ticks = ticks.saturating_add(1);
            let now: Vec<Envelope> = std::mem::take(&mut self.queue);
            for envelope in now {
                self.deliver(envelope);
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
            (At::Full(at), Carried::RootsAfter(since)) => {
                let roots = self
                    .fulls
                    .get(at)
                    .map(|full| full.syncer.roster().roots_after(&since))
                    .unwrap_or_default();
                let answer = crate::lookup::encode_roots(&roots);
                self.queue.push(Envelope { from: to, to: from, carried: Carried::Roots(answer) });
            }
            (At::Full(at), Carried::Renew) => {
                let At::Light(light) = from else { return };
                let device = self.lights.get(light).map(|light| light.member.device());
                let evidence = match (self.fulls.get(at), device) {
                    (Some(full), Some(device)) => {
                        crate::snapshots::evidence_of(full.syncer.roster(), &device)
                    }
                    _ => Vec::new(),
                };
                self.queue.push(Envelope {
                    from: to,
                    to: from,
                    carried: Carried::Evidence(evidence),
                });
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
            (At::Full(at), Carried::Footing(held)) => {
                let At::Light(light) = from else { return };
                let device = self.lights.get(light).map(|light| light.member.device());
                let footing = match (self.fulls.get(at), device) {
                    (Some(full), Some(device)) => crate::lookup::footing_of(
                        full.syncer.roster(),
                        &device,
                        held.as_ref(),
                        &|_| true,
                    ),
                    _ => Vec::new(),
                };
                self.queue.push(Envelope { from: to, to: from, carried: Carried::Footed(footing) });
            }
            (At::Light(at), carried) => self.light_receives(at, from, carried),
            (
                At::Full(_),
                Carried::Roots(_) | Carried::Evidence(_) | Carried::Shown(_) | Carried::Footed(_),
            ) => {}
        }
    }

    fn full_receives(&mut self, at: usize, from: At, payload: &[u8]) {
        let peer = match from {
            At::Full(other) => self.fulls.get(other).map(|other| other.id),
            At::Light(light) => self.lights.get(light).map(|light| light.member.device()),
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

    fn light_receives(&mut self, at: usize, from: At, carried: Carried) {
        let Some(light) = self.lights.get_mut(at) else { return };
        let mut asks = Vec::new();
        match carried {
            Carried::Roster(payload) => {
                let Ok(Message::Snapshot(root)) = Message::decode(&payload) else { return };
                match light.member.offer_root(&root) {
                    Ok(roster::light::RootOutcome::NeedsChain) => {
                        if let Some(current) = light.member.current() {
                            asks.push(Carried::RootsAfter(current));
                        }
                    }
                    // Asked once, on taking the root that named it: the same root
                    // from its other anchors asks nothing again.
                    Ok(
                        roster::light::RootOutcome::Adopted
                        | roster::light::RootOutcome::Switched
                        | roster::light::RootOutcome::KeptAside,
                    ) if light.member.needs_renewal() => asks.push(Carried::Renew),
                    _ => {}
                }
            }
            Carried::Shown(shown) => {
                // As the light member's transport judges it as a session opens:
                // believed against a root it remembers, or the chain asked.
                let Ok(shown) = roster::membership::Shown::from_bytes(&shown) else { return };
                if light.member.believes_shown(&shown) {
                    return;
                }
                if let Some(current) = light.member.behind(&shown.against) {
                    asks.push(Carried::Behind(current));
                }
            }
            Carried::Roots(answer) => {
                let chain = crate::lookup::decode_roots(&answer).unwrap_or_default();
                if light.member.take_chain(&chain) {
                    asks.push(Carried::Footing(light.footing));
                    if light.member.needs_renewal() {
                        asks.push(Carried::Renew);
                    }
                }
            }
            Carried::Evidence(bytes) => {
                let renewed = roster::membership::Evidence::from_bytes(&bytes)
                    .ok()
                    .is_some_and(|evidence| light.member.renew(evidence).is_ok());
                if renewed {
                    light.renewed = light.renewed.saturating_add(1);
                }
            }
            Carried::Footed(answer) => {
                // As `Node::take_footing_from`: its own digest back is nothing
                // new; a footing is taken, and its digest kept.
                if light.footing.is_some_and(|held| answer == held) {
                    return;
                }
                if let Some(footing) = crate::lookup::Footing::decode(&answer) {
                    let _taken = crate::lookup::take_footing(&mut light.member, &footing);
                    light.footing = Some(footing.digest());
                }
            }
            Carried::RootsAfter(_) | Carried::Renew | Carried::Behind(_) | Carried::Footing(_) => {}
        }
        for carried in asks {
            self.queue.push(Envelope { from: At::Light(at), to: from, carried });
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
    /// members behind a dozen full ones by default. A batch reaches every
    /// full member, the root after an act every light member, and a light
    /// member that was off catches up as its anchors greet it; what each
    /// phase cost is printed for the record.
    #[test]
    #[ignore = "a measurement, run by hand: cargo test -p daemon --lib simulator -- --ignored --nocapture"]
    fn measure() {
        let read = |name: &str, default: usize| {
            std::env::var(name).ok().and_then(|value| value.parse().ok()).unwrap_or(default)
        };
        run(
            read("PEERFECTLY_SIM_LIGHTS", 10_000),
            read("PEERFECTLY_SIM_FULLS", 12),
            read("PEERFECTLY_SIM_ANCHORS", 4),
        );
    }

    fn run(lights: usize, fulls: usize, anchors: usize) {
        let started = std::time::Instant::now();
        let mut simulation = Simulation::founded(fulls, anchors);
        let batch = simulation.admit_light_batch(lights);
        assert!(batch.reached, "the batch reaches every full member: {batch:?}");
        assert_eq!(simulation.size(), (fulls, lights));
        println!("batch of {lights}: {batch}  ({:?} so far)", started.elapsed());

        // The first hour after a start asks each light member's footing whole,
        // as the daemon does of the first full member it meets.
        let first = simulation.hour();
        println!("the first hour, after a start: {first}");
        assert!(first.reached, "every light member holds the root: {first:?}");
        let quiet = simulation.hour();
        println!("an hour with nothing new: {quiet}");
        assert!(quiet.reached, "and still does: {quiet:?}");

        let act = simulation.revoke_and_rename(0, 1);
        println!("revoke and rename, to the full members: {act}");
        assert!(act.reached, "every full member has the act: {act:?}");
        let next = simulation.hour();
        println!("the hour after it: {next}  ({:?} so far)", started.elapsed());
        assert!(next.reached, "every light member takes the root as it meets a full one: {next:?}");
        assert_eq!(next.renewals, 1, "the renamed member renews its proof, once");

        // A tenth of the light members off across two acts, then back.
        let off: Vec<usize> = (2..lights).step_by(10).collect();
        simulation.switch_off(&off);
        assert!(simulation.rename(3).reached);
        assert!(simulation.hour().reached);
        assert!(simulation.rename(4).reached);
        simulation.switch_on(&off);
        let back = simulation.hour();
        println!("{} back after two roots, and an act: {back}", off.len());
        assert!(back.reached, "each catches up from the full members it keeps: {back:?}");
        println!("roots held: {:?}", simulation.light_roots().values().collect::<Vec<_>>());

        let memory = simulation.light_memory();
        println!("light memory (bytes kept, average and largest): {memory:?}");
        println!("in {:?}", started.elapsed());
    }
}

//! A light member whole: its engine and its sessions, with no input or output
//! of its own, for a microcontroller to run.
//!
//! It keeps in touch with two full members — its anchors it knows, else the
//! admin whose root it holds, else the full members it keeps — as the daemon's
//! light member does (`Node::chosen_neighbours`), dialling each one it holds no
//! session with, a peer that did not answer rested from a minute up to six
//! hours. What arrives on a session goes to the engine by channel; what the
//! engine asks is sent on a session with the member it names.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use roster::id::DeviceId;
use roster::member::LightMember;
use roster::types::{Algorithm, KeyPurpose};
use transport_wire::frame::{Limits, Reason};

use crate::channel::{Channel, frame, unframe};
use crate::engine::{self, Engine};
use crate::lookup::Query;
use crate::sessions::{DialFailure, Keys, Sessions, To};

/// How many full members a light member keeps in touch with.
pub const KEPT: usize = 2;

/// How long a peer that did not answer is first rested, in milliseconds.
pub const FIRST_REST_MS: u64 = 60_000;

/// The longest a peer is rested, in milliseconds.
pub const LONGEST_REST_MS: u64 = 6 * 60 * 60 * 1_000;

/// The longest a peer is rested by a member awaiting admission.
pub const LONGEST_REST_AWAITING_MS: u64 = 5 * 60 * 1_000;

/// What the host is to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action<P> {
    /// Send `bytes` as one reliable message.
    Message {
        /// To whom.
        to: To<P>,
        /// A frame, or a part of one.
        bytes: Vec<u8>,
    },
    /// What the member keeps changed: keep [`Member::member`] before what
    /// follows.
    Keep,
    /// The state the member knows changed.
    StateChanged,
    /// Send `bytes` as one datagram to a peer already speaking to this node.
    Datagram {
        /// To whom.
        to: P,
        /// A packet's fragment, framed.
        bytes: Vec<u8>,
    },
    /// A packet for this device, from a member it holds a session with, its
    /// source that member's: hand it to the board's network stack.
    Packet(Vec<u8>),
    /// Call [`Member::tick`] at this time, or after.
    WakeAt(u64),
}

/// A peer not reached: until when it is left alone, and for how long next.
#[derive(Debug, Clone, Copy)]
struct Rest {
    until: u64,
    next: u64,
}

/// A light member, its engine and its sessions.
#[derive(Debug)]
pub struct Member<K: Keys> {
    engine: Engine,
    sessions: Sessions<K>,
    /// The tunnel's rule, over the state the member knows.
    tunnel: Option<tunnel::Tunnel>,
    resting: BTreeMap<DeviceId, Rest>,
    out: VecDeque<Action<K::Peer>>,
}

impl<K: Keys> Member<K> {
    /// A member running on `member`, telling peers apart by `keys`, taking
    /// `own`.
    #[must_use]
    pub fn new(member: LightMember, keys: K, own: Limits) -> Self {
        let shown = member.shown();
        let mut built = Self {
            engine: Engine::new(member),
            sessions: Sessions::new(keys, own, shown),
            tunnel: None,
            resting: BTreeMap::new(),
            out: VecDeque::new(),
        };
        built.follow_state();
        built
    }

    /// The tunnel's rule, made again over the state the member now knows: its
    /// prefix, and who holds which IPv4 address.
    fn follow_state(&mut self) {
        let member = self.engine.member();
        let state = member.state();
        self.tunnel = tunnel::Prefix::from_parameter(&member.params().ula).ok().map(|prefix| {
            tunnel::Tunnel::new(prefix, member.device())
                .with_holdings(tunnel::Ipv4Holdings::of_state(&state))
        });
    }

    /// This device's overlay addresses, where the member knows its network's.
    #[must_use]
    pub fn addresses(&self) -> Option<(core::net::Ipv6Addr, Option<core::net::Ipv4Addr>)> {
        self.tunnel.as_ref().map(|tunnel| (tunnel.own_address(), tunnel.own_ipv4()))
    }

    /// Sends `packet`, from the board's network stack, to the member its
    /// destination names. Whether it went: not where the tunnel's rule refuses
    /// it, or nobody holding a session is its destination. A member this one
    /// does not know is asked for, and one it knows and holds no session with
    /// is dialled, for the next packet.
    pub fn send_packet(&mut self, packet: &[u8], now: u64, ids: &mut dyn FnMut() -> u64) -> bool {
        let Some(tunnel) = &self.tunnel else { return false };
        if !tunnel.outbound(packet).is_carried() {
            return false;
        }
        let destination = tunnel::destination_of(packet);
        let device = match destination {
            Some(core::net::IpAddr::V6(address)) => {
                let prefix = *tunnel.prefix();
                self.engine
                    .member()
                    .state()
                    .devices
                    .iter()
                    .map(|(device, _)| device)
                    .find(|device| tunnel::address_of(device, &prefix) == address)
            }
            Some(core::net::IpAddr::V4(address)) => tunnel.holdings().holder(address),
            None => None,
        };
        let Some(device) = device else {
            if let Some(address) = destination {
                let query = match address {
                    core::net::IpAddr::V6(address) => Query::Ipv6(address),
                    core::net::IpAddr::V4(address) => Query::Ipv4(address),
                };
                self.engine.find(query, now);
                self.drive(now);
            }
            return false;
        };
        if let Some(id) = self.sessions.with(&device) {
            let sent = self.sessions.send_packet(id, packet);
            self.drive(now);
            return sent;
        }
        if let Some(key) = self.transport_key(&device)
            && !self.sessions.dialling(&key)
        {
            self.sessions.dial(ids(), key, now);
            self.drive(now);
        }
        false
    }

    /// A datagram from `peer`: a packet's fragment.
    pub fn on_datagram(&mut self, peer: K::Peer, datagram: &[u8], now: u64) {
        self.sessions.on_datagram(peer, datagram, now);
        self.drive(now);
    }

    /// The light member, as it is to be kept.
    #[must_use]
    pub const fn member(&self) -> &LightMember {
        self.engine.member()
    }

    /// The devices it holds a session with.
    pub fn in_session(&self) -> impl Iterator<Item = DeviceId> + '_ {
        self.sessions.devices()
    }

    /// The next thing for the host to do, in order.
    pub fn poll_action(&mut self) -> Option<Action<K::Peer>> {
        self.out.pop_front()
    }

    /// The earliest time something waits for, if anything does.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        let rested = self.resting.values().map(|rest| rest.until);
        [self.engine.next_deadline(), self.sessions.next_deadline()]
            .into_iter()
            .flatten()
            .chain(rested)
            .min()
    }

    /// A start: the engine's, then whom to keep in touch with dialled.
    pub fn start(&mut self, now: u64, ids: &mut dyn FnMut() -> u64) {
        self.engine.start(now);
        self.drive(now);
        self.keep_in_touch(now, ids);
    }

    /// A reliable message from `peer`.
    pub fn on_message(
        &mut self,
        peer: K::Peer,
        message: &[u8],
        now: u64,
        ids: &mut dyn FnMut() -> u64,
    ) {
        self.sessions.on_message(&mut self.engine, peer, message, now);
        self.drive(now);
        self.keep_in_touch(now, ids);
    }

    /// The convesso session with `peer` ended.
    pub fn lost(&mut self, peer: &K::Peer, now: u64, ids: &mut dyn FnMut() -> u64) {
        self.sessions.lost(peer);
        self.drive(now);
        self.keep_in_touch(now, ids);
    }

    /// The time is `now`.
    pub fn tick(&mut self, now: u64, ids: &mut dyn FnMut() -> u64) {
        self.sessions.tick(now);
        self.engine.tick(now);
        self.drive(now);
        self.keep_in_touch(now, ids);
    }

    /// Dials each full member it keeps in touch with and holds no session
    /// with, nor a dial, nor a rest.
    fn keep_in_touch(&mut self, now: u64, ids: &mut dyn FnMut() -> u64) {
        for device in self.chosen() {
            if self.sessions.with(&device).is_some()
                || self.resting.get(&device).is_some_and(|rest| rest.until > now)
            {
                continue;
            }
            let Some(key) = self.transport_key(&device) else { continue };
            if self.sessions.dialling(&key) {
                continue;
            }
            self.sessions.dial(ids(), key, now);
        }
        self.drive(now);
    }

    /// The full members it keeps in touch with, in order: its anchors it
    /// knows, the admin whose root it holds, the full members it keeps.
    fn chosen(&self) -> Vec<DeviceId> {
        let member = self.engine.member();
        let state = member.state();
        let anchors: Vec<DeviceId> =
            crate::seeking::anchors_for(&member.device(), &member.params().anchors)
                .into_iter()
                .filter(|anchor| state.devices.contains_key(anchor))
                .collect();
        let kept = member.known_fulls();
        crate::seeking::first_start_order(&anchors, Some(member.contact()), &kept, &[], &[])
            .into_iter()
            .filter(|device| *device != member.device())
            .take(KEPT)
            .collect()
    }

    /// The Ed25519 transport key of `device`, as its leaf the member holds
    /// names it.
    fn transport_key(&self, device: &DeviceId) -> Option<[u8; 32]> {
        let state = self.engine.member().state();
        let leaf = state.devices.get(device)?;
        leaf.record.keys.iter().find_map(|entry| {
            (entry.purpose == KeyPurpose::Transport && entry.alg == Algorithm::Ed25519)
                .then(|| <[u8; 32]>::try_from(entry.value.as_slice()).ok())
                .flatten()
        })
    }

    /// Carries what the sessions and the engine give each other, until
    /// neither has anything left, and queues what is the host's.
    fn drive(&mut self, now: u64) {
        loop {
            let mut moved = false;
            while let Some(output) = self.sessions.poll_output() {
                moved = true;
                self.take_from_sessions(output, now);
            }
            while let Some(output) = self.engine.poll_output() {
                moved = true;
                self.take_from_engine(output);
            }
            if !moved {
                return;
            }
        }
    }

    fn take_from_sessions(&mut self, output: crate::sessions::Output<K::Peer>, now: u64) {
        use crate::sessions::Output;
        match output {
            Output::Message { to, bytes } => self.out.push_back(Action::Message { to, bytes }),
            Output::Datagram { to, bytes } => self.out.push_back(Action::Datagram { to, bytes }),
            Output::Packet { device, bytes, .. } => {
                // Its source must be the session's, its destination this
                // device: anything else a peer lied about, or misdirected.
                if self
                    .tunnel
                    .as_ref()
                    .is_some_and(|tunnel| tunnel.inbound(device, &bytes).is_accepted())
                {
                    self.out.push_back(Action::Packet(bytes));
                }
            }
            Output::Opened { device, .. } => {
                self.resting.remove(&device);
                self.engine.session_opened(device, now);
            }
            Output::Closed { device, .. } => self.engine.session_closed(&device),
            Output::DialFailed { key, failure } => {
                if failure == DialFailure::Refused(Reason::NotAMember) {
                    // Refused as a stranger: its proof may rest on a root they
                    // no longer hold.
                    self.engine.refused_as_a_stranger(now);
                }
                if let Some(device) = self.device_of(&key) {
                    // Awaiting admission, it tries again within minutes: it is
                    // refused only until the admin admits its batch.
                    let longest = if self.engine.member().is_admitted() {
                        LONGEST_REST_MS
                    } else {
                        LONGEST_REST_AWAITING_MS
                    };
                    let rest = self
                        .resting
                        .entry(device)
                        .or_insert(Rest { until: now, next: FIRST_REST_MS });
                    rest.until = now.saturating_add(rest.next);
                    rest.next = rest.next.saturating_mul(2).min(longest);
                    let until = rest.until;
                    self.out.push_back(Action::WakeAt(until));
                }
            }
            Output::Payload { device, bytes, .. } => match unframe(&bytes) {
                Some((Channel::Roster, body)) => {
                    if let Ok(roster_sync::message::Message::Snapshot(root)) =
                        roster_sync::message::Message::decode(body)
                    {
                        self.engine.root_pushed(device, &root, now);
                    }
                }
                Some((Channel::Lookup, body)) => self.engine.lookup(device, body, now),
                Some((Channel::Neighbour, _)) | None => {}
            },
            Output::WakeAt(at) => self.out.push_back(Action::WakeAt(at)),
        }
    }

    fn take_from_engine(&mut self, output: engine::Output) {
        match output {
            engine::Output::Send { peer, channel, body } => {
                // Asked of a member a session is open with: the one that
                // pushed, or one met.
                if let Some(id) = self.sessions.with(&peer) {
                    let _sent = self.sessions.send_payload(id, &frame(channel, &body));
                }
            }
            engine::Output::Keep => self.out.push_back(Action::Keep),
            engine::Output::Renewed => {
                self.sessions.set_evidence(self.engine.member().shown());
                // Its own leaf may hold what it did not before: an IPv4
                // address, given as a board awaiting admission was admitted.
                self.follow_state();
                self.out.push_back(Action::StateChanged);
            }
            engine::Output::Reconsider => self.sessions.reconsider(&self.engine),
            engine::Output::StateChanged => {
                self.follow_state();
                self.out.push_back(Action::StateChanged);
            }
            engine::Output::WakeAt(at) => self.out.push_back(Action::WakeAt(at)),
            engine::Output::Found { .. } => {}
        }
    }

    /// The device whose leaf the member holds names `key` for the transport.
    fn device_of(&self, key: &[u8; 32]) -> Option<DeviceId> {
        let state = self.engine.member().state();
        state.devices.iter().find_map(|(device, leaf)| {
            leaf.record
                .keys
                .iter()
                .any(|entry| {
                    entry.purpose == KeyPurpose::Transport && entry.value == key.as_slice()
                })
                .then_some(device)
        })
    }
}

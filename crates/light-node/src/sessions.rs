//! A light member's sessions, as the binding over convesso opens and carries
//! them (`transport-wire`), with no input or output of its own.
//!
//! What `transport-convesso` does for a node holding no roster, written as a
//! machine a microcontroller drives from its convesso events:
//! - **a dial**: `OPEN` with what it shows; the `ACCEPT`'s evidence must name
//!   the key dialled and be believed, or the roots after the member's own are
//!   asked (`BEHIND`), taken (`ROOTS`) and the evidence judged again;
//! - **an open**: the evidence must name a transport key of the peer that
//!   sent it and be believed, or its roots are asked for while the open is
//!   held; then `ACCEPT`, or `REFUSE`;
//! - **a session**: payloads both ways, each frame cut to what the peer takes
//!   and put back together on the way in (`transport_wire::parts`); closed by
//!   either side, or when the member stops believing its peer.
//!
//! It holds no roster and serves no roots: a `BEHIND` asked of it is not
//! answered, as the daemon's light member answers none. Judging is the
//! engine's (`crate::engine::Engine`), passed in.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use roster::id::DeviceId;
use roster::membership::Shown;
use roster::types::{Algorithm, KeyPurpose};
use transport_wire::fragment::Reassembler;
use transport_wire::frame::{
    FRAGMENT_ROOM, Frame, Limits, PAYLOAD_HEADER, Reason, SessionId, VERSION,
};
use transport_wire::parts::{Joiner, MAX_OPENING, split};

use crate::engine::Engine;

/// How long a dial waits for its answer, in milliseconds.
pub const DIAL_PATIENCE_MS: u64 = 20_000;

/// How long a dial waits for the roots it asked for, in milliseconds.
pub const CATCH_UP_PATIENCE_MS: u64 = 10_000;

/// How many opens are held at once while their roots are asked for.
pub const MAX_HELD: usize = 2;

/// How many sessions this node does not hold it remembers telling so.
const MAX_TOLD: usize = 64;

/// How a peer is told apart from the keys its leaf names: convesso's peer id
/// of an Ed25519 transport key, on whatever the platform runs.
pub trait Keys {
    /// A peer, as convesso authenticates it.
    type Peer: Copy + Ord + core::fmt::Debug;

    /// The peer holding Ed25519 transport key `key`, where it is one.
    fn peer_of(&self, key: &[u8; 32]) -> Option<Self::Peer>;
}

/// Where a message goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum To<P> {
    /// The peer holding this Ed25519 transport key, dialled if need be.
    Key([u8; 32]),
    /// A peer already speaking to this node.
    Peer(P),
}

/// Why a dial failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialFailure {
    /// The far end refused for this reason.
    Refused(Reason),
    /// Its evidence did not hold, even after catching up.
    NotBelieved,
    /// Nothing came back in time.
    Unanswered,
    /// The convesso session with it ended.
    Lost,
}

/// What the host is to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output<P> {
    /// Send `bytes` as one reliable message.
    Message {
        /// To whom.
        to: To<P>,
        /// A frame, or a part of one.
        bytes: Vec<u8>,
    },
    /// A session is open with `device`, either way.
    Opened {
        /// The session.
        id: SessionId,
        /// Who.
        device: DeviceId,
    },
    /// A session closed.
    Closed {
        /// The session.
        id: SessionId,
        /// With whom.
        device: DeviceId,
    },
    /// A dial to the holder of `key` failed.
    DialFailed {
        /// The key dialled.
        key: [u8; 32],
        /// Why.
        failure: DialFailure,
    },
    /// Send `bytes` as one datagram to a peer already speaking to this node.
    Datagram {
        /// To whom.
        to: P,
        /// A packet's fragment, framed.
        bytes: Vec<u8>,
    },
    /// A packet arrived on a session, put back together from its fragments.
    /// Not yet held to the tunnel's rule: that is the member's.
    Packet {
        /// The session.
        id: SessionId,
        /// From whom.
        device: DeviceId,
        /// The packet.
        bytes: Vec<u8>,
    },
    /// A payload arrived on a session.
    Payload {
        /// The session.
        id: SessionId,
        /// From whom.
        device: DeviceId,
        /// The payload.
        bytes: Vec<u8>,
    },
    /// Call [`Sessions::tick`] at this time, or after.
    WakeAt(u64),
}

/// An open session.
#[derive(Debug)]
struct Open<P> {
    peer: P,
    device: DeviceId,
    /// What the peer showed, to judge it again by.
    evidence: Vec<u8>,
    /// The key it was believed for.
    key: [u8; 32],
    inbound: bool,
    /// The number of the next packet sent on it.
    packets: u32,
    /// Its packets' fragments, put back together.
    fragments: Reassembler,
}

impl<P> Open<P> {
    fn new(peer: P, device: DeviceId, evidence: Vec<u8>, key: [u8; 32], inbound: bool) -> Self {
        Self { peer, device, evidence, key, inbound, packets: 0, fragments: Reassembler::new() }
    }
}

/// A dial waiting.
#[derive(Debug, Clone)]
struct Dial<P> {
    peer: P,
    key: [u8; 32],
    deadline: u64,
    /// The evidence of an `ACCEPT`, while its roots are asked for.
    catching_up: Option<Vec<u8>>,
}

/// An open held while its roots are asked for.
#[derive(Debug, Clone)]
struct Held<P> {
    peer: P,
    key: [u8; 32],
    evidence: Vec<u8>,
    deadline: u64,
}

/// One peer's frames.
#[derive(Debug, Clone)]
struct Wire {
    limits: Option<Limits>,
    joiner: Joiner,
}

impl Wire {
    /// A peer's, putting back one frame at a time: what a microcontroller
    /// holds room for.
    const fn new() -> Self {
        Self { limits: None, joiner: Joiner::holding(1) }
    }
}

/// A light member's sessions.
#[derive(Debug)]
pub struct Sessions<K: Keys> {
    keys: K,
    /// What this node takes.
    own: Limits,
    /// What it shows as a session opens.
    evidence: Vec<u8>,
    open: BTreeMap<SessionId, Open<K::Peer>>,
    dials: BTreeMap<SessionId, Dial<K::Peer>>,
    held: BTreeMap<SessionId, Held<K::Peer>>,
    told: BTreeSet<SessionId>,
    wires: BTreeMap<K::Peer, Wire>,
    sequence: u32,
    out: VecDeque<Output<K::Peer>>,
}

impl<K: Keys> Sessions<K> {
    /// Sessions of a node taking `own`, showing `evidence`.
    #[must_use]
    pub const fn new(keys: K, own: Limits, evidence: Vec<u8>) -> Self {
        Self {
            keys,
            own,
            evidence,
            open: BTreeMap::new(),
            dials: BTreeMap::new(),
            held: BTreeMap::new(),
            told: BTreeSet::new(),
            wires: BTreeMap::new(),
            sequence: 0,
            out: VecDeque::new(),
        }
    }

    /// The next thing for the host to do, in order.
    pub fn poll_output(&mut self) -> Option<Output<K::Peer>> {
        self.out.pop_front()
    }

    /// What this node shows from now on, its proof renewed.
    pub fn set_evidence(&mut self, evidence: Vec<u8>) {
        self.evidence = evidence;
    }

    /// The devices it holds a session with.
    pub fn devices(&self) -> impl Iterator<Item = DeviceId> + '_ {
        self.open.values().map(|open| open.device)
    }

    /// A session with `device`, if one is open.
    #[must_use]
    pub fn with(&self, device: &DeviceId) -> Option<SessionId> {
        self.open.iter().find(|(_, open)| open.device == *device).map(|(id, _)| *id)
    }

    /// Whether a dial to the holder of `key` is under way.
    #[must_use]
    pub fn dialling(&self, key: &[u8; 32]) -> bool {
        self.dials.values().any(|dial| dial.key == *key)
    }

    /// The earliest deadline of what waits, if anything does.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        let dials = self.dials.values().map(|dial| dial.deadline);
        let held = self.held.values().map(|held| held.deadline);
        dials.chain(held).min()
    }

    /// Dials the holder of `key`, as session `id`, which the host drew at
    /// random. Nothing where the key is not one a peer can hold.
    pub fn dial(&mut self, id: SessionId, key: [u8; 32], now: u64) {
        let Some(peer) = self.keys.peer_of(&key) else { return };
        let deadline = now.saturating_add(DIAL_PATIENCE_MS);
        self.dials.insert(id, Dial { peer, key, deadline, catching_up: None });
        let open =
            Frame::Open { version: VERSION, id, limits: self.own, evidence: self.evidence.clone() };
        self.send(To::Key(key), peer, open.encode());
        self.out.push_back(Output::WakeAt(deadline));
    }

    /// Sends `payload` on session `id`. Whether it was: not where the session
    /// is not open, or the payload is larger than its peer puts back together.
    pub fn send_payload(&mut self, id: SessionId, payload: &[u8]) -> bool {
        let Some(peer) = self.open.get(&id).map(|open| open.peer) else { return false };
        let frame = Frame::Payload { id, bytes: payload.to_vec() }.encode();
        if frame.len() > self.limits(&peer).frame_len() {
            return false;
        }
        self.send(To::Peer(peer), peer, frame);
        true
    }

    /// Sends `packet` on session `id`, in fragments that fit every path.
    /// Whether it was: not where the session is not open, or the packet needs
    /// more fragments than a packet may have.
    pub fn send_packet(&mut self, id: SessionId, packet: &[u8]) -> bool {
        let Some(open) = self.open.get_mut(&id) else { return false };
        let number = open.packets;
        open.packets = open.packets.wrapping_add(1);
        let peer = open.peer;
        let Some(pieces) = transport_wire::fragment::split(number, packet, FRAGMENT_ROOM) else {
            return false;
        };
        for fragment in pieces {
            let bytes = Frame::Packet { id, fragment }.encode();
            self.out.push_back(Output::Datagram { to: peer, bytes });
        }
        true
    }

    /// A datagram from `peer`, at `now`: a packet's fragment for one of its
    /// sessions.
    pub fn on_datagram(&mut self, peer: K::Peer, datagram: &[u8], now: u64) {
        let Some(Frame::Packet { id, fragment }) = Frame::decode(datagram) else { return };
        let Some(open) = self.open.get_mut(&id).filter(|open| open.peer == peer) else {
            self.unknown(peer, id);
            return;
        };
        if let Some(bytes) = open.fragments.accept(&fragment, now) {
            let device = open.device;
            self.out.push_back(Output::Packet { id, device, bytes });
        }
    }

    /// Closes session `id`.
    pub fn close(&mut self, id: SessionId) {
        self.close_with(id, Reason::Ordinary);
    }

    /// The convesso session with `peer` ended, and with it every one of this
    /// binding's.
    pub fn lost(&mut self, peer: &K::Peer) {
        self.wires.remove(peer);
        let closed: Vec<SessionId> =
            self.open.iter().filter(|(_, open)| open.peer == *peer).map(|(id, _)| *id).collect();
        for id in closed {
            if let Some(open) = self.open.remove(&id) {
                self.out.push_back(Output::Closed { id, device: open.device });
            }
        }
        let failed: Vec<SessionId> =
            self.dials.iter().filter(|(_, dial)| dial.peer == *peer).map(|(id, _)| *id).collect();
        for id in failed {
            if let Some(dial) = self.dials.remove(&id) {
                self.out
                    .push_back(Output::DialFailed { key: dial.key, failure: DialFailure::Lost });
            }
        }
        self.held.retain(|_, held| held.peer != *peer);
    }

    /// The time is `now`: dials and held opens past their deadline are given
    /// up.
    pub fn tick(&mut self, now: u64) {
        let late: Vec<SessionId> =
            self.dials.iter().filter(|(_, dial)| dial.deadline <= now).map(|(id, _)| *id).collect();
        for id in late {
            let Some(dial) = self.dials.remove(&id) else { continue };
            if dial.catching_up.is_some() {
                self.send(
                    To::Peer(dial.peer),
                    dial.peer,
                    Frame::Close { id, reason: Reason::NotAMember }.encode(),
                );
            }
            self.out
                .push_back(Output::DialFailed { key: dial.key, failure: DialFailure::Unanswered });
        }
        self.held.retain(|_, held| held.deadline > now);
    }

    /// Judges every open session again, under what the member now believes:
    /// a peer it no longer believes is closed.
    pub fn reconsider(&mut self, engine: &Engine) {
        let lost: Vec<SessionId> = self
            .open
            .iter()
            .filter(|(_, open)| believed(engine, &open.evidence, &open.key).is_none())
            .map(|(id, _)| *id)
            .collect();
        for id in lost {
            self.close_with(id, Reason::MembershipLost);
        }
    }

    /// A reliable message from `peer`.
    pub fn on_message(&mut self, engine: &mut Engine, peer: K::Peer, message: &[u8], now: u64) {
        // From a peer this node does not yet speak to, nothing larger than an
        // opening is put back together: a stranger would make it hold a
        // frame's worth of memory for nothing.
        let largest = if self.speaks_to(&peer) {
            self.own.frame_len()
        } else {
            self.own.frame_len().min(MAX_OPENING)
        };
        let wire = self.wires.entry(peer).or_insert_with(Wire::new);
        let Some(frame) = wire.joiner.take(message, largest) else {
            return;
        };
        match Frame::decode(&frame) {
            Some(Frame::Open { version, id, limits, evidence }) => {
                self.opened(engine, peer, version, id, limits, evidence, now);
            }
            Some(Frame::Accept { id, limits, evidence }) => {
                self.heard(peer, limits);
                self.accepted(engine, peer, id, evidence, now);
            }
            Some(Frame::Refuse { id, reason }) => {
                if let Some(dial) = self.dials.remove(&id).filter(|dial| dial.peer == peer) {
                    self.out.push_back(Output::DialFailed {
                        key: dial.key,
                        failure: DialFailure::Refused(reason),
                    });
                }
            }
            Some(Frame::Close { id, .. }) => {
                if self.open.get(&id).is_some_and(|open| open.peer == peer)
                    && let Some(open) = self.open.remove(&id)
                {
                    self.out.push_back(Output::Closed { id, device: open.device });
                }
            }
            Some(Frame::Payload { id, bytes }) => {
                match self.open.get(&id).filter(|open| open.peer == peer) {
                    Some(open) => {
                        let device = open.device;
                        self.out.push_back(Output::Payload { id, device, bytes });
                    }
                    None => self.unknown(peer, id),
                }
            }
            Some(Frame::Roots { id, roots }) => self.roots(engine, peer, id, &roots, now),
            // It holds no roots to serve; a packet is not a message.
            Some(Frame::Behind { .. } | Frame::Packet { .. }) | None => {}
        }
    }

    /// A peer opens a session with this node.
    #[allow(clippy::too_many_arguments, reason = "an OPEN's fields, taken apart once")]
    fn opened(
        &mut self,
        engine: &mut Engine,
        peer: K::Peer,
        version: u8,
        id: SessionId,
        limits: Limits,
        evidence: Vec<u8>,
        now: u64,
    ) {
        if version != VERSION {
            self.send(To::Peer(peer), peer, Frame::Refuse { id, reason: Reason::Version }.encode());
            return;
        }
        self.heard(peer, limits);
        if self.open.contains_key(&id) || self.held.contains_key(&id) {
            return;
        }
        let Some(key) = self.key_of(&peer, &evidence) else {
            self.send(
                To::Peer(peer),
                peer,
                Frame::Refuse { id, reason: Reason::NotAMember }.encode(),
            );
            return;
        };
        if let Some(device) = believed(engine, &evidence, &key) {
            self.accept(peer, id, device, evidence, key);
            return;
        }
        match engine.behind(&evidence) {
            Some(root) if self.held.len() < MAX_HELD => {
                let deadline = now.saturating_add(DIAL_PATIENCE_MS);
                self.held.insert(id, Held { peer, key, evidence, deadline });
                self.send(To::Peer(peer), peer, Frame::Behind { id, root }.encode());
                self.out.push_back(Output::WakeAt(deadline));
            }
            _ => {
                self.send(
                    To::Peer(peer),
                    peer,
                    Frame::Refuse { id, reason: Reason::NotAMember }.encode(),
                );
            }
        }
    }

    /// Takes an open: any older one from the same peer closed, as it was
    /// replaced.
    fn accept(
        &mut self,
        peer: K::Peer,
        id: SessionId,
        device: DeviceId,
        evidence: Vec<u8>,
        key: [u8; 32],
    ) {
        let older: Vec<SessionId> = self
            .open
            .iter()
            .filter(|(_, open)| open.peer == peer && open.inbound)
            .map(|(older, _)| *older)
            .collect();
        for older in older {
            self.close_with(older, Reason::Ordinary);
        }
        self.open.insert(id, Open::new(peer, device, evidence, key, true));
        let accept = Frame::Accept { id, limits: self.own, evidence: self.evidence.clone() };
        self.send(To::Peer(peer), peer, accept.encode());
        self.out.push_back(Output::Opened { id, device });
    }

    /// A dial was answered.
    fn accepted(
        &mut self,
        engine: &mut Engine,
        peer: K::Peer,
        id: SessionId,
        evidence: Vec<u8>,
        now: u64,
    ) {
        let Some(dial) =
            self.dials.get(&id).filter(|dial| dial.peer == peer && dial.catching_up.is_none())
        else {
            // An accept for a dial given up on, or nobody's: closed.
            if !self.open.contains_key(&id) {
                self.send(
                    To::Peer(peer),
                    peer,
                    Frame::Close { id, reason: Reason::Ordinary }.encode(),
                );
            }
            return;
        };
        let key = dial.key;
        if let Some(device) = believed(engine, &evidence, &key) {
            self.dials.remove(&id);
            self.open.insert(id, Open::new(peer, device, evidence, key, false));
            self.out.push_back(Output::Opened { id, device });
            return;
        }
        match engine.behind(&evidence) {
            Some(root) => {
                let deadline = now.saturating_add(CATCH_UP_PATIENCE_MS);
                if let Some(dial) = self.dials.get_mut(&id) {
                    dial.catching_up = Some(evidence);
                    dial.deadline = deadline;
                }
                self.send(To::Peer(peer), peer, Frame::Behind { id, root }.encode());
                self.out.push_back(Output::WakeAt(deadline));
            }
            None => self.not_believed(peer, id),
        }
    }

    /// Roots asked for, arrived: taken, and what waited judged again.
    fn roots(&mut self, engine: &mut Engine, peer: K::Peer, id: SessionId, roots: &[u8], now: u64) {
        if let Some(dial) = self.dials.get(&id).filter(|dial| dial.peer == peer).cloned()
            && let Some(evidence) = dial.catching_up
        {
            let taken = engine.take_roots(&evidence, roots, now);
            match believed(engine, &evidence, &dial.key).filter(|_| taken) {
                Some(device) => {
                    self.dials.remove(&id);
                    self.open.insert(id, Open::new(peer, device, evidence, dial.key, false));
                    self.out.push_back(Output::Opened { id, device });
                }
                None => self.not_believed(peer, id),
            }
            return;
        }
        if let Some(held) = self.held.get(&id).filter(|held| held.peer == peer).cloned() {
            self.held.remove(&id);
            let taken = engine.take_roots(&held.evidence, roots, now);
            match believed(engine, &held.evidence, &held.key).filter(|_| taken) {
                Some(device) => self.accept(peer, id, device, held.evidence, held.key),
                None => {
                    self.send(
                        To::Peer(peer),
                        peer,
                        Frame::Refuse { id, reason: Reason::NotAMember }.encode(),
                    );
                }
            }
        }
    }

    /// A dial whose peer is not believed: closed, and failed.
    fn not_believed(&mut self, peer: K::Peer, id: SessionId) {
        if let Some(dial) = self.dials.remove(&id) {
            self.send(
                To::Peer(peer),
                peer,
                Frame::Close { id, reason: Reason::NotAMember }.encode(),
            );
            self.out
                .push_back(Output::DialFailed { key: dial.key, failure: DialFailure::NotBelieved });
        }
    }

    /// A frame for a session this node does not hold: its sender told, once.
    fn unknown(&mut self, peer: K::Peer, id: SessionId) {
        if self.told.len() >= MAX_TOLD {
            self.told.clear();
        }
        if self.told.insert(id) {
            self.send(To::Peer(peer), peer, Frame::Close { id, reason: Reason::Ordinary }.encode());
        }
    }

    /// Closes session `id`, telling its peer why.
    fn close_with(&mut self, id: SessionId, reason: Reason) {
        if let Some(open) = self.open.remove(&id) {
            self.send(To::Peer(open.peer), open.peer, Frame::Close { id, reason }.encode());
            self.out.push_back(Output::Closed { id, device: open.device });
        }
    }

    /// Whether this node speaks to `peer`: a session open, a dial waiting on
    /// it, or its open held while roots are asked for.
    fn speaks_to(&self, peer: &K::Peer) -> bool {
        self.open.values().any(|open| open.peer == *peer)
            || self.dials.values().any(|dial| dial.peer == *peer)
            || self.held.values().any(|held| held.peer == *peer)
    }

    /// The Ed25519 transport key `evidence`'s leaf names that `peer` holds.
    fn key_of(&self, peer: &K::Peer, evidence: &[u8]) -> Option<[u8; 32]> {
        let shown = Shown::from_bytes(evidence).ok()?;
        shown.leaf.record.keys.iter().find_map(|entry| {
            if entry.purpose != KeyPurpose::Transport || entry.alg != Algorithm::Ed25519 {
                return None;
            }
            let key = <[u8; 32]>::try_from(entry.value.as_slice()).ok()?;
            (self.keys.peer_of(&key).as_ref() == Some(peer)).then_some(key)
        })
    }

    /// What `peer` said it takes.
    fn heard(&mut self, peer: K::Peer, limits: Limits) {
        self.wires.entry(peer).or_insert_with(Wire::new).limits = Some(limits.at_least_the_least());
    }

    /// What `peer` takes: what it said, or the least every end takes.
    fn limits(&self, peer: &K::Peer) -> Limits {
        self.wires.get(peer).and_then(|wire| wire.limits).unwrap_or(Limits::LEAST)
    }

    /// Queues `frame` to `to`, in parts where `peer` takes less.
    fn send(&mut self, to: To<K::Peer>, peer: K::Peer, frame: Vec<u8>) {
        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        for bytes in split(frame, sequence, self.limits(&peer).message_len()) {
            self.out.push_back(Output::Message { to: to.clone(), bytes });
        }
    }
}

/// The device `evidence` shows, where it names `key` for the transport and
/// the member believes it.
fn believed(engine: &Engine, evidence: &[u8], key: &[u8; 32]) -> Option<DeviceId> {
    let shown = Shown::from_bytes(evidence).ok()?;
    let names = shown.leaf.record.keys.iter().any(|entry| {
        entry.purpose == KeyPurpose::Transport
            && entry.alg == Algorithm::Ed25519
            && entry.value == key.as_slice()
    });
    (names && engine.judge(&shown)).then_some(shown.leaf.record.id)
}

/// The most bytes of a payload a peer taking `limits` is sent.
#[must_use]
pub fn largest_payload(limits: Limits) -> usize {
    limits.frame_len().saturating_sub(PAYLOAD_HEADER)
}

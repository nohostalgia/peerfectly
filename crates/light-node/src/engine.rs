//! A light member's upkeep and judging, as a machine with no input or output.
//!
//! What it does is what the daemon's light member did, written as the waits it
//! made:
//! - a root pushed is offered; one it cannot place has the chain asked of the
//!   peer that pushed it; one adopted is kept, and what the member stands on
//!   under it (its footing) asked of that peer;
//! - a footing that came back is taken where it holds; one that did not is
//!   asked of the next member a session opens with;
//! - a proof that has aged is renewed, from the member's contact first, then
//!   from each member it holds a session with;
//! - a peer's evidence is judged against the roots the member remembers, and a
//!   root it does not know caught up to as the session opens.
//!
//! Never on a clock: a quiet network costs nothing. The only times are the
//! deadlines of questions asked, which the host is told of ([`Output::WakeAt`])
//! and reports back ([`Engine::tick`]).
//!
//! The host does the rest, in the order the outputs come: sends, keeps the
//! member ([`Output::Keep`]) before acting on what follows, judges its sessions
//! again, follows the state. One upkeep at a time, as the daemon's single
//! upkeep task did: a chain owed first, then a footing, then a renewal.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use roster::id::DeviceId;
use roster::member::LightMember;
use roster::membership::{Evidence, Shown};
use roster::merkle::Hash;

use crate::channel::Channel;
use crate::lookup::{self, Footing, Message, Query};

/// How long an answer is waited for, in milliseconds, before the question is
/// taken as unanswered.
pub const LOOKUP_PATIENCE_MS: u64 = 5_000;

/// What the host is to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Send `body` to `peer` on `channel`.
    Send {
        /// To whom.
        peer: DeviceId,
        /// On which channel.
        channel: Channel,
        /// The payload, unframed.
        body: Vec<u8>,
    },
    /// What the member keeps changed: keep [`Engine::member`] before acting on
    /// what follows.
    Keep,
    /// The member's proof was renewed: show [`LightMember::shown`] from now on.
    /// Its leaf may now say it is full.
    Renewed,
    /// Judge every open session again, under the roots now held.
    Reconsider,
    /// The state the member knows changed: routes and names follow it.
    StateChanged,
    /// Call [`Engine::tick`] at this time, or after.
    WakeAt(u64),
    /// What [`Engine::find`] asked for: the member learned, or `None` where
    /// nobody asked knew.
    Found {
        /// The question.
        query: Query,
        /// Who it names.
        device: Option<DeviceId>,
    },
}

/// What a question asked is for.
#[derive(Debug, Clone)]
enum Asking {
    /// The roots after the current one, then `root`, which could not be placed.
    Chain { root: Vec<u8> },
    /// What the member stands on. `adopted` where asked after a root adopted,
    /// so an answer missing is asked again of the next member met.
    Footing { adopted: bool },
    /// The member's own evidence, by its address; `rest` asked next.
    Renewal { query: Query, rest: Vec<DeviceId> },
    /// A member, by `query`; `rest` asked next.
    Find { query: Query, rest: Vec<DeviceId> },
}

impl Asking {
    /// Whether it is the upkeep's, of which one runs at a time.
    const fn is_upkeep(&self) -> bool {
        !matches!(self, Self::Find { .. })
    }
}

/// A question waiting for its answer.
#[derive(Debug, Clone)]
struct Pending {
    /// Who was asked.
    peer: DeviceId,
    /// When it is taken as unanswered.
    deadline: u64,
    /// What for.
    asking: Asking,
}

/// A light member, and what its upkeep owes.
#[derive(Debug, Clone)]
pub struct Engine {
    member: LightMember,
    /// The members it holds a session with.
    sessions: BTreeSet<DeviceId>,
    /// A root it could not place, and the peer that pushed it.
    chain_owed: Option<(DeviceId, Vec<u8>)>,
    /// The peer it last adopted a root from, whose footing is to be asked.
    adopted_from: Option<DeviceId>,
    /// Whether its proof is to be renewed.
    renewal_owed: bool,
    /// Whether the next member met is to be asked for the footing.
    footing_due: bool,
    /// The digest of the footing it last took. In memory only: after a start
    /// the footing is taken whole once.
    footing_held: Option<[u8; 32]>,
    /// Questions asked, by id.
    pending: BTreeMap<u32, Pending>,
    /// The next question's id: how many were ever asked.
    next_id: u32,
    out: VecDeque<Output>,
}

impl Engine {
    /// An engine over `member`, which owes the footing of the first member a
    /// session opens with.
    #[must_use]
    pub const fn new(member: LightMember) -> Self {
        Self {
            member,
            sessions: BTreeSet::new(),
            chain_owed: None,
            adopted_from: None,
            renewal_owed: false,
            footing_due: true,
            footing_held: None,
            pending: BTreeMap::new(),
            next_id: 0,
            out: VecDeque::new(),
        }
    }

    /// The member.
    #[must_use]
    pub const fn member(&self) -> &LightMember {
        &self.member
    }

    /// The member, to change from outside: the host keeps it afterwards.
    pub const fn member_mut(&mut self) -> &mut LightMember {
        &mut self.member
    }

    /// The member, the engine done with.
    #[must_use]
    pub fn into_member(self) -> LightMember {
        self.member
    }

    /// How many questions it ever asked.
    #[must_use]
    pub const fn asked(&self) -> u32 {
        self.next_id
    }

    /// The members it holds a session with.
    #[must_use]
    pub const fn sessions(&self) -> &BTreeSet<DeviceId> {
        &self.sessions
    }

    /// The earliest deadline of a question waiting, if any.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        self.pending.values().map(|pending| pending.deadline).min()
    }

    /// Whether the upkeep owes or waits for anything.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        self.chain_owed.is_some()
            || self.adopted_from.is_some()
            || self.renewal_owed
            || self.pending.values().any(|pending| pending.asking.is_upkeep())
    }

    /// The next thing for the host to do, in order.
    pub fn poll_output(&mut self) -> Option<Output> {
        self.out.pop_front()
    }

    /// A start: the proof may have aged while the device was off.
    pub fn start(&mut self, now: u64) {
        if self.member.needs_renewal() {
            self.renewal_owed = true;
        }
        self.work(now);
    }

    /// A session opened with `peer`, its evidence believed.
    pub fn session_opened(&mut self, peer: DeviceId, now: u64) {
        self.sessions.insert(peer);
        // A proof aged, or never given (a board awaiting admission): asked of
        // the members met.
        if self.member.needs_renewal() {
            self.renewal_owed = true;
        }
        if core::mem::take(&mut self.footing_due) {
            // A root adopted from someone already names whom to ask.
            self.adopted_from.get_or_insert(peer);
        }
        self.work(now);
    }

    /// The session with `peer` closed. What was asked of it waits out its
    /// deadline, as an answer may still be on its way.
    pub fn session_closed(&mut self, peer: &DeviceId) {
        self.sessions.remove(peer);
    }

    /// A dial was refused as by a member that does not know this one: its
    /// proof may rest on a root they no longer hold.
    pub fn refused_as_a_stranger(&mut self, now: u64) {
        self.renewal_owed = true;
        self.work(now);
    }

    /// A root `peer` pushed, as the bytes of a signed snapshot.
    ///
    /// Adopted, it is kept, every session judged again under it, and what the
    /// member stands on asked of `peer`: asked by the upkeep rather than here,
    /// so the answer does not wait behind this very message on the session.
    pub fn root_pushed(&mut self, peer: DeviceId, root: &[u8], now: u64) {
        let Ok(outcome) = self.member.offer_root(root) else { return };
        match outcome {
            roster::light::RootOutcome::NeedsChain => {
                // Roots were missed: the one who sent this has the chain.
                self.chain_owed = Some((peer, root.to_vec()));
            }
            roster::light::RootOutcome::Adopted
            | roster::light::RootOutcome::Switched
            | roster::light::RootOutcome::KeptAside => {
                self.out.push_back(Output::Keep);
                self.adopted_from = Some(peer);
                if self.member.needs_renewal() {
                    self.renewal_owed = true;
                }
                self.out.push_back(Output::Reconsider);
                self.out.push_back(Output::StateChanged);
            }
            _ => return,
        }
        self.work(now);
    }

    /// Lookup traffic from `peer`: a question, which a light member answers
    /// with nothing, holding no roster; or an answer it waits for.
    pub fn lookup(&mut self, peer: DeviceId, body: &[u8], now: u64) {
        match Message::decode(body) {
            Some(Message::Request { id, .. }) => {
                let answer = Message::Answer { id, evidence: Vec::new() };
                self.out.push_back(Output::Send {
                    peer,
                    channel: Channel::Lookup,
                    body: answer.encode(),
                });
            }
            Some(Message::Answer { id, evidence }) => {
                // An answer is taken from whoever was asked, and nobody else.
                if self.pending.get(&id).is_some_and(|pending| pending.peer == peer)
                    && let Some(pending) = self.pending.remove(&id)
                {
                    self.answered(pending, Some(&evidence), now);
                    self.work(now);
                }
            }
            None => {}
        }
    }

    /// The time is `now`: questions past their deadline are unanswered.
    pub fn tick(&mut self, now: u64) {
        let late: Vec<u32> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in late {
            if let Some(pending) = self.pending.remove(&id) {
                self.answered(pending, None, now);
            }
        }
        self.work(now);
    }

    /// Whether the compact evidence a peer shows as a session opens holds,
    /// against a root this member remembers.
    #[must_use]
    pub fn judge(&self, shown: &Shown) -> bool {
        self.member.believes_shown(shown)
    }

    /// The root this member holds, where a peer's evidence rests on one it
    /// does not know: what it asks the roots after, as the session opens.
    #[must_use]
    pub fn behind(&self, shown: &[u8]) -> Option<Hash> {
        let shown = Shown::from_bytes(shown).ok()?;
        self.member.behind(&shown.against)
    }

    /// Takes the roots a peer showing `shown` answered as a session opened.
    /// Whether they were taken; if so, the member is kept and what it stands
    /// on asked of that peer by the upkeep.
    pub fn take_roots(&mut self, shown: &[u8], roots: &[u8], now: u64) -> bool {
        let Some(chain) = lookup::decode_roots(roots) else { return false };
        if !self.member.take_chain(&chain) {
            return false;
        }
        if let Ok(shown) = Shown::from_bytes(shown) {
            self.adopted_from = Some(shown.leaf.record.id);
        }
        self.work(now);
        true
    }

    /// Finds the member `query` names by asking: the members it holds a
    /// session with, then its anchors among them, in the order `seeking`
    /// gives. Answered by [`Output::Found`].
    pub fn find(&mut self, query: Query, now: u64) {
        let anchors =
            crate::seeking::anchors_for(&self.member.device(), &self.member.params().anchors);
        let in_session: Vec<DeviceId> = self.sessions.iter().copied().collect();
        let reachable: Vec<DeviceId> =
            anchors.iter().filter(|anchor| self.sessions.contains(anchor)).copied().collect();
        let asked: Vec<DeviceId> = crate::seeking::lookup_order(&[], &in_session, &reachable)
            .into_iter()
            .filter_map(|source| match source {
                crate::seeking::Source::Cache => None,
                crate::seeking::Source::Lan(peer)
                | crate::seeking::Source::Session(peer)
                | crate::seeking::Source::Anchor(peer) => Some(peer),
            })
            .collect();
        self.ask_in_turn(Asking::Find { query, rest: asked }, now);
    }

    /// Starts what the upkeep owes, where it waits for nothing: a chain first,
    /// then a footing, then a renewal.
    fn work(&mut self, now: u64) {
        if self.pending.values().any(|pending| pending.asking.is_upkeep()) {
            return;
        }
        // Taken either way: with no current root there is nothing to ask after.
        if let Some((peer, root)) = self.chain_owed.take()
            && let Some(current) = self.member.current()
        {
            self.ask(peer, Query::RootsAfter(current), Asking::Chain { root }, now);
            return;
        }
        if let Some(peer) = self.adopted_from.take() {
            self.out.push_back(Output::Keep);
            self.ask_footing(peer, true, now);
            return;
        }
        if core::mem::take(&mut self.renewal_owed) {
            let Ok(prefix) = tunnel::Prefix::from_parameter(&self.member.params().ula) else {
                return;
            };
            let query = Query::Ipv6(tunnel::address_of(&self.member.device(), &prefix));
            let contact = self.member.contact();
            let mut asked = Vec::from([contact]);
            asked.extend(self.sessions.iter().copied().filter(|peer| *peer != contact));
            self.ask_in_turn(Asking::Renewal { query, rest: asked }, now);
        }
    }

    /// Asks the footing of `peer`.
    fn ask_footing(&mut self, peer: DeviceId, adopted: bool, now: u64) {
        let query = Query::Footing(self.member.device(), self.footing_held);
        self.ask(peer, query, Asking::Footing { adopted }, now);
    }

    /// Asks the first of the peers `asking` holds, the rest kept for after.
    fn ask_in_turn(&mut self, asking: Asking, now: u64) {
        match asking {
            Asking::Renewal { query, mut rest } => {
                if rest.is_empty() {
                    return;
                }
                let peer = rest.remove(0);
                self.ask(peer, query.clone(), Asking::Renewal { query, rest }, now);
            }
            Asking::Find { query, mut rest } => {
                if rest.is_empty() {
                    self.out.push_back(Output::Found { query, device: None });
                    return;
                }
                let peer = rest.remove(0);
                self.ask(peer, query.clone(), Asking::Find { query, rest }, now);
            }
            Asking::Chain { .. } | Asking::Footing { .. } => {}
        }
    }

    /// Sends a question to `peer` and waits for it.
    fn ask(&mut self, peer: DeviceId, query: Query, asking: Asking, now: u64) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let deadline = now.saturating_add(LOOKUP_PATIENCE_MS);
        self.pending.insert(id, Pending { peer, deadline, asking });
        let request = Message::Request { id, query };
        self.out.push_back(Output::Send { peer, channel: Channel::Lookup, body: request.encode() });
        self.out.push_back(Output::WakeAt(deadline));
    }

    /// What came back for a question, or `None` where nothing did in time. The
    /// caller then starts what the upkeep owes next.
    fn answered(&mut self, pending: Pending, answer: Option<&[u8]>, now: u64) {
        let peer = pending.peer;
        match pending.asking {
            Asking::Chain { root } => {
                let Some(chain) = answer.and_then(lookup::decode_roots) else { return };
                for missed in
                    chain.iter().map(Vec::as_slice).chain(core::iter::once(root.as_slice()))
                {
                    let _ = self.member.offer_root(missed);
                }
                self.out.push_back(Output::Keep);
                self.out.push_back(Output::Reconsider);
                self.out.push_back(Output::StateChanged);
                if self.member.needs_renewal() {
                    self.renewal_owed = true;
                }
                self.ask_footing(peer, false, now);
            }
            Asking::Footing { adopted } => {
                let taken = answer.is_some_and(|answer| self.take_footing(answer));
                if adopted && !taken {
                    // Nothing came back: a light peer, or no answer in time.
                    self.footing_due = true;
                }
                self.out.push_back(Output::StateChanged);
            }
            Asking::Renewal { query, rest } => {
                let renewed = answer
                    .and_then(|evidence| Evidence::from_bytes(evidence).ok())
                    .is_some_and(|shown| self.member.renew(shown).is_ok());
                if renewed {
                    self.out.push_back(Output::Keep);
                    self.out.push_back(Output::Renewed);
                } else {
                    self.ask_in_turn(Asking::Renewal { query, rest }, now);
                }
            }
            Asking::Find { query, rest } => {
                let found = answer.and_then(|evidence| {
                    lookup::take_answer(&mut self.member, &query, evidence).ok()
                });
                match found {
                    Some(device) => {
                        self.out.push_back(Output::Keep);
                        self.out.push_back(Output::StateChanged);
                        self.out.push_back(Output::Found { query, device: Some(device) });
                    }
                    None => self.ask_in_turn(Asking::Find { query, rest }, now),
                }
            }
        }
    }

    /// Takes a footing answer: its own digest back, nothing changed; else the
    /// footing, where it holds. Whether one was taken.
    fn take_footing(&mut self, answer: &[u8]) -> bool {
        if self.footing_held.is_some_and(|held| answer == held.as_slice()) {
            return true;
        }
        let Some(footing) = Footing::decode(answer) else { return false };
        if lookup::take_footing(&mut self.member, &footing) {
            self.out.push_back(Output::Keep);
        }
        self.footing_held = Some(footing.digest());
        true
    }
}

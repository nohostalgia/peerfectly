//! Finding a peer the relay alone would not find, and being findable.
//!
//! §2.9 orders the paths to a peer: the local network first, then addresses
//! already cached from when it was, and then the relay, through which the
//! transport finds the rest itself. This module runs the two that need
//! something said out loud.
//!
//! **Announcing** puts this device's own addresses on the local network, signed
//! with its transport key, every few seconds and immediately whenever they
//! change. **Listening** hears other devices do the same, checks the announcing
//! key against the roster, and hands what it heard to the transport as a hint.
//! **Hinting** offers the transport what was heard before, for peers that have
//! no session.
//!
//! # Nothing here decides anything
//!
//! An address is not authority. A session opened over an address heard here is
//! authorised from the signed roster exactly like any other, so the worst a
//! liar achieves is a dial that reaches a peer which refuses it, or nobody.
//! That is why announcements are accepted from members without further
//! ceremony and why an unparseable one is dropped rather than reported: it is
//! background noise on a shared port, not an attack to be logged.
//!
//! # Why it starts with the tunnel and not before
//!
//! Multicast is a socket. §2.6c says a node reaches nothing while the person
//! believes it is off, so the loops are
//! spawned by `bring_up` and aborted by `take_down`, and the sockets they own
//! cease to exist with them. There is no flag to forget to check.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use local_discovery::Record;
use local_discovery::{Announcement, Cache, Candidate, Conditions, Multicast, Source, order};
use roster::sign::PublicKey;
use roster::state::RosterState;
use tokio::sync::Mutex;

use crate::endpoints::Endpoints;
use crate::node::Node;
use crate::routes::Interface;
use crate::schedule::Announcing;

/// The subsystem name faults from here carry.
const SUBSYSTEM: &str = "discovery";

/// The local network, for as long as the tunnel is up.
pub struct Discovery {
    /// The node whose peers are being looked for.
    node: Arc<Node>,
    /// What has been heard, and from whom.
    cache: Mutex<Cache>,
    /// Where that survives a restart.
    ///
    /// §2.6b budgets 500 ms from activation to the first useful session using
    /// cached endpoints. A cache that emptied on every start would meet that
    /// only for a device that had already been running.
    endpoints: Endpoints,
    /// Whether the cache has changed since it was last written.
    dirty: Mutex<bool>,
    /// The adapter this daemon created, so announcements never go out of it.
    own: Option<Interface>,
    /// Where the interfaces to announce on come from.
    interfaces: Arc<dyn crate::connectivity::Interfaces>,
}

/// Which local networks this device should announce on.
///
/// **A decision, taken here rather than inherited.** A multicast socket that
/// names no outgoing interface is given one by the routing table, which ranks by
/// metric for reasons unrelated to discovery — and the adapter this daemon
/// creates can rank first. On the machine where this was found, `peerfectly` carried
/// interface metric 5 against 25 for the local network, so every announcement
/// left through the tunnel, reached nobody, and failed with `WSAEHOSTUNREACH`.
///
/// Pure, and over a supplied list, so the rule is testable on any machine while
/// the enumeration that feeds it is not. Which is the same split the rest of this
/// crate keeps.
///
/// `own` is the adapter this daemon created, excluded because an announcement
/// there reaches only devices that can already reach this one, and carries
/// addresses describing paths that exist only for them.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the desktop path reads interfaces through `choosing`; this form is what the tests drive"
    )
)]
pub fn announcing_on(interfaces: &[netdev::Interface], own: Option<Interface>) -> Vec<Ipv4Addr> {
    let supplied: Vec<crate::connectivity::LocalInterface> =
        interfaces.iter().map(crate::connectivity::LocalInterface::from).collect();
    choosing(&supplied, own)
}

/// The same rule over interfaces an edge supplied.
///
/// What [`announcing_on`] decides, over the platform-neutral shape a phone hands
/// over. One rule, so a desktop and a phone cannot come to announce on different
/// kinds of interface.
pub fn choosing(
    interfaces: &[crate::connectivity::LocalInterface],
    own: Option<Interface>,
) -> Vec<Ipv4Addr> {
    let mut chosen = Vec::new();
    for interface in interfaces {
        if Some(Interface::new(interface.index)) == own {
            continue;
        }
        // Up, running, and able to carry multicast. An interface that is none of
        // those is not a local network this device is on.
        if !interface.up || !interface.running || !interface.multicast {
            continue;
        }
        // Loopback reaches nothing but this machine, and two nodes on one host
        // already hear each other through multicast loopback on a real
        // interface.
        if interface.loopback {
            continue;
        }
        // The address is what a multicast socket names its interface by.
        if let Some(address) = interface.ipv4.first()
            && !chosen.contains(address)
        {
            chosen.push(*address);
        }
    }
    chosen
}

/// The local networks this machine is on right now.
///
/// Asked again each time rather than held, so an interface appearing or
/// disappearing is taken into account without a restart and without an
/// OS notification API. One enumeration per announce interval is the cost.
fn local_networks(
    interfaces: &dyn crate::connectivity::Interfaces,
    own: Option<Interface>,
) -> Vec<Ipv4Addr> {
    choosing(&interfaces.list(), own)
}

impl Discovery {
    /// Loads what was known last time.
    ///
    /// A cache that cannot be read is not a reason to refuse to start: it costs
    /// the fast path, not correctness. The failure is recorded and an empty
    /// cache used.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the service passes its interfaces through `resume_with`")
    )]
    pub async fn resume(node: Arc<Node>, endpoints: Endpoints, own: Option<Interface>) -> Self {
        Self::resume_with(node, endpoints, own, Arc::new(crate::connectivity::SystemInterfaces))
            .await
    }

    /// Loads what was known last time, announcing on interfaces from `interfaces`.
    pub async fn resume_with(
        node: Arc<Node>,
        endpoints: Endpoints,
        own: Option<Interface>,
        interfaces: Arc<dyn crate::connectivity::Interfaces>,
    ) -> Self {
        let cache = match endpoints.load(Instant::now()) {
            Ok(held) => held,
            Err(cause) => {
                node.record(
                    crate::node::Severity::Problem,
                    SUBSYSTEM,
                    format!("the endpoint cache could not be read: {cause}"),
                )
                .await;
                Cache::new()
            }
        };
        Self {
            node,
            cache: Mutex::new(cache),
            endpoints,
            dirty: Mutex::new(false),
            own,
            interfaces,
        }
    }

    /// Announces this device on the local network, for as long as it runs.
    ///
    /// The socket is opened here rather than held, so a network that comes and
    /// goes is survived by the next attempt rather than ending the loop.
    pub async fn announce_forever(self: Arc<Self>) {
        let mut announcing = Announcing::new();
        let interval = self.node.schedule().announce;
        let check = crate::limits::INTERFACE_RECHECK;
        // Due at once: the network has just come up.
        let mut since = interval;
        let mut repeats = 0u8;

        loop {
            let Some(state) = self.network().await else { return };
            let Some(transport) = self.node.transport().await else { return };

            let addresses = transport.addresses();
            // Looked at every few seconds, announced on a change and otherwise
            // once a minute. `should_announce` compares against what it saw last
            // time, so a changed address set goes out at once. Moving from
            // tethering to home Wi-Fi is the case that matters: waiting a minute
            // to notice the machine in the next room is the absurd failure
            // `local-discovery` names.
            let changed = announcing.would_change(&addresses);
            let due = since >= interval || repeats > 0;
            if !announcing.should_announce(&addresses, due) || addresses.is_empty() {
                tokio::time::sleep(check).await;
                since = since.saturating_add(check);
                continue;
            }
            if changed {
                repeats = crate::schedule::ANNOUNCE_REPEATS;
            } else {
                repeats = repeats.saturating_sub(1);
            }

            if let Err(cause) = self.announce_once(&state, &addresses).await {
                self.node.record(crate::node::Severity::Event, SUBSYSTEM, cause).await;
                // Forget what was announced, so the next round tries again
                // rather than deciding nothing has changed.
                announcing.forget();
            }
            since = core::time::Duration::ZERO;
            tokio::time::sleep(check).await;
            since = since.saturating_add(check);
        }
    }

    /// Sends one announcement.
    async fn announce_once(&self, state: &RosterState, addresses: &[String]) -> Result<(), String> {
        let identity = self.node.identity();
        let key = identity.transport_key().public_key();

        let record = Record::new(key, state.network, sequence_now(), addresses.to_vec())
            .map_err(|cause| format!("the announcement could not be built: {cause}"))?;
        let announcement = Announcement::sign(record, identity.transport_key().signer())
            .map_err(|cause| format!("the announcement could not be signed: {cause}"))?;

        // Chosen now, not at startup: an interface that has appeared since is
        // announced on, and one that has gone is not.
        let interfaces = local_networks(self.interfaces.as_ref(), self.own);
        if interfaces.is_empty() {
            return Err("no local network to announce on".to_owned());
        }

        // A sender that does not join the group: this only speaks. It names its
        // outgoing interfaces, so nothing is left to the routing table.
        let socket = Multicast::sender(&interfaces, state.network)
            .await
            .map_err(|cause| format!("no socket to announce on: {cause}"))?;
        socket
            .announce(&announcement)
            .await
            .map_err(|cause| format!("the announcement was not sent: {cause}"))
    }

    /// Hears other devices announce, for as long as it runs.
    ///
    /// The group is joined on the interfaces this machine has **now**, and the
    /// set is asked again on the announce interval. An interface that appears —
    /// a cable plugged in, a Wi-Fi network joined — is listened on without a
    /// restart, and one that goes stops costing a join.
    pub async fn listen_forever(self: Arc<Self>) {
        let interval = self.node.schedule().announce;

        loop {
            let Some(state) = self.network().await else { return };

            let interfaces = local_networks(self.interfaces.as_ref(), self.own);
            if interfaces.is_empty() {
                // No local network to listen on is not fatal: everything still
                // works through the relay. Waiting for one to appear is right.
                tokio::time::sleep(interval).await;
                continue;
            }

            // A failure to join is worth reporting: it means the local path is
            // not available at all. Not fatal, and retried on the next round.
            let socket = match Multicast::join(&interfaces, state.network).await {
                Ok(socket) => socket,
                Err(cause) => {
                    self.node
                        .record(
                            crate::node::Severity::Event,
                            SUBSYSTEM,
                            format!("the local network cannot be listened on: {cause}"),
                        )
                        .await;
                    tokio::time::sleep(interval).await;
                    continue;
                }
            };

            // Listen until the set of interfaces changes under us, then rebuild.
            loop {
                // Most of what arrives on a shared port belongs to somebody
                // else. Those come back as refusals and are the background, not
                // faults — recording them would drown the one line that matters.
                match tokio::time::timeout(interval, socket.receive()).await {
                    Ok(Ok((announcement, _from))) => self.heard(announcement).await,
                    Ok(Err(_refused)) => continue,
                    Err(_elapsed) => {
                        if local_networks(self.interfaces.as_ref(), self.own) != interfaces {
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Records one announcement, if the roster knows who sent it.
    async fn heard(&self, announcement: Announcement) {
        let Ok(state) = self.node.state().await else { return };
        let record = announcement.record();

        // The announcement carries a transport key; the roster says whether it
        // belongs to a member. A key it does not name is not an attack, it is a
        // device from another network on the same wire, or one this node has
        // not yet learned about.
        if record.network != state.network || !member_holds(&state, &record.key) {
            return;
        }
        if record.key.as_bytes() == self.node.identity().transport_key().public_key().as_bytes() {
            return;
        }

        let now = Instant::now();
        let key_id = record.key.key_id();
        {
            let mut cache = self.cache.lock().await;
            // A refusal here is the sequence rule doing its job: an older
            // announcement must not walk a peer's addresses backwards.
            if cache.record(key_id, record.sequence, record.addresses.clone(), now).is_err() {
                return;
            }
        }
        *self.dirty.lock().await = true;

        if let Some(transport) = self.node.transport().await {
            transport.learned(&record.key, &record.addresses);
        }
        // Newer news of where it is: a rest earned before it says nothing now.
        let announcing = state.devices.values().find(|device| {
            transport_key_of(device).is_some_and(|held| held.as_bytes() == record.key.as_bytes())
        });
        if let Some(device) = announcing {
            self.node.announced(device.id);
        }
    }

    /// Offers the transport what is known about peers it has no session with.
    ///
    /// What was heard before, which is the reason the cache is kept across
    /// restarts at all.
    pub async fn hint_forever(self: Arc<Self>) {
        let interval = self.node.schedule().sync;

        loop {
            self.hint_once().await;
            self.persist().await;
            tokio::time::sleep(interval).await;
        }
    }

    /// One pass over the peers with no session.
    async fn hint_once(&self) {
        let Ok(state) = self.node.state().await else { return };
        let Some(transport) = self.node.transport().await else { return };

        let me = self.node.identity().device_id();

        for device in state.devices.values() {
            if device.id == me || self.node.has_session(&device.id).await {
                continue;
            }
            let Some(key) = transport_key_of(device) else { continue };

            let cached = self.cache.lock().await.addresses_for(&key.key_id(), Instant::now());
            if !cached.is_empty() {
                // Heard on this network, or heard on it recently enough to be
                // worth one attempt.
                transport.learned(&key, &ranked(cached, Source::Local));
            }
        }
    }

    /// Writes the cache if anything has changed.
    async fn persist(&self) {
        if !*self.dirty.lock().await {
            return;
        }
        let saved = {
            let cache = self.cache.lock().await;
            self.endpoints.save(&cache, Instant::now())
        };
        match saved {
            Ok(()) => *self.dirty.lock().await = false,
            Err(cause) => {
                self.node
                    .record(
                        crate::node::Severity::Problem,
                        SUBSYSTEM,
                        format!("the endpoint cache could not be written: {cause}"),
                    )
                    .await;
            }
        }
    }

    /// The network, or nothing if this node has no roster yet.
    async fn network(&self) -> Option<RosterState> {
        self.node.state().await.ok()
    }
}

/// Whether a member of this network holds this transport key.
fn member_holds(state: &RosterState, key: &PublicKey) -> bool {
    state.devices.values().any(|device| {
        transport_key_of(device).is_some_and(|held| held.as_bytes() == key.as_bytes())
    })
}

/// A device's transport key, as the roster declares it.
fn transport_key_of(record: &roster::types::DeviceRecord) -> Option<PublicKey> {
    let entry =
        record.keys.iter().find(|entry| entry.purpose == roster::types::KeyPurpose::Transport)?;
    PublicKey::new(entry.alg, entry.value.clone()).ok()
}

/// Puts addresses in the order §8 asks for before handing them on.
///
/// The transport receives a list and tries what it is given; the ordering is
/// this layer's answer to "which first", and `local-discovery` already holds
/// the rule.
fn ranked(addresses: Vec<String>, source: Source) -> Vec<String> {
    let candidates: Vec<Candidate> =
        addresses.into_iter().map(|address| Candidate::new(address, source)).collect();
    // No local prefixes are supplied and no shared external address is claimed:
    // both are things the daemon would have to measure, and neither is measured
    // yet. Stated here rather than guessed at.
    let conditions = Conditions { local_prefixes: Vec::new(), shares_external_address: false };
    order(&candidates, &conditions).into_iter().map(|candidate| candidate.address).collect()
}

/// A sequence that increases across restarts.
///
/// Seconds since the epoch. The rule the announcement cache enforces is that a
/// record must be *newer* than the last one accepted, so what matters is that
/// this never goes backwards for a given device — and a counter kept in memory
/// would restart at zero, after which nothing this device announced would be
/// accepted until it caught up.
///
/// A clock moved backwards by more than the gap between two announcements has the
/// same effect until it catches up. That is a worse failure than it sounds and
/// a better one than the alternative, and it is why this is written down here.
fn sequence_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

/// How long a loop waits before retrying something that failed outright.
///
/// Unused while every loop above sleeps on its own schedule; kept so the
/// intervals stay in one place if that changes.
#[allow(dead_code, reason = "the schedules live in `schedule.rs`; this is the floor")]
const RETRY: Duration = Duration::from_secs(1);

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use super::*;

    /// The ordering rule belongs to `local-discovery`, and this must not grow a
    /// An interface as the platform would report it, for exercising the rule
    /// without depending on the machine the test runs on.
    fn adapter(index: u32, address: [u8; 4], flags: u32) -> netdev::Interface {
        let mut interface = netdev::Interface::dummy();
        interface.index = index;
        interface.flags = flags;
        interface.ipv4 =
            vec![netdev::ipnet::Ipv4Net::new(Ipv4Addr::from(address), 24).expect("a /24 is valid")];
        interface
    }

    /// Up and multicast-capable, which is what an ordinary LAN adapter reports.
    ///
    /// Built from the platform's own constants rather than written as a number:
    /// the flag values differ between Windows and Linux, and a hard-coded one
    /// would make this test pass on the machine it was written on and mean
    /// nothing anywhere else. `local-discovery` is in the portable core.
    ///
    /// Cast because the **type** differs too — `u32` on Windows and `i32` on
    /// Linux — which compiled here for as long as this crate was one nobody
    /// built for Linux. A portable crate whose tests do not compile everywhere
    /// is a portable crate in name.
    fn usable() -> u32 {
        use netdev::interface::flags;
        #[cfg_attr(windows, allow(unused_mut, reason = "only Unix adds a bit below"))]
        let mut bits = flag(flags::IFF_UP) | flag(flags::IFF_MULTICAST);
        // `is_running` is not the same kind of question on both platforms, and
        // this is where that shows.
        //
        // On Unix it is a flag, so a fabricated interface can carry it. On
        // Windows `netdev` answers it by asking the operating system about the
        // interface **index** — so for an interface this test invented, the
        // answer is about whatever real adapter happens to have that index on
        // the machine running the test.
        //
        // That is a weakness in the Windows side of this test, found by building
        // for Linux and worth writing down rather than smoothing over: it has
        // been passing partly because of this developer's hardware. Making it
        // sound means letting the selection be told whether an interface is
        // running instead of asking `netdev`, which is a change to production
        // code and belongs to its own piece of work.
        #[cfg(unix)]
        {
            bits |= flag(flags::IFF_RUNNING);
        }
        bits
    }

    /// One of `netdev`'s flag constants, whatever integer type it is here.
    fn flag(value: impl Into<i64>) -> u32 {
        u32::try_from(value.into()).unwrap_or(0)
    }

    /// The daemon never announces on the adapter it created.
    ///
    /// An announcement there reaches only devices that can already reach this
    /// one, and carries addresses describing paths that exist only for them.
    /// It is also the adapter the routing table prefers, which is the whole
    /// defect: on the machine where this was found, `peerfectly` carried interface
    /// metric 5 against 25 for the local network.
    #[test]
    fn a_supplied_list_is_chosen_from_by_the_same_rule() {
        use crate::connectivity::LocalInterface;
        let wifi = LocalInterface {
            index: 30,
            ipv4: vec![Ipv4Addr::new(192, 168, 1, 40)],
            subnets: Vec::new(),
            gateways: Vec::new(),
            resolvers: Vec::new(),
            up: true,
            running: true,
            multicast: true,
            loopback: false,
        };
        let cellular = LocalInterface {
            index: 31,
            ipv4: vec![Ipv4Addr::new(10, 64, 0, 2)],
            multicast: false,
            ..wifi.clone()
        };
        let vpn =
            LocalInterface { index: 32, ipv4: vec![Ipv4Addr::new(10, 0, 0, 1)], ..wifi.clone() };
        let loopback = LocalInterface {
            index: 1,
            ipv4: vec![Ipv4Addr::LOCALHOST],
            loopback: true,
            ..wifi.clone()
        };

        let chosen = choosing(&[wifi, cellular, vpn, loopback], Some(Interface::new(32)));
        assert_eq!(chosen, vec![Ipv4Addr::new(192, 168, 1, 40)], "only the Wi-Fi a phone is on");
    }

    #[test]
    fn the_daemons_own_adapter_is_never_announced_on() {
        let lan = adapter(11, [192, 168, 1, 20], usable());
        let tunnel = adapter(14, [10, 0, 0, 1], usable());

        let chosen = announcing_on(&[lan, tunnel], Some(Interface::new(14)));

        assert_eq!(chosen, vec![Ipv4Addr::new(192, 168, 1, 20)]);
        assert!(
            !chosen.contains(&Ipv4Addr::new(10, 0, 0, 1)),
            "the adapter this daemon created must never be announced on"
        );
    }

    /// A device on two local networks announces on both.
    ///
    /// Wired and wireless at once is ordinary, and a peer may be on either.
    /// Announcing on whichever won a metric comparison would make discovery
    /// depend on a number chosen for unrelated reasons.
    #[test]
    fn a_device_on_two_networks_announces_on_both() {
        let wired = adapter(11, [192, 168, 1, 20], usable());
        let wireless = adapter(17, [192, 168, 4, 33], usable());

        let chosen = announcing_on(&[wired, wireless], None);

        assert_eq!(chosen, vec![Ipv4Addr::new(192, 168, 1, 20), Ipv4Addr::new(192, 168, 4, 33)]);
    }

    /// An interface that cannot carry an announcement is not chosen.
    #[test]
    fn an_interface_that_cannot_carry_one_is_not_chosen() {
        let down =
            adapter(2, [192, 168, 1, 21], usable() & !flag(netdev::interface::flags::IFF_UP));
        let no_multicast = adapter(
            3,
            [192, 168, 1, 22],
            usable() & !flag(netdev::interface::flags::IFF_MULTICAST),
        );
        let mut without_address = adapter(4, [0, 0, 0, 0], usable());
        without_address.ipv4 = Vec::new();

        assert!(announcing_on(&[down, no_multicast, without_address], None).is_empty());
    }

    /// The set is recomputed, so an interface appearing is taken into account
    /// without a restart.
    #[test]
    fn an_interface_appearing_changes_what_is_announced_on() {
        let wired = adapter(11, [192, 168, 1, 20], usable());
        let before = announcing_on(core::slice::from_ref(&wired), None);

        let wireless = adapter(17, [192, 168, 4, 33], usable());
        let after = announcing_on(&[wired, wireless], None);

        assert_ne!(before, after, "a changed set of interfaces must change the answer");
        assert_eq!(after.len(), 2);
    }

    /// second one.
    #[test]
    fn local_addresses_are_offered_as_they_were_heard() {
        let local = ranked(vec!["192.168.1.7:41641".to_owned()], Source::Local);
        assert_eq!(local, vec!["192.168.1.7:41641".to_owned()]);
    }

    /// A sequence that restarted at zero would leave this device unable to
    /// announce anything a peer would accept until it caught up.
    #[test]
    fn the_sequence_does_not_restart_at_zero() {
        assert!(sequence_now() > 1_700_000_000, "seconds since the epoch, not a counter");
    }

    /// Everything this module does is a socket or a request, so it must not
    /// exist while the tunnel is down. The proof is structural: every loop
    /// stops the moment the transport is gone.
    #[test]
    fn every_loop_ends_when_the_transport_does() {
        let source = crate::code_of(include_str!("discovery.rs"));
        for loop_name in ["announce_forever", "hint_once"] {
            assert!(source.contains(loop_name), "{loop_name} must exist to be checked");
        }
        assert!(
            source.matches("self.node.transport().await else").count() >= 2,
            "each loop must end rather than spin when the transport is gone"
        );
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod over_the_wire {
    use std::sync::Mutex as SyncMutex;

    use identity::NodeIdentity;
    use roster::id::NetworkId;
    use roster::roster::Roster;
    use roster::sign::sign_operation;
    use roster::types::{NetworkParams, OperationBody, OperationCore, Role};
    use roster_sync::Syncer;
    use tunnel::{Prefix, Tunnel as Rules};

    use super::*;
    use crate::gateway::Gateway;
    use crate::router::Router;
    use crate::schedule::Schedule;
    use crate::state::{Log, Paths};

    /// A transport that says where it is and remembers what it was told.
    ///
    /// It cannot connect to anything, which is the point: this test is about
    /// what the two loops say to each other over a real socket, not about
    /// sessions.
    struct Speaking {
        /// What this node claims as its own addresses.
        mine: Vec<String>,
        /// Every hint handed down, in order.
        heard: SyncMutex<Vec<(Vec<u8>, Vec<String>)>>,
        /// How many times it was asked to connect.
        dialled: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl transport::session::Transport for Speaking {
        async fn connect(
            &self,
            _peer: &PublicKey,
        ) -> transport::error::Result<Box<dyn transport::session::Session>> {
            self.dialled.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(transport::error::Error::PeerUnreachable { cause: Some("not dialled".to_owned()) })
        }

        async fn accept(&self) -> transport::error::Result<Box<dyn transport::session::Session>> {
            // Never resolves: the test drives the loops directly.
            std::future::pending().await
        }

        fn addresses(&self) -> Vec<String> {
            self.mine.clone()
        }

        fn learned(&self, peer: &PublicKey, addresses: &[String]) {
            if let Ok(mut heard) = self.heard.lock() {
                heard.push((peer.as_bytes().to_vec(), addresses.to_vec()));
            }
        }
    }

    /// Two devices in one network, and a node for each.
    fn two_nodes() -> (Arc<Node>, Arc<Node>, Vec<tempfile::TempDir>) {
        let founder = Arc::new(NodeIdentity::generate().expect("generates"));
        let joiner = Arc::new(NodeIdentity::generate().expect("generates"));
        let params = NetworkParams::with_relay(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            None::<String>,
            "example.internal",
            2_592_000,
        )
        .expect("valid");

        let genesis = OperationCore::new(
            1,
            founder.signing_key().algorithm(),
            OperationBody::CreateNetwork {
                device: founder.device_spec("a", Role::Admin, true, vec![]).expect("spec"),
                params,
            },
            vec![],
            founder.signing_key().key_id(),
            NetworkId::from_bytes([0; 32]),
        )
        .expect("well-formed");
        let genesis_bytes = sign_operation(&genesis, founder.signer()).expect("signs");
        let network = NetworkId::from_bytes(*genesis.id().as_bytes());

        let add = OperationCore::new(
            2,
            founder.signing_key().algorithm(),
            OperationBody::AddDevice(
                joiner.device_spec("b", Role::Member, false, vec![]).expect("spec"),
            ),
            vec![genesis.id()],
            founder.signing_key().key_id(),
            network,
        )
        .expect("well-formed");
        let add_bytes = sign_operation(&add, founder.signer()).expect("signs");

        let roster_of = || {
            let mut roster = Roster::new();
            assert!(roster.offer_bytes(&genesis_bytes).is_accepted());
            assert!(roster.offer_bytes(&add_bytes).is_accepted());
            roster
        };
        let prefix = Prefix::from_parameter(&[0xfd, 0, 0, 0, 0, 0, 0, 0]).expect("usable");

        let mut scratches = Vec::new();
        let mut build = |identity: &Arc<NodeIdentity>| {
            let scratch = tempfile::tempdir().expect("a scratch directory");
            let node = Arc::new(Node::new(
                Arc::clone(identity),
                Syncer::new(roster_of()),
                Arc::new(Gateway::new(Rules::new(prefix, identity.device_id()))),
                Router::new(prefix),
                Log::at(scratch.path().join("roster.log")),
                Schedule::provisional(),
            ));
            scratches.push(scratch);
            node
        };
        let a = build(&founder);
        let b = build(&joiner);
        (a, b, scratches)
    }

    /// The whole local path, over a real multicast socket: one node announces
    /// where it is, the other hears it, checks the roster, and hands the
    /// addresses to its transport as a hint.
    ///
    /// Written because everything up to here could be true with nothing ever
    /// leaving the machine — a cache filled by the test that reads it.
    #[tokio::test]
    async fn a_node_hears_where_another_says_it_is() {
        let (a, b, _scratches) = two_nodes();

        let speaker = Arc::new(Speaking {
            mine: vec!["192.168.1.7:41641".to_owned()],
            heard: SyncMutex::new(Vec::new()),
            dialled: 0.into(),
        });
        let listener = Arc::new(Speaking {
            mine: Vec::new(),
            heard: SyncMutex::new(Vec::new()),
            dialled: 0.into(),
        });
        a.started(Arc::clone(&speaker) as Arc<dyn transport::session::Transport>).await;
        b.started(Arc::clone(&listener) as Arc<dyn transport::session::Transport>).await;

        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());
        paths.create().expect("creates");

        let announcing = Arc::new(
            Discovery::resume(Arc::clone(&a), Endpoints::at(paths.endpoints()), None).await,
        );
        let hearing = Arc::new(
            Discovery::resume(Arc::clone(&b), Endpoints::at(scratch.path().join("b.json")), None)
                .await,
        );

        let listening = tokio::spawn(Arc::clone(&hearing).listen_forever());
        // The listener has to be on the group before anything is said, or the
        // first announcement goes into a socket nobody has joined yet.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let announcing_task = tokio::spawn(Arc::clone(&announcing).announce_forever());

        let arrived = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if listener.heard.lock().is_ok_and(|heard| !heard.is_empty()) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;

        listening.abort();
        announcing_task.abort();

        assert!(arrived.is_ok(), "the announcement never arrived: {:?}", b.fault().await);
        let heard = listener.heard.lock().expect("not poisoned").clone();
        let (key, addresses) = heard.first().expect("one hint").clone();
        assert_eq!(
            key,
            a.identity().transport_key().public_key().as_bytes(),
            "the hint must be attributed to the device that sent it"
        );
        assert_eq!(addresses, vec!["192.168.1.7:41641".to_owned()]);

        // Heard, believed as a hint, and not contact. An announcement can be made
        // by anybody who ever held the network id, a revoked device included.
        assert_eq!(
            b.last_contact(&a.identity().device_id()).await,
            crate::control::Contact::NoneRecorded,
            "an announcement is not contact"
        );

        // And it survives a restart, which is what the cache is for.
        hearing.persist().await;
        let again = Discovery::resume(b, Endpoints::at(scratch.path().join("b.json")), None).await;
        let key_id = a.identity().transport_key().public_key().key_id();
        assert!(
            !again.cache.lock().await.addresses_for(&key_id, Instant::now()).is_empty(),
            "what was heard must outlive the process that heard it"
        );
    }

    /// A revoked device knows the network id for good, so it can go on
    /// announcing. That must never read as contact.
    #[tokio::test]
    async fn a_revoked_devices_announcements_are_not_contact() {
        let (a, b, _scratches) = two_nodes();
        let transport = Arc::new(Speaking {
            mine: Vec::new(),
            heard: SyncMutex::new(Vec::new()),
            dialled: 0.into(),
        });
        a.started(Arc::clone(&transport) as Arc<dyn transport::session::Transport>).await;

        let scratch = tempfile::tempdir().expect("a scratch directory");
        let discovery = Arc::new(
            Discovery::resume(Arc::clone(&a), Endpoints::at(scratch.path().join("e")), None).await,
        );

        let state = a.state().await.expect("derives");
        let expulsion = crate::revoking::resolve(
            &state,
            a.identity(),
            &crate::control::Target::Name("b".to_owned()),
            "lost",
        )
        .expect("names it");
        let revocation = crate::revoking::sign(&expulsion, a.identity(), &state, a.heads().await)
            .expect("signs");
        a.admit_without_activating(&revocation).await.expect("admits");

        let record = Record::new(
            b.identity().transport_key().public_key(),
            state.network,
            1,
            vec!["10.0.0.9:41641".to_owned()],
        )
        .expect("well-formed");
        let announcement =
            Announcement::sign(record, b.identity().transport_key().signer()).expect("signs");
        discovery.heard(announcement).await;

        assert_eq!(
            a.last_contact(&b.identity().device_id()).await,
            crate::control::Contact::NoneRecorded,
            "a revoked device announcing itself is not in contact"
        );
    }

    /// An announcement from a key the roster does not name is background, not a
    /// peer. Nothing is cached and nothing is handed to the transport.
    #[tokio::test]
    async fn a_members_newer_announcement_ends_its_rest_and_dials_nothing() {
        let (a, b, _scratches) = two_nodes();
        let transport = Arc::new(Speaking {
            mine: Vec::new(),
            heard: SyncMutex::new(Vec::new()),
            dialled: 0.into(),
        });
        a.started(Arc::clone(&transport) as Arc<dyn transport::session::Transport>).await;
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let discovery = Arc::new(
            Discovery::resume(Arc::clone(&a), Endpoints::at(scratch.path().join("e")), None).await,
        );
        let state = a.state().await.expect("derives");
        let announcing = |sequence| {
            let record = Record::new(
                b.identity().transport_key().public_key(),
                state.network,
                sequence,
                vec!["10.0.0.9:41641".to_owned()],
            )
            .expect("well-formed");
            Announcement::sign(record, b.identity().transport_key().signer()).expect("signs")
        };
        let peer = b.identity().device_id();

        a.rest_after_failure(peer);
        a.rest(peer);
        discovery.heard(announcing(5)).await;
        assert!(!a.resting_after_failure(&peer), "a newer announcement ends the rest");
        assert!(!a.resting_as_a_neighbour(&peer), "both rests");
        assert_eq!(
            0,
            transport.dialled.load(std::sync::atomic::Ordering::SeqCst),
            "and the announcement alone dials nothing"
        );

        a.rest_after_failure(peer);
        discovery.heard(announcing(5)).await;
        assert!(a.resting_after_failure(&peer), "an announcement that is not newer leaves it");
    }

    #[tokio::test]
    async fn an_announcement_from_a_stranger_is_ignored() {
        let (a, _b, _scratches) = two_nodes();
        let transport = Arc::new(Speaking {
            mine: Vec::new(),
            heard: SyncMutex::new(Vec::new()),
            dialled: 0.into(),
        });
        a.started(Arc::clone(&transport) as Arc<dyn transport::session::Transport>).await;

        let scratch = tempfile::tempdir().expect("a scratch directory");
        let discovery = Arc::new(
            Discovery::resume(Arc::clone(&a), Endpoints::at(scratch.path().join("e")), None).await,
        );

        let stranger = NodeIdentity::generate().expect("generates");
        let state = a.state().await.expect("derives");
        let record = Record::new(
            stranger.transport_key().public_key(),
            state.network,
            1,
            vec!["10.0.0.9:41641".to_owned()],
        )
        .expect("well-formed");
        let announcement =
            Announcement::sign(record, stranger.transport_key().signer()).expect("signs");

        discovery.heard(announcement).await;

        assert!(
            transport.heard.lock().expect("not poisoned").is_empty(),
            "a key the roster does not name is not a peer"
        );
    }
}

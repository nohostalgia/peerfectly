//! What the daemon does when asked.
//!
//! Holds the node and the lifecycle together and answers commands. In the core,
//! over the [`crate::machine::Machine`] interface, so the answers a person gets —
//! including the ones after a failed bring-up — are testable without a machine to
//! bring up.
//!
//! # Everything it says is marked known or remembered
//!
//! §2.6c means that with the tunnel down the daemon reaches no infrastructure, so
//! everything it knows about other devices is old and it has no way to refresh it
//! without breaking the property. Rather than hide that, every answer says which
//! it is.
//!
//! A status display that showed a peer as reachable because it was reachable last
//! night would not be a small inaccuracy. It is the failure §2.6c's own
//! consequences call the most dangerous in the system: a person believing a
//! revocation has taken effect while it sits in a queue.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use tokio::sync::Mutex;
use tunnel::Prefix;

use crate::connectivity::Connectivity;
use crate::control::{Command, Outcome, Peer, Report, Standing, Tunnel};
use crate::error::{Error, Result};
use crate::lifecycle::{Lifecycle, Up};
use crate::networks::{Home, Label, Record};
use crate::node::Node;
use crate::resolving::{Answering, Resolving};
use crate::state::{Choice, Paths};

/// Something waiting on a person, of whichever kind.
///
/// Named as one thing because there is only ever one: `Confirm` and `Abandon`
/// apply to whatever is waiting, and a person confirming has one screen in front
/// of them.
enum Pending {
    /// A relay change, waiting for a person to confirm the new relay's
    /// certificate before anything is signed.
    ChangingRelay {
        /// Which network.
        label: Label,
        /// Where it is moving.
        relay: String,
        /// What it presented, to be pinned once confirmed.
        certificate: Option<Vec<u8>>,
        /// Whether everybody moves at once.
        immediately: bool,
        /// Who asked, carried for the reason `Founding` gives.
        for_whom: crate::control::Caller,
    },
    /// A device is being admitted, and two screens must be compared.
    Admitting {
        /// Which network it is being admitted into.
        ///
        /// Remembered from the moment the enrolment opened. Asking again when the
        /// person confirms would let the answer change between the two halves of
        /// one act — the code shown for one network and the admission signed into
        /// another.
        label: Label,
        /// The exchange itself.
        pending: crate::admitting::Pending,
    },
    /// A network is being founded, and a relay certificate nobody has vouched for
    /// is waiting to be confirmed against the relay host.
    Founding {
        /// What this device will call the network, once it exists.
        label: Label,
        /// What the network will say, once it is signed.
        wanted: crate::founding::Founding,
        /// Who asked for it.
        ///
        /// **Carried, not read again at the end.** These acts finish later, and
        /// on a machine that holds networks for more than one person the person
        /// who confirms is not necessarily the person who began. Reading it at
        /// the end would hand the network to whoever was at the keyboard when it
        /// completed.
        for_whom: crate::control::Caller,
    },
    /// This device is waiting to be given a network.
    Joining {
        /// What this device will call the network, once it arrives.
        label: Label,
        /// Where the join has got to, and how to confirm it.
        underway: crate::joining::Underway,
        /// The join itself, so abandoning can end it.
        task: tokio::task::JoinHandle<()>,
        /// Who asked for it, carried for the reason `Founding` gives.
        for_whom: crate::control::Caller,
    },
}

/// What a prepared act finishes doing once its signatures arrive.
///
/// Only acts a person authorises are here. Attesting is not one: its key is held
/// by this device precisely so that dating a roster asks nobody, which is what
/// lets an admin machine keep a network fresh while nobody is present.
///
/// **One per act, not one per signature.** An act that needs several signatures
/// — an operation and the snapshot over it; a revocation and the admission that
/// replaces it — prepares all of them before any is made, and they are answered
/// together as one batch and applied together or not at all. What each variant
/// carries is what the act needs once the batch is back; the batch itself is in
/// the store, beside it. `prepared_against` is where the roster stood when the
/// batch was built, and a batch whose roster has moved since is not applied.
#[derive(Debug, Clone)]
enum Resume {
    /// A device is being expelled from the network this device calls `label`:
    /// the revocation, and the snapshot the network is then owed, if it is.
    Revoking {
        /// Which network.
        label: Label,
        /// Where its roster stood when the batch was built.
        prepared_against: crate::signing::Moment,
    },
    /// The network this device calls `label` is changing its parameters: its
    /// relay, or its rendezvous. Resumed the same way for either.
    ChangingParameters {
        /// Which network.
        label: Label,
        /// Where its roster stood when the batch was built.
        prepared_against: crate::signing::Moment,
    },
    /// A network is being founded: its genesis, and its first snapshot.
    ///
    /// Carries the genesis rather than rebuilding it: the operation's id is the
    /// network's id, and an operation rebuilt a minute later would be a different
    /// one. It carries the identity for the same reason — `keys.identity` created
    /// it, and asking again once the network exists is asking a different
    /// question.
    ///
    /// Both are one batch. A person who declines declines the network, and
    /// nothing is left behind — where signing them one at a time left a network
    /// standing without the snapshot whenever the second prompt was refused.
    Founding {
        /// What this device will call the network.
        label: Label,
        /// The operation the first signature is over.
        genesis: Box<roster::types::OperationCore>,
        /// The identity that will hold it.
        identity: Arc<identity::NodeIdentity>,
        /// Who asked for it, carried across the wait for a signature for the
        /// reason `Pending::Founding` gives.
        for_whom: crate::control::Caller,
    },
    /// A joining device is proving it holds the signing key it presented.
    ///
    /// The only one of these whose signature goes back into a task rather than
    /// into an operation: a join is already running, already waiting on a person
    /// for the six digits, and this is a second thing it waits for. A batch of
    /// one, and never anything else beside it.
    Possession,
    /// A device is being admitted: the admission, the revocation before it when
    /// it takes over a name another device holds, and the snapshot the network is
    /// then owed.
    ///
    /// The exchange stays in `pending` across the round trip rather than moving
    /// in here: it holds an open endpoint, and `Command::Abandon` already knows
    /// how to close one. Two places that could be holding a live socket is one
    /// place too many.
    ///
    /// # A replacement is still revocation first
    ///
    /// Two operations signed against the same heads are concurrent, and one
    /// author holding two branches is what equivocation is. So the admission in a
    /// replacing batch names the revocation as its parent and is checked against
    /// the state the revocation leaves — previewed, since neither is signed yet —
    /// and the two are applied in that order.
    Admitting {
        /// Which network.
        label: Label,
        /// Whether the batch begins with the revocation of the device holding
        /// the name.
        replacing: bool,
        /// The name it admits under, which is not always the one proposed.
        spec_name: String,
        /// Where its roster stood when the batch was built.
        prepared_against: crate::signing::Moment,
    },
}

/// What a person is told when the roster moved under a batch they were
/// deciding on.
const MOVED_WHILE_DECIDING: &str = "the network changed while you were deciding: another \
     change was signed here or arrived from another admin, so what you were shown is no longer \
     what it would do. Nothing was applied; run the command again to see it as it is now";

/// The revocation of the device holding a name another is being admitted under.
///
/// The reason is written into the operation, so a person shown the batch reads
/// who is taking the name over out of the bytes they sign.
fn expulsion_of(taken: &crate::admitting::Taken) -> crate::revoking::Expulsion {
    crate::revoking::Expulsion {
        device: taken.device,
        name: taken.name.clone(),
        reason: format!(
            "replaced by a device admitted under the name `{}`",
            crate::control::shown(&taken.name)
        ),
    }
}

/// What the key store knows a signing key by, when a custodian holds it.
fn reference_of(identity: &identity::NodeIdentity) -> String {
    identity.signing_key().custodian().map(|held| held.reference().to_owned()).unwrap_or_default()
}

/// The device already answering to a joining device's proposed name, as the
/// report says it.
fn taken_name(pending: &crate::admitting::Pending) -> Option<crate::control::TakenName> {
    pending.taken().map(|taken| crate::control::TakenName {
        name: taken.name.clone(),
        id: crate::control::short_id(&taken.device),
    })
}

/// One network this device holds, with everything that belongs to it.
///
/// This used to be a two-state enum — a network or none — because a device held
/// at most one. What it held has not changed; how many of them it may hold has,
/// so "which network" stops being a question with a yes-or-no answer and becomes
/// a lookup, and "none" stops being a state of the daemon and becomes an empty
/// map.
///
/// Each of the mutable parts keeps its own lock rather than living under the map's
/// lock. Bringing one network up creates an adapter and waits on a relay, and the
/// map's lock held across that would stop a person asking about a different
/// network for as long as it took.
pub struct Network {
    /// What this network's directory says it is.
    record: Record,
    /// Where its files are.
    paths: Paths,
    /// The node that carries it.
    node: Arc<Node>,
    /// What is installed while its tunnel is up.
    up: Mutex<Option<Up>>,
    /// The resolver answering its names, while its tunnel is up.
    answering: Mutex<Option<Box<dyn Answering>>>,
    /// The loops driving its node, while its tunnel is up.
    driving: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// When this network last knew anything for certain.
    known_at: Mutex<SystemTime>,
    /// The relays its running transport was built for, while it is up.
    ///
    /// Compared against what the parameters ask for now, so that a relay that
    /// moved — or a move that ended — rebuilds the transport. Without it a node
    /// keeps the relay it started with until somebody takes it down.
    plan: Mutex<Option<RelayPlan>>,
}

/// Which relays a transport is built for, at a moment.
///
/// The relay, its pin, and the relay being left while its transition lasts.
/// Two plans that differ need two different transports; two that are equal need
/// nothing done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayPlan {
    relay: Option<String>,
    pinned: Option<Vec<u8>>,
    leaving: Option<roster::types::Leaving>,
}

impl RelayPlan {
    /// What these parameters ask for at `now`.
    ///
    /// The time is part of it because a transition's end changes the answer with
    /// nothing signed to announce it: the same parameters give one plan the
    /// minute before and another the minute after.
    pub(crate) fn of(params: &roster::types::NetworkParams, now: u64) -> Self {
        Self {
            relay: params.relay.clone(),
            pinned: params.relay_cert.clone(),
            leaving: params.leaving_at(now).cloned(),
        }
    }
}

impl Network {
    /// A network, as the daemon holds it.
    #[must_use]
    pub fn new(record: Record, paths: Paths, node: Arc<Node>) -> Self {
        let known_at = crate::state::read_known(&paths.known());
        Self {
            record,
            paths,
            node,
            up: Mutex::new(None),
            answering: Mutex::new(None),
            driving: Mutex::new(Vec::new()),
            known_at: Mutex::new(known_at),
            plan: Mutex::new(None),
        }
    }

    /// The label this device keeps it under.
    #[must_use]
    pub const fn label(&self) -> &Label {
        &self.record.label
    }

    /// The node that carries it.
    #[must_use]
    pub const fn node(&self) -> &Arc<Node> {
        &self.node
    }

    /// Whether its tunnel is up.
    pub async fn tunnel(&self) -> Tunnel {
        if self.up.lock().await.is_some() { Tunnel::Up } else { Tunnel::Down }
    }

    /// Whether the loops that drive its node are running.
    ///
    /// Observable so that "this network is up" and "this network is being driven"
    /// can be told apart. They came apart once already: the daemon installed
    /// everything, answered names locally, and spoke to nobody, because the loops
    /// were never started. Per network there is one more way for that to happen —
    /// one network's loops running while another's do not.
    pub async fn is_driving(&self) -> bool {
        !self.driving.lock().await.is_empty()
    }

    /// Stops the loops that drive its node.
    ///
    /// Aborted rather than asked to finish: each is blocked on a socket that is
    /// about to be taken away, and waiting politely for a read that will never
    /// return is how a shutdown hangs.
    async fn stop_driving(&self) {
        for task in self.driving.lock().await.drain(..) {
            task.abort();
        }
    }
}

/// A network directory this device cannot carry, and why.
///
/// Reported rather than dropped. A network whose identity will not open, or whose
/// record cannot be read, is not a network this device never had — and a daemon
/// that silently held one fewer network than its owner believed would be the same
/// class of quiet as replacing an identity that would not unseal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Broken {
    /// The directory it was found under.
    pub label: String,
    /// Why it could not be carried, as a value each surface says in its own
    /// words.
    ///
    /// **Never the daemon's own account of the failure.** That is a path inside
    /// the process's private storage and a system error number: a person cannot
    /// reach the file, cannot inspect it and cannot repair it, so as an
    /// explanation it is worse than none — it reads as a fault in the product and
    /// offers nothing to do about it. It arrived on a phone as
    /// `/data/user/0/org.nohostalgia.peerfectly/files/peerfectly/networks/studio/network.json: No such
    /// file or directory (os error 2)`.
    ///
    /// The daemon's own account of it stays in [`Self::detail`].
    pub cause: crate::control::Trouble,
    /// What the daemon itself hit, kept for whoever is debugging it.
    ///
    /// Not in the report, and not for a person reading a screen. It is here so
    /// that replacing the account above with something a person can act on does
    /// not throw away what somebody with the machine in front of them needs.
    pub detail: String,
}

/// The daemon, as a thing that answers.
pub struct Service {
    /// The networks this device holds, by the label it keeps each under.
    ///
    /// Empty is an ordinary state and not a failure: a daemon runs before a person
    /// has founded a network or joined one. Refusing to run without one is what
    /// used to force founding and joining into a separate process, writing a
    /// roster behind a daemon that could not see it.
    networks: Mutex<BTreeMap<Label, Arc<Network>>>,
    /// Network directories this device could not carry, and why.
    ///
    /// Decided once, while the networks are being assembled, and never changed
    /// after: a directory that would not load does not start loading later.
    broken: Mutex<Vec<Broken>>,
    /// Where the network directories live.
    home: Home,
    /// Bringing a tunnel up and down.
    lifecycle: Lifecycle,
    /// Where a transport comes from when the person turns a network on.
    connectivity: Arc<dyn Connectivity>,
    /// What answers names while a tunnel is up.
    resolving: Arc<dyn Resolving>,
    /// Where each network's keys come from.
    keys: Arc<dyn crate::keys::Keys>,
    /// Where discovery learns which interfaces this device is on.
    interfaces: Arc<dyn crate::connectivity::Interfaces>,
    /// Where a port opened to one network is written: the machine's firewall,
    /// or nowhere on a platform that has none.
    exposing: Arc<dyn crate::exposing::Exposing>,
    /// The one thing waiting for a person to look at something.
    ///
    /// Held here rather than passed back and forth because a person stands in the
    /// middle of it: an enrolment is a live connection that has to survive the gap
    /// between two commands, and a founding is a certificate nobody has vouched
    /// for yet. Nothing in either has been signed, so dropping one costs the
    /// attempt and nothing else.
    ///
    /// **One at a time, whatever kind, across every network.** Two would mean two
    /// things on one screen and a person with no way to tell which they were being
    /// asked about — which is as true of two networks as it was of one.
    pending: Mutex<Option<Pending>>,
    /// Acts prepared and waiting for a signature this process cannot make.
    ///
    /// Separate from `pending` because it is a different kind of waiting: that
    /// one is an act waiting for a person to compare two screens, this one is an
    /// act waiting for a key. A founding can be in both at once.
    unsigned: Mutex<crate::signing::Waiting<Resume>>,
    /// The request a running join is waiting to have signed, and the id it was
    /// asked for under, so a poll does not ask again for the same one.
    proving: Mutex<Option<(String, Vec<u8>)>>,
    /// Who is asking, for the act being answered.
    ///
    /// Set by `handle_for` from what the platform read off the channel. It is
    /// **not** a session: it is whoever asked for the command in flight, and
    /// nothing outside answering a command may read it as authority.
    asking: Mutex<crate::control::Caller>,
    /// An act stopped because its signing key must be made where a person is.
    ///
    /// **One slot, which is not a limitation.** Founding and joining are already
    /// serialised by [`Self::pending`], and this can only ever hold one of those
    /// two — so a second slot would be a capacity for a state nothing produces.
    unkeyed: Mutex<Option<Unkeyed>>,
    /// Set when the person asks the daemon to stop.
    stopping: Mutex<bool>,
    /// Woken when IPv4 routes may need to change: a roster change on a network
    /// that is up. Networks coming up or down reconcile directly.
    reconciling: Arc<tokio::sync::Notify>,
}

/// An act held while a signing key is made where a person can be asked.
///
/// It carries **who began it** for the reason `Pending::Founding` does: the act
/// finishes later, and on a machine holding networks for more than one person,
/// whoever answers is not necessarily whoever asked.
struct Unkeyed {
    /// What the answer must carry back.
    id: String,
    /// When it was asked for, so an act nobody answered does not wait for ever.
    issued: u64,
    /// Who asked.
    by: crate::control::Caller,
    /// Where the identity goes once the key exists.
    paths: crate::state::Paths,
    /// The name the person was asked to make the key under.
    ///
    /// **Kept, never asked for again.** A key's name is drawn fresh (F-22), so
    /// asking a second time draws a different one, and the identity would name a
    /// key nobody made — which is how founding broke once names became fresh.
    name: String,
    /// What to do next.
    then: Unfinished,
}

/// The act waiting on that key.
enum Unfinished {
    /// A network being founded.
    Founding {
        /// What it will be called here.
        label: Label,
        /// What it will say.
        wanted: Box<crate::founding::Founding>,
    },
    /// A network being joined.
    Joining {
        /// What it will be called here.
        label: Label,
        /// The relay to wait at.
        relay: String,
        /// The name this device proposes for itself.
        name: String,
    },
}

/// Whether taking a network down is the person's choice about that network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// A person turned this network off: it stays off on the next start.
    Chosen,
    /// Everything is stopping: what the person last chose is left as it was.
    Everything,
}

impl Service {
    /// A service over the networks a home already holds.
    ///
    /// Each network's identity is loaded and its node assembled here. One that
    /// cannot be — an identity that will not open, a roster that describes
    /// nothing — becomes a [`Broken`] entry and stops that network alone. The
    /// daemon goes on running and goes on carrying every other network, because
    /// the alternative is a machine where one unreadable folder takes the rest of
    /// a person's networks off the air.
    ///
    /// # Errors
    ///
    /// When the home exists and cannot be listed.
    pub fn over(
        home: Home,
        lifecycle: Lifecycle,
        connectivity: Arc<dyn Connectivity>,
        resolving: Arc<dyn Resolving>,
    ) -> Result<Self> {
        Self::over_with_keys(
            home,
            lifecycle,
            connectivity,
            resolving,
            Arc::new(crate::keys::PlatformKeys),
        )
    }

    /// A service over the networks a home holds, with keys from `keys`.
    ///
    /// # Errors
    ///
    /// As [`Self::over`].
    pub fn over_with_keys(
        home: Home,
        lifecycle: Lifecycle,
        connectivity: Arc<dyn Connectivity>,
        resolving: Arc<dyn Resolving>,
        keys: Arc<dyn crate::keys::Keys>,
    ) -> Result<Self> {
        // Before the survey, because a device upgrading from the single-network
        // layout keeps its files in the root and the survey would find nothing
        // there. One network becomes one network; nothing is re-enrolled and no
        // key changes.
        let _adopted = home.adopt_anything_in_the_old_shape()?;
        // An attempt the process did not live to finish holds a name and no network.
        let _discarded = home.discard_every_unfounded()?;
        // And one that got as far as a roster but not as far as the record: the
        // membership is proved and only the note of which network it is was lost.
        // Run before the survey, so what is recovered is surveyed as a network
        // rather than reported as one this device could not carry.
        let recovered = home.recover_every_unrecorded(keys.as_ref())?;

        let survey = home.survey()?;
        let mut broken: Vec<Broken> = survey
            .unreadable
            .into_iter()
            .map(|found| Broken {
                label: found.name,
                cause: crate::control::Trouble::NotOurs,
                detail: found.cause,
            })
            .collect();

        let mut carried = Vec::new();
        // A network that was just adopted has no record yet: its id is not known
        // until its roster is replayed, which assembling is what does.
        for held in survey.held {
            let label = held.record.label.clone();
            match Self::assemble(held.record, held.paths, keys.as_ref()) {
                Ok(network) => carried.push(network),
                Err((cause, detail)) => {
                    // What failed, as the thing that failed says it — and the
                    // daemon's own words kept beside it for whoever is debugging.
                    broken.push(Broken { label: label.to_string(), cause, detail });
                }
            }
        }

        // A directory removed because it proved nothing is worth saying: it held
        // keys, and a person who expected a network there is owed the reason it
        // is not there rather than its silent absence.
        for outcome in recovered {
            if let crate::networks::Recovered::Discarded(label) = outcome {
                broken.push(Broken {
                    label: label.to_string(),
                    cause: crate::control::Trouble::RosterProvesNothing,
                    detail: "recovery replayed its log and it named no device this machine holds keys for, so the directory was removed"
                        .to_owned(),
                });
            }
        }

        tracing::info!(networks = carried.len(), "started");
        for one in &broken {
            tracing::warn!(
                network = %one.label,
                cause = %one.cause,
                detail = %crate::logging::scrubbed(&one.detail),
                "could not be carried"
            );
        }

        let mut service = Self::holding(home, carried, lifecycle, connectivity, resolving);
        service.broken = Mutex::new(broken);
        service.keys = keys;
        Ok(service)
    }

    /// A service over networks already assembled.
    #[must_use]
    pub fn holding(
        home: Home,
        networks: Vec<Network>,
        lifecycle: Lifecycle,
        connectivity: Arc<dyn Connectivity>,
        resolving: Arc<dyn Resolving>,
    ) -> Self {
        Self {
            networks: Mutex::new(
                networks
                    .into_iter()
                    .map(|network| (network.record.label.clone(), Arc::new(network)))
                    .collect(),
            ),
            broken: Mutex::new(Vec::new()),
            home,
            lifecycle,
            connectivity,
            resolving,
            keys: Arc::new(crate::keys::PlatformKeys),
            interfaces: Arc::new(crate::connectivity::SystemInterfaces),
            exposing: Arc::new(crate::exposing::Nowhere),
            pending: Mutex::new(None),
            unsigned: Mutex::new(crate::signing::Waiting::default()),
            proving: Mutex::new(None),
            asking: Mutex::new(crate::control::Caller::Unattributed),
            unkeyed: Mutex::new(None),
            stopping: Mutex::new(false),
            reconciling: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// The same service, taking each network's keys from `keys`.
    ///
    /// For founding and joining, which create an identity. A service assembled
    /// over networks that already exist loads theirs through
    /// [`Self::over_with_keys`].
    #[must_use]
    pub fn with_keys(mut self, keys: Arc<dyn crate::keys::Keys>) -> Self {
        self.keys = keys;
        self
    }

    /// The same service, writing exposed ports into `exposing`.
    #[must_use]
    pub fn with_exposing(mut self, exposing: Arc<dyn crate::exposing::Exposing>) -> Self {
        self.exposing = exposing;
        self
    }

    /// The same service, with discovery reading interfaces from `interfaces`.
    ///
    /// For a platform that does not let this process enumerate them itself.
    #[must_use]
    pub fn with_interfaces(mut self, interfaces: Arc<dyn crate::connectivity::Interfaces>) -> Self {
        self.interfaces = interfaces;
        self
    }

    /// Loads one network's identity and builds the node that carries it.
    /// Builds the node that carries a network, or says **which part** would not.
    ///
    /// Each branch names the thing that actually failed. Working it out afterwards
    /// from which files are present cannot tell an identity that will not open
    /// from a roster that will not load — both leave every file exactly where it
    /// was — and it named the wrong one the first time a real device failed.
    fn assemble(
        record: Record,
        paths: Paths,
        keys: &dyn crate::keys::Keys,
    ) -> core::result::Result<Network, (crate::control::Trouble, String)> {
        use crate::control::Trouble;

        if !paths.identity().exists() {
            return Err((Trouble::NoIdentity, "no identity file in that directory".to_owned()));
        }
        let identity = match keys.identity(&paths) {
            Ok(identity) => Arc::new(identity),
            // Never answered by making a new one: an identity that exists and will
            // not open is a reason to stop, which `keys` owes and this respects.
            Err(cause) => return Err((Trouble::IdentityWillNotOpen, cause.to_string())),
        };
        if !paths.roster().exists() {
            return Err((Trouble::NoRoster, "no roster file beside that identity".to_owned()));
        }
        match Node::from_log(
            identity,
            crate::state::Log::at(paths.roster()),
            crate::state::read_snapshot(&paths),
            crate::state::read_attestation(&paths),
        ) {
            Ok(Some(node)) => Ok(Network::new(record, paths, node)),
            Ok(None) => Err((
                Trouble::RosterProvesNothing,
                "the log derives no network this device is named in".to_owned(),
            )),
            Err(cause) => Err((Trouble::RosterRefused, cause.to_string())),
        }
    }

    /// Where this device's networks live.
    #[must_use]
    pub const fn home(&self) -> &Home {
        &self.home
    }

    /// Every network this device holds, in label order.
    pub async fn all(&self) -> Vec<Arc<Network>> {
        self.networks.lock().await.values().map(Arc::clone).collect()
    }

    /// The networks this device could not carry.
    #[must_use]
    pub async fn broken(&self) -> Vec<Broken> {
        self.broken.lock().await.clone()
    }

    /// The network kept under a label.
    ///
    /// # Errors
    ///
    /// When this device holds no network by that name.
    pub async fn named(&self, label: &Label) -> Result<Arc<Network>> {
        self.networks
            .lock()
            .await
            .get(label)
            .map(Arc::clone)
            .ok_or_else(|| Error::NoSuchNetwork { label: label.to_string() })
    }

    /// The network a command with no name must have meant.
    ///
    /// One network needs no naming. Several do, and picking one would be the
    /// daemon deciding something only the person can: `down` against the wrong
    /// network cuts somebody off from their own house in order to switch off a
    /// client's.
    ///
    /// # Errors
    ///
    /// When this device holds no network, or holds more than one.
    pub async fn only(&self) -> Result<Arc<Network>> {
        let networks = self.networks.lock().await;
        let mut held = networks.values();
        match (held.next(), held.next()) {
            (None, _) => Err(Error::NoNetwork),
            (Some(one), None) => Ok(Arc::clone(one)),
            (Some(_), Some(_)) => {
                Err(Error::WhichNetwork { held: networks.keys().map(Label::to_string).collect() })
            }
        }
    }

    /// The network a command named, or the only one if it named none.
    ///
    /// # Errors
    ///
    /// When the name is not held, or none was given and more than one could have
    /// been meant.
    pub async fn which(&self, label: Option<&Label>) -> Result<Arc<Network>> {
        match label {
            Some(label) => self.named(label).await,
            None => self.only().await,
        }
    }

    /// The node underneath, when exactly one network could be meant.
    #[must_use]
    pub async fn node(&self) -> Option<Arc<Node>> {
        self.only().await.ok().map(|network| Arc::clone(network.node()))
    }

    /// Whether this device holds any network at all.
    pub async fn has_network(&self) -> bool {
        !self.networks.lock().await.is_empty()
    }

    /// The label a command carried, checked.
    ///
    /// A name that cannot be a label is refused here rather than looked up and
    /// reported as absent: "there is no network called `../../etc`" would be a
    /// true sentence and the wrong one.
    fn wanted(network: Option<String>) -> Result<Option<Label>> {
        network.map(|text| Label::new(&text)).transpose()
    }

    /// Refuses a suffix that overlaps one this device already holds.
    ///
    /// Not equality: a resolution rule captures everything beneath its suffix, so
    /// a network under another's suffix would have one resolver answering for
    /// names that belong to the other. The refusal names the network that holds
    /// the overlapping suffix, because the person has to decide between them and
    /// cannot without knowing which.
    async fn namespace_free(&self, suffix: &str) -> core::result::Result<(), Outcome> {
        for network in self.all().await {
            let Ok(state) = network.node().state().await else { continue };
            if crate::rule::overlapping(suffix, &state.params.suffix) {
                return Err(Outcome::Failed {
                    message: format!(
                        "`{suffix}` overlaps `{held}`, which the network called `{label}` on \
                         this device already answers for. Two networks whose names sit under \
                         one another would have one resolver answering for the other's \
                         devices.",
                        held = state.params.suffix,
                        label = network.label(),
                    ),
                    left_behind: Vec::new(),
                });
            }
        }
        Ok(())
    }

    /// Refuses a label this device already keeps a network under.
    async fn free(&self, label: &Label) -> core::result::Result<(), Outcome> {
        if self.networks.lock().await.contains_key(label) {
            return Err(Outcome::Failed {
                message: format!(
                    "this device already holds a network called `{label}`. Choose another name \
                     for this one — the name is how you tell them apart on this machine, and it \
                     is yours to pick."
                ),
                left_behind: Vec::new(),
            });
        }
        Ok(())
    }

    /// Whether the person has asked the daemon to stop.
    pub async fn is_stopping(&self) -> bool {
        *self.stopping.lock().await
    }

    /// Whether any network this device holds is up.
    ///
    /// What one icon can honestly say about several networks. Reading the only
    /// network instead would say "down" on a device holding two that are both
    /// carrying traffic — and the README is emphatic that an icon saying the
    /// network is off while it is on is worse than no icon at all.
    pub async fn anything_up(&self) -> Tunnel {
        for network in self.all().await {
            if network.tunnel().await == Tunnel::Up {
                return Tunnel::Up;
            }
        }
        Tunnel::Down
    }

    /// Whether the tunnel of the only network is up.
    ///
    /// A device holding several has no single answer, and a device holding none
    /// has nothing to be up. Both read as down, which is what a caller with no
    /// network in mind can act on; a caller that means one asks the network.
    pub async fn tunnel(&self) -> Tunnel {
        match self.only().await {
            Ok(network) => network.tunnel().await,
            Err(_) => Tunnel::Down,
        }
    }

    /// Removes anything an earlier run left behind.
    ///
    /// # Errors
    ///
    /// When a leftover was found and would not go.
    pub async fn sweep(&self) -> Result<bool> {
        self.lifecycle.sweep().await
    }

    /// Brings the tunnel up and records that the person chose it.
    ///
    /// # Errors
    ///
    /// When any step fails. The error names the step and what is still installed.
    pub async fn bring_up(&self, which: Option<&Label>) -> Result<()> {
        let network = self.which(which).await?;
        self.raise(&network).await
    }

    /// Brings one network's tunnel up.
    ///
    /// # Errors
    ///
    /// When any step fails. The error names the step and what is still installed.
    async fn raise(&self, network: &Arc<Network>) -> Result<()> {
        if network.up.lock().await.is_some() {
            return Ok(());
        }
        // Refused before anything is installed: there is no address, prefix or
        // suffix to install, because all three come from signed parameters that
        // do not exist yet.
        let node = Arc::clone(network.node());
        let state = node.state().await.map_err(|cause| Error::Parameters {
            cause: format!("the roster does not describe a network: {cause}"),
        })?;

        let resolver = Self::own_address(&node, &state).ok_or_else(|| Error::Parameters {
            cause: "this device has no address on its own network".to_owned(),
        })?;

        let (installed, device) =
            self.lifecycle.up(network.label().as_str(), &state, resolver).await?;

        // The device makes the tunnel up, and the transport makes the node
        // reachable. Both start here and nowhere earlier: §2.6c means nothing
        // may reach infrastructure until the person asks for it.
        node.gateway().attach(device).await;

        let plan = RelayPlan::of(&state.params, crate::clock::now_ms());
        match self.connectivity.start(node.identity(), state).await {
            Ok(transport) => {
                node.started(transport).await;
                *network.plan.lock().await = Some(plan);
            }
            Err(failure) => {
                // Undo the machine changes rather than leaving a tunnel that
                // carries nothing: a half-up network is worse than a down one,
                // because it looks up.
                node.gateway().detach().await;
                let _undone = self.lifecycle.down(&installed).await;
                return Err(failure);
            }
        }

        // Now drive it. A node with a transport and nobody reading from it is a
        // node that accepts connections and ignores them.
        let mut driving = vec![
            tokio::spawn(Arc::clone(&node).accept_forever()),
            tokio::spawn(Arc::clone(&node).carry_forever()),
        ];

        // Dialling repeats: a peer that is switched off now may be on later, and
        // there is no event that says so.
        //
        // The re-offer repeats with it. Full reconciliation happens only when a
        // session opens; after that an operation travels as a single push, and a
        // push whose send fails is recorded as a fault and abandoned. So two
        // devices that stay connected for hours, one of which lost a push, stayed
        // divergent until something dropped the session. `offer_to_everyone` was
        // written for exactly this and had no caller for as long as it existed —
        // it is `pub` in a library, so nothing warned.
        let schedule = node.schedule();
        let dialling = Arc::clone(&node);
        driving.push(tokio::spawn(async move {
            loop {
                dialling.dial_missing().await;
                dialling.offer_to_everyone().await;
                tokio::time::sleep(schedule.sync).await;
            }
        }));

        // Urgency sets its own pace. A revocation nobody has received yet is not
        // the same situation as an idle network, and until now both waited the
        // same minute. This presses only the members that are owed something and
        // have no session, and widens back toward the ordinary tick as attempts
        // go unanswered — so a laptop switched off for a week is not dialled every
        // two seconds for a week.
        let pressing_node = Arc::clone(&node);
        driving.push(tokio::spawn(async move {
            let mut pacing = crate::schedule::Pressing::new(schedule.press);
            loop {
                let waiting = pacing.next(pressing_node.owed().await, &schedule);
                tokio::time::sleep(waiting).await;
                pressing_node.press().await;
            }
        }));

        // The paths a relay does not provide: the local network, the addresses
        // cached from when it was, and the rendezvous. §2.9 puts all three
        // before the relay, and all three are sockets — so they start here, with
        // the tunnel, and stop with it. §2.6c is kept by there being nothing
        // left running rather than by a flag.
        let discovery = Arc::new(
            crate::discovery::Discovery::resume_with(
                Arc::clone(&node),
                crate::endpoints::Endpoints::at(network.paths.endpoints()),
                // The adapter just created, so discovery never announces into
                // the tunnel it is trying to find peers for.
                Some(installed.interface()),
                Arc::clone(&self.interfaces),
            )
            .await,
        );
        driving.push(tokio::spawn(Arc::clone(&discovery).announce_forever()));
        driving.push(tokio::spawn(Arc::clone(&discovery).listen_forever()));
        driving.push(tokio::spawn(Arc::clone(&discovery).hint_forever()));
        driving.push(tokio::spawn(discovery.publish_forever()));

        *network.driving.lock().await = driving;

        // Names last, because it binds to the address the adapter was just
        // given. A tunnel whose names do not resolve is a tunnel a person cannot
        // use, so this failing undoes the rest rather than being reported and
        // shrugged off.
        match self.resolving.start(resolver, Arc::clone(&node)).await {
            Ok(answering) => *network.answering.lock().await = Some(answering),
            Err(failure) => {
                network.stop_driving().await;
                node.stopped().await;
                node.gateway().detach().await;
                let _undone = self.lifecycle.down(&installed).await;
                return Err(failure);
            }
        }

        *network.up.lock().await = Some(installed);
        Self::knew(network).await;

        // A roster change while up can move IPv4 routes: a device admitted gains
        // one, a device revoked loses one. The node signals it; this passes it on.
        let mut holdings = node.ipv4_holdings();
        let wake = Arc::clone(&self.reconciling);
        network.driving.lock().await.push(tokio::spawn(async move {
            while holdings.changed().await.is_ok() {
                wake.notify_one();
            }
        }));
        // IPv4 routes and this device's IPv4 address, for this network and for
        // any other whose peers a new network's addresses now conflict with.
        self.reconcile().await;

        // Recorded after it worked, not before. A choice written first would
        // bring the tunnel up on the next start after a failure that had left
        // the person with it down.
        Choice::Up.write(&network.paths.choice())
    }

    /// Takes one network's tunnel down and records that the person chose it.
    ///
    /// Every other network this device holds is untouched: its address, its
    /// route, its resolution rule and its sessions are not consulted, let alone
    /// removed. A person switching off the network for one client has not asked
    /// to be cut off from their own house.
    ///
    /// # Errors
    ///
    /// When something could not be removed. The error names what is still there.
    pub async fn take_down(&self, which: Option<&Label>) -> Result<()> {
        // A device holding nothing has nothing to take down, and saying so as a
        // refusal would make a daemon that had never joined one that cannot be
        // stopped cleanly. Down is what a person asked for and down is what they
        // have. Naming a network that is not held is still a refusal: that is a
        // person expecting something to happen somewhere it cannot.
        if which.is_none() && !self.has_network().await {
            return Ok(());
        }
        self.lower(&self.which(which).await?, Stop::Chosen).await
    }

    /// Takes every network down, for a daemon that is stopping.
    ///
    /// Reports the first failure and still attempts the rest: stopping with one
    /// network's routes left behind is bad, and stopping with three networks'
    /// left behind because the first would not go is worse.
    ///
    /// What each network was last chosen to be is kept. Stopping is not a choice
    /// about any one network: a machine shutting down, or a phone's tile turning
    /// everything off, has not asked for the network the person left on to be off
    /// the next time it starts or is restored. Recording `Down` here made every
    /// orderly stop overwrite the choice the start is obliged to restore.
    ///
    /// # Errors
    ///
    /// When a network would not come down. The error names what is still there.
    pub async fn take_all_down(&self) -> Result<()> {
        tracing::info!("stopping");
        let mut refused = Ok(());
        for network in self.all().await {
            let outcome = self.lower(&network, Stop::Everything).await;
            if refused.is_ok() {
                refused = outcome;
            }
        }
        match &refused {
            Ok(()) => tracing::info!("stopped"),
            Err(cause) => {
                tracing::warn!(cause = %crate::logging::scrubbed(&cause.to_string()), "stopped, with something left behind")
            }
        }
        refused
    }

    /// Takes one network down, recording it as the person's choice when it was one.
    async fn lower(&self, network: &Arc<Network>, stop: Stop) -> Result<()> {
        let installed = network.up.lock().await.take();
        // Nothing running, so nothing for a relay change to rebuild.
        network.plan.lock().await.take();

        // The resolver first: it listens on an address the adapter is about to
        // lose, and a socket outliving its address is a socket nothing can reach
        // and nothing will close.
        network.answering.lock().await.take();
        network.stop_driving().await;

        // Then the transport. Everything after this is local, so from here on the
        // daemon reaches nothing for this network — which is what a packet
        // capture during shutdown should show.
        //
        // Taking down what is already down stays the success it has always been:
        // `take_down` is what shutdown runs, and a daemon that refused to stop
        // because a network was already off would be one that cannot be stopped
        // cleanly.
        network.node().stopped().await;
        network.node().gateway().detach().await;

        let outcome = match &installed {
            Some(up) => self.lifecycle.down(up).await,
            None => Ok(()),
        };
        // What it knew was current until now, and is last known from here on.
        if installed.is_some() {
            Self::knew(network).await;
            // Nothing is routed while down, so nothing is withheld from a route;
            // and a peer elsewhere that conflicted with this network no longer
            // does.
            network.node().set_withheld(BTreeMap::new());
            self.reconcile().await;
        }

        if stop == Stop::Chosen {
            Choice::Down.write(&network.paths.choice())?;
        }
        outcome
    }

    /// Notes that a network knew things for certain until this moment.
    ///
    /// Written to disk as well, best effort: failing to record a time is not a
    /// reason to refuse bringing a network up or down.
    async fn knew(network: &Network) {
        let now = SystemTime::now();
        *network.known_at.lock().await = now;
        let _recorded = crate::state::write_known(&network.paths.known(), now);
    }

    /// Brings every network that is up in line with what its IPv4 routes should
    /// be now.
    ///
    /// Decides, in label order, which peers each network withholds on this
    /// device — against this device's interfaces, the network's relay and
    /// rendezvous, and every other network that is up — then hands each network's
    /// plan to the lifecycle. Idempotent: a network whose plan has not changed
    /// has nothing added or removed.
    ///
    /// Failures are recorded on the network's node rather than returned. A host
    /// route that would not go in leaves that one peer unreachable over IPv4; it
    /// is not a reason to take a network down.
    pub async fn reconcile(&self) {
        struct Gathered {
            network: Arc<Network>,
            state: roster::state::RosterState,
            interface: crate::routes::Interface,
            own: Ipv6Addr,
            me: roster::id::DeviceId,
            addresses: Vec<(roster::id::DeviceId, std::net::Ipv4Addr)>,
        }

        // Before the rest: an admin attesting to what its networks say is how
        // every other device stays able to confirm its own roster, and it reaches
        // nothing to do it.
        for network in self.all().await {
            // The attestation first, because it is the one that decides
            // freshness and the one a phone can produce with nobody present.
            network.node().keep_fresh().await;
            network.node().attest_unattended().await;
        }

        let mut gathered = Vec::new();
        for network in self.all().await {
            let Some((interface, own)) =
                network.up.lock().await.as_ref().map(|up| (up.interface(), up.address()))
            else {
                continue;
            };
            let node = network.node();
            let Ok(state) = node.state().await else {
                continue;
            };
            let me = node.identity().device_id();
            let addresses = node.current_ipv4_holdings().held().collect();
            gathered.push(Gathered {
                network: Arc::clone(&network),
                state,
                interface,
                own,
                me,
                addresses,
            });
        }

        // This daemon's own adapters are not the machine's networks: this
        // device's own address on one of them is not a conflict with itself.
        let adapters: Vec<u32> = gathered.iter().map(|each| each.interface.index()).collect();
        let local: Vec<crate::connectivity::LocalInterface> = self
            .interfaces
            .list()
            .into_iter()
            .filter(|interface| !adapters.contains(&interface.index))
            .collect();

        let mut others: Vec<crate::conflicts::OtherNetwork> = gathered
            .iter()
            .map(|each| crate::conflicts::OtherNetwork {
                label: each.network.label().to_string(),
                own: each
                    .addresses
                    .iter()
                    .find(|(device, _)| *device == each.me)
                    .map(|(_, at)| *at),
                routed: Vec::new(),
            })
            .collect();

        // `all` is in label order, so every earlier network's routed peers are
        // known by the time a later one is decided.
        let mut served: Vec<transport::Range> = Vec::new();
        for (index, each) in gathered.iter().enumerate() {
            let label = each.network.label().to_string();
            let infrastructure = crate::conflicts::Infrastructure::literal(
                each.state.params.relay.as_deref(),
                each.state.params.rendezvous.as_deref(),
            );
            let withheld = crate::conflicts::withheld(
                &label,
                &local,
                &infrastructure,
                &others,
                each.addresses.iter().copied(),
            );
            let own_ipv4 = each
                .addresses
                .iter()
                .find(|(device, _)| *device == each.me && !withheld.contains_key(device))
                .map(|(_, at)| *at);
            let routed: Vec<(roster::id::DeviceId, std::net::Ipv4Addr)> = each
                .addresses
                .iter()
                .filter(|(device, _)| *device != each.me && !withheld.contains_key(device))
                .copied()
                .collect();
            if let Some(entry) = others.get_mut(index) {
                entry.routed.clone_from(&routed);
            }

            // What this network's tunnel actually carries, for the loop check
            // below. Gathered here because this is where the withheld addresses
            // are known: an address that is withheld has no route into the
            // adapter, so a path to it is an ordinary path.
            served.extend(crate::routes::served(
                &each.state.params,
                own_ipv4,
                routed.iter().map(|(_, at)| *at),
            ));

            let node = each.network.node();
            node.set_withheld(withheld);
            let plan = match crate::routes::Plan::wanted(
                &each.state.params,
                each.interface,
                Some(each.own),
                own_ipv4,
                routed.iter().map(|(_, at)| *at),
            ) {
                Ok(plan) => plan,
                Err(failure) => {
                    node.record(crate::node::Severity::Problem, "routes", failure.to_string())
                        .await;
                    continue;
                }
            };
            let mut up = each.network.up.lock().await;
            if let Some(up) = up.as_mut()
                && let Err(failure) = self.lifecycle.reconcile(up, &plan).await
            {
                node.record(crate::node::Severity::Problem, "routes", failure.to_string()).await;
            }
        }

        // Every network's connectivity layer is told what every tunnel of this
        // device carries — not only its own. A path through *any* of them is this
        // machine's traffic asked to travel over a tunnel this machine carries,
        // and a device holding three networks must refuse a path through all
        // three. Told after the loop, because a later network's addresses are as
        // much a loop for an earlier one as its own are.
        for each in &gathered {
            if let Some(transport) = each.network.node().transport().await {
                transport.avoid(&served);
            }
        }
    }

    /// Reconciles whenever something may have moved, for as long as the daemon
    /// runs.
    ///
    /// Woken by a roster change on a network that is up, and every few seconds
    /// to look at this device's interfaces: a machine that moves to another
    /// Wi-Fi may have a peer that did not conflict before and does now.
    pub async fn reconcile_forever(self: Arc<Self>) {
        let mut seen = self.interfaces.list();
        loop {
            let woken = tokio::select! {
                () = self.reconciling.notified() => true,
                () = tokio::time::sleep(crate::limits::INTERFACE_RECHECK) => false,
            };
            // Every wake, notified or not: a roster change can move a relay, and
            // a move ends with nothing arriving to say so — this tick is what
            // notices, within one interval of the end.
            self.follow_relays().await;
            if !woken {
                let now = self.interfaces.list();
                if now == seen {
                    continue;
                }
                seen = now;
            }
            self.reconcile().await;
        }
    }

    /// Rebuilds the transport of every network that is up and whose relays are
    /// not what its parameters now ask for.
    ///
    /// A failure is recorded against that network and the old transport kept:
    /// a network on the relay it had is better than one on none.
    pub(crate) async fn follow_relays(&self) {
        let now = crate::clock::now_ms();
        for network in self.all().await {
            let Some(had) = network.plan.lock().await.clone() else { continue };
            let node = Arc::clone(network.node());
            let Ok(state) = node.state().await else { continue };
            let wanted = RelayPlan::of(&state.params, now);
            if wanted == had {
                continue;
            }
            if let Err(cause) = self.rebind(&network, state, wanted).await {
                node.record(crate::node::Severity::Problem, "relay", cause).await;
            }
        }
    }

    /// Replaces a network's transport with one built for `wanted`.
    ///
    /// **Only the transport.** The adapter, the routes and the resolution rule
    /// stay, so the tunnel is never down while a relay moves — a relay change is
    /// not a reason for a person's network to go dark. A network that is down is
    /// left alone: §2.6c gives it no licence to reach a relay, moving or not.
    async fn rebind(
        &self,
        network: &Arc<Network>,
        state: roster::state::RosterState,
        wanted: RelayPlan,
    ) -> Result<()> {
        if network.up.lock().await.is_none() {
            return Ok(());
        }
        let node = Arc::clone(network.node());
        let transport = self.connectivity.start(node.identity(), state).await?;
        node.replace_transport(transport).await;
        *network.plan.lock().await = Some(wanted);
        Ok(())
    }

    /// This device's address on its own network.
    fn own_address(node: &Node, state: &roster::state::RosterState) -> Option<Ipv6Addr> {
        let prefix = Prefix::from_parameter(&state.params.ula).ok()?;
        let me = node.identity().device_id();
        state.devices.contains_key(&me).then(|| tunnel::address_of(&me, &prefix))
    }

    /// How things stand, for every network this device holds.
    ///
    /// Each network is described on its own. Gathering peers, faults or
    /// outstanding operations across networks would attribute one network's
    /// trouble to another, and a person reading it would have no way to tell.
    pub async fn report(&self) -> Report {
        // **What is shown is bounded by whose it is.** Reading is allowed to
        // everybody precisely because of this: the authorisation table lets a
        // `Status` through from anyone, and what comes back is theirs.
        //
        // The ones that are not are counted rather than dropped. A machine that
        // showed nothing would read as a machine holding nothing, and the person
        // would go and found a second network beside one they cannot see.
        let asking = self.asking.lock().await.clone();
        let mut networks = Vec::new();
        let mut elsewhere = 0_usize;
        for network in self.all().await {
            if asking.is(crate::state::read_owner(&network.paths).as_deref()) {
                networks.push(self.describe(&network).await);
            } else {
                elsewhere = elsewhere.saturating_add(1);
            }
        }

        let unusable = self
            .broken()
            .await
            .iter()
            .map(|broken| crate::control::Unusable {
                label: broken.label.clone(),
                cause: broken.cause,
            })
            .collect();

        // No network at all is a state, not a failure. It looks identical to a
        // network that is down — no address, no peers, nothing installed — and
        // the remedies are opposites, so the report says which it is and what a
        // person does next.
        let note = networks.is_empty().then(|| match elsewhere {
            0 => Error::NoNetwork.to_string(),
            1 => "one network on this machine belongs to somebody else, and none to you".to_owned(),
            many => {
                format!("{many} networks on this machine belong to other people, and none to you")
            }
        });

        Report {
            networks,
            unusable,
            note,
            admin_refusal: self.keys.admin_refusal(),
            elsewhere,
            // The same question `may_ask` answers for `Command::Stop`, asked
            // once and handed back — rather than left for each surface to guess
            // at from its own token, which would be a second decision beside the
            // one that counts.
            may_stop_the_daemon: self.may_ask(&asking, &Command::Stop).await.is_ok(),
            // For offering only: whoever could, after confirming, is offered
            // the act, and the elevated process that asks for it is decided.
            could_stop_the_daemon: asking.could_act_on_the_machine(),
        }
    }

    /// Where this device keeps a network's signing key.
    ///
    /// Asked of the platform about this identity, never decided here: only the
    /// platform can tell a key store from a passphrase, and the default it gives
    /// reads the key rather than what the platform said it would do.
    fn custody_of(&self, node: &Node) -> crate::control::Custody {
        self.keys.custody_of(node.identity())
    }

    /// One network, as the report describes it.
    async fn describe(&self, network: &Arc<Network>) -> crate::control::Network {
        let node = network.node();
        let tunnel = network.tunnel().await;
        let standing = match tunnel {
            Tunnel::Up => Standing::Current,
            Tunnel::Down => Standing::LastKnown { at: *network.known_at.lock().await },
        };
        let label = network.label().to_string();
        let me = node.identity().device_id();
        let id = crate::control::short_id(&me);

        let Ok(state) = node.state().await else {
            return crate::control::Network {
                label,
                tunnel,
                standing,
                address: None,
                ipv4: None,
                name: None,
                id,
                admin: false,
                custody: self.custody_of(node),
                owner_taken: crate::state::was_taken(&network.paths),
                // A roster that derives no state has no network to be unable to
                // confirm. The trouble here is a different one, and reported as
                // itself.
                confirmation: None,
                relay: None,
                rendezvous: None,
                relay_pinned: false,
                relay_leaving: None,
                accused: Vec::new(),
                peers: Vec::new(),
                revoked: Vec::new(),
                waiting: Vec::new(),
                waiting_unlisted: 0,
                problem: node.problem(std::time::SystemTime::now()).await,
            };
        };

        // Everything about membership comes from one pass, named one way: the
        // revoked, the accused, what is owed to whom, and when each device last
        // spoke. A device the roster no longer holds a name for is named by its
        // id, so that an accusation or a revocation never silently loses its
        // subject.
        let membership = node.membership(&state).await;
        let holdings = tunnel::Ipv4Holdings::of_state(&state);
        let withheld = node.withheld();
        let ipv4 = |device: &roster::id::DeviceId| -> Option<crate::control::Ipv4State> {
            if let (Some(address), Some(conflict)) = (holdings.of(device), withheld.get(device)) {
                return Some(crate::control::Ipv4State::Withheld {
                    address,
                    with: conflict.to_string(),
                });
            }
            if let Some(address) = holdings.of(device) {
                return Some(crate::control::Ipv4State::Held(address));
            }
            let other = holdings.collision(device)?.with.first().copied()?;
            Some(crate::control::Ipv4State::Collides(crate::control::Named::new(
                &other,
                state.devices.get(&other).map(|record| record.name.clone()),
            )))
        };

        let mut peers = Vec::new();
        for record in state.devices.values() {
            if record.id == me {
                continue;
            }
            peers.push(Peer {
                name: format!("{}.{}", record.name, state.params.suffix),
                id: membership.directory.named(&record.id).id,
                address: Prefix::from_parameter(&state.params.ula)
                    .map_or(Ipv6Addr::UNSPECIFIED, |prefix| {
                        tunnel::address_of(&record.id, &prefix)
                    }),
                ipv4: ipv4(&record.id),
                reachable: node.has_session(&record.id).await,
                path: node.path_to(&record.id).await.map(crate::control::Path::from),
                standing,
                last_contact: crate::describing::contact(&membership.contacts, &record.id),
            });
        }

        crate::control::Network {
            label,
            tunnel,
            standing,
            custody: self.custody_of(node),
            owner_taken: crate::state::was_taken(&network.paths),
            confirmation: node.unconfirmed().await,
            address: Self::own_address(node, &state),
            ipv4: ipv4(&me),
            name: state
                .devices
                .get(&me)
                .map(|record| format!("{}.{}", record.name, state.params.suffix)),
            id,
            admin: state
                .devices
                .get(&me)
                .is_some_and(|record| record.role == roster::types::Role::Admin),
            relay: state.params.relay.clone(),
            rendezvous: state.params.rendezvous.clone(),
            relay_pinned: state.params.relay_cert.is_some(),
            relay_leaving: state.params.leaving_at(crate::clock::now_ms()).map(|leaving| {
                crate::control::RelayLeaving {
                    relay: leaving.relay.clone(),
                    until: crate::clock::operation_time(leaving.until)
                        .unwrap_or(SystemTime::UNIX_EPOCH),
                }
            }),
            accused: membership.accused,
            peers,
            revoked: membership.revoked,
            waiting: membership.waiting,
            waiting_unlisted: membership.waiting_unlisted,
            problem: node.problem(std::time::SystemTime::now()).await,
        }
    }

    /// The networks the person last left on, which is what a restore brings back.
    ///
    /// Asked before restoring when the answer decides what happens instead: the
    /// phone's tile opens the app when there is nothing to bring back, rather than
    /// starting a VPN service to find that out.
    pub async fn left_on(&self) -> Vec<Label> {
        let mut left = Vec::new();
        for network in self.all().await {
            if crate::lifecycle::resume(Choice::read(&network.paths.choice())) {
                left.push(network.label().clone());
            }
        }
        left
    }

    /// Brings the tunnel back to whatever the person last chose.
    ///
    /// Returns whether it came up. Called on start, after the sweep.
    ///
    /// Restored rather than defaulted, in both directions. A daemon that always
    /// starts down has quietly overruled someone who left it up and will wonder
    /// why their machine is unreachable after a reboot; one that always starts up
    /// has done something worse, since §2.6b makes turning the network on the
    /// person's own deliberate act.
    ///
    /// # Errors
    ///
    /// When the tunnel was chosen and will not come up.
    pub async fn resume(&self) -> Result<bool> {
        let mut any = false;
        for network in self.all().await {
            if crate::lifecycle::resume(Choice::read(&network.paths.choice())) {
                self.raise(&network).await?;
                any = true;
            }
        }
        Ok(any)
    }

    /// Admits an operation authored on this device, bringing the network up.
    ///
    /// Returns whether the network had to be turned on.
    ///
    /// §2.6c's consequence, and the failure it calls the most dangerous in the
    /// system: an administrative act taken with the network down has nowhere to
    /// go, and a person who has revoked a device and been shown nothing believes
    /// the revocation has taken effect. So the act turns the network on — the
    /// gesture is already the consent — and the caller is told, so it can be
    /// said out loud rather than happening quietly.
    ///
    /// # Errors
    ///
    /// When the roster refuses the operation, or the network will not come up.
    pub async fn admit(&self, operation: &[u8]) -> Result<bool> {
        let network = self.only().await?;
        self.admit_to(&network, operation).await
    }

    /// Admits an operation into one named network, bringing that network up.
    ///
    /// # Errors
    ///
    /// When the roster refuses the operation, or the network will not come up.
    pub async fn admit_to(&self, network: &Arc<Network>, operation: &[u8]) -> Result<bool> {
        network.node().admit_without_activating(operation).await?;

        // The roster just changed, and the person who changed it is here. On a
        // phone this is the one moment a signature may ask for the lock without
        // arriving out of nowhere: they have this second signed an admission or a
        // revocation, and attesting to the result is the same act finished.
        network.node().attest_now().await;

        if network.tunnel().await == Tunnel::Up {
            return Ok(false);
        }
        self.raise(network).await?;
        Ok(true)
    }

    /// Completes an act with the signatures it was waiting for.
    ///
    /// Every signature in the batch is checked against the request that was
    /// prepared, by `identity::detached::finish_all`, before anything is
    /// assembled or applied: one that does not verify refuses the whole batch
    /// here rather than turning any of it into an artifact whose refusal would
    /// first be seen on somebody else's device.
    async fn signed(&self, id: &str, signatures: &[Vec<u8>]) -> Outcome {
        let (taken, lapsed) = {
            let mut unsigned = self.unsigned.lock().await;
            let taken = unsigned.answer(id, signatures.len(), crate::clock::now_ms());
            (taken, unsigned.lapsed())
        };
        self.tidy_after(lapsed).await;
        let (requests, resume) = match taken {
            Ok(held) => held,
            // A replayed answer, an invented id, one that waited too long and
            // one that came back short all arrive here, and the store's words
            // say which of those it was without saying whether the id was ever
            // real.
            Err(unmatched) => {
                return Outcome::Failed { message: unmatched.to_string(), left_behind: Vec::new() };
            }
        };

        match resume {
            Resume::Revoking { label, prepared_against } => {
                self.revocation_signed(&label, &prepared_against, &requests, signatures).await
            }
            Resume::ChangingParameters { label, prepared_against } => {
                self.relay_change_signed(&label, &prepared_against, &requests, signatures).await
            }
            Resume::Founding { label, genesis, identity, for_whom } => {
                self.founding_signed(label, &genesis, &identity, &for_whom, &requests, signatures)
                    .await
            }
            // Handed to the join as it arrived, and checked there.
            //
            // Every other act here verifies before assembling, and so does this
            // one — but in the join, against the identity that prepared the
            // challenge, which is the only place the key this must match is
            // known. Nothing is sent on the strength of a signature that has not
            // verified against that key.
            Resume::Possession => {
                let _ = &requests;
                let Some(signature) = signatures.first().cloned() else {
                    return Outcome::refused("no proof came back".to_owned());
                };
                let held = self.pending.lock().await;
                match &*held {
                    Some(Pending::Joining { underway, .. }) if underway.proved(signature) => {
                        Outcome::Enrolling
                    }
                    _ => Outcome::refused(
                        "the join this signature belongs to is no longer waiting for it".to_owned(),
                    ),
                }
            }
            Resume::Admitting { label, replacing, spec_name, prepared_against } => {
                self.admission_signed(
                    &label,
                    replacing,
                    spec_name,
                    &prepared_against,
                    &requests,
                    signatures,
                )
                .await
            }
        }
    }

    /// Verifies a batch for a network that exists, and checks its roster has not
    /// moved since the batch was built.
    ///
    /// **Nothing is applied before this answers `Ok`.** Every signature is
    /// checked first, and then whether what was authorised is still what it
    /// would do: an operation from another admin, or their snapshot, arriving
    /// while a person was deciding makes the batch describe a roster that is no
    /// longer there.
    async fn verified_batch(
        &self,
        network: &Arc<Network>,
        prepared_against: &crate::signing::Moment,
        requests: &[identity::detached::SigningRequest],
        signatures: &[Vec<u8>],
    ) -> core::result::Result<Vec<Vec<u8>>, Outcome> {
        let key = network.node().identity().signing_key().public_key();
        let artifacts = identity::detached::finish_all(requests, &key, signatures).map_err(|cause| {
            Outcome::refused(format!(
                "that signature does not match what was prepared, so nothing was signed: {cause}"
            ))
        })?;
        if network.node().moment().await != *prepared_against {
            return Err(Outcome::refused(MOVED_WHILE_DECIDING.to_owned()));
        }
        Ok(artifacts)
    }

    /// Keeps the snapshot a batch ended with, once the acts before it are in.
    ///
    /// Offered to the live roster rather than written straight to disk, so what
    /// is kept is a snapshot this node can verify rather than one it merely
    /// received. **A refusal costs the snapshot and not the acts**: they are
    /// signed, valid and in a log that cannot be unsaid, and reporting otherwise
    /// would leave a person with acts this daemon disowns. It is recorded, and an
    /// admin signs another as a matter of course.
    ///
    /// Only kept where the acts were: an outcome that is not a report is handed
    /// back as it is.
    async fn with_the_snapshot(
        &self,
        network: &Arc<Network>,
        outcome: Outcome,
        snapshot: Option<Vec<u8>>,
    ) -> Outcome {
        let (Some(snapshot), Outcome::Reported(_)) = (snapshot, &outcome) else { return outcome };
        let node = network.node();
        if !node.restore_snapshot(&snapshot, crate::state::wall_seconds()).await {
            node.record(
                crate::node::Severity::Problem,
                "snapshot",
                "a snapshot signed with an act was not one this device's own roster would take",
            )
            .await;
            return Outcome::Reported(self.report().await.with_note(
                "the snapshot signed with it was not one this device's own roster would take; \
                 an admin will sign another. Everything else was applied",
            ));
        }
        let _kept =
            crate::state::write_snapshot(&network.paths, &snapshot, crate::state::wall_seconds());
        Outcome::Reported(self.report().await)
    }

    /// Delivers an admission that was signed where this process could not sign
    /// it — after the revocation before it, when it is a replacement.
    async fn admission_signed(
        &self,
        label: &Label,
        replacing: bool,
        spec_name: String,
        prepared_against: &crate::signing::Moment,
        requests: &[identity::detached::SigningRequest],
        signatures: &[Vec<u8>],
    ) -> Outcome {
        let waiting = self.pending.lock().await.take();
        let Some(Pending::Admitting { pending, .. }) = waiting else {
            // The exchange is gone — abandoned, or expired while a person was at
            // a prompt. Nothing is signed into the roster on the strength of an
            // enrolment nobody is holding open any more.
            return Outcome::refused(
                "the enrolment this signature belongs to is no longer open. Nothing was signed; \
                 start it again"
                    .to_owned(),
            );
        };

        let network = match self.named(label).await {
            Ok(network) => network,
            Err(cause) => {
                crate::admitting::abandon(pending).await;
                return Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() };
            }
        };

        let artifacts =
            match self.verified_batch(&network, prepared_against, requests, signatures).await {
                Ok(artifacts) => artifacts,
                Err(refused) => {
                    crate::admitting::abandon(pending).await;
                    return refused;
                }
            };
        let mut artifacts = artifacts.into_iter();

        // The revocation lands first, and the admission — built on top of it —
        // after. See `Resume::Admitting`.
        if replacing {
            let Some(revocation) = artifacts.next() else {
                crate::admitting::abandon(pending).await;
                return Outcome::refused("the batch held no revocation".to_owned());
            };
            if let Err(cause) = self.admit_to(&network, &revocation).await {
                crate::admitting::abandon(pending).await;
                return Outcome::Failed {
                    message: format!(
                        "the device holding that name could not be revoked, so nothing was \
                         admitted: {cause}"
                    ),
                    left_behind: Vec::new(),
                };
            }
        }
        let Some(admission) = artifacts.next() else {
            crate::admitting::abandon(pending).await;
            return Outcome::refused("the batch held no admission".to_owned());
        };

        let delivered = self.deliver_admission(&network, pending, admission, spec_name).await;
        let delivered = match delivered {
            // Said which acts took effect: the revocation is signed and in the
            // log, and cannot be unsaid, whatever happened to the admission.
            Outcome::Failed { message, left_behind } if replacing => Outcome::Failed {
                message: format!(
                    "the device holding that name was revoked, and the new device was not \
                     admitted: {message}"
                ),
                left_behind,
            },
            other => other,
        };
        self.with_the_snapshot(&network, delivered, artifacts.next()).await
    }

    /// Puts a signed genesis in the log, takes the network on, and keeps its
    /// first snapshot.
    ///
    /// A batch that does not verify leaves no network and no directory, which
    /// is what the synchronous path does when a person declines: an attempt that
    /// produced nothing must not be reported later as a network this daemon
    /// cannot carry.
    async fn founding_signed(
        &self,
        label: Label,
        genesis: &roster::types::OperationCore,
        identity: &Arc<identity::NodeIdentity>,
        for_whom: &crate::control::Caller,
        requests: &[identity::detached::SigningRequest],
        signatures: &[Vec<u8>],
    ) -> Outcome {
        let paths = self.home.paths_for(&label);
        let key = identity.signing_key().public_key();
        let artifacts = match identity::detached::finish_all(requests, &key, signatures) {
            Ok(artifacts) => artifacts,
            Err(cause) => {
                let _discarded = self.home.discard_unfounded(&label);
                return Outcome::refused(format!(
                    "that signature does not match what was prepared, so no network was \
                     founded: {cause}"
                ));
            }
        };
        let mut artifacts = artifacts.into_iter();
        let Some(bytes) = artifacts.next() else {
            let _discarded = self.home.discard_unfounded(&label);
            return Outcome::refused("the batch held no genesis".to_owned());
        };

        // What `adopt` would ask for is the snapshot already in this batch.
        if let Err(refusal) = crate::founding::adopt(&paths, genesis, &bytes, identity) {
            let _discarded = self.home.discard_unfounded(&label);
            return Outcome::refused(refusal);
        }
        if let Err(refusal) = self.record_who_it_is_for(&paths, for_whom).await {
            let _discarded = self.home.discard_unfounded(&label);
            return Outcome::refused(refusal);
        }
        let carried = self.carry_the_founded(label.clone(), paths).await;
        let Ok(network) = self.named(&label).await else { return carried };
        self.with_the_snapshot(&network, carried, artifacts.next()).await
    }

    /// Assembles a signed revocation, puts it into the roster, and keeps the
    /// snapshot signed with it.
    ///
    /// Every signature is checked against the request that was prepared, by
    /// `identity::detached::finish_all`, before anything is assembled: one that
    /// does not verify is refused here rather than turned into an operation whose
    /// refusal would first be seen on somebody else's device.
    async fn revocation_signed(
        &self,
        label: &Label,
        prepared_against: &crate::signing::Moment,
        requests: &[identity::detached::SigningRequest],
        signatures: &[Vec<u8>],
    ) -> Outcome {
        let network = match self.named(label).await {
            Ok(network) => network,
            Err(cause) => {
                return Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() };
            }
        };
        let artifacts =
            match self.verified_batch(&network, prepared_against, requests, signatures).await {
                Ok(artifacts) => artifacts,
                Err(refused) => return refused,
            };
        let mut artifacts = artifacts.into_iter();
        let Some(signed) = artifacts.next() else {
            return Outcome::refused("the batch held no revocation".to_owned());
        };
        let carried = self.carry_revocation(&network, signed).await;
        self.with_the_snapshot(&network, carried, artifacts.next()).await
    }

    /// Fetches the certificate a relay presents, and refuses one that cannot
    /// work as a server certificate.
    ///
    /// Shared by founding and by moving a relay, so the two confirm a relay the
    /// same way. The refusal is an answer to give a person, not an error.
    async fn fetched_certificate(&self, address: &str) -> core::result::Result<Vec<u8>, Outcome> {
        let (host, port) = match crate::relay::host_and_port(address) {
            Ok(parts) => parts,
            Err(refusal) => {
                return Err(Outcome::Failed { message: refusal, left_behind: Vec::new() });
            }
        };
        // On the blocking pool: the fetch is a synchronous TLS handshake, and
        // running it on the reactor would stall every other task in the daemon
        // for as long as the relay takes to answer — including the QUIC sessions
        // of a network that is already up. A blocking call inside the runtime is
        // how the enrolment test once hung for forty-three minutes.
        let fetching = tokio::task::spawn_blocking(move || {
            crate::relay::presented_certificate(&host, port).map(|der| (der, host))
        });
        let (certificate, host) = match fetching.await {
            Ok(Ok(fetched)) => fetched,
            Ok(Err(refusal)) => {
                return Err(Outcome::Failed { message: refusal, left_behind: Vec::new() });
            }
            Err(cause) => {
                return Err(Outcome::Failed {
                    message: format!("the certificate fetch did not finish: {cause}"),
                    left_behind: Vec::new(),
                });
            }
        };
        // Refused now rather than pinned and discovered later: a certificate a
        // verifying client cannot accept produces a network where every device
        // fails to reach the relay, and the only sign of it is a line in the
        // relay's log.
        if let Err(reason) = crate::relay::usable_as_a_server_certificate(&certificate, &host) {
            return Err(Outcome::Failed {
                message: format!(
                    "{host}:{port} presented a certificate that cannot work:
{reason}"
                ),
                left_behind: Vec::new(),
            });
        }

        Ok(certificate)
    }

    /// Starts moving a network to another relay.
    ///
    /// Refused before anything is fetched where it would change nothing. Where
    /// the relay is to be pinned its certificate is fetched and shown, and the act
    /// waits for a person — **nothing is signed before that confirmation**, and a
    /// declined one changes nothing. Where it is not, it goes straight to signing.
    async fn change_relay(
        &self,
        which: Option<&Label>,
        relay: &str,
        pin: bool,
        immediately: bool,
    ) -> Outcome {
        let network = match self.which(which).await {
            Ok(network) => network,
            Err(cause) => {
                return Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() };
            }
        };
        let label = network.label().clone();
        let state = match network.node().state().await {
            Ok(state) => state,
            Err(cause) => {
                return Outcome::Failed {
                    message: format!("the roster does not describe a network: {cause}"),
                    left_behind: Vec::new(),
                };
            }
        };
        // Compared the way admission compares relays, so a relay written
        // differently is not mistaken for a move.
        if let Some(current) = state.params.relay.as_deref()
            && crate::relay::same_relay(current, relay)
        {
            return Outcome::refused(format!(
                "`{label}` already uses {}. Nothing was changed.",
                crate::control::shown(relay)
            ));
        }
        if self.pending.lock().await.is_some() {
            return Outcome::Failed {
                message: "something is already waiting to be confirmed".to_owned(),
                left_behind: Vec::new(),
            };
        }

        if !pin {
            return self.finish_changing_relay(&label, relay, None, immediately).await;
        }

        let certificate = match self.fetched_certificate(relay).await {
            Ok(certificate) => certificate,
            Err(refused) => return refused,
        };
        let fingerprint = crate::relay::fingerprint(&certificate);
        let der_len = certificate.len();
        let moving = Some(label.to_string());
        let for_whom = self.asking.lock().await.clone();
        *self.pending.lock().await = Some(Pending::ChangingRelay {
            label,
            relay: relay.to_owned(),
            certificate: Some(certificate),
            immediately,
            for_whom,
        });
        Outcome::Pinning { fingerprint, der_len, relay: relay.to_owned(), moving }
    }

    /// Builds the move and signs it, or asks for it to be signed elsewhere.
    ///
    /// The end of the transition is dated from **the same instant the operation
    /// carries**, so the two cannot disagree about when the move began.
    async fn finish_changing_relay(
        &self,
        label: &Label,
        relay: &str,
        certificate: Option<Vec<u8>>,
        immediately: bool,
    ) -> Outcome {
        let network = match self.named(label).await {
            Ok(network) => network,
            Err(cause) => {
                return Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() };
            }
        };
        if let Some(refusal) = self.keys.admin_refusal() {
            return Outcome::refused(format!(
                "this network makes this device an admin, and {refusal}. Nothing was signed."
            ));
        }
        let node = Arc::clone(network.node());
        let state = match node.state().await {
            Ok(state) => state,
            Err(cause) => {
                return Outcome::Failed {
                    message: format!("the roster does not describe a network: {cause}"),
                    left_behind: Vec::new(),
                };
            }
        };

        let issued = crate::clock::signing_time();
        let params = if immediately {
            state.params.switching_to(relay, certificate)
        } else {
            state.params.moving_to(relay, certificate, issued)
        };
        let params = match params {
            Ok(params) => params,
            Err(cause) => {
                return Outcome::refused(format!("that relay cannot be used: {cause}"));
            }
        };
        self.sign_parameters(&network, label, &state, params, issued).await
    }

    /// Signs new parameters for a network as its admin, and carries them.
    ///
    /// **One path for every parameter change**, so the admin check, the custody
    /// prompt, a signature made elsewhere and the refusals are the same whether
    /// the relay or the rendezvous is changing.
    async fn sign_parameters(
        &self,
        network: &Arc<Network>,
        label: &Label,
        state: &roster::state::RosterState,
        params: roster::types::NetworkParams,
        issued: u64,
    ) -> Outcome {
        let node = network.node();
        let identity = node.identity();
        let prepared_against = node.moment().await;
        let core = match roster::types::OperationCore::new(
            issued,
            identity.signing_key().algorithm(),
            roster::types::OperationBody::SetNetwork(params),
            prepared_against.heads.clone(),
            identity.signing_key().key_id(),
            state.network,
        ) {
            Ok(core) => core,
            Err(cause) => return Outcome::refused(cause.to_string()),
        };

        if !identity.signing_key().answers_here() {
            let requests = Self::with_owed_snapshot(node, core::slice::from_ref(&core)).await;
            let resume = Resume::ChangingParameters { label: label.clone(), prepared_against };
            return self.wants_signatures(requests, identity, label, resume).await;
        }
        match identity.sign_operation(&core) {
            Ok(signed) => self.carry_relay_change(network, signed).await,
            Err(cause) => Outcome::refused(crate::control::declined(&cause)),
        }
    }

    /// Sets or removes a network's rendezvous, as its admin.
    ///
    /// Refused before anything is signed when the address is not HTTPS, or is
    /// the rendezvous the network already has.
    async fn change_rendezvous(&self, which: Option<&Label>, rendezvous: Option<&str>) -> Outcome {
        if let Some(address) = rendezvous
            && let Err(refusal) = crate::control::Command::rendezvous_address(address)
        {
            return Outcome::refused(refusal);
        }
        let network = match self.which(which).await {
            Ok(network) => network,
            Err(cause) => {
                return Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() };
            }
        };
        let label = network.label().clone();
        if let Some(refusal) = self.keys.admin_refusal() {
            return Outcome::refused(format!(
                "this network makes this device an admin, and {refusal}. Nothing was signed."
            ));
        }
        let state = match network.node().state().await {
            Ok(state) => state,
            Err(cause) => {
                return Outcome::Failed {
                    message: format!("the roster does not describe a network: {cause}"),
                    left_behind: Vec::new(),
                };
            }
        };
        if state.params.rendezvous.as_deref() == rendezvous {
            let said = rendezvous.map_or_else(
                || "no rendezvous".to_owned(),
                |address| crate::control::shown(address).to_string(),
            );
            return Outcome::refused(format!("`{label}` already has {said}. Nothing was changed."));
        }

        let params = match rendezvous {
            Some(address) => match state.params.clone().meeting_at(address) {
                Ok(params) => params,
                Err(cause) => {
                    return Outcome::refused(format!("that rendezvous cannot be used: {cause}"));
                }
            },
            None => {
                let mut params = state.params.clone();
                params.rendezvous = None;
                params
            }
        };
        let issued = crate::clock::signing_time();
        self.sign_parameters(&network, &label, &state, params, issued).await
    }

    /// Keeps a parameter change that was signed elsewhere, and the snapshot
    /// signed with it.
    async fn relay_change_signed(
        &self,
        label: &Label,
        prepared_against: &crate::signing::Moment,
        requests: &[identity::detached::SigningRequest],
        signatures: &[Vec<u8>],
    ) -> Outcome {
        let network = match self.named(label).await {
            Ok(network) => network,
            Err(cause) => {
                return Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() };
            }
        };
        let artifacts =
            match self.verified_batch(&network, prepared_against, requests, signatures).await {
                Ok(artifacts) => artifacts,
                Err(refused) => return refused,
            };
        let mut artifacts = artifacts.into_iter();
        let Some(signed) = artifacts.next() else {
            return Outcome::refused("the batch held no change".to_owned());
        };
        let carried = self.carry_relay_change(&network, signed).await;
        self.with_the_snapshot(&network, carried, artifacts.next()).await
    }

    /// Puts a signed relay change into the roster, bringing the network up to
    /// carry it — as every administrative act does.
    async fn carry_relay_change(&self, network: &Arc<Network>, signed: Vec<u8>) -> Outcome {
        match self.admit_to(network, &signed).await {
            Ok(false) => Outcome::Reported(self.report().await),
            Ok(true) => Outcome::Reported(
                self.report().await.with_note("the network was brought up to carry it"),
            ),
            Err(cause) => Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() },
        }
    }

    /// Holds a prepared batch, and asks for its signatures.
    ///
    /// **Nothing is signed and nothing has changed** when this answers. What goes
    /// back carries, for each item, the bytes to sign and the artifact they commit
    /// to — the second so that whoever asks a person can read the act out of what
    /// will happen, rather than out of a description this process sent alongside
    /// it. The one word sent beside them is the network's label, which says whose
    /// key rather than what act; see `SignaturesWanted::network`.
    async fn wants_signatures(
        &self,
        requests: Vec<identity::detached::SigningRequest>,
        identity: &identity::NodeIdentity,
        label: &Label,
        resume: Resume,
    ) -> Outcome {
        let items = requests.iter().map(crate::control::ToSign::from_request).collect();
        let asked = self.asking.lock().await.clone();
        let (id, lapsed) = {
            let mut unsigned = self.unsigned.lock().await;
            let id = unsigned.issue_for(requests, resume, crate::clock::now_ms(), asked);
            (id, unsigned.lapsed())
        };
        self.tidy_after(lapsed).await;
        Outcome::NeedsSignatures(crate::control::SignaturesWanted {
            id,
            key: reference_of(identity),
            network: label.to_string(),
            items,
        })
    }

    /// Tidies after acts that ended without being applied — declined, or left to
    /// expire.
    ///
    /// A founding is the one that leaves something: it made a directory and an
    /// identity before it stopped at its signature. A batch nobody signed leaves
    /// no network, so it must not leave a directory either — or the next start
    /// reports a network the person never had.
    async fn tidy_after(&self, ended: Vec<Resume>) {
        for act in ended {
            if let Resume::Founding { label, .. } = act {
                let _discarded = self.home.discard_unfounded(&label);
            }
        }
    }

    /// The requests for `cores`, followed by the snapshot the network will be
    /// owed once they are in, if it will be.
    ///
    /// The snapshot is prepared **with** the operations rather than after them,
    /// over a preview of the roster they make: a person is shown the whole act and
    /// asked once, where signing the snapshot afterwards asked twice and showed the
    /// second only once the first was authorised.
    async fn with_owed_snapshot(
        node: &Arc<crate::node::Node>,
        cores: &[roster::types::OperationCore],
    ) -> Vec<identity::detached::SigningRequest> {
        let key = node.identity().signing_key().public_key();
        let mut requests: Vec<identity::detached::SigningRequest> =
            cores.iter().map(|core| identity::detached::prepare_operation(core, &key)).collect();
        if let Some(snapshot) = node.snapshot_after(cores).await {
            requests.push(snapshot);
        }
        requests
    }

    /// Answers a command from a platform that does not distinguish between
    /// people.
    ///
    /// A phone is one: the device is the person's, there is no second account,
    /// and there is nobody for a network to belong to. Kept as its own entry
    /// point rather than as a default argument, so that a platform which *can*
    /// tell has to say so rather than fall into this by omission.
    pub async fn handle(&self, command: Command) -> Outcome {
        self.handle_for(&crate::control::Caller::Unattributed, command).await
    }

    /// Answers a command from somebody the platform identified.
    ///
    /// The caller comes from the channel and never from the command: a client
    /// that could say who it is, is a client that can say it is somebody else.
    pub async fn handle_for(&self, caller: &crate::control::Caller, command: Command) -> Outcome {
        // Held for the act, so that what is recorded for a network founded or
        // joined here is who asked for it rather than who happened to be asking
        // when the writing got round to it.
        *self.asking.lock().await = caller.clone();

        let logged = command.logged().map(|(word, network)| (word, network.map(str::to_owned)));

        // **Before the command is answered, not inside it.** A check in each arm
        // is a check somebody can forget to write, and the arm that forgot would
        // be the one that let anybody through.
        let outcome = match self.may_ask(caller, &command).await {
            Err(refusal) => Outcome::not_allowed(refusal),
            Ok(()) => self.answer(command).await,
        };

        // The word, the network and the kind of answer: chosen fields, never the
        // command — see `Command::logged`.
        if let Some((act, network)) = logged {
            tracing::info!(
                who = caller.name().unwrap_or("this device's person"),
                act,
                network = network.as_deref().unwrap_or("-"),
                outcome = outcome.kind(),
                "asked"
            );
        }
        outcome
    }

    /// Whether this caller may ask this command, per `Command::needs`.
    ///
    /// **What it does not decide is whether the command makes sense.** A network
    /// that is not there, a label that will not parse, an act that is not in
    /// flight: all of those are the command's own to report, and answering them
    /// here would turn every mistake into *«you are not authorised»*, which sends
    /// a person to an administrator over a typing error.
    async fn may_ask(
        &self,
        caller: &crate::control::Caller,
        command: &Command,
    ) -> core::result::Result<(), String> {
        match command.needs() {
            crate::control::Needs::Nobody => Ok(()),

            crate::control::Needs::TheMachine => Self::on_the_machine(caller),

            // Both, the machine first: an owner without elevation is told what
            // is missing is the elevation, not that the network is someone else's.
            crate::control::Needs::TheOwnerOfAsAdministrator(which) => {
                Self::on_the_machine(caller)?;
                let Ok(label) = Self::wanted(which) else { return Ok(()) };
                let Ok(network) = self.which(label.as_ref()).await else { return Ok(()) };
                Self::belongs_to(caller, &network.paths, network.label())
            }

            crate::control::Needs::TheOwnerOf(which) => {
                let Ok(label) = Self::wanted(which) else { return Ok(()) };
                let Ok(network) = self.which(label.as_ref()).await else { return Ok(()) };
                Self::belongs_to(caller, &network.paths, network.label())
            }

            crate::control::Needs::WhoeverBeganTheAct => self.began_it(caller, command).await,
        }
    }

    /// Whether a network is this caller's.
    /// Whether this caller may act on the machine.
    fn on_the_machine(caller: &crate::control::Caller) -> core::result::Result<(), String> {
        // **Where the platform draws no distinction, there is nothing to
        // check.** A phone has one person, and refusing them the machine
        // would mean it could not stop its own daemon.
        //
        // Not a hole on a platform that *does* draw it: there, a caller
        // the channel could not identify never reaches this at all — the
        // connection is refused before a command is answered, which
        // `serving::a_caller_that_cannot_be_established_is_refused`
        // holds.
        let nobody_to_ask = matches!(caller, crate::control::Caller::Unattributed);
        if nobody_to_ask || caller.may_act_on_the_machine() {
            Ok(())
        } else {
            Err(format!(
                "that is an administrator's on this machine, and you are {}. Nothing was \
                 changed.",
                crate::control::AUTHORISATION
            ))
        }
    }

    fn belongs_to(
        caller: &crate::control::Caller,
        paths: &crate::state::Paths,
        label: &Label,
    ) -> core::result::Result<(), String> {
        if caller.is(crate::state::read_owner(paths).as_deref()) {
            return Ok(());
        }
        Err(format!(
            "`{label}` belongs to somebody else on this machine, and you are {}. Nothing \
             about it was changed.",
            crate::control::AUTHORISATION
        ))
    }

    /// Whether the act this command finishes was begun by this caller.
    ///
    /// Three things can be in flight and they are owned differently. An
    /// **admission** is an act on a network, so it belongs to whoever the network
    /// does. A **founding** or a **join** has no network yet, so the person who
    /// began it is carried along with it. A **signature** belongs to whoever the
    /// act waiting for it was issued to.
    ///
    /// Where nothing is in flight, this allows: the command will say so itself,
    /// and it says it better.
    async fn began_it(
        &self,
        caller: &crate::control::Caller,
        command: &Command,
    ) -> core::result::Result<(), String> {
        let mistaken = || {
            format!(
                "that was begun by somebody else on this machine, and you are {}. Nothing was \
                 changed.",
                crate::control::AUTHORISATION
            )
        };

        // A signature answers an act by its id, and the id is the issuing time
        // and a counter — not a secret. Which is why the act remembers who it
        // was issued to rather than treating knowing the id as evidence.
        if let Command::Signed { id, .. } | Command::NotSigned { id } = command {
            return match self.unsigned.lock().await.asked_by(id) {
                None => Ok(()),
                Some(began) if began == caller => Ok(()),
                Some(_) => Err(mistaken()),
            };
        }

        let waiting = self.pending.lock().await;
        match &*waiting {
            None => Ok(()),
            Some(
                Pending::Founding { for_whom, .. }
                | Pending::Joining { for_whom, .. }
                | Pending::ChangingRelay { for_whom, .. },
            ) => {
                if for_whom == caller {
                    Ok(())
                } else {
                    Err(mistaken())
                }
            }
            Some(Pending::Admitting { label, .. }) => {
                let paths = self.home().paths_for(label);
                Self::belongs_to(caller, &paths, label)
            }
        }
    }

    /// Hands a network to whoever asked, where they may act on the machine.
    ///
    /// How a network survives the account that made it being deleted. It is also
    /// how one person takes another's, which is why it is privileged and why
    /// what it did is recorded rather than left to look as though it had always
    /// been so.
    async fn take_ownership(&self, which: Option<&Label>) -> Outcome {
        let asking = self.asking.lock().await.clone();
        if !asking.may_act_on_the_machine() {
            return Outcome::refused(
                "taking a network that belongs to somebody else on this machine is an \
                 administrator's act. Nothing was changed."
                    .to_owned(),
            );
        }
        let Some(name) = asking.name() else {
            return Outcome::refused(
                "this platform does not say who is asking, so there is nobody to give it to."
                    .to_owned(),
            );
        };

        let network = match self.which(which).await {
            Ok(network) => network,
            Err(cause) => {
                return Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() };
            }
        };
        if let Err(cause) = crate::state::take_ownership(&network.paths, name) {
            return Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() };
        }
        Outcome::Reported(
            self.report().await.with_note("that network was taken; it belongs to you now"),
        )
    }

    /// Holds an act until a signing key is made where a person can be asked.
    ///
    /// Returns `None` when there is nothing to wait for — the key store here can
    /// make its own — and the caller carries on.
    async fn wants_a_key(&self, paths: &crate::state::Paths, then: Unfinished) -> Option<Outcome> {
        let asked = self.keys.must_be_made_elsewhere(paths)?;
        // A network being joined has no name here yet: its label is a
        // placeholder until it arrives, and a person shown `network` would be
        // shown a word that means nothing. Empty says *the one being joined*.
        let network =
            if matches!(then, Unfinished::Joining { .. }) { String::new() } else { asked.network };

        let issued = crate::clock::now_ms();
        let id = format!("k{issued:x}");
        *self.unkeyed.lock().await = Some(Unkeyed {
            id: id.clone(),
            issued,
            by: self.asking.lock().await.clone(),
            paths: paths.clone(),
            name: asked.name.clone(),
            then,
        });
        Some(Outcome::NeedsKey(crate::control::KeyWanted { id, name: asked.name, network }))
    }

    /// Takes up an act that was waiting for its key.
    ///
    /// The identity is written from the key that was made — **not** from one this
    /// process makes — and then the act is re-entered from the top, where it
    /// finds the identity already there.
    async fn key_made(&self, id: &str, public: Vec<u8>) -> Outcome {
        let waiting = self.unkeyed.lock().await.take();
        let Some(held) = waiting else {
            return Outcome::refused(
                "no act is waiting for a key. It may have been completed already, or abandoned"
                    .to_owned(),
            );
        };
        if held.id != id {
            // Put back what was not asked about: answering the wrong act must not
            // end the right one.
            *self.unkeyed.lock().await = Some(held);
            return Outcome::refused(
                "no act is waiting for a key under that name. Nothing was changed".to_owned(),
            );
        }
        if crate::clock::now_ms().saturating_sub(held.issued) > crate::signing::WAITS_FOR {
            return Outcome::refused(
                "the act waited too long for a key and was dropped. Nothing was made; ask for it \
                 again"
                    .to_owned(),
            );
        }

        // Still wanted? An identity that appeared while this waited was made by
        // something else, and is not overwritten.
        if self.keys.must_be_made_elsewhere(&held.paths).is_some() {
            let made = crate::keys::Made { name: held.name.clone(), public };
            if let Err(cause) = self.keys.identity_from(&held.paths, &made) {
                return Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() };
            }
        }

        match held.then {
            Unfinished::Founding { label, wanted } => {
                self.finish_founding(label, *wanted, &held.by).await
            }
            Unfinished::Joining { label, relay, name } => {
                self.join_under(label, &relay, &name).await
            }
        }
    }

    /// Answers a command.
    async fn answer(&self, command: Command) -> Outcome {
        match command {
            Command::Status => Outcome::Reported(self.report().await),
            // A reading command that names a network is asking about that one,
            // so a name this device does not hold is a mistake to say rather
            // than a report about everything else. Naming none is not a mistake:
            // reading about them all shows more than was asked for and changes
            // nothing, which is why `up` and `down` refuse there and these do
            // not.
            Command::Peers { network } | Command::Address { network } => {
                match Self::wanted(network) {
                    Ok(Some(label)) => match self.named(&label).await {
                        Ok(_) => Outcome::Reported(self.report().await),
                        Err(refusal) => Self::said(Err(refusal)),
                    },
                    Ok(None) => Outcome::Reported(self.report().await),
                    Err(cause) => Self::said(Err(cause)),
                }
            }
            Command::Up { network } => match Self::wanted(network) {
                Ok(label) => Self::said(self.bring_up(label.as_ref()).await),
                Err(cause) => Self::said(Err(cause)),
            },
            Command::Down { network } => match Self::wanted(network) {
                Ok(label) => Self::said(self.take_down(label.as_ref()).await),
                Err(cause) => Self::said(Err(cause)),
            },
            // Stopping is not an act on one network. Every one this device holds
            // goes down, because the daemon is going away and leaving a tunnel up
            // with nothing driving it would leave routes to nowhere.
            Command::Stop => {
                *self.stopping.lock().await = true;
                Self::said(self.take_all_down().await)
            }
            Command::Admit { network, payload } => match Self::wanted(network) {
                Ok(label) => self.begin_admitting(label.as_ref(), &payload).await,
                Err(cause) => {
                    Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() }
                }
            },
            Command::Confirm => self.confirm().await,
            Command::ConfirmJoin { code } => self.confirm_join(code).await,
            Command::Abandon => {
                match self.pending.lock().await.take() {
                    Some(Pending::Admitting { pending, .. }) => {
                        crate::admitting::abandon(pending).await;
                    }
                    // A founding that is abandoned has signed nothing and opened
                    // no socket: dropping the parameters is the whole of it.
                    Some(Pending::Founding { .. } | Pending::ChangingRelay { .. }) | None => {}
                    // A join has a socket. Ending the task closes the endpoint it
                    // opened, which is what takes the daemon back to silence —
                    // §2.6c gives it no licence to stay registered at a relay for
                    // a join nobody is coming back to.
                    Some(Pending::Joining { mut task, underway, .. }) => {
                        // Asked to stop, so it closes its endpoint; ended by force
                        // only if it does not within a few seconds.
                        underway.abandon();
                        if tokio::time::timeout(Duration::from_secs(5), &mut task).await.is_err() {
                            task.abort();
                        }
                    }
                }
                Outcome::Done
            }
            Command::Revoke { network, target, reason } => match Self::wanted(network) {
                Ok(label) => self.revoke(label.as_ref(), &target, &reason).await,
                Err(cause) => {
                    Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() }
                }
            },
            Command::TakeOwnership { network } => match Self::wanted(network) {
                Ok(label) => self.take_ownership(label.as_ref()).await,
                Err(cause) => {
                    Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() }
                }
            },
            Command::Signed { id, signatures } => self.signed(&id, &signatures).await,
            Command::KeyMade { id, public } => self.key_made(&id, public).await,
            Command::Expose { network, protocol, port } => match Self::wanted(network) {
                Ok(label) => self.expose(label.as_ref(), protocol, port).await,
                Err(cause) => Self::said(Err(cause)),
            },
            Command::Unexpose { network, protocol, port } => match Self::wanted(network) {
                Ok(label) => self.unexpose(label.as_ref(), protocol, port).await,
                Err(cause) => Self::said(Err(cause)),
            },
            Command::Exposed { network } => match Self::wanted(network) {
                Ok(label) => self.exposed(label.as_ref()).await,
                Err(cause) => Self::said(Err(cause)),
            },
            Command::ChangeRelay { network, relay, pin, immediately } => {
                match Self::wanted(network) {
                    Ok(label) => self.change_relay(label.as_ref(), &relay, pin, immediately).await,
                    Err(cause) => Self::said(Err(cause)),
                }
            }
            Command::ChangeRendezvous { network, rendezvous } => match Self::wanted(network) {
                Ok(label) => self.change_rendezvous(label.as_ref(), rendezvous.as_deref()).await,
                Err(cause) => Self::said(Err(cause)),
            },
            // Said rather than left to expire: the act is over the moment a
            // person declines, and holding it for five more minutes would leave
            // something completable that nobody means to complete.
            Command::NotSigned { id } => {
                let ended = self.unsigned.lock().await.abandon(&id);
                self.tidy_after(ended.into_iter().collect()).await;
                Outcome::Done
            }
            Command::Join { relay, name } => self.begin_joining(&relay, &name).await,
            Command::Replace => self.confirm_replacing().await,
            Command::Forget { label, last_admin } => self.forget(&label, last_admin).await,
            Command::Waiting => self.waiting_on().await,
            Command::Found { label, name, suffix, relay, rendezvous, certificate, ipv4_range } => {
                let fetch = certificate == crate::control::Certificate::FromTheRelay;
                // Before anything else, and before any certificate is fetched: a
                // range that is not allowed is refused with nothing signed.
                let ipv4_range = match crate::founding::ipv4_range(ipv4_range.as_deref()) {
                    Ok(range) => range,
                    Err(refusal) => {
                        return Outcome::Failed { message: refusal, left_behind: Vec::new() };
                    }
                };
                let wanted = crate::founding::Founding {
                    ipv4_range,
                    name,
                    suffix,
                    relay,
                    rendezvous,
                    certificate: match certificate {
                        crate::control::Certificate::Given(bytes) => Some(bytes),
                        crate::control::Certificate::None
                        | crate::control::Certificate::FromTheRelay => None,
                    },
                };
                match Label::new(&label) {
                    Ok(label) => self.found(label, wanted, fetch).await,
                    Err(cause) => {
                        Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() }
                    }
                }
            }
        }
    }

    /// Expels a device from the network.
    ///
    /// Signs the revocation and hands it to the node by the same path an
    /// admission takes, so it reaches `enforce_roster` — which closes the
    /// session the revoked device holds and tells the transport, rather than
    /// leaving both until something is restarted.
    ///
    /// Whether this device may make the revocation is **the roster's** decision,
    /// not checked here. A refusal comes back in the roster's words.
    async fn revoke(
        &self,
        which: Option<&Label>,
        target: &crate::control::Target,
        reason: &str,
    ) -> Outcome {
        let network = match self.which(which).await {
            Ok(network) => network,
            Err(cause) => {
                return Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() };
            }
        };
        let node = Arc::clone(network.node());
        let state = match node.state().await {
            Ok(state) => state,
            Err(cause) => {
                return Outcome::Failed {
                    message: format!("there is no network on this device: {cause}"),
                    left_behind: Vec::new(),
                };
            }
        };

        let identity = node.identity();
        let expulsion = match crate::revoking::resolve(&state, identity, target, reason) {
            Ok(expulsion) => expulsion,
            Err(refusal) => return Outcome::Failed { message: refusal, left_behind: Vec::new() },
        };

        let prepared_against = node.moment().await;
        let heads = prepared_against.heads.clone();

        // An admin role the roster gives a machine that cannot hold an admin's
        // key is declared, not exercised. Signing anyway would put this
        // network's authority behind a key the platform cannot protect, which is
        // the finding this change exists to close — a role is not a capability.
        if let Some(refusal) = self.keys.admin_refusal() {
            return Outcome::refused(format!(
                "this network makes this device an admin, and {refusal}. Nothing was signed."
            ));
        }

        // Where the signing key is somewhere this process cannot reach, the act
        // stops here and somebody else signs these exact bytes. Asked before
        // signing rather than found out by signing; see `answers_here`.
        if !identity.signing_key().answers_here() {
            let core = match crate::revoking::core(&expulsion, identity, &state, heads) {
                Ok(core) => core,
                Err(refusal) => {
                    return Outcome::Failed { message: refusal, left_behind: Vec::new() };
                }
            };
            let requests = Self::with_owed_snapshot(&node, core::slice::from_ref(&core)).await;
            let label = network.label().clone();
            let resume = Resume::Revoking { label: label.clone(), prepared_against };
            return self.wants_signatures(requests, identity, &label, resume).await;
        }

        let signed = match crate::revoking::sign(&expulsion, identity, &state, heads) {
            Ok(signed) => signed,
            Err(cause) => {
                return Outcome::refused(format!("the revocation could not be signed: {cause}"));
            }
        };

        // Through `admit`, not `admit_without_activating`. Every administrative action taken
        // while the network is down brings it up — the requirement says so, and
        // admitting a device has always done it — but revoking called one layer
        // lower and skipped it. A person revoking a stolen laptop and walking
        // away from the machine has every reason to think it is done, and that
        // was the one action where it was not.
        //
        // A failure to come up is reported and the revocation is kept: it is
        // signed, it is in the log, and it is outstanding. Discarding it because
        // the tunnel would not start would throw away the very thing the person
        // asked for.
        self.carry_revocation(&network, signed).await
    }

    /// Puts a signed revocation into the roster, bringing the network up for it.
    ///
    /// Reached by both paths, because by the time the bytes exist it no longer
    /// matters which of them produced the signature.
    async fn carry_revocation(&self, network: &Arc<Network>, signed: Vec<u8>) -> Outcome {
        match self.admit_to(network, &signed).await {
            Ok(false) => Outcome::Reported(self.report().await),
            Ok(true) => Outcome::Reported(
                self.report().await.with_note("the network was brought up to carry it"),
            ),
            Err(cause) => Outcome::Failed {
                message: format!(
                    "the revocation is signed and held, but the network would not come \
                     up to carry it: {cause}"
                ),
                left_behind: Vec::new(),
            },
        }
    }

    /// Opens an enrolment and stops before signing anything.
    async fn begin_admitting(&self, which: Option<&Label>, payload: &str) -> Outcome {
        // A second enrolment would mean two codes on one screen, and a person
        // with no way to tell which they were being asked about.
        if self.pending.lock().await.is_some() {
            return Outcome::Failed {
                message: "an enrolment is already waiting. Finish or abandon it first.".to_owned(),
                left_behind: Vec::new(),
            };
        }

        // Named, because a device holding several networks is admitting a
        // device into one of them and only the person knows which.
        let network = match self.which(which).await {
            Ok(network) => network,
            Err(cause) => {
                return Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() };
            }
        };
        let admitting = network.label().clone();
        let node = Arc::clone(network.node());
        let Ok(state) = node.state().await else {
            return Outcome::Failed {
                message: "this device holds no network, so it cannot admit another".to_owned(),
                left_behind: Vec::new(),
            };
        };

        match crate::admitting::open(node.identity(), &state, payload).await {
            Ok(pending) => {
                let outcome = Outcome::Admitting {
                    proposed_name: pending.proposed_name().to_owned(),
                    fingerprint: pending.fingerprint(),
                    code: pending.code().to_string(),
                    taken: taken_name(&pending),
                    accepted: pending.accepted(),
                };
                *self.pending.lock().await = Some(Pending::Admitting { label: admitting, pending });
                outcome
            }
            Err(refusal) => Outcome::refused(refusal),
        }
    }

    /// Finishes whatever is waiting on this device's own person.
    ///
    /// A join is not one of those. Its person supplies six digits read off
    /// another machine, so it is confirmed through [`Self::confirm_join`] and a
    /// bare confirmation is refused here rather than treated as agreement — the
    /// agreement being exactly what this change removes.
    async fn confirm(&self) -> Outcome {
        self.confirm_with(false).await
    }

    /// Confirms an admission and revokes the device already holding that name.
    ///
    /// Two operations, signed as one act and with nothing waited for in between,
    /// because that is what a person answered. The revocation is definitive:
    /// whoever is asked has been told so before they choose.
    async fn confirm_replacing(&self) -> Outcome {
        self.confirm_with(true).await
    }

    /// Confirms whatever is waiting. `keeping_the_name` is the admin's answer to
    /// a proposed name the network already uses, and means nothing otherwise.
    async fn confirm_with(&self, keeping_the_name: bool) -> Outcome {
        let waiting = self.pending.lock().await.take();
        match waiting {
            Some(Pending::Admitting { label, pending }) => {
                self.finish_admitting(label, pending, keeping_the_name).await
            }
            Some(Pending::Founding { label, wanted, for_whom }) => {
                self.finish_founding(label, wanted, &for_whom).await
            }
            Some(Pending::ChangingRelay { label, relay, certificate, immediately, .. }) => {
                self.finish_changing_relay(&label, &relay, certificate, immediately).await
            }
            Some(Pending::Joining { label, underway, task, for_whom }) => {
                *self.pending.lock().await =
                    Some(Pending::Joining { label, underway, task, for_whom });
                Outcome::Failed {
                    message: "a join is confirmed with the code shown on the other machine, not with a yes"
                        .to_owned(),
                    left_behind: Vec::new(),
                }
            }
            None => Outcome::Failed {
                message: "nothing is waiting to be confirmed".to_owned(),
                left_behind: Vec::new(),
            },
        }
    }

    /// Finishes a join with the digits a person read off the admitting machine.
    ///
    /// The code comes from the person and goes to the join, which compares it
    /// with the one it derived. Nothing here may substitute a code of its own:
    /// reading the join's own code and handing it back was what made the
    /// comparison always succeed.
    async fn confirm_join(&self, code: String) -> Outcome {
        let waiting = self.pending.lock().await.take();
        match waiting {
            Some(Pending::Joining { label, underway, task, for_whom }) => {
                self.finish_joining(label, underway, task, &code, &for_whom).await
            }
            Some(other) => {
                *self.pending.lock().await = Some(other);
                Outcome::Failed {
                    message: "no join is waiting for a code on this device".to_owned(),
                    left_behind: Vec::new(),
                }
            }
            None => Outcome::Failed {
                message: "nothing is waiting to be confirmed".to_owned(),
                left_behind: Vec::new(),
            },
        }
    }

    /// Starts waiting to be given a network.
    ///
    /// The join runs as a task here rather than in the process that typed the
    /// command, so the roster it receives is the one this daemon is using. It
    /// answers as soon as there is a payload to carry to an admin, and the rest
    /// of the conversation is asked for with `Waiting`.
    async fn begin_joining(&self, relay: &str, name: &str) -> Outcome {
        // The daemon names the directory, because nobody else can. A person
        // starting a join has not seen the network, does not know its suffix, and
        // would be inventing a name for something that has not arrived — a
        // question with no right answer, whose default became a real directory on
        // a test phone whether or not anybody meant it. What the network is
        // called here is decided once it is here, from its own suffix.
        let label = match self.home.free_label(None) {
            Ok(label) => label,
            Err(cause) => {
                return Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() };
            }
        };
        if let Err(refusal) = self.free(&label).await {
            return refusal;
        }
        if self.pending.lock().await.is_some() {
            return Outcome::Failed {
                message: "something is already waiting to be confirmed".to_owned(),
                left_behind: Vec::new(),
            };
        }

        // **Before the endpoint is opened, not after.** A join that reached a
        // relay and then stopped to ask for a key would have spoken on behalf of
        // a device that does not exist yet.
        let paths = self.home.paths_for(&label);
        let asked = self
            .wants_a_key(
                &paths,
                Unfinished::Joining {
                    label: label.clone(),
                    relay: relay.to_owned(),
                    name: name.to_owned(),
                },
            )
            .await;
        if let Some(waiting) = asked {
            return waiting;
        }

        self.join_under(label, relay, name).await
    }

    /// The join itself, once this device has an identity to join with.
    async fn join_under(&self, label: Label, relay: &str, name: &str) -> Outcome {
        let (person, underway) = crate::joining::AcrossTheChannel::new();
        let paths = self.home.paths_for(&label);
        let address = relay.to_owned();
        let name = name.to_owned();

        // The endpoint this opens is one of the two things that license the
        // daemon to reach anything, and it exists only until the join ends.
        let keys = Arc::clone(&self.keys);
        let home = self.home.clone();
        let joining = label.clone();
        let task = tokio::spawn(async move {
            let outcome =
                crate::joining::join_with(&paths, &address, &name, person.clone(), keys.as_ref())
                    .await;
            if outcome.is_err() {
                // A join that ended without a network leaves no directory behind.
                let _discarded = home.discard_unfounded(&joining);
            }
            person.finished(outcome);
        });

        // Answered at once, before the relay has been reached. Waiting here for a
        // payload would block the daemon on however long a relay takes to
        // answer — up to thirty seconds — with every other command queued behind
        // it. The command line asks what this has got to, which it has to do
        // anyway for the code that appears later.
        let progress = underway.progress();
        let for_whom = self.asking.lock().await.clone();
        *self.pending.lock().await = Some(Pending::Joining { label, underway, task, for_whom });

        match progress {
            crate::joining::Progress::Waiting { payload, scannable } => {
                Outcome::Joining { payload, scannable }
            }
            crate::joining::Progress::Failed(why) => Outcome::refused(why),
            _ => Outcome::Joining { payload: String::new(), scannable: String::new() },
        }
    }

    /// Removes a network from this device, carried or not.
    ///
    /// # Why this is not only for what is broken
    ///
    /// A device that has been **revoked** holds a roster that loads, derives, and
    /// names it as a member: the expulsion was signed elsewhere and it has no way
    /// to hear it. From in here nothing is wrong with that membership, and there
    /// is no test this daemon could run that would say otherwise — so a removal
    /// that only worked on what this device could tell was broken would leave
    /// exactly the case that most needs it. Found in verification, on a phone
    /// whose name had been given to another device.
    ///
    /// # What it is not
    ///
    /// It is **local**. The directory goes, and the keys in it go with it, so
    /// this device cannot rejoin under the identity it is discarding. The network
    /// is told nothing: the other devices go on listing this device until an
    /// administrator revokes it. Saying that is the surface's to do, and it is
    /// the part a person is likeliest to get wrong — removing a network is not
    /// leaving one.
    /// Opens `port` to one network, through its adapter and from its addresses.
    ///
    /// **The network must be on.** The rule is bound to the network's adapter,
    /// and the firewall resolves an interface when the rule is written; an
    /// adapter that does not exist yet cannot be named.
    async fn expose(
        &self,
        which: Option<&Label>,
        protocol: crate::exposing::Protocol,
        port: u16,
    ) -> Outcome {
        let network = match self.which(which).await {
            Ok(network) => network,
            Err(cause) => return Self::said(Err(cause)),
        };
        let label = network.label().clone();
        if network.up.lock().await.is_none() {
            return Outcome::refused(format!(
                "`{label}` is off: turn it on first. The rule is bound to the network's adapter, \
                 which exists only while it is on. Nothing was changed."
            ));
        }
        let state = match network.node().state().await {
            Ok(state) => state,
            Err(cause) => {
                return Outcome::refused(format!("`{label}` has no state to read: {cause}"));
            }
        };
        let rule = match crate::exposing::rule_for(
            &label.to_string(),
            state.network,
            protocol,
            port,
            &state.params,
        ) {
            Ok(rule) => rule,
            Err(refusal) => return Outcome::refused(format!("{refusal}. Nothing was changed.")),
        };
        if let Err(refusal) = self.exposing.expose(&rule).await {
            return Outcome::refused(format!("{refusal}. Nothing was changed."));
        }
        self.exposed(Some(&label)).await
    }

    /// Closes what [`Self::expose`] opened. Needs no adapter: a rule is removed by
    /// the network it names, on or off.
    async fn unexpose(
        &self,
        which: Option<&Label>,
        protocol: crate::exposing::Protocol,
        port: u16,
    ) -> Outcome {
        let network = match self.which(which).await {
            Ok(network) => network,
            Err(cause) => return Self::said(Err(cause)),
        };
        let label = network.label().clone();
        let state = match network.node().state().await {
            Ok(state) => state,
            Err(cause) => {
                return Outcome::refused(format!("`{label}` has no state to read: {cause}"));
            }
        };
        match self.exposing.unexpose(&state.network, protocol, port).await {
            Ok(true) => self.exposed(Some(&label)).await,
            Ok(false) => Outcome::refused(format!(
                "nothing is open on {} {port} to `{label}`. Nothing was changed.",
                protocol.word()
            )),
            Err(refusal) => Outcome::refused(format!("{refusal}. Nothing was changed.")),
        }
    }

    /// What is open, to one network or to every network the person asking holds.
    async fn exposed(&self, which: Option<&Label>) -> Outcome {
        let held = match self.exposing.held().await {
            Ok(held) => held,
            Err(refusal) => return Outcome::refused(refusal),
        };
        let asking = self.asking.lock().await.clone();
        let mut rules = Vec::new();
        for network in self.all().await {
            if which.is_some_and(|wanted| wanted != network.label())
                || !asking.is(crate::state::read_owner(&network.paths).as_deref())
            {
                continue;
            }
            let Ok(state) = network.node().state().await else { continue };
            rules.extend(held.iter().filter(|rule| rule.network == state.network).map(|rule| {
                crate::exposing::Exposure {
                    network: network.label().to_string(),
                    protocol: rule.protocol,
                    port: rule.port,
                }
            }));
        }
        Outcome::Exposed { rules }
    }

    /// Every network this machine keeps a record of, carried or not.
    ///
    /// A network that will not open today still has its record, and its rules
    /// are not a leftover: they are kept until the network itself goes.
    ///
    /// # Errors
    ///
    /// When the networks cannot be listed — which must stop a sweep, not become
    /// "no network at all" and take every rule with it.
    fn recorded_networks(&self) -> core::result::Result<Vec<roster::id::NetworkId>, String> {
        let survey = self.home.survey().map_err(|cause| cause.to_string())?;
        Ok(survey.held.into_iter().map(|held| held.record.network).collect())
    }

    /// Removes every exposed port whose network this machine no longer holds.
    ///
    /// Run at start, beside the sweep of name-resolution rules, and after a
    /// network is forgotten.
    ///
    /// # Errors
    ///
    /// When the networks cannot be listed, or the firewall will not answer.
    pub async fn sweep_exposures(&self) -> core::result::Result<usize, String> {
        let kept = self.recorded_networks()?;
        self.exposing.sweep(&kept).await
    }

    /// Removes a network from this device, and every key it keeps for it.
    ///
    /// In this order, and the order is the point:
    ///
    /// 1. **Refuse**, touching nothing: a network not held, an enrolment for it
    ///    still waiting for a person, or this device its only admin without the
    ///    person having said they know.
    /// 2. **Down**, so nothing is left running for a network that is going.
    /// 3. **The keys**, while the identity that names them is still there. A key
    ///    that will not go keeps the directory, and the network stays held —
    ///    down — so removing it again can finish rather than leaving a key that
    ///    nothing names.
    /// 4. **The directory**, and then off the lists and its exposed ports.
    async fn forget(&self, label: &str, last_admin: bool) -> Outcome {
        let Ok(wanted) = Label::new(label) else {
            return Outcome::Failed {
                message: format!("`{label}` is not a name this daemon gives a directory"),
                left_behind: Vec::new(),
            };
        };

        let carried = self.all().await.into_iter().find(|network| *network.label() == wanted);
        let broken = self.broken.lock().await.iter().position(|held| held.label == label);
        if carried.is_none() && broken.is_none() {
            return Outcome::Failed {
                message: format!("this device holds no network called `{label}`"),
                left_behind: Vec::new(),
            };
        }

        // An enrolment still open for it: the exchange would have its directory
        // pulled out from under it while a person is looking at a code.
        let enrolling = matches!(
            &*self.pending.lock().await,
            Some(Pending::Admitting { label: waiting, .. } | Pending::Joining { label: waiting, .. })
                if *waiting == wanted
        );
        if enrolling {
            return Outcome::Failed {
                message: format!(
                    "an enrolment for `{label}` is waiting for a person. Finish it or abandon it \
                     first; nothing was removed."
                ),
                left_behind: Vec::new(),
            };
        }

        // The only admin, asked first. A broken network is not judged: its
        // roster cannot say who its admins are.
        if !last_admin
            && let Some(network) = &carried
            && Self::is_its_only_admin(network).await
        {
            return Outcome::OnlyAdmin { network: label.to_owned() };
        }
        let carried = carried.is_some();

        // Down before it goes. A network removed while its tunnel was up would
        // leave an adapter, a route and a resolution rule behind for a network
        // that no longer exists, which reads to a person as the machine being
        // broken rather than as a leftover.
        if carried && let Err(cause) = self.take_down(Some(&wanted)).await {
            return Outcome::Failed {
                message: format!(
                    "`{label}` could not be taken down, so it was not removed: {cause}"
                ),
                left_behind: Vec::new(),
            };
        }
        let paths = self.home.paths_for(&wanted);

        // The keys kept outside the directory, while the identity in it still
        // names them. One that will not go keeps everything else where it is.
        if let Err(cause) = self.keys.forget(&paths) {
            return Outcome::Failed {
                message: format!(
                    "`{label}` is down, but its signing key would not go, so its directory was \
                     kept: remove it again to finish. {cause}"
                ),
                left_behind: vec![format!("the signing key of `{label}`")],
            };
        }

        self.networks.lock().await.remove(&wanted);
        if let Err(cause) = std::fs::remove_dir_all(paths.root()) {
            return Outcome::Failed {
                message: format!("`{label}` could not be removed: {cause}"),
                left_behind: vec![paths.root().display().to_string()],
            };
        }
        // Off the list as well as off the disk: a directory reported after it was
        // removed is an account of a machine that no longer exists.
        if let Some(position) = broken {
            self.broken.lock().await.remove(position);
        }
        // Its exposed ports go with it. Said beside the forget rather than
        // instead of it: the network is gone either way.
        let mut report = self.report().await;
        if let Err(cause) = self.sweep_exposures().await {
            report.note = Some(format!(
                "`{label}` was removed, but its firewall rules would not go: {cause}"
            ));
        }
        Outcome::Reported(report)
    }

    /// Whether this device is the network's only admin.
    ///
    /// Read from the network's own state: this device an admin, and no other
    /// device in it — the revoked are not in it — an admin as well.
    async fn is_its_only_admin(network: &Arc<Network>) -> bool {
        let Ok(state) = network.node().state().await else { return false };
        let me = network.node().identity().device_id();
        state.is_admin(&me)
            && !state.devices.keys().any(|device| *device != me && state.is_admin(device))
    }

    /// What a waiting enrolment has got to.
    ///
    /// # Asking is also how a join finishes
    ///
    /// A join is completed by whoever next notices it has arrived, and this is
    /// usually that: a surface asks every couple of seconds, and the answer is
    /// what a person is shown.
    ///
    /// It used to **report** a join as adopted and do nothing about it. The
    /// network arrived, the roster was written, this said `Adopted`, the screen
    /// said *"you are now a device in casa"* — and no record was ever written, so
    /// the daemon carried nothing and the directory sat there stranded. A success
    /// reported without being performed is worse than a failure: nothing looks
    /// wrong until much later, somewhere else.
    ///
    /// Completing it here also takes the weight off the confirming request. That
    /// request waits on a person reading prompts **at the other machine**, which
    /// is unbounded by nature; it is a fast path now rather than the only path.
    async fn waiting_on(&self) -> Outcome {
        // Read without holding the lock across the work that may follow.
        let joining = {
            let held = self.pending.lock().await;
            match &*held {
                Some(Pending::Joining { underway, label, .. }) => {
                    Some((underway.progress(), label.clone()))
                }
                _ => None,
            }
        };
        if let Some((progress, label)) = joining {
            return match progress {
                crate::joining::Progress::Registering => {
                    Outcome::Joining { payload: String::new(), scannable: String::new() }
                }
                crate::joining::Progress::Waiting { payload, scannable } => {
                    Outcome::Joining { payload, scannable }
                }
                crate::joining::Progress::Confirming { .. } => Outcome::Enrolling,
                crate::joining::Progress::Signing { request, .. } => {
                    self.wants_proving(&request, &self.joining_key(&label)).await
                }
                crate::joining::Progress::Joined { .. } => self.take_the_network_on().await,
                crate::joining::Progress::Failed(why) => Outcome::refused(why),
            };
        }

        let held = self.pending.lock().await;
        match &*held {
            Some(Pending::Joining { .. }) => {
                Outcome::Joining { payload: String::new(), scannable: String::new() }
            }
            Some(Pending::Admitting { pending, .. }) => Outcome::Admitting {
                proposed_name: pending.proposed_name().to_owned(),
                fingerprint: pending.fingerprint(),
                code: pending.code().to_string(),
                taken: taken_name(pending),
                accepted: pending.accepted(),
            },
            // A founding waiting on a certificate is waiting. Answering that
            // nothing was would be a lie with a consequence: it is a pending like
            // any other, it refuses the next enrolment like any other, and a
            // surface told there is nothing there has nothing to offer a person
            // but the refusal.
            Some(Pending::ChangingRelay { label, relay, certificate, .. }) => match certificate {
                Some(certificate) => Outcome::Pinning {
                    relay: relay.clone(),
                    fingerprint: crate::relay::fingerprint(certificate),
                    der_len: certificate.len(),
                    moving: Some(label.to_string()),
                },
                // Only ever pending on a certificate, as a founding is; answered
                // as waiting for the reason given below.
                None => Outcome::Failed {
                    message: "a relay change is waiting to be confirmed".to_owned(),
                    left_behind: Vec::new(),
                },
            },
            Some(Pending::Founding { wanted, .. }) => match &wanted.certificate {
                Some(certificate) => Outcome::Pinning {
                    relay: wanted.relay.clone().unwrap_or_default(),
                    fingerprint: crate::relay::fingerprint(certificate),
                    der_len: certificate.len(),
                    moving: None,
                },
                // A founding is only ever pending on a certificate, so this is
                // unreachable — and it is still answered as something waiting,
                // because what a surface must not be told is that the thing
                // blocking it is not there.
                None => Outcome::Failed {
                    message: "a founding is waiting to be confirmed".to_owned(),
                    left_behind: Vec::new(),
                },
            },
            // Nothing waiting is not a failure, and it must not arrive looking
            // like one. A surface asking what is open needs to tell "nothing" from
            // "an enrolment that ended badly and is still held" — the second is
            // what blocks the next join, and telling them apart by reading the
            // words of a refusal is not telling them apart.
            None => Outcome::Done,
        }
    }

    /// Gives a joined network its name, replacing any membership this device
    /// already held in **the same** network.
    ///
    /// # One directory per network
    ///
    /// A device gets one identity per network, and a second directory holding the
    /// same network id is always the residue of enrolling again — most often
    /// after an administrator answered "replace it" on the other machine. Keeping
    /// both leaves this device holding an identity the network has expelled: it
    /// carries on trying to use it, shows that network as broken, and asks a
    /// person to tidy up after a machine. The first run of this on a phone left
    /// exactly that: `casa`, revoked and unusable, beside `network`, working.
    ///
    /// So the new membership supersedes the old one and **takes its name**, which
    /// is also what keeps a person's own word for the network — `casa` stays
    /// `casa` rather than becoming `network` because the good name was taken by
    /// the thing being replaced.
    ///
    /// **This discards the old identity's keys.** It is not asked about, and that
    /// is deliberate: to arrive here a person has just completed an enrolment, on
    /// two screens, into this same network. The alternative is not a safer
    /// choice — it is two memberships, one of them dead, and a question about a
    /// directory they did not know existed.
    async fn settle(&self, provisional: Label, suffix: &str) -> Label {
        let paths = self.home.paths_for(&provisional);
        let arrived = crate::networks::network_of(&paths);
        // What the person had chosen about this network, where one is replaced.
        let mut inherited = Choice::Down;

        // A membership already held in the same network, if there is one. Its own
        // directory is skipped: what is looked for is another.
        let superseded = match arrived {
            Some(network) => self
                .all()
                .await
                .iter()
                .find(|held| held.record.network == network && *held.label() != provisional)
                .map(|held| held.label().clone()),
            None => None,
        };

        let wanted = match &superseded {
            // Its name, because it is the name this device already used for this
            // network and the one a person knows it by.
            Some(taken) => {
                // **Read before anything is taken down**, because taking a network
                // down is itself recorded as a choice. What is being read is the
                // person's, not the membership's: replacing the device in a
                // network is a decision about identity, and it must not quietly
                // become a decision about whether that network carries traffic.
                inherited = Choice::read(&self.home.paths_for(taken).choice());

                // Down before it goes, or its adapter, routes and resolution rule
                // outlive the network they belong to.
                let _down = self.take_down(Some(taken)).await;
                self.networks.lock().await.remove(taken);
                let old = self.home.paths_for(taken);
                if let Err(cause) = std::fs::remove_dir_all(old.root()) {
                    // The membership that just arrived is on the disk and valid;
                    // failing here would disown it over a directory that is merely
                    // still there. Kept under the derived name instead.
                    let _said = cause;
                    self.home.free_label(Some(suffix)).unwrap_or_else(|_| provisional.clone())
                } else {
                    taken.clone()
                }
            }
            None => self.home.free_label(Some(suffix)).unwrap_or_else(|_| provisional.clone()),
        };

        let label = match self.home.rename(&provisional, &wanted) {
            Ok(()) => wanted,
            // A network held under a name nobody would have chosen is still held.
            Err(_kept) => provisional,
        };

        // And carried into the directory that takes its place. Only this: the
        // keys, the roster and the attestation all belong to the membership being
        // replaced, and carrying any of those would be carrying the thing that was
        // replaced rather than what the person asked of the network.
        if crate::lifecycle::resume(inherited) {
            let _written = Choice::Up.write(&self.home.paths_for(&label).choice());
        }
        label
    }

    /// Takes on a network a join has finished delivering.
    ///
    /// Idempotent by construction: it takes the pending out first, so whichever
    /// of the two callers gets there first does the work and the other finds
    /// nothing waiting.
    async fn take_the_network_on(&self) -> Outcome {
        let waiting = self.pending.lock().await.take();
        let Some(Pending::Joining { label, underway, task, for_whom }) = waiting else {
            // Somebody else finished it between the look and the take. Put back
            // whatever was there — it is not this one's to discard.
            if let Some(other) = waiting {
                *self.pending.lock().await = Some(other);
            }
            return Outcome::Reported(self.report().await);
        };
        let crate::joining::Progress::Joined { suffix, devices, relay_confirmed } =
            underway.progress()
        else {
            *self.pending.lock().await = Some(Pending::Joining { label, underway, task, for_whom });
            return Outcome::Failed {
                message: "that join has not finished".to_owned(),
                left_behind: Vec::new(),
            };
        };

        // The network is known now — its id and its suffix — so this is where the
        // directory stops being provisional.
        let label = self.settle(label, &suffix).await;
        let paths = self.home.paths_for(&label);
        // **Whose it is, before it is usable** — as founding does. A joined
        // network with no owner recorded belongs to nobody, and nobody can bring
        // it up: the Linux testbed's first join ended exactly there, `adopted`
        // and then refused to the person who had just joined it.
        if let Err(refusal) = self.record_who_it_is_for(&paths, &for_whom).await {
            return Outcome::Failed { message: refusal, left_behind: Vec::new() };
        }
        if let Err(cause) = self.acquire(label.clone(), paths.clone()).await {
            return Outcome::Failed {
                message: format!("the network arrived but this daemon did not take it on: {cause}"),
                left_behind: Vec::new(),
            };
        }

        let carrying = self.raise_if_chosen(&label).await;

        Outcome::Adopted { suffix, devices, relay_confirmed, carrying }
    }

    /// Raises a network this device has just taken on, where a standing
    /// instruction says it should be up.
    ///
    /// # Why taking a network on is not enough
    ///
    /// `Service::resume` raises what the stored choice says was up, and it runs on
    /// **start**. Nothing does that at runtime. So a replacement that carried the
    /// person's choice across and stopped there would leave the network marked up
    /// and not raised — which is the symptom this came from, reproduced by its own
    /// fix.
    ///
    /// # Why this is not §2.6b being bent
    ///
    /// That rule makes turning a network on a person's own deliberate act. This
    /// network was turned on by a person, and nothing since has been them turning
    /// it off: replacing the device in it is a decision about identity. Refusing
    /// to honour a standing instruction is not restraint.
    ///
    /// A network with nothing to inherit — an ordinary first join — has no stored
    /// choice, so nothing is raised and nothing is asked.
    /// Answers whether that network is carrying traffic when this returns, which
    /// is read off the network and not off the instruction: a raise that failed
    /// is recorded and leaves the tunnel down, and saying otherwise would be
    /// saying what was asked for rather than what happened.
    async fn raise_if_chosen(&self, label: &Label) -> bool {
        let Ok(network) = self.named(label).await else { return false };
        if crate::lifecycle::resume(Choice::read(&network.paths.choice()))
            && let Err(cause) = self.raise(&network).await
        {
            // Recorded where the network's own faults are read, not raised: the
            // membership is on the disk and valid, and a tunnel that would not
            // come up is a thing to show rather than a reason to disown it.
            network
                .node()
                .record(crate::node::Severity::Problem, "tunnel", cause.to_string())
                .await;
        }
        network.tunnel().await == Tunnel::Up
    }

    /// Hands a waiting join the code a person typed, and takes on what arrives.
    async fn finish_joining(
        &self,
        label: Label,
        underway: crate::joining::Underway,
        task: tokio::task::JoinHandle<()>,
        code: &str,
        for_whom: &crate::control::Caller,
    ) -> Outcome {
        let crate::joining::Progress::Confirming { .. } = underway.progress() else {
            *self.pending.lock().await =
                Some(Pending::Joining { label, underway, task, for_whom: for_whom.clone() });
            return Outcome::Failed {
                message: "no code has appeared yet; nobody has come to this device".to_owned(),
                left_behind: Vec::new(),
            };
        };

        // The digits a person typed, and nothing this device worked out for
        // itself. The join compares them with its own code and refuses a
        // mismatch; this only carries them.
        if !underway.confirm(code) {
            return Outcome::Failed {
                message: "the join ended before it could be confirmed".to_owned(),
                left_behind: Vec::new(),
            };
        }

        // The join writes the log; this takes the network on, which is what makes
        // a restart unnecessary.
        //
        // # How long this may wait, and why it is not a round number
        //
        // Derived from the exchange's own deadline rather than chosen. Between a
        // person typing the six digits here and the admission arriving, there is
        // a person at the *other* machine reading and answering — and everything
        // they are asked fits inside one exchange deadline, because the exchange
        // refuses itself after that. Giving up sooner than the exchange does is
        // giving up on something still in flight.
        //
        // That is not theory: this was 60 seconds flat, the admitting side gained
        // a second question to answer, and a real enrolment landed its roster on
        // the joining device **after** this loop had stopped watching. The log was
        // written and the record was not, which is precisely the stranded
        // directory this change exists to clean up — produced, here, by this
        // timeout. Twice the deadline leaves room for a person to read.
        let budget =
            Duration::from_secs(enrollment::limits::EXCHANGE_DEADLINE_SECS.saturating_mul(2));
        let step = Duration::from_millis(100);
        let rounds = budget.as_millis().checked_div(step.as_millis()).unwrap_or(0);
        for _ in 0..rounds {
            // A refused exchange does not end the wait — a person who mistyped
            // tries again — so there is no failure here to wait for. What there
            // is, is somebody standing in front of six digits they just typed,
            // who has to be told now.
            if let Some(refusal) = underway.refusal() {
                *self.pending.lock().await =
                    Some(Pending::Joining { label, underway, task, for_whom: for_whom.clone() });
                return Outcome::refused(refusal);
            }
            match underway.progress() {
                crate::joining::Progress::Joined { .. } => {
                    // Put back what was taken at the top of this function, so the
                    // one place that finishes a join is the one that does it.
                    *self.pending.lock().await = Some(Pending::Joining {
                        label,
                        underway,
                        task,
                        for_whom: for_whom.clone(),
                    });
                    return self.take_the_network_on().await;
                }
                crate::joining::Progress::Failed(why) => return Outcome::refused(why),
                _ => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }

        // Not a failure: the wait is still open, the roster may be seconds away,
        // and whoever asks next finishes it. Saying "it did not work" here is how
        // a person comes to abandon something that was about to succeed.
        *self.pending.lock().await =
            Some(Pending::Joining { label, underway, task, for_whom: for_whom.clone() });
        Outcome::Enrolling
    }

    /// Takes on a network this device has just acquired.
    ///
    /// The step that removes the restart. Founding and joining used to write the
    /// roster from another process, so the running daemon went on using the one
    /// it had read at startup — which was none, which is why it had refused to
    /// start at all. Now the log is re-read and the node assembled here, while
    /// everything else keeps running.
    ///
    /// Nothing is brought up: acquiring a network is not asking for one to be
    /// running, and §2.6c gives the daemon no licence to speak until a person
    /// asks for `up`.
    async fn acquire(&self, label: Label, paths: Paths) -> Result<()> {
        let identity = Arc::new(self.keys.identity(&paths)?);
        let node = Node::from_log(
            identity,
            crate::state::Log::at(paths.roster()),
            crate::state::read_snapshot(&paths),
            crate::state::read_attestation(&paths),
        )?
        .ok_or(Error::NoNetwork)?;

        // Written now that the network exists and its id is known. Before this
        // moment there was nothing to record: at founding the id is the id of the
        // operation being signed, and at joining it arrives with the roster.
        let state = node.state().await.map_err(|cause| Error::Parameters {
            cause: format!("the roster does not describe a network: {cause}"),
        })?;

        // A network this device is already in is not acquired again. It would be
        // a second directory, a second identity and a second membership in one
        // roster — a device asking to be admitted somewhere it already belongs.
        if let Some(held) =
            self.networks.lock().await.values().find(|held| held.record.network == state.network)
        {
            return Err(Error::Parameters {
                cause: format!(
                    "this device is already in that network, as `{}`",
                    held.record.label
                ),
            });
        }

        // The one place both founding and joining pass through. A joined
        // network's suffix arrives with its roster and is nobody's to change, so
        // this is the last moment it can be refused — and refusing to hold it is
        // the only honest answer, because holding both would have one resolver
        // answering for the other's devices.
        for held in self.all().await {
            let Ok(theirs) = held.node().state().await else { continue };
            if crate::rule::overlapping(&state.params.suffix, &theirs.params.suffix) {
                return Err(Error::Parameters {
                    cause: format!(
                        "`{}` overlaps `{}`, which `{}` already answers for on this device",
                        state.params.suffix,
                        theirs.params.suffix,
                        held.label(),
                    ),
                });
            }
        }

        let record = Record { label: label.clone(), network: state.network };
        record.write(&paths)?;

        let network = Network::new(record, paths, node);
        self.networks.lock().await.insert(label, Arc::new(network));
        Ok(())
    }

    /// Creates a network on this device.
    ///
    /// Where a certificate has to be looked at first, this stops and says so; the
    /// signing happens on confirmation. Where there is nothing to look at, it
    /// founds and takes the network on at once.
    async fn found(&self, label: Label, wanted: crate::founding::Founding, fetch: bool) -> Outcome {
        if let Err(refusal) = self.free(&label).await {
            return refusal;
        }
        // Before anything is signed. A network refused after its genesis exists
        // would be one a person holds the keys to and cannot use.
        if let Err(refusal) = self.namespace_free(&wanted.suffix).await {
            return refusal;
        }
        if self.pending.lock().await.is_some() {
            return Outcome::Failed {
                message: "something is already waiting to be confirmed".to_owned(),
                left_behind: Vec::new(),
            };
        }

        if !fetch {
            let for_whom = self.asking.lock().await.clone();
            return self.finish_founding(label, wanted, &for_whom).await;
        }

        // Fetched here because this is the process that will use it, and only
        // after a person asked — which is one of the two things that license the
        // daemon to reach anything.
        let Some(address) = wanted.relay.clone() else {
            return Outcome::Failed {
                message: "fetching a relay certificate needs a relay to fetch it from".to_owned(),
                left_behind: Vec::new(),
            };
        };

        let certificate = match self.fetched_certificate(&address).await {
            Ok(certificate) => certificate,
            Err(refused) => return refused,
        };

        let fingerprint = crate::relay::fingerprint(&certificate);
        let der_len = certificate.len();
        let waiting = crate::founding::Founding { certificate: Some(certificate), ..wanted };
        let for_whom = self.asking.lock().await.clone();
        *self.pending.lock().await = Some(Pending::Founding { label, wanted: waiting, for_whom });

        Outcome::Pinning { fingerprint, der_len, relay: address, moving: None }
    }

    /// Signs the founding and takes the network on.
    async fn finish_founding(
        &self,
        label: Label,
        wanted: crate::founding::Founding,
        for_whom: &crate::control::Caller,
    ) -> Outcome {
        // Before the directory, before the identity, before anything. A person
        // founding on a machine that cannot protect the key must be told so
        // rather than handed a network that looks like every other one.
        if let Some(refusal) = self.keys.admin_refusal() {
            return Outcome::refused(format!(
                "founding a network here would make this device an admin, and {refusal}. \
                 Nothing was created. This device can join a network as a member."
            ));
        }

        let paths = self.home.paths_for(&label);

        // **Here, and not earlier.** Everything that could refuse this founding
        // has refused: the label is free, the suffix does not overlap, the
        // machine can hold a key at all. So a person is only ever shown the key
        // store's prompt for a network that is going to exist — a prompt for a
        // founding that then fails on a typo is a key left in the store and a
        // person taught to click through.
        let asked = self
            .wants_a_key(
                &paths,
                Unfinished::Founding { label: label.clone(), wanted: Box::new(wanted.clone()) },
            )
            .await;
        if let Some(waiting) = asked {
            return waiting;
        }

        let (identity, genesis) =
            match crate::founding::genesis(&paths, &wanted, self.keys.as_ref()) {
                Ok(prepared) => prepared,
                Err(refusal) => {
                    // Nothing was founded, so nothing is left behind to be
                    // reported later as a network that could not be carried.
                    let _discarded = self.home.discard_unfounded(&label);
                    return Outcome::refused(refusal);
                }
            };

        // The key may be somewhere this process cannot reach, and then the
        // founding stops here with a directory and an identity and no network.
        // Everything that could refuse a founding has already refused, so what is
        // being asked for is a signature over something that will be used.
        //
        // One batch: the genesis and the first snapshot, built over a preview of
        // the genesis since neither is signed yet. A person is shown both and
        // asked once, and declining leaves no network rather than one without a
        // snapshot.
        if !identity.signing_key().answers_here() {
            let identity = Arc::new(identity);
            let key = identity.signing_key().public_key();
            let mut requests = vec![identity::detached::prepare_operation(&genesis, &key)];
            if let Some(body) = crate::founding::first_snapshot_body(&genesis, &identity) {
                requests.push(identity::detached::prepare_snapshot(&body, &key));
            }
            let resume = Resume::Founding {
                label: label.clone(),
                genesis: Box::new(genesis),
                identity: Arc::clone(&identity),
                for_whom: for_whom.clone(),
            };
            return self.wants_signatures(requests, &identity, &label, resume).await;
        }

        let bytes = match identity.sign_operation(&genesis) {
            Ok(bytes) => bytes,
            Err(cause) => {
                let _discarded = self.home.discard_unfounded(&label);
                return Outcome::refused(crate::control::declined(&cause));
            }
        };
        if let Err(refusal) = crate::founding::adopt(&paths, &genesis, &bytes, &identity) {
            let _discarded = self.home.discard_unfounded(&label);
            return Outcome::refused(refusal);
        }
        if let Err(refusal) = self.record_who_it_is_for(&paths, for_whom).await {
            let _discarded = self.home.discard_unfounded(&label);
            return Outcome::refused(refusal);
        }
        self.carry_the_founded(label, paths).await
    }

    /// Writes down who the network under `paths` is for.
    ///
    /// Called where a network comes into being, before it is usable. A network
    /// that exists and says nothing about whose it is, is a network a daemon
    /// would have to give to whoever asked.
    async fn record_who_it_is_for(
        &self,
        paths: &Paths,
        for_whom: &crate::control::Caller,
    ) -> core::result::Result<(), String> {
        match for_whom {
            // Nobody to record. The platform draws no distinction, so there is
            // no second person for this to protect the network from.
            crate::control::Caller::Unattributed => Ok(()),
            crate::control::Caller::Identified { name, .. } => {
                crate::state::write_owner(paths, name)
                    .map_err(|cause| format!("the network could not be recorded as yours: {cause}"))
            }
        }
    }

    /// Takes a network this daemon has just founded, and reports.
    ///
    /// Reached by both paths, because by the time the log holds a genesis it no
    /// longer matters which of them signed it.
    async fn carry_the_founded(&self, label: Label, paths: Paths) -> Outcome {
        if let Err(cause) = self.acquire(label, paths).await {
            return Outcome::Failed {
                message: format!(
                    "the network was founded but this daemon did not take it on: {cause}"
                ),
                left_behind: Vec::new(),
            };
        }
        Outcome::Reported(self.report().await)
    }

    /// Signs the admission a person has confirmed, and delivers the network.
    /// Revokes the device whose name an admission is about to take over.
    ///
    /// Signed and admitted **before** the admission, so that a person who
    /// answered "replace it" gets both halves of what they asked for or neither.
    /// A failure here stops the admission: admitting without revoking would leave
    /// two devices answering to one name, which is the thing being replaced.
    ///
    /// The revocation is definitive, as every revocation is. Whoever is asked has
    /// been shown the identifier it falls on and told it cannot be undone, because
    /// the decision is being taken on the strength of a name and a name is not an
    /// identity.
    async fn expel_for_replacement(
        &self,
        network: &Arc<Network>,
        taken: &crate::admitting::Taken,
    ) -> core::result::Result<(), Outcome> {
        let node = network.node();
        let Ok(state) = node.state().await else {
            return Err(Outcome::Failed {
                message: "this device holds no network".to_owned(),
                left_behind: Vec::new(),
            });
        };
        let expulsion = expulsion_of(taken);
        let heads = node.heads().await;

        // Reached only where the key signs here. Where it is out of reach, the
        // revocation and the admission are one batch; see `admitting_batch`.
        let identity = node.identity();
        let signed = match crate::revoking::sign(&expulsion, identity, &state, heads) {
            Ok(signed) => signed,
            Err(cause) => {
                return Err(Outcome::refused(format!(
                    "the device holding that name could not be revoked, so nothing was admitted: {cause}"
                )));
            }
        };
        if let Err(cause) = self.admit_to(network, &signed).await {
            return Err(Outcome::Failed {
                message: format!(
                    "the device holding that name was revoked, and the network would not come up to carry it: {cause}"
                ),
                left_behind: Vec::new(),
            });
        }
        Ok(())
    }

    async fn finish_admitting(
        &self,
        label: Label,
        pending: crate::admitting::Pending,
        keeping_the_name: bool,
    ) -> Outcome {
        // Put back where it was. An admission may now stop in the middle — twice,
        // when it is also a replacement — and across those pauses the exchange has
        // to be somewhere a person abandoning it can still reach, which is here.
        *self.pending.lock().await = Some(Pending::Admitting { label: label.clone(), pending });
        self.admitting_step(label, keeping_the_name).await
    }

    /// Carries an admission as far as it can go before it needs a signature.
    async fn admitting_step(&self, label: Label, keeping_the_name: bool) -> Outcome {
        let network = match self.named(&label).await {
            Ok(network) => network,
            Err(cause) => {
                self.abandon_admission().await;
                return Outcome::Failed { message: cause.to_string(), left_behind: Vec::new() };
            }
        };
        let node = Arc::clone(network.node());
        let paths = network.paths.clone();

        // Where the key is out of reach, the whole admission — the revocation
        // too, when there is one — is prepared as one batch and signed at once.
        if !node.identity().signing_key().answers_here() {
            return self.admitting_batch(label, &network, keeping_the_name).await;
        }

        // The device whose name is being taken over, revoked **first**, and
        // everything the admission is built from read **after**.
        //
        // # Why the order is the whole of it
        //
        // Two operations signed against the same heads are concurrent: neither is
        // an ancestor of the other, and one author holding two branches is what
        // equivocation *is*. The roster then voids what that author signed —
        // `state::judge_one` exempts revocations and nothing else — so a
        // replacement built this way splits in the worst possible direction: the
        // revocation stands and the admission does not. The device holding the
        // name is expelled and the device meant to take it never becomes a
        // member, on a log that cannot be unsaid.
        //
        // That is not a hypothetical. It was built this way, run between a
        // desktop and a phone, and the desktop accused itself of equivocation
        // over exactly these two operations. So the admission is signed on top of
        // the revocation, and everything it is built from — the heads it names as
        // parents, the state it is checked against, and the log the joining
        // device is given — is read once the revocation is in.
        //
        // When the key is out of reach the two are still in that order, as one
        // batch: see `admitting_batch`.
        if keeping_the_name {
            let taken = {
                let held = self.pending.lock().await;
                match held.as_ref() {
                    Some(Pending::Admitting { pending, .. }) => pending.taken().cloned(),
                    _ => None,
                }
            };
            if let Some(taken) = taken
                && let Err(refusal) = self.expel_for_replacement(&network, &taken).await
            {
                self.abandon_admission().await;
                return refusal;
            }
        }

        if let Some(refusal) = self.keys.admin_refusal() {
            self.abandon_admission().await;
            return Outcome::refused(format!(
                "admitting a device is an admin's act, and {refusal}. Nothing was signed."
            ));
        }

        let Ok(state) = node.state().await else {
            self.abandon_admission().await;
            return Outcome::Failed {
                message: "this device holds no network".to_owned(),
                left_behind: Vec::new(),
            };
        };
        let heads = node.heads().await;

        let mut held = self.pending.lock().await;
        let Some(Pending::Admitting { pending, .. }) = held.as_mut() else {
            drop(held);
            return Outcome::refused("nothing is waiting to be admitted".to_owned());
        };

        let prepared =
            crate::admitting::core(pending, node.identity(), &state, heads, keeping_the_name).await;
        drop(held);

        let (operation, spec_name) = match prepared {
            Ok(prepared) => prepared,
            Err(refusal) => {
                self.abandon_admission().await;
                return Outcome::refused(refusal);
            }
        };

        let identity = node.identity();
        let signed = match identity.sign_operation(&operation) {
            Ok(signed) => signed,
            Err(cause) => {
                self.abandon_admission().await;
                return Outcome::refused(crate::control::declined(&cause));
            }
        };

        let Some(Pending::Admitting { pending, .. }) = self.pending.lock().await.take() else {
            return Outcome::refused("nothing is waiting to be admitted".to_owned());
        };
        let _ = paths;
        self.deliver_admission(&network, pending, signed, spec_name).await
    }

    /// Prepares an admission as one batch, where the key is out of reach.
    ///
    /// The revocation of the device holding the name, when it is a replacement;
    /// the admission, built on top of it; and the snapshot the network will then
    /// be owed. None is signed, so the admission is built against a **preview**
    /// of the roster once the revocation is in — the same state `admitting_step`
    /// reads, with the same checks, the IPv4 collision among them — and names the
    /// revocation as its parent, which is the order the replacement comment above
    /// is about.
    async fn admitting_batch(
        &self,
        label: Label,
        network: &Arc<Network>,
        keeping_the_name: bool,
    ) -> Outcome {
        if let Some(refusal) = self.keys.admin_refusal() {
            self.abandon_admission().await;
            return Outcome::refused(format!(
                "admitting a device is an admin's act, and {refusal}. Nothing was signed."
            ));
        }
        let node = network.node();
        let identity = node.identity();
        let Ok(state) = node.state().await else {
            self.abandon_admission().await;
            return Outcome::Failed {
                message: "this device holds no network".to_owned(),
                left_behind: Vec::new(),
            };
        };
        let prepared_against = node.moment().await;

        let taken = if keeping_the_name {
            let held = self.pending.lock().await;
            match held.as_ref() {
                Some(Pending::Admitting { pending, .. }) => pending.taken().cloned(),
                _ => None,
            }
        } else {
            None
        };

        let mut cores = Vec::new();
        let (state, heads) = match taken {
            None => (state, prepared_against.heads.clone()),
            Some(taken) => {
                let expulsion = expulsion_of(&taken);
                let revocation = match crate::revoking::core(
                    &expulsion,
                    identity,
                    &state,
                    prepared_against.heads.clone(),
                ) {
                    Ok(core) => core,
                    Err(refusal) => {
                        self.abandon_admission().await;
                        return Outcome::refused(refusal);
                    }
                };
                let after = match node.preview(core::slice::from_ref(&revocation)).await {
                    Ok(after) => after,
                    Err(cause) => {
                        self.abandon_admission().await;
                        return Outcome::refused(format!(
                            "the device holding that name could not be revoked, so nothing was \
                             admitted: {cause}"
                        ));
                    }
                };
                cores.push(revocation);
                (after.state, after.heads)
            }
        };

        let prepared = {
            let mut held = self.pending.lock().await;
            let Some(Pending::Admitting { pending, .. }) = held.as_mut() else {
                drop(held);
                return Outcome::refused("nothing is waiting to be admitted".to_owned());
            };
            crate::admitting::core(pending, identity, &state, heads, keeping_the_name).await
        };
        let (admission, spec_name) = match prepared {
            Ok(prepared) => prepared,
            Err(refusal) => {
                self.abandon_admission().await;
                return Outcome::refused(refusal);
            }
        };
        let replacing = !cores.is_empty();
        cores.push(admission);

        let requests = Self::with_owed_snapshot(node, &cores).await;
        let resume =
            Resume::Admitting { label: label.clone(), replacing, spec_name, prepared_against };
        self.wants_signatures(requests, identity, &label, resume).await
    }

    /// Hands a signed admission to the device waiting for it, and records it here.
    ///
    /// Reached by both paths, because by the time the bytes exist it no longer
    /// matters which of them signed them.
    async fn deliver_admission(
        &self,
        network: &Arc<Network>,
        pending: crate::admitting::Pending,
        signed: Vec<u8>,
        spec_name: String,
    ) -> Outcome {
        let paths = network.paths.clone();
        let log = match crate::state::Log::at(paths.roster()).read() {
            Ok(held) => held,
            Err(cause) => {
                crate::admitting::abandon(pending).await;
                return Outcome::Failed {
                    message: format!("the roster could not be read: {cause}"),
                    left_behind: Vec::new(),
                };
            }
        };

        // What this device holds, if anything. An admin with none sends none,
        // and the joiner is told so by its absence rather than by a field that
        // says nothing.
        let snapshot = crate::state::read_snapshot(&paths).map(|(bytes, _at)| bytes);

        match crate::admitting::finish_with(pending, signed, spec_name, &log, snapshot).await {
            Ok((operation, said)) => {
                // Recorded here as well as delivered. The daemon holds the
                // roster it is running on, so an admission that reached the
                // other device and not this one would leave a member this node
                // refuses to talk to.
                // Into the network this admission was opened for. Recording it into
                // "the only network" failed on every device holding more than one,
                // after the other device had already been given the network — found
                // admitting a phone from a desktop holding three.
                if let Err(cause) = self.admit_to(network, &operation).await {
                    return Outcome::Failed {
                        message: format!(
                            "the device was admitted but this node did not record \
                                          it: {cause}"
                        ),
                        left_behind: Vec::new(),
                    };
                }
                Outcome::Reported(self.report().await.with_note(&said))
            }
            Err(refusal) => Outcome::refused(refusal),
        }
    }

    /// Ends the admission that is waiting, closing the endpoint it opened.
    ///
    /// §2.6c gives the daemon no licence to stay registered at a relay for an
    /// enrolment nobody is coming back to, so an admission that will not finish
    /// is closed rather than left to time out.
    async fn abandon_admission(&self) {
        let waiting = self.pending.lock().await.take();
        if let Some(Pending::Admitting { pending, .. }) = waiting {
            crate::admitting::abandon(pending).await;
        }
    }

    /// Asks for the signature a join is waiting on, once.
    ///
    /// The command line polls, so this is reached every half second for as long
    /// as somebody is at a prompt. Issuing a request each time would leave a
    /// trail of them and hand out an id a moment before handing out another. So
    /// the id is remembered against the request it belongs to, and the same one
    /// goes back until it is answered.
    /// The name the key store knows a joining device's signing key by.
    ///
    /// **Named, or the proof cannot be made.** A key held elsewhere is reached
    /// by its name, and the command line asked to prove possession with none had
    /// nothing to sign with — a join from the command line of a machine whose key
    /// is held elsewhere could not finish. Read from the identity the join wrote,
    /// which is the one the challenge was prepared with. Empty where the key is
    /// held here, which signs without being asked.
    fn joining_key(&self, label: &Label) -> String {
        self.keys
            .identity(&self.home.paths_for(label))
            .ok()
            .and_then(|identity| {
                identity.signing_key().custodian().map(|held| held.reference().to_owned())
            })
            .unwrap_or_default()
    }

    async fn wants_proving(
        &self,
        request: &identity::detached::SigningRequest,
        key: &str,
    ) -> Outcome {
        let mut asked = self.proving.lock().await;
        let id = match asked.as_ref() {
            Some((id, message)) if message == request.message() => id.clone(),
            _ => {
                let by = self.asking.lock().await.clone();
                let id = self.unsigned.lock().await.issue_for(
                    vec![request.clone()],
                    Resume::Possession,
                    crate::clock::now_ms(),
                    by,
                );
                *asked = Some((id.clone(), request.message().to_vec()));
                id
            }
        };
        drop(asked);

        Outcome::NeedsSignatures(crate::control::SignaturesWanted {
            id,
            key: key.to_owned(),
            // The network being joined has no name here yet; see `wants_a_key`.
            network: String::new(),
            // A batch of one, and never anything beside it. A proof of possession
            // has no artifact but its signature, and is not an administrative act
            // a person authorises separately.
            items: vec![crate::control::ToSign {
                kind: request.kind().into(),
                message: request.message().to_vec(),
                payload: Vec::new(),
            }],
        })
    }

    /// Turns a result into something to send back.
    ///
    /// A failure carries what is still on the machine, because after a failed
    /// bring-up the useful question is not why it happened but what the machine
    /// looks like now.
    fn said(outcome: Result<()>) -> Outcome {
        match outcome {
            Ok(()) => Outcome::Done,
            Err(failure) => Outcome::Failed {
                message: failure.to_string(),
                left_behind: failure
                    .left_behind()
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod tests {
    use identity::NodeIdentity;
    use roster::id::NetworkId;
    use roster::roster::Roster;
    use roster::sign::sign_operation;
    use roster::types::{NetworkParams, OperationBody, OperationCore, Role};
    use roster_sync::Syncer;
    use tunnel::Tunnel as Rules;

    use super::*;
    use crate::connectivity::testing::InProcess;
    use crate::gateway::Gateway;
    use crate::machine::Machine;
    use crate::machine::testing::{Fail, Recording};
    use crate::resolving::testing::Recording as Names;
    use crate::router::Router;
    use crate::schedule::Schedule;
    use crate::state::Log;

    /// The label every single-network test keeps its network under.
    fn only_label() -> Label {
        Label::new("test").expect("a usable label")
    }

    /// One network, wrapped as the service holds it.
    fn one_network(node: Arc<Node>, paths: Paths) -> Vec<Network> {
        let network = roster::id::NetworkId::from_bytes([0; 32]);
        vec![Network::new(Record { label: only_label(), network }, paths, node)]
    }

    /// A service holding at most one network, as a device with one sees it.
    ///
    /// Most of what is tested here predates a device being able to hold more than
    /// one, and reads the same either way: a command that names no network acts
    /// on the only one there is.
    fn service_over(
        home: Home,
        node: Option<Arc<Node>>,
        paths: Paths,
        machine: &Arc<Recording>,
        connectivity: &Arc<InProcess>,
        names: &Arc<Names>,
    ) -> Service {
        let networks = node
            .map(|node| {
                let network = roster::id::NetworkId::from_bytes([0; 32]);
                Network::new(Record { label: only_label(), network }, paths, node)
            })
            .into_iter()
            .collect();

        Service::holding(
            home,
            networks,
            Lifecycle::new(Arc::clone(machine) as Arc<dyn Machine>),
            Arc::clone(connectivity) as Arc<dyn Connectivity>,
            Arc::clone(names) as Arc<dyn Resolving>,
        )
    }

    /// A second service over the same state directory, standing in for a restart.
    async fn restart(fixture: &Fixture) -> Service {
        service_over(
            Home::under(fixture._scratch.path()),
            fixture.service.node().await,
            Paths::under(fixture._scratch.path()),
            &fixture.machine,
            &fixture.connectivity,
            &fixture.names,
        )
    }

    /// The same, against heads the caller chooses — for showing what signing two
    /// operations on one set of heads does.
    async fn add_a_device_on(
        service: &Service,
        founder: &Arc<NodeIdentity>,
        heads: Vec<roster::id::OperationId>,
    ) -> Vec<u8> {
        use roster::sign::sign_operation;
        use roster::types::{OperationBody, OperationCore};

        let state = service
            .node()
            .await
            .expect("the fixture holds a network")
            .state()
            .await
            .expect("derives");
        let joiner = NodeIdentity::generate().expect("generates");
        let core = OperationCore::new(
            3,
            founder.signing_key().algorithm(),
            OperationBody::AddDevice(
                joiner.device_spec("phone", Role::Member, false, vec![]).expect("spec"),
            ),
            heads,
            founder.signing_key().key_id(),
            state.network,
        )
        .expect("well-formed");
        sign_operation(&core, founder.signer()).expect("signs")
    }

    /// A signed operation adding a fresh device, authored by the founder.
    async fn add_a_device(service: &Service, founder: &Arc<NodeIdentity>) -> Vec<u8> {
        use roster::sign::sign_operation;
        use roster::types::{OperationBody, OperationCore};

        let state = service
            .node()
            .await
            .expect("the fixture holds a network")
            .state()
            .await
            .expect("derives");
        let joiner = NodeIdentity::generate().expect("generates");

        let core = OperationCore::new(
            2,
            founder.signing_key().algorithm(),
            OperationBody::AddDevice(
                joiner.device_spec("laptop", Role::Member, false, vec![]).expect("spec"),
            ),
            service.node().await.expect("the fixture holds a network").heads().await,
            founder.signing_key().key_id(),
            state.network,
        )
        .expect("well-formed");

        sign_operation(&core, founder.signer()).expect("signs")
    }

    struct Fixture {
        service: Service,
        machine: Arc<Recording>,
        connectivity: Arc<InProcess>,
        names: Arc<Names>,
        _scratch: tempfile::TempDir,
    }

    /// A name the roster does not hold signs nothing.
    ///
    /// The log is append-only: a revocation aimed at a typo cannot be withdrawn,
    /// only followed by admitting the device again under a new identity.
    #[tokio::test]
    async fn revoking_a_name_nobody_holds_signs_nothing() {
        let fixture = fixture(None).await;
        let before =
            fixture.service.node().await.expect("the fixture holds a network").outstanding().await;

        let outcome = fixture
            .service
            .handle(Command::Revoke {
                network: None,
                target: crate::control::Target::Name("nowhere".to_owned()),
                reason: "a reason".to_owned(),
            })
            .await;

        match outcome {
            Outcome::Failed { message, .. } => {
                assert!(
                    message.contains("nowhere"),
                    "the refusal must name what was asked: {message}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(
            fixture.service.node().await.expect("the fixture holds a network").outstanding().await,
            before,
            "nothing was signed"
        );
    }

    /// Revoking this device would expel the machine from a network it would go
    /// on holding a roster for. The roster would accept it; this does not.
    #[tokio::test]
    async fn revoking_this_device_is_refused() {
        let fixture = fixture(None).await;

        let outcome = fixture
            .service
            .handle(Command::Revoke {
                network: None,
                target: crate::control::Target::Name("founder".to_owned()),
                reason: "a reason".to_owned(),
            })
            .await;

        match outcome {
            Outcome::Failed { message, .. } => {
                assert!(message.contains("this device"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// A revocation carries a reason because somebody reads it later.
    #[tokio::test]
    async fn revoking_without_a_reason_is_refused() {
        let fixture = fixture(None).await;

        let outcome = fixture
            .service
            .handle(Command::Revoke {
                network: None,
                target: crate::control::Target::Name("founder".to_owned()),
                reason: "  ".to_owned(),
            })
            .await;

        match outcome {
            Outcome::Failed { message, .. } => {
                assert!(message.contains("needs a reason"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// The recurring reconciliation has a caller.
    ///
    /// `Node::offer_to_everyone` was written for the case the schedule describes
    /// — two devices connected for hours that need to notice a revocation made
    /// elsewhere — and had no caller for as long as it existed. It is `pub` in a
    /// library crate, so no dead-code warning fires on an uncalled one, and the
    /// behaviour it was missing has no symptom until a push happens to fail.
    ///
    /// A test that a function is *used* is a poor test in general. It earns its
    /// place here because the failure it guards is silent on both sides: nothing
    /// warns, and nothing observable changes until the day it matters.
    #[test]
    fn the_recurring_reconciliation_is_actually_run() {
        let daemon = crate::code_of(include_str!("service.rs"));
        assert!(
            daemon.contains("offer_to_everyone"),
            "reconciliation must repeat on an open session, not only when one is established"
        );
        assert!(
            daemon.contains(".press().await"),
            "and what is outstanding must be pressed rather than waiting on the idle tick"
        );
    }

    /// A service on a device that has never been founded or joined.
    ///
    /// The state this whole change exists for: an identity, an empty log, and no
    /// network. The daemon used to refuse to exist in it.
    async fn unjoined() -> (Service, Arc<Recording>, tempfile::TempDir) {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());
        paths.create().expect("creates");

        let identity = Arc::new(crate::state::identity_of(&paths).expect("an identity"));
        let node = Node::from_log(identity, crate::state::Log::at(paths.roster()), None, None)
            .expect("an empty log is readable");
        assert!(node.is_none(), "an empty log describes no network");

        let machine = Arc::new(Recording::new());
        let service = Service::holding(
            Home::under(scratch.path()),
            node.map(|node| one_network(node, paths)).unwrap_or_default(),
            Lifecycle::new(Arc::clone(&machine) as Arc<dyn Machine>),
            Arc::new(InProcess::new()) as Arc<dyn Connectivity>,
            Arc::new(Names::new()) as Arc<dyn Resolving>,
        );
        (service, machine, scratch)
    }

    /// The daemon runs on a device with no network, and answers.
    #[tokio::test]
    async fn a_service_with_no_network_answers() {
        let (service, _machine, _scratch) = unjoined().await;

        assert!(!service.has_network().await);
        assert!(service.node().await.is_none());

        // It answers rather than failing: a report is a report even when what it
        // reports is that there is nothing yet.
        let report = service.report().await;
        assert!(!report.holds_a_network(), "a device with no network holds none");
        assert!(report.networks.is_empty(), "so there is no network to describe");
        assert!(report.note.is_some(), "and the report says so, with what to do next");
    }

    /// Bringing the tunnel up without a network is refused, and the machine is
    /// left untouched.
    ///
    /// There is nothing to install: the address, the prefix and the suffix all
    /// come from signed parameters that do not exist yet. The refusal happens
    /// before the first call to the machine, so there is nothing to undo either —
    /// which is the difference between a refusal and a failed bring-up.
    #[tokio::test]
    async fn bringing_up_without_a_network_is_refused_and_installs_nothing() {
        let (service, machine, _scratch) = unjoined().await;

        let refusal = service.bring_up(None).await.expect_err("there is no network to bring up");
        assert!(
            matches!(refusal, Error::NoNetwork),
            "the refusal must name the absence, not a failed step: {refusal:?}"
        );
        assert!(
            refusal.to_string().contains("peerfectly found"),
            "and say what a person does next: {refusal}"
        );

        let installed = machine.installed();
        assert!(installed.adapters.is_empty(), "no adapter");
        assert!(installed.addresses.is_empty(), "no address");
        assert!(installed.routes.is_empty(), "no route");
        assert!(installed.rules.is_empty(), "no resolution rule");

        assert_eq!(service.tunnel().await, Tunnel::Down);
    }

    /// Taking down a daemon that never had a network is not an error.
    ///
    /// `take_down` is what shutdown runs. A daemon that refused to stop because
    /// it had never joined would be a daemon that cannot be stopped cleanly.
    #[tokio::test]
    async fn taking_down_a_daemon_with_no_network_succeeds() {
        let (service, machine, _scratch) = unjoined().await;

        service.take_down(None).await.expect("stopping must always be possible");
        assert!(machine.installed().routes.is_empty());
    }

    /// The report says which of the two look-alike states this is, and what to
    /// do about it.
    ///
    /// A device with no network and a network that is down both show no address
    /// and no peers. The remedies are opposites, so telling them apart is the
    /// whole value of the line.
    #[tokio::test]
    async fn a_report_with_no_network_says_so_and_names_what_to_do() {
        let (unjoined, _machine, _scratch) = unjoined().await;
        let joined = fixture(None).await;

        let without = unjoined.report().await;
        let with = joined.service.report().await;

        assert!(!without.holds_a_network());
        assert!(with.holds_a_network());
        assert_ne!(without.to_string(), with.to_string());

        let said = without.to_string();
        assert!(said.contains("no network"), "it must name the state: {said}");
        assert!(
            said.contains("peerfectly found") && said.contains("peerfectly join"),
            "and name both ways out of it: {said}"
        );

        // Nothing below the note is true of a device with no network, so none of
        // it is printed. "relay: none — direct paths only" would describe a
        // network that does not exist.
        assert!(!said.contains("relay"), "no relay line: {said}");
        assert!(!said.contains("meet"), "no rendezvous line: {said}");

        // And the two are not merely worded differently: the one that has a
        // network still reports the things a network has.
        assert!(with.to_string().contains("infrastructure"));
    }

    /// A daemon with no network holds no transport, so there is nothing that
    /// could speak even by mistake.
    #[tokio::test]
    async fn a_daemon_with_no_network_holds_no_transport() {
        let (service, _machine, _scratch) = unjoined().await;

        assert!(service.node().await.is_none(), "no node, so no transport to hold");
        assert_eq!(service.tunnel().await, Tunnel::Down);

        // Asking for a report is the most a person does before founding or
        // joining, and it must not be a reason to speak.
        let _report = service.report().await;
        assert!(service.node().await.is_none());
    }

    /// A network founded through a running daemon is usable at once.
    ///
    /// **This is the restart, removed.** Founding used to happen in the process
    /// that typed the command, appending to a log the running daemon could not
    /// see — so it had to be stopped and started again. Here nothing is stopped:
    /// the daemon holds no network, is asked to found one, and brings the tunnel
    /// up without anything being restarted.
    #[tokio::test]
    async fn founding_through_a_running_daemon_needs_no_restart() {
        let (service, machine, _scratch) = unjoined().await;
        assert!(!service.has_network().await, "nothing to begin with");

        let outcome = service
            .handle(Command::Found {
                label: "test".to_owned(),
                name: "nas".to_owned(),
                suffix: "example.internal".to_owned(),
                relay: None,
                rendezvous: None,
                certificate: crate::control::Certificate::None,
                ipv4_range: None,
            })
            .await;

        match outcome {
            Outcome::Reported(report) => {
                assert!(report.holds_a_network(), "the daemon holds the network it just founded");
            }
            other => panic!("expected a report, got {other:?}"),
        }

        assert!(service.has_network().await, "and holds it without being restarted");

        // Founding is not asking for the network to be running: §2.6c gives no
        // licence to speak until a person asks for `up`.
        assert_eq!(service.tunnel().await, Tunnel::Down);
        assert!(machine.installed().adapters.is_empty(), "founding installs nothing");

        service.bring_up(None).await.expect("and the tunnel comes up, with no restart");
        assert!(!machine.installed().adapters.is_empty());
    }

    /// Founding twice is refused, through the new path as through the old.
    #[tokio::test]
    async fn founding_when_a_network_is_already_held_is_refused() {
        let fixture = fixture(None).await;

        let outcome = fixture
            .service
            .handle(Command::Found {
                label: "test".to_owned(),
                name: "second".to_owned(),
                suffix: "example.internal".to_owned(),
                relay: None,
                rendezvous: None,
                certificate: crate::control::Certificate::None,
                ipv4_range: None,
            })
            .await;

        match outcome {
            Outcome::Failed { message, .. } => {
                assert!(message.contains("already holds a network"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// A fetched certificate is shown before it is pinned, and nothing is signed
    /// until a person has confirmed it.
    ///
    /// Nothing has vouched for what the relay presents — anyone in the path could
    /// have answered — so the fingerprint goes to a person first. Against a real
    /// TLS server, because a fetch that returned anything other than the bytes
    /// presented would pin a certificate nobody has.
    #[tokio::test]
    async fn a_fetched_certificate_is_confirmed_before_anything_is_signed() {
        let issued = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
            .expect("a certificate");
        let presented = issued.cert.der().to_vec();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(issued.signing_key.serialize_der());

        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocols supported by ring")
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(presented.clone())],
            key.into(),
        )
        .expect("a usable key pair");

        let listener =
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("binds");
        let port = listener.local_addr().expect("bound").port();
        std::thread::spawn(move || {
            let Ok((mut socket, _)) = listener.accept() else {
                return;
            };
            let Ok(mut server) = rustls::ServerConnection::new(Arc::new(config)) else {
                return;
            };
            let _ = server.complete_io(&mut socket);
        });

        let (service, _machine, _scratch) = unjoined().await;
        let found = Command::Found {
            label: "test".to_owned(),
            name: "nas".to_owned(),
            suffix: "example.internal".to_owned(),
            relay: Some(format!("https://127.0.0.1:{port}")),
            rendezvous: None,
            certificate: crate::control::Certificate::FromTheRelay,
            ipv4_range: None,
        };

        let outcome = service.handle(found).await;

        match outcome {
            Outcome::Pinning { fingerprint, der_len, relay, .. } => {
                assert_eq!(fingerprint, crate::relay::fingerprint(&presented));
                assert_eq!(der_len, presented.len());
                assert!(relay.contains(&port.to_string()));
            }
            other => panic!("expected a certificate to confirm, got {other:?}"),
        }

        // The whole point: it is waiting, not done.
        assert!(
            !service.has_network().await,
            "nothing may be signed before a person has compared the fingerprint"
        );

        match service.handle(Command::Confirm).await {
            Outcome::Reported(report) => assert!(report.holds_a_network()),
            other => panic!("expected the founding to complete, got {other:?}"),
        }
        assert!(service.has_network().await, "and only then does the network exist");
    }

    /// A join that is abandoned closes what it opened and leaves nothing.
    ///
    /// The endpoint a join opens is one of the only two things that license this
    /// daemon to reach anything. A join nobody comes back to would otherwise
    /// leave the device registered at a relay with the tunnel down, which is a
    /// §2.6c breach that nothing in the report would show.
    #[tokio::test]
    async fn abandoning_a_join_leaves_no_roster_and_no_enrolment() {
        let (service, _machine, scratch) = unjoined().await;

        // A relay nobody is listening on: the join gets no further than trying,
        // which is all this needs — what is asserted is what abandoning leaves.
        let outcome = service
            .handle(Command::Join {
                relay: "https://127.0.0.1:1".to_owned(),
                name: "laptop".to_owned(),
            })
            .await;
        assert!(
            matches!(outcome, Outcome::Failed { .. } | Outcome::Joining { .. }),
            "either it is waiting or it could not start; both are fine here"
        );

        service.handle(Command::Abandon).await;

        assert!(service.pending.lock().await.is_none(), "nothing is left waiting");
        assert!(!service.has_network().await, "and no network was adopted");

        let log = crate::state::Log::at(Paths::under(scratch.path()).roster());
        assert!(log.read().expect("readable").is_empty(), "the roster is still empty");
    }

    /// A directory this device cannot carry and cannot recover either.
    ///
    /// It has a **record**, so recovery does not touch it — the note of which
    /// network it is was never lost. What it has is a roster this build will not
    /// load, which is what is left once the recoverable cases are recovered.
    fn unreadable_network(home: &Home) -> (Label, Paths) {
        let label = Label::new("rotta").expect("a label");
        let paths = home.paths_for(&label);
        paths.create().expect("creates");
        // A real identity, so that what fails is the roster and not the key. The
        // two are different troubles and the whole point is telling them apart.
        let _made =
            crate::keys::Keys::identity(&crate::keys::PlatformKeys, &paths).expect("an identity");
        std::fs::write(paths.roster(), b"not a log at all").expect("writes");
        Record { label: label.clone(), network: roster::id::NetworkId::from_bytes([7; 32]) }
            .write(&paths)
            .expect("the record is written");
        (label, paths)
    }

    /// The opposite trouble: a key that will not open, beside a roster that is
    /// perfectly good.
    fn unopenable_identity(home: &Home) -> (Label, Paths) {
        let label = Label::new("chiusa").expect("a label");
        let paths = home.paths_for(&label);
        paths.create().expect("creates");
        // A roster that reads and derives, written by a real founding.
        let source = Paths::under(paths.root().join("source"));
        crate::founding::found_with(
            &source,
            &crate::founding::Founding {
                name: "nas".to_owned(),
                suffix: "casa.internal".to_owned(),
                relay: None,
                rendezvous: None,
                certificate: None,
                ipv4_range: None,
            },
            &crate::keys::PlatformKeys,
        )
        .expect("founds");
        std::fs::copy(source.roster(), paths.roster()).expect("a roster that reads");
        std::fs::remove_dir_all(source.root()).expect("tidies up");
        // And an identity that is not one.
        std::fs::write(paths.identity(), b"not an identity").expect("writes");
        Record { label: label.clone(), network: roster::id::NetworkId::from_bytes([9; 32]) }
            .write(&paths)
            .expect("the record is written");
        (label, paths)
    }

    /// What a person is given about a network that cannot be carried is about
    /// their network, never about a file they cannot reach.
    ///
    /// It arrived on a phone as
    /// `/data/user/0/org.nohostalgia.peerfectly/files/peerfectly/networks/studio/network.json: No such
    /// file or directory (os error 2)`, which names a path inside the app's
    /// private storage and a system error number. A person can do nothing with
    /// either, and it reads as a fault in the product.
    #[tokio::test]
    async fn an_unusable_network_is_explained_without_a_path_or_an_errno() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");

        let (_label, _paths) = unreadable_network(&home);

        let service = Service::over(
            home,
            Lifecycle::new(Arc::new(Recording::new()) as Arc<dyn Machine>),
            Arc::new(InProcess::new()) as Arc<dyn Connectivity>,
            Arc::new(Names::new()) as Arc<dyn Resolving>,
        )
        .expect("assembles");

        let broken = service.broken().await;
        let held = broken.first().expect("one unusable network");

        // The part that actually failed, named as itself. Worked out from which
        // files are present instead, this directory and one whose identity will
        // not open cannot be told apart — both have every file — and the first
        // real failure was the second kind, reported as the first.
        assert_eq!(crate::control::Trouble::RosterRefused, held.cause);

        // What a person reads carries no path and no error number; the daemon's
        // own account of it is kept beside, where it is useful.
        let said = held.cause.to_string();
        assert!(!said.contains('/') && !said.contains('\\'), "no path: {said}");
        assert!(!said.contains("os error"), "and no error number: {said}");
        assert!(!held.detail.is_empty(), "and the daemon's own words are not thrown away");
    }

    /// An identity that will not open is not a roster that will not load.
    ///
    /// They leave every file exactly where it was, so nothing about the
    /// directory tells them apart — and the first real failure was a phone whose
    /// keystore would not open an identity while the roster beside it read and
    /// derived without complaint. It was reported as the network's history being
    /// damaged, which is a false alarm about the one thing a person cannot
    /// replace.
    #[tokio::test]
    async fn an_identity_that_will_not_open_is_not_blamed_on_the_roster() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");
        let (_label, _paths) = unopenable_identity(&home);

        let service = Service::over(
            home,
            Lifecycle::new(Arc::new(Recording::new()) as Arc<dyn Machine>),
            Arc::new(InProcess::new()) as Arc<dyn Connectivity>,
            Arc::new(Names::new()) as Arc<dyn Resolving>,
        )
        .expect("assembles");

        let broken = service.broken().await;
        let held = broken.first().expect("one unusable network");
        assert_eq!(
            crate::control::Trouble::IdentityWillNotOpen,
            held.cause,
            "the key is what failed; the roster beside it is intact"
        );
        assert!(held.cause.rejoining_fixes_it(), "and joining again is what fixes it");
    }

    /// Forgetting removes the directory and stops reporting it. Before this,
    /// nothing could remove one and it was reported for ever.
    #[tokio::test]
    async fn forgetting_removes_what_cannot_be_carried_and_nothing_else() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");
        let (_label, paths) = unreadable_network(&home);

        let service = Service::over(
            home,
            Lifecycle::new(Arc::new(Recording::new()) as Arc<dyn Machine>),
            Arc::new(InProcess::new()) as Arc<dyn Connectivity>,
            Arc::new(Names::new()) as Arc<dyn Resolving>,
        )
        .expect("assembles");
        assert_eq!(1, service.broken().await.len());

        let outcome =
            service.handle(Command::Forget { label: "rotta".to_owned(), last_admin: false }).await;

        assert!(matches!(outcome, Outcome::Reported(_)), "{outcome:?}");
        assert!(!paths.root().exists(), "the directory is gone");
        assert!(service.broken().await.is_empty(), "and it stops being reported");
    }

    /// A network this device *can* use is removable too, and this is the case
    /// that matters: a device that has been revoked holds a roster that loads and
    /// names it, because the expulsion was signed elsewhere. Nothing this daemon
    /// could test would tell it apart from a healthy membership, so a removal
    /// that only worked on what looked broken would refuse exactly the one a
    /// person needs. Found in verification, on a phone that had been replaced.
    #[tokio::test]
    async fn a_network_this_device_can_use_is_removable() {
        let (service, _machine, _scratch) = two_networks().await;
        let held = service.all().await;
        assert_eq!(2, held.len(), "two, so the other can be checked afterwards");
        let going = held.first().expect("a network").label().to_string();
        let staying = held.get(1).expect("the other").label().to_string();
        let paths = service.home.paths_for(&Label::new(&going).expect("a label"));

        let outcome =
            service.handle(Command::Forget { label: going.clone(), last_admin: true }).await;

        assert!(matches!(outcome, Outcome::Reported(_)), "{outcome:?}");
        assert!(!paths.root().exists(), "the directory and its keys are gone");
        let left: Vec<String> =
            service.all().await.iter().map(|network| network.label().to_string()).collect();
        assert_eq!(vec![staying], left, "and the other network is untouched");
    }

    /// Removing is local. Nothing about it reaches the network, which is the part
    /// a person is likeliest to get wrong — so the daemon must not pretend
    /// otherwise by signing anything.
    #[tokio::test]
    async fn removing_a_network_signs_nothing() {
        let (service, _machine, _scratch) = two_networks().await;
        let going = service.all().await.first().expect("a network").label().to_string();
        let before = service.home.paths_for(&Label::new(&going).expect("a label"));
        let held = crate::state::Log::at(before.roster()).read().expect("readable").len();
        assert!(held > 0, "there is a roster to have signed into");

        service.handle(Command::Forget { label: going, last_admin: true }).await;

        // Nothing is left to have been signed into: the whole directory is gone,
        // and no operation was added anywhere else.
        assert!(!before.root().exists());
    }

    /// **The only admin is asked first.** Removing a network this device is the
    /// only admin of answers `OnlyAdmin` and touches nothing; with the
    /// acknowledgement, it goes.
    #[tokio::test]
    async fn the_only_admin_is_asked_first() {
        let (service, _machine, _scratch) = two_networks().await;
        let going = service.all().await.first().expect("a network").label().to_string();
        let paths = service.home.paths_for(&Label::new(&going).expect("a label"));

        let asked =
            service.handle(Command::Forget { label: going.clone(), last_admin: false }).await;
        assert_eq!(Outcome::OnlyAdmin { network: going.clone() }, asked);
        assert!(paths.root().exists(), "nothing was touched");
        assert_eq!(2, service.all().await.len(), "and both are still held");

        let done = service.handle(Command::Forget { label: going, last_admin: true }).await;
        assert!(matches!(done, Outcome::Reported(_)), "{done:?}");
        assert!(!paths.root().exists(), "acknowledged, it goes");
    }

    /// **A network with another admin is removed without the question**: it
    /// can still admit and revoke after this device goes.
    #[tokio::test]
    async fn a_network_with_another_admin_is_removed_without_the_question() {
        use roster::types::{OperationBody, OperationCore};

        let (service, _machine, _scratch) = two_networks().await;
        let network = service.all().await.first().map(Arc::clone).expect("a network");
        let going = network.label().to_string();
        let node = network.node();
        let state = node.state().await.expect("derives");
        let other = NodeIdentity::generate().expect("generates");
        let core = OperationCore::new(
            2,
            node.identity().signing_key().algorithm(),
            OperationBody::AddDevice(
                other.device_spec("desk", Role::Admin, false, vec![]).expect("spec"),
            ),
            node.heads().await,
            node.identity().signing_key().key_id(),
            state.network,
        )
        .expect("well-formed");
        let signed = node.identity().sign_operation(&core).expect("signs");
        service.admit_to(&network, &signed).await.expect("admits");

        let done = service.handle(Command::Forget { label: going, last_admin: false }).await;
        assert!(matches!(done, Outcome::Reported(_)), "no question to ask: {done:?}");
    }

    /// **Removing is refused while an enrolment for the network waits for a
    /// person**, and nothing is touched.
    #[tokio::test]
    async fn removing_is_refused_during_an_enrolment() {
        let (service, _machine, _scratch) = two_networks().await;
        let going = service.all().await.first().expect("a network").label().clone();
        let paths = service.home.paths_for(&going);
        let (_person, underway) = crate::joining::AcrossTheChannel::new();
        *service.pending.lock().await = Some(Pending::Joining {
            label: going.clone(),
            underway,
            task: tokio::spawn(async {}),
            for_whom: crate::control::Caller::Unattributed,
        });

        let refused =
            service.handle(Command::Forget { label: going.to_string(), last_admin: true }).await;
        let Outcome::Failed { message, .. } = refused else { panic!("refused: {refused:?}") };
        assert!(message.contains("enrolment"), "{message}");
        assert!(paths.root().exists(), "nothing was removed");
        assert_eq!(2, service.all().await.len());
    }

    /// Keys kept as this platform keeps them, with a `forget` that can be made
    /// to refuse, and that records what it was asked about.
    struct Stubborn {
        refuses: std::sync::atomic::AtomicBool,
        /// For each call: the directory asked about, and whether its identity
        /// was still there at the time.
        asked: std::sync::Mutex<Vec<(std::path::PathBuf, bool)>>,
    }

    impl crate::keys::Keys for Stubborn {
        fn identity(&self, paths: &Paths) -> Result<NodeIdentity> {
            crate::keys::PlatformKeys.identity(paths)
        }

        fn forget(&self, paths: &Paths) -> Result<()> {
            self.asked
                .lock()
                .expect("not poisoned")
                .push((paths.root().to_path_buf(), paths.identity().exists()));
            if self.refuses.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Error::State {
                    path: paths.root().to_path_buf(),
                    cause: "the key store is busy".to_owned(),
                });
            }
            Ok(())
        }
    }

    /// **A key that will not go keeps the directory**, the network down and
    /// still held, and says what is left; removing again finishes. And the key
    /// is asked about while the identity naming it is still there.
    #[tokio::test]
    async fn a_key_that_will_not_go_keeps_the_directory() {
        let (service, _machine, _scratch) = two_networks().await;
        let keys = Arc::new(Stubborn {
            refuses: std::sync::atomic::AtomicBool::new(true),
            asked: std::sync::Mutex::default(),
        });
        let service = service.with_keys(Arc::clone(&keys) as Arc<dyn crate::keys::Keys>);
        let network = service.all().await.first().map(Arc::clone).expect("a network");
        let going = network.label().to_string();
        let paths = service.home.paths_for(network.label());

        let failed =
            service.handle(Command::Forget { label: going.clone(), last_admin: true }).await;
        let Outcome::Failed { message, left_behind } = failed else {
            panic!("it must say it could not finish: {failed:?}");
        };
        assert!(message.contains("remove it again"), "{message}");
        assert_eq!(vec![format!("the signing key of `{going}`")], left_behind);
        assert!(paths.root().exists(), "the directory is kept");
        assert!(
            service.all().await.iter().any(|held| held.label().to_string() == going),
            "and the network is still held"
        );
        assert_eq!(Tunnel::Down, network.tunnel().await, "down");

        keys.refuses.store(false, std::sync::atomic::Ordering::SeqCst);
        let done = service.handle(Command::Forget { label: going, last_admin: true }).await;
        assert!(matches!(done, Outcome::Reported(_)), "{done:?}");
        assert!(!paths.root().exists(), "removing again finishes");

        let asked = keys.asked.lock().expect("not poisoned").clone();
        assert_eq!(2, asked.len());
        assert!(
            asked.iter().all(|(root, identity_there)| *root == paths.root() && *identity_there),
            "asked about this network, while its identity still named the key: {asked:?}"
        );
    }

    /// What happens when two operations by one author are signed against the
    /// same heads — which is what replacing did, and why it broke.
    ///
    /// They are concurrent: neither is an ancestor of the other, one author
    /// holds two branches, and that is what equivocation *is*. The roster then
    /// voids what that author signed and **exempts only revocations**
    /// (`state::judge_one`), so the split goes the worst way: the device holding
    /// the name is expelled and the device meant to take it never arrives.
    ///
    /// This pins the mechanism. The ordering that avoids it is pinned below.
    #[tokio::test]
    async fn two_operations_on_one_set_of_heads_void_the_admission_and_keep_the_revocation() {
        let fixture = fixture(None).await;
        let founder = Arc::clone(fixture.service.node().await.expect("a network").identity());
        let first = add_a_device(&fixture.service, &founder).await;
        fixture.service.admit(&first).await.expect("the founder may add a device");

        let network = fixture.service.all().await.first().map(Arc::clone).expect("a network");
        let node = network.node();
        let state = node.state().await.expect("a roster");
        let held = state
            .devices
            .values()
            .find(|record| record.id != founder.device_id())
            .map(|record| record.id)
            .expect("a device to replace");

        // Both signed against the heads as they are now: the mistake, exactly.
        let heads = node.heads().await;
        let expulsion = crate::revoking::Expulsion {
            device: held,
            name: "laptop".to_owned(),
            reason: "replaced".to_owned(),
        };
        let revocation =
            crate::revoking::sign(&expulsion, &founder, &state, heads.clone()).expect("signs");
        let admission = add_a_device_on(&fixture.service, &founder, heads).await;

        node.admit_without_activating(&revocation).await.expect("the revocation is admitted");
        node.admit_without_activating(&admission).await.expect("the admission is admitted");

        assert!(
            !node.equivocations().await.is_empty(),
            "one author, two branches: this is what the roster calls equivocation"
        );
        let after = node.state().await.expect("a roster");
        assert!(
            after.revoked.contains(&held),
            "the revocation stands, because revocations are exempt"
        );
        assert_eq!(
            1,
            after.devices.len(),
            "and the admission does not: only the admin is left, which is the split that leaves a person with a name expelled and nobody holding it"
        );
    }

    /// The ordering that avoids it, pinned at the source.
    ///
    /// A behavioural test of `finish_admitting` needs a live exchange over a
    /// relay, which is `tests/enrolling.rs`. What can be pinned here is the one
    /// thing that went wrong: everything the admission is built from must be read
    /// **after** the revocation is in, or the two are siblings.
    ///
    /// Found on real hardware, on a log that cannot be unsaid.
    #[test]
    fn the_admission_is_built_after_the_revocation_it_replaces() {
        let source = crate::code_of(include_str!("service.rs"));
        let body = source
            .split("async fn finish_admitting")
            .nth(1)
            .expect("present")
            .split(
                "
    }
",
            )
            .next()
            .expect("its body");

        let revokes = body.find("expel_for_replacement").expect("it revokes");
        for built_after in ["let heads = node.heads()", "node.state()", "Log::at(paths.roster())"] {
            let at = body.find(built_after).unwrap_or_else(|| panic!("{built_after} is read"));
            assert!(
                at > revokes,
                "`{built_after}` must be read after the revocation, or the admission is signed against the same heads and the two are siblings"
            );
        }
    }

    /// A device gets one directory per network, and the new membership takes the
    /// old one's name.
    ///
    /// # What this caught
    ///
    /// The first run of a replacement on a phone left two directories for one
    /// network: `casa`, holding the identity the network had just expelled, and
    /// `network`, holding the live one. The phone reported `casa` as unusable and
    /// asked a person to remove it — tidying up after a machine, for a state the
    /// product never means to be in. And the live membership was stuck with the
    /// provisional name, because the good one was taken by the thing being
    /// replaced.
    #[tokio::test]
    async fn a_join_into_a_network_already_held_replaces_it_and_takes_its_name() {
        let (service, _machine, scratch) = two_networks().await;
        let home = Home::under(scratch.path());
        let existing = service.all().await.first().map(Arc::clone).expect("a network");
        let taken = existing.label().clone();
        let network = existing.record.network;

        // What a join leaves just before it settles: its own directory, holding
        // the same network under a name the daemon chose.
        let provisional = home.free_label(None).expect("a name");
        let from = home.paths_for(&taken);
        let to = home.paths_for(&provisional);
        to.create().expect("creates");
        std::fs::copy(from.roster(), to.roster()).expect("the same roster");
        std::fs::copy(from.identity(), to.identity()).expect("an identity of its own");

        let settled = service.settle(provisional.clone(), "one.internal").await;

        assert_eq!(taken, settled, "the new membership takes the old one's name");
        assert!(
            !home.paths_for(&provisional).root().exists(),
            "and nothing is left under the provisional one"
        );
        // Counted over the directories themselves: the record is written by
        // `acquire` afterwards, so at this point the settled one has none yet.
        let holding: Vec<String> = std::fs::read_dir(scratch.path().join("networks"))
            .expect("reads")
            .flatten()
            .filter(|entry| entry.path().is_dir())
            .filter(|entry| {
                Label::new(&entry.file_name().to_string_lossy()).is_ok_and(|label| {
                    crate::networks::network_of(&home.paths_for(&label)) == Some(network)
                })
            })
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            vec![taken.to_string()],
            holding,
            "one directory for one network, never two, and it is the one a person knows"
        );
        assert!(
            service.all().await.iter().all(|one| *one.label() != taken),
            "and the superseded one is no longer carried"
        );
    }

    /// Replacing the device in a network is a decision about identity. It must
    /// not quietly become a decision about whether that network carries traffic.
    ///
    /// # What this caught
    ///
    /// `choice` — whether the tunnel is up — is kept **per directory**, and the
    /// rule that leaves one directory per network removes the superseded one and
    /// renames the provisional one into its place. The provisional one has never
    /// been brought up and has no choice. So a network the person had switched on
    /// came back off, under the same name, with nothing saying so; and `resume`
    /// raises what the stored choice says, so it stayed off across the restart
    /// too. Measured on a phone, in the Android client's verification.
    #[tokio::test]
    async fn a_replacement_keeps_what_the_person_chose() {
        let (service, _machine, scratch) = two_networks().await;
        let home = Home::under(scratch.path());
        let existing = service.all().await.first().map(Arc::clone).expect("a network");
        let taken = existing.label().clone();

        // The person had this network on.
        Choice::Up.write(&home.paths_for(&taken).choice()).expect("writes");

        // What a join leaves just before it settles.
        let provisional = home.free_label(None).expect("a name");
        let to = home.paths_for(&provisional);
        to.create().expect("creates");
        let from = home.paths_for(&taken);
        std::fs::copy(from.roster(), to.roster()).expect("the same roster");
        std::fs::copy(from.identity(), to.identity()).expect("an identity of its own");

        let settled = service.settle(provisional, "one.internal").await;

        assert_eq!(taken, settled, "the same network, the same name");
        assert!(
            crate::lifecycle::resume(Choice::read(&home.paths_for(&settled).choice())),
            "and still on, without a person being asked again"
        );
    }

    /// And a network the person had taken down stays down: inheriting a choice is
    /// carrying what they asked for, in both directions.
    #[tokio::test]
    async fn a_replacement_of_a_network_that_was_off_leaves_it_off() {
        let (service, _machine, scratch) = two_networks().await;
        let home = Home::under(scratch.path());
        let taken = service.all().await.first().map(Arc::clone).expect("a network").label().clone();
        Choice::Down.write(&home.paths_for(&taken).choice()).expect("writes");

        let provisional = home.free_label(None).expect("a name");
        let to = home.paths_for(&provisional);
        to.create().expect("creates");
        let from = home.paths_for(&taken);
        std::fs::copy(from.roster(), to.roster()).expect("the same roster");
        std::fs::copy(from.identity(), to.identity()).expect("an identity of its own");

        let settled = service.settle(provisional, "one.internal").await;

        assert!(
            !crate::lifecycle::resume(Choice::read(&home.paths_for(&settled).choice())),
            "nothing turns a network on that the person turned off"
        );
    }

    /// Only the choice is carried. The keys, the roster and the attestation all
    /// belong to the membership being replaced, and carrying any of them would be
    /// carrying the thing that was replaced.
    #[tokio::test]
    async fn a_replacement_carries_the_choice_and_nothing_else() {
        let (service, _machine, scratch) = two_networks().await;
        let home = Home::under(scratch.path());
        let taken = service.all().await.first().map(Arc::clone).expect("a network").label().clone();
        let from = home.paths_for(&taken);
        Choice::Up.write(&from.choice()).expect("writes");
        // Something only the superseded membership has.
        std::fs::write(from.root().join("only-the-old-one"), b"x").expect("writes");
        let was = std::fs::read(from.identity()).expect("its identity");

        let provisional = home.free_label(None).expect("a name");
        let to = home.paths_for(&provisional);
        to.create().expect("creates");
        std::fs::copy(from.roster(), to.roster()).expect("the same roster");
        let _made =
            crate::keys::Keys::identity(&crate::keys::PlatformKeys, &to).expect("its own identity");
        let now = std::fs::read(to.identity()).expect("the new identity");

        let settled = service.settle(provisional, "one.internal").await;
        let where_it_is = home.paths_for(&settled);

        assert!(!where_it_is.root().join("only-the-old-one").exists(), "nothing else came across");
        assert_eq!(now, std::fs::read(where_it_is.identity()).expect("reads"), "its own keys");
        assert_ne!(was, now, "which are not the ones that were replaced");
    }

    /// Carrying the choice is only half of it: nothing raises a network at
    /// runtime, so a network marked up and not raised is the same symptom the
    /// inheritance exists to cure.
    #[tokio::test]
    async fn a_network_that_was_chosen_is_raised_when_it_is_taken_on() {
        let (service, _machine, scratch) = two_networks().await;
        let label = service.all().await.first().map(Arc::clone).expect("a network").label().clone();
        let paths = Home::under(scratch.path()).paths_for(&label);
        service.take_down(Some(&label)).await.expect("starts down");
        assert_eq!(Tunnel::Down, service.named(&label).await.expect("held").tunnel().await);

        // The standing instruction the replacement carried across.
        Choice::Up.write(&paths.choice()).expect("writes");
        let carrying = service.raise_if_chosen(&label).await;

        assert_eq!(
            Tunnel::Up,
            service.named(&label).await.expect("held").tunnel().await,
            "a standing instruction is acted on, not merely recorded"
        );
        // And what the join answers with is that, so that a surface ending a
        // join does not offer to raise what is already raised.
        assert!(carrying, "and the join says so");
    }

    /// And an ordinary first join, which inherits nothing, raises nothing: §2.6b
    /// makes turning a network on the person's own act.
    #[tokio::test]
    async fn a_network_with_nothing_to_inherit_is_not_raised() {
        let (service, _machine, scratch) = two_networks().await;
        let label = service.all().await.first().map(Arc::clone).expect("a network").label().clone();
        let paths = Home::under(scratch.path()).paths_for(&label);
        service.take_down(Some(&label)).await.expect("starts down");
        // What a first join leaves: no choice at all.
        let _gone = std::fs::remove_file(paths.choice());

        let carrying = service.raise_if_chosen(&label).await;

        assert_eq!(
            Tunnel::Down,
            service.named(&label).await.expect("held").tunnel().await,
            "nothing turns on a network nobody asked for"
        );
        // Which is what the join answers with, and is why the command line still
        // ends an ordinary first join by saying how to bring the tunnel up.
        assert!(!carrying, "and the join says it is off rather than claiming otherwise");
    }

    /// What a join answers is read off the network, never off the instruction it
    /// acted on. A choice that says up over a network that is already up must
    /// answer the same as one that raised it — and a surface that believed the
    /// instruction instead would say `carrying` of a tunnel that never came up.
    #[tokio::test]
    async fn what_a_join_says_about_the_tunnel_is_what_the_network_is() {
        let (service, _machine, scratch) = two_networks().await;
        let label = service.all().await.first().map(Arc::clone).expect("a network").label().clone();
        let paths = Home::under(scratch.path()).paths_for(&label);

        // A choice saying up over a network already up: nothing to raise, and
        // the answer is still the network's.
        Choice::Up.write(&paths.choice()).expect("writes");
        service.raise(&service.named(&label).await.expect("held")).await.expect("raises");
        assert!(service.raise_if_chosen(&label).await, "it is up, so that is the answer");

        // And a network this daemon does not hold at all carries nothing, rather
        // than reporting whatever the last one did.
        let unheld = Label::new("nothing-here").expect("a name");
        assert!(!service.raise_if_chosen(&unheld).await, "nothing held carries nothing");
    }

    /// A network this device does not already hold is simply named after itself.
    #[tokio::test]
    async fn a_join_into_a_new_network_takes_a_name_from_its_suffix() {
        let (service, _machine, scratch) = unjoined().await;
        let home = Home::under(scratch.path());
        let provisional = home.free_label(None).expect("a name");
        home.paths_for(&provisional).create().expect("creates");

        let settled = service.settle(provisional, "casa.internal").await;

        assert_eq!("casa", settled.as_str(), "from the network's own suffix");
    }

    /// Asking what a join has got to must **finish** it, not merely describe it.
    ///
    /// # What this caught
    ///
    /// The roster arrived, the log and the snapshot were written, and asking said
    /// `Adopted` — so the phone's screen said *"you are now a device in casa"*.
    /// Nothing had written the record: the daemon carried no network, and the
    /// directory sat there stranded. A success reported without being performed
    /// is worse than a failure, because nothing looks wrong until much later and
    /// somewhere else.
    ///
    /// It happened three times on real hardware before the cause was found, each
    /// time blamed on a timeout — the confirming request waits on a person
    /// reading prompts at the *other* machine, which is unbounded by nature. That
    /// request is a fast path now; this is what the join actually rests on.
    #[tokio::test]
    async fn asking_what_a_join_has_got_to_finishes_it() {
        let (service, _machine, scratch) = unjoined().await;
        let home = Home::under(scratch.path());
        home.create().expect("creates");

        // A directory in the state a join leaves the moment before it is taken
        // on: the roster delivered and written, the identity made, and no record.
        let provisional = home.free_label(None).expect("a name");
        let paths = home.paths_for(&provisional);
        crate::founding::found_with(
            &paths,
            &crate::founding::Founding {
                name: "phone".to_owned(),
                suffix: "casa.internal".to_owned(),
                relay: None,
                rendezvous: None,
                certificate: None,
                ipv4_range: None,
            },
            &crate::keys::PlatformKeys,
        )
        .expect("a roster to have been given");
        assert!(!paths.record().exists(), "this is what has not happened yet");

        let settled = service.settle(provisional, "casa.internal").await;
        let where_it_is = home.paths_for(&settled);
        service.acquire(settled.clone(), where_it_is.clone()).await.expect("takes it on");

        assert_eq!("casa", settled.as_str(), "under the network's own name");
        assert!(where_it_is.record().exists(), "the record is written");
        assert!(
            service.all().await.iter().any(|one| *one.label() == settled),
            "and the daemon carries it, rather than reporting that it does"
        );
    }

    /// **A joined network is the joiner's**, recorded as it is taken on, as a
    /// founded one is the founder's.
    ///
    /// # What this caught
    ///
    /// Nothing wrote the owner on the join path, and no test took a join as far
    /// as `Adopted` through the service. On the Linux testbed a person joined,
    /// was told `adopted`, and was then refused `up` on their own network.
    #[tokio::test]
    async fn a_joined_network_belongs_to_whoever_joined_it() {
        let (service, _machine, scratch) = unjoined().await;
        let home = Home::under(scratch.path());
        home.create().expect("creates");

        let provisional = home.free_label(None).expect("a name");
        crate::founding::found_with(
            &home.paths_for(&provisional),
            &crate::founding::Founding {
                name: "laptop".to_owned(),
                suffix: "casa.internal".to_owned(),
                relay: None,
                rendezvous: None,
                certificate: None,
                ipv4_range: None,
            },
            &crate::keys::PlatformKeys,
        )
        .expect("a roster to have been given");

        let (person, underway) = crate::joining::AcrossTheChannel::new();
        person.reached(crate::joining::Progress::Joined {
            suffix: "casa.internal".to_owned(),
            devices: 2,
            relay_confirmed: true,
        });
        let alice = crate::control::Caller::Identified {
            name: "1000".to_owned(),
            privileged: true,
            could_be_privileged: false,
        };
        *service.pending.lock().await = Some(Pending::Joining {
            label: provisional,
            underway,
            task: tokio::spawn(async {}),
            for_whom: alice,
        });

        let adopted = service.take_the_network_on().await;
        assert!(matches!(adopted, Outcome::Adopted { .. }), "{adopted:?}");
        let casa = Label::new("casa").expect("a label");
        assert_eq!(
            Some("1000".to_owned()),
            crate::state::read_owner(&home.paths_for(&casa)),
            "recorded for the person who joined"
        );
    }

    /// Asked what is waiting when nothing is, the daemon says so as a plain
    /// answer — not as a refusal.
    ///
    /// The distinction is the whole point. A surface has to tell "the daemon
    /// holds nothing" from "the daemon holds an enrolment that ended badly",
    /// because the second is what refuses the next join and the first is not, and
    /// a surface that has to read the words of a refusal to tell them apart will
    /// one day read them wrong.
    #[tokio::test]
    async fn nothing_waiting_is_not_reported_as_a_failure() {
        let (service, _machine, _scratch) = unjoined().await;

        match service.handle(Command::Waiting).await {
            Outcome::Done => {}
            other => panic!("expected a plain answer, got {other:?}"),
        }
    }

    /// A founding waiting on a certificate is waiting, and is named.
    ///
    /// It occupies the daemon's one pending slot and refuses the next enrolment
    /// like any other. Answering that nothing was waiting left a surface with a
    /// refusal it could not explain and no way to clear what caused it.
    #[tokio::test]
    async fn a_founding_waiting_on_a_certificate_is_reported_as_waiting() {
        let (service, _machine, _scratch) = unjoined().await;

        // Any bytes: what is under test is that the pending is named at all, and
        // the fingerprint is of whatever it holds.
        let der = b"not a certificate, and this answer does not verify one".to_vec();
        *service.pending.lock().await = Some(Pending::Founding {
            label: only_label(),
            wanted: crate::founding::Founding {
                name: "nas".to_owned(),
                suffix: "example.internal".to_owned(),
                relay: Some("https://relay.example:443".to_owned()),
                rendezvous: None,
                certificate: Some(der.clone()),
                ipv4_range: None,
            },
            for_whom: crate::control::Caller::Unattributed,
        });

        match service.handle(Command::Waiting).await {
            Outcome::Pinning { relay, fingerprint, der_len, .. } => {
                assert_eq!("https://relay.example:443", relay, "it says which relay");
                assert_eq!(der.len(), der_len, "and how much certificate there is");
                assert_eq!(crate::relay::fingerprint(&der), fingerprint, "and of what");
            }
            other => panic!("expected the founding to be named, got {other:?}"),
        }
    }

    /// One thing at a time, whatever kind it is.
    ///
    /// Two would mean two things on one screen and a person with no way to tell
    /// which they were being asked about.
    #[tokio::test]
    async fn a_second_enrolment_is_refused_while_one_is_pending() {
        let (service, _machine, _scratch) = unjoined().await;

        // A founding waiting on a certificate occupies the slot.
        *service.pending.lock().await = Some(Pending::Founding {
            label: only_label(),
            wanted: crate::founding::Founding {
                name: "nas".to_owned(),
                suffix: "example.internal".to_owned(),
                relay: None,
                rendezvous: None,
                certificate: None,
                ipv4_range: None,
            },
            for_whom: crate::control::Caller::Unattributed,
        });

        let outcome = service
            .handle(Command::Join {
                relay: "https://127.0.0.1:1".to_owned(),
                name: "laptop".to_owned(),
            })
            .await;

        match outcome {
            Outcome::Failed { message, .. } => {
                assert!(message.contains("already waiting"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// A join is confirmed with digits read off the other machine, never with a
    /// bare yes. The daemon refuses the bare one rather than treating it as
    /// agreement — agreement being exactly what used to make the check pass.
    #[tokio::test]
    async fn a_join_is_not_confirmed_by_agreeing() {
        let (service, _machine, _scratch) = unjoined().await;

        match service.handle(Command::Confirm).await {
            Outcome::Failed { message, .. } => {
                assert!(message.contains("nothing is waiting"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// And the digits go where a person's digits go: to the join. Nothing on
    /// this path may read the code the device derived — the service cannot even
    /// see it, because the progress it reads no longer carries one.
    #[tokio::test]
    async fn confirming_a_join_that_is_not_waiting_is_refused() {
        let (service, _machine, _scratch) = unjoined().await;

        match service.handle(Command::ConfirmJoin { code: "123456".to_owned() }).await {
            Outcome::Failed { message, .. } => {
                assert!(message.contains("nothing is waiting"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// The daemon never hands a joining device its own code: what it reports
    /// while waiting for a person carries no digits at all.
    #[test]
    fn what_a_joining_device_reports_carries_no_code() {
        // Nothing here asserts what the service does not read: it cannot read a
        // field that does not exist, and the compiler is the check for that.
        // What is worth pinning is that the field stays gone.
        let joining = include_str!("joining.rs");
        let at = joining.find("    Confirming {").expect("the variant");
        let end = joining[at..]
            .find(
                "
    },",
            )
            .map_or(joining.len(), |offset| at + offset);
        let variant = joining.get(at..end).unwrap_or_default();
        assert!(
            !variant.contains("code:"),
            "the variant a joining device reports carries no code: {variant}"
        );
    }

    /// An empty log is not a corrupt one.
    #[tokio::test]
    async fn an_empty_log_describes_no_network_rather_than_failing() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());
        paths.create().expect("creates");
        let identity = Arc::new(crate::state::identity_of(&paths).expect("an identity"));

        let outcome = Node::from_log(identity, crate::state::Log::at(paths.roster()), None, None);

        assert!(
            matches!(outcome, Ok(None)),
            "a device nobody has founded or joined is an ordinary state, not a failure"
        );
    }

    /// A log whose genesis this build refuses is a network that cannot be used,
    /// and saying so is not the same as saying there is no network. A build
    /// whose rules were looser could have written one — parameters under a
    /// public name, or a prefix outside `fd00::/8` — and the person who founded
    /// it needs to know it is the parameters this build will not have, not their
    /// identity.
    #[tokio::test]
    async fn a_log_whose_genesis_is_refused_reports_the_network_as_unusable() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let paths = Paths::under(scratch.path());
        paths.create().expect("creates");
        let identity = Arc::new(crate::state::identity_of(&paths).expect("an identity"));

        // A genesis built the ordinary way, with the suffix then replaced in its
        // core bytes by one this build refuses, and the operation reassembled
        // around the new core so its id still matches. The replacement is the
        // same length, so the CBOR around it is untouched. The signature no
        // longer belongs to the core, which does not matter here: the body is
        // decoded before anything is verified, so this is the refusal an older
        // build's log produces.
        let params = NetworkParams::new(
            vec![0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "example.internal",
            2_592_000,
        )
        .expect("valid");
        let genesis = OperationCore::new(
            1,
            identity.signing_key().algorithm(),
            OperationBody::CreateNetwork {
                device: identity.device_spec("founder", Role::Admin, true, vec![]).expect("spec"),
                params,
            },
            vec![],
            identity.signing_key().key_id(),
            NetworkId::from_bytes([0; 32]),
        )
        .expect("well-formed");
        let old = b"example.internal";
        let refused = b"azienda.italiana";
        let mut core = genesis.encode();
        let at = core.windows(old.len()).position(|window| window == old).expect("the suffix");
        core.splice(at..at.saturating_add(old.len()), refused.iter().copied());
        let tampered = roster::sign::assemble_operation(&core, &[0u8; 64]);

        let log = crate::state::Log::at(paths.roster());
        log.append(&tampered).expect("writes");

        match Node::from_log(identity, log, None, None) {
            Err(crate::error::Error::Parameters { cause }) => {
                assert!(
                    cause.contains("suffix not under a private namespace"),
                    "the report says why the network is unusable: {cause}"
                );
            }
            Err(other) => panic!("expected a refusal naming the parameters, got {other}"),
            Ok(node) => panic!(
                "a refused genesis must not read as {}",
                if node.is_some() { "a usable network" } else { "no network at all" }
            ),
        }
    }

    async fn fixture(fail_at: Option<Fail>) -> Fixture {
        let founder = Arc::new(NodeIdentity::generate().expect("generates"));
        let params = NetworkParams::new(
            vec![0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "example.internal",
            2_592_000,
        )
        .expect("valid");

        let genesis = OperationCore::new(
            1,
            founder.signing_key().algorithm(),
            OperationBody::CreateNetwork {
                device: founder.device_spec("founder", Role::Admin, true, vec![]).expect("spec"),
                params,
            },
            vec![],
            founder.signing_key().key_id(),
            NetworkId::from_bytes([0; 32]),
        )
        .expect("well-formed");
        let bytes = sign_operation(&genesis, founder.signer()).expect("signs");

        let mut roster = Roster::new();
        assert!(roster.offer_bytes(&bytes).is_accepted());
        let state = roster.state().expect("derives");

        let scratch = tempfile::tempdir().expect("a scratch directory");
        let prefix = Prefix::from_parameter(&state.params.ula).expect("usable");
        let gateway = Arc::new(Gateway::new(Rules::new(prefix, founder.device_id())));

        let node = Arc::new(Node::new(
            Arc::clone(&founder),
            Syncer::new(roster),
            gateway,
            Router::new(prefix),
            Log::at(scratch.path().join("roster.log")),
            Schedule::provisional(),
        ));

        let machine = Arc::new(match fail_at {
            Some(step) => Recording::failing_at(step),
            None => Recording::new(),
        });
        let paths = Paths::under(scratch.path());
        paths.create().expect("creates");

        let connectivity = Arc::new(InProcess::new());
        let names = Arc::new(Names::new());
        let service = service_over(
            Home::under(scratch.path()),
            Some(node),
            paths,
            &machine,
            &connectivity,
            &names,
        );

        Fixture { service, machine, connectivity, names, _scratch: scratch }
    }

    /// A device holding two networks, each with its own roster and its own keys.
    ///
    /// Founded separately, so nothing is shared: two identities, two prefixes,
    /// two suffixes, two directories. That is the point — a fixture where one
    /// network were a copy of the other would pass tests that a real second
    /// network would fail.
    async fn two_networks() -> (Service, Arc<Recording>, tempfile::TempDir) {
        two_networks_over(Arc::new(InProcess::new()) as Arc<dyn Connectivity>).await
    }

    /// The same, over a connectivity the caller chose.
    async fn two_networks_over(
        connectivity: Arc<dyn Connectivity>,
    ) -> (Service, Arc<Recording>, tempfile::TempDir) {
        use roster::sign::sign_operation;
        use roster::types::{NetworkParams, OperationBody, OperationCore, Role};

        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");

        let mut networks = Vec::new();
        for (name, ula) in [("casa", 0x11_u8), ("lavoro", 0x22)] {
            let label = Label::new(name).expect("a usable label");
            let paths = home.paths_for(&label);
            paths.create().expect("creates");

            let founder = Arc::new(NodeIdentity::generate().expect("generates"));
            let params = NetworkParams::new(
                vec![0xfd, ula, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                format!("{name}.internal"),
                2_592_000,
            )
            .expect("valid");
            let genesis = OperationCore::new(
                1,
                founder.signing_key().algorithm(),
                OperationBody::CreateNetwork {
                    device: founder.device_spec("nas", Role::Admin, true, vec![]).expect("spec"),
                    params,
                },
                vec![],
                founder.signing_key().key_id(),
                NetworkId::from_bytes([0; 32]),
            )
            .expect("well-formed");
            let bytes = sign_operation(&genesis, founder.signer()).expect("signs");

            let log = Log::at(paths.roster());
            log.append(&bytes).expect("writes");

            let mut roster = Roster::new();
            assert!(roster.offer_bytes(&bytes).is_accepted());
            let state = roster.state().expect("derives");
            let prefix = Prefix::from_parameter(&state.params.ula).expect("usable");

            let node = Arc::new(Node::new(
                Arc::clone(&founder),
                Syncer::new(roster),
                Arc::new(Gateway::new(Rules::new(prefix, founder.device_id()))),
                Router::new(prefix),
                log,
                Schedule::provisional(),
            ));

            identity::store::save(&founder, &paths.identity()).expect("seals the identity");

            let record = Record { label, network: state.network };
            record.write(&paths).expect("writes");
            networks.push(Network::new(record, paths, node));
        }

        let machine = Arc::new(Recording::new());
        let service = Service::holding(
            home,
            networks,
            Lifecycle::new(Arc::clone(&machine) as Arc<dyn Machine>),
            connectivity,
            Arc::new(Names::new()) as Arc<dyn Resolving>,
        );
        (service, machine, scratch)
    }

    fn label(text: &str) -> Label {
        Label::new(text).expect("a usable label")
    }

    /// Both, side by side, each answering about itself.
    #[tokio::test]
    async fn a_device_holds_two_networks_at_once() {
        let (service, _machine, _scratch) = two_networks().await;

        let held: Vec<String> =
            service.all().await.iter().map(|network| network.label().to_string()).collect();
        assert_eq!(held, vec!["casa", "lavoro"]);

        for name in ["casa", "lavoro"] {
            let network = service.named(&label(name)).await.expect("held");
            assert_eq!(network.label().to_string(), name);
        }
    }

    /// The suffixes differ, the prefixes differ, and the devices are unrelated.
    /// A fixture that shared any of them would not be two networks.
    #[tokio::test]
    async fn two_networks_share_nothing() {
        let (service, _machine, _scratch) = two_networks().await;

        let casa = service.named(&label("casa")).await.expect("held");
        let lavoro = service.named(&label("lavoro")).await.expect("held");

        let one = casa.node().state().await.expect("a network");
        let other = lavoro.node().state().await.expect("a network");

        assert_ne!(one.network, other.network);
        assert_ne!(one.params.ula, other.params.ula);
        assert_ne!(one.params.suffix, other.params.suffix);
        assert_ne!(casa.node().identity().device_id(), lavoro.node().identity().device_id());

        for device in one.devices.keys() {
            assert!(!other.devices.contains_key(device), "neither roster holds the other's");
        }
    }

    /// Naming a network this device does not hold is a refusal that says so,
    /// rather than acting on whichever one happens to be there.
    #[tokio::test]
    async fn a_network_that_is_not_held_is_refused_by_name() {
        let (service, _machine, _scratch) = two_networks().await;

        let refusal = match service.named(&label("cliente")).await {
            Err(refusal) => refusal,
            Ok(_) => panic!("a network this device does not hold must not resolve"),
        };
        assert!(refusal.to_string().contains("cliente"), "{refusal}");
    }

    /// A command that names no network, on a device holding several, is refused
    /// with what the choices are. Picking one would be the daemon deciding
    /// something only the person can.
    #[tokio::test]
    async fn an_ambiguous_command_is_refused_with_the_choices() {
        let (service, _machine, _scratch) = two_networks().await;

        let refusal = match service.only().await {
            Err(refusal) => refusal,
            Ok(_) => panic!("more than one network could be meant, so none may be chosen"),
        };
        let said = refusal.to_string();
        assert!(said.contains("casa"), "{said}");
        assert!(said.contains("lavoro"), "{said}");

        match service.handle(Command::Up { network: None }).await {
            Outcome::Failed { message, .. } => {
                assert!(message.contains("casa") && message.contains("lavoro"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// One network needs no naming, which is what keeps a device holding one
    /// exactly as simple as it was.
    #[tokio::test]
    async fn one_network_needs_no_naming() {
        let fixture = fixture(None).await;
        assert!(fixture.service.only().await.is_ok());
        assert!(fixture.service.bring_up(None).await.is_ok());
    }

    /// Naming a network this device does not hold is a mistake worth saying.
    /// Answering about every other network instead would let a person believe
    /// they had asked about one thing and read another.
    #[tokio::test]
    async fn a_reading_command_refuses_a_network_this_device_does_not_hold() {
        let (service, _machine, _scratch) = two_networks().await;

        for command in [
            Command::Peers { network: Some("cliente".to_owned()) },
            Command::Address { network: Some("cliente".to_owned()) },
        ] {
            match service.handle(command).await {
                Outcome::Failed { message, .. } => {
                    assert!(message.contains("cliente"), "names what was asked for: {message}");
                }
                other => panic!("expected a refusal, got {other:?}"),
            }
        }
    }

    /// Naming none is not a mistake for a command that reads: it describes them
    /// all, where `up` and `down` would refuse.
    #[tokio::test]
    async fn a_reading_command_with_no_network_named_describes_them_all() {
        let (service, _machine, _scratch) = two_networks().await;

        for command in
            [Command::Peers { network: None }, Command::Address { network: None }, Command::Status]
        {
            match service.handle(command).await {
                Outcome::Reported(report) => {
                    assert_eq!(report.networks.len(), 2, "both networks are covered");
                }
                other => panic!("a reading command is not ambiguous, got {other:?}"),
            }
        }

        // The same device, asked to act without naming one, is refused.
        match service.handle(Command::Up { network: None }).await {
            Outcome::Failed { message, .. } => {
                assert!(message.contains("casa") && message.contains("lavoro"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// A path through any tunnel of this device is the machine's own traffic
    /// asked to travel over a tunnel the machine is carrying, so every network's
    /// connectivity layer is told what every tunnel carries — not only its own.
    #[tokio::test]
    async fn every_network_is_told_what_every_tunnel_of_this_device_carries() {
        let watching = Arc::new(crate::connectivity::testing::Watching::new());
        let (service, _machine, _scratch) =
            two_networks_over(Arc::clone(&watching) as Arc<dyn Connectivity>).await;

        service.bring_up(Some(&label("casa"))).await.expect("comes up");
        service.bring_up(Some(&label("lavoro"))).await.expect("comes up");

        let handed = watching.handed();
        assert_eq!(handed.len(), 2, "one transport per network");
        for transport in &handed {
            let told: Vec<String> = transport.avoided().iter().map(ToString::to_string).collect();
            assert!(told.contains(&"fd11::/64".to_owned()), "casa's prefix: {told:?}");
            assert!(told.contains(&"fd22::/64".to_owned()), "lavoro's prefix: {told:?}");
            // Each network's own IPv4 address, as a single address rather than
            // as the range it was derived from. An IPv4 range prints as a
            // `/32` too, so the count is of the ones carrying a dot.
            assert_eq!(
                told.iter().filter(|range| range.contains('.')).count(),
                2,
                "one address per network, both told to both: {told:?}"
            );
        }

        // A tunnel that goes down takes what it carried with it: a path through
        // an adapter that no longer exists is an ordinary path again.
        service.take_down(Some(&label("casa"))).await.expect("goes down");
        let lavoro = watching.handed().into_iter().nth(1).expect("the second transport");
        let told: Vec<String> = lavoro.avoided().iter().map(ToString::to_string).collect();
        assert!(told.contains(&"fd22::/64".to_owned()), "{told:?}");
        assert!(!told.contains(&"fd11::/64".to_owned()), "casa is down: {told:?}");
    }

    /// The whole point of the change, as a person meets it.
    #[tokio::test]
    async fn taking_one_network_down_leaves_the_other_up() {
        let (service, machine, _scratch) = two_networks().await;

        service.bring_up(Some(&label("casa"))).await.expect("comes up");
        service.bring_up(Some(&label("lavoro"))).await.expect("comes up");

        let casa = service.named(&label("casa")).await.expect("held");
        let lavoro = service.named(&label("lavoro")).await.expect("held");
        assert_eq!(casa.tunnel().await, Tunnel::Up);
        assert_eq!(lavoro.tunnel().await, Tunnel::Up);

        service.take_down(Some(&label("casa"))).await.expect("goes down");

        assert_eq!(casa.tunnel().await, Tunnel::Down);
        assert_eq!(
            lavoro.tunnel().await,
            Tunnel::Up,
            "switching off one network must not switch off another"
        );

        // And on the machine itself: one of everything left, all of it the
        // network that is still up. The tunnel flag agreeing while the adapter,
        // the address, the route or the rule had gone would be the daemon
        // believing something the machine does not.
        let installed = machine.installed();
        assert_eq!(installed.adapters.len(), 1, "one adapter left: {installed:?}");
        assert_eq!(
            installed.addresses.iter().filter(|held| held.is_ipv6()).count(),
            1,
            "one IPv6 address left"
        );
        assert!(
            installed.addresses.iter().filter(|held| held.is_ipv4()).count() <= 1,
            "and at most its IPv4 address beside it"
        );
        assert_eq!(installed.routes.len(), 1, "one route left");
        assert_eq!(installed.rules.len(), 1, "one rule left");

        assert!(!casa.is_driving().await, "the loops of the network that went down are stopped");
        assert!(lavoro.is_driving().await, "and the other network is still being driven");

        let left = installed.rules.first().expect("one rule");
        assert_eq!(left.network(), "lavoro", "and it belongs to the network still up");
        assert_eq!(
            left.nameserver(),
            installed.addresses.first().copied().expect("one address"),
            "pointing at an address the machine still holds"
        );
    }

    /// A rule points at its own network's address, which exists exactly while
    /// that network is up.
    #[tokio::test]
    async fn each_rule_points_at_its_own_networks_address() {
        let (service, machine, _scratch) = two_networks().await;

        service.bring_up(Some(&label("casa"))).await.expect("comes up");
        service.bring_up(Some(&label("lavoro"))).await.expect("comes up");

        let installed = machine.installed();
        assert_eq!(installed.rules.len(), 2);
        for rule in &installed.rules {
            assert!(
                installed.addresses.contains(&rule.nameserver().into()),
                "a rule pointing at an address nothing holds answers nothing: {rule:?}"
            );
        }

        let addresses: Vec<_> = installed.addresses.clone();
        assert_ne!(addresses.first(), addresses.get(1), "two networks, two addresses");
        assert_ne!(
            installed.rules.first().map(crate::rule::Rule::suffix),
            installed.rules.get(1).map(crate::rule::Rule::suffix),
            "and two suffixes"
        );
    }

    /// Acquiring a network while another is running disturbs nothing.
    #[tokio::test]
    async fn acquiring_a_network_leaves_the_others_alone() {
        let (service, _machine, scratch) = two_networks().await;
        service.bring_up(Some(&label("casa"))).await.expect("comes up");

        let outcome = service
            .handle(Command::Found {
                label: "cliente".to_owned(),
                name: "nas".to_owned(),
                suffix: "cliente.internal".to_owned(),
                relay: None,
                rendezvous: None,
                certificate: crate::control::Certificate::None,
                ipv4_range: None,
            })
            .await;
        assert!(matches!(outcome, Outcome::Reported(_)), "founding a third: {outcome:?}");

        let casa = service.named(&label("casa")).await.expect("still held");
        assert_eq!(casa.tunnel().await, Tunnel::Up, "the network that was up is still up");
        assert_eq!(service.all().await.len(), 3, "and the new one joined the others");

        // On disk as well as in memory, under its own directory.
        let home = Home::under(scratch.path());
        assert!(home.survey().expect("lists").holding(&label("cliente")).is_some());
    }

    /// Keys belong to a network, so a daemon holding none holds none.
    ///
    /// An identity created at startup would be the one thing every network this
    /// device later joined had in common — which is exactly what the separate
    /// identities exist to prevent, arrived at before any network existed.
    #[tokio::test]
    async fn a_daemon_holding_nothing_holds_no_keys() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");

        let service = Service::over(
            home,
            Lifecycle::new(Arc::new(Recording::new()) as Arc<dyn Machine>),
            Arc::new(InProcess::new()) as Arc<dyn Connectivity>,
            Arc::new(Names::new()) as Arc<dyn Resolving>,
        )
        .expect("a home that holds nothing is not a failure");

        assert!(!service.has_network().await);
        assert!(service.broken().await.is_empty());

        // Nothing was written at all. Not an empty identity, not a placeholder.
        let mut under_networks =
            std::fs::read_dir(Home::under(scratch.path()).networks()).expect("lists");
        assert!(under_networks.next().is_none(), "a daemon holding nothing writes nothing");
    }

    /// A chosen IPv4 range is written into the signed parameters; no range, or
    /// the default by name, leaves the key out; a range that is not allowed is
    /// refused with nothing signed.
    #[tokio::test]
    async fn founding_writes_a_chosen_ipv4_range_and_leaves_the_default_unwritten() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");
        let service = Service::holding(
            home,
            Vec::new(),
            Lifecycle::new(Arc::new(Recording::new()) as Arc<dyn Machine>),
            Arc::new(InProcess::new()) as Arc<dyn Connectivity>,
            Arc::new(Names::new()) as Arc<dyn Resolving>,
        );

        let found = |label: &str, range: Option<&str>| Command::Found {
            label: label.to_owned(),
            name: "nas".to_owned(),
            suffix: format!("{label}.internal"),
            relay: None,
            rendezvous: None,
            certificate: crate::control::Certificate::None,
            ipv4_range: range.map(str::to_owned),
        };

        for (label, range, expected) in [
            ("scelto", Some("10.42.0.0/16"), Some("10.42.0.0/16")),
            ("predefinito", None, None),
            ("nominato", Some("100.64.0.0/10"), None),
        ] {
            let outcome = service.handle(found(label, range)).await;
            assert!(matches!(outcome, Outcome::Reported(_)), "founding {label}: {outcome:?}");
            let network = service.named(&Label::new(label).unwrap()).await.expect("held");
            let state = network.node().state().await.expect("a network");
            assert_eq!(
                state.params.ipv4.map(|range| range.to_string()),
                expected.map(str::to_owned),
                "{label}"
            );
        }

        let outcome = service.handle(found("pubblico", Some("8.8.8.0/24"))).await;
        match outcome {
            Outcome::Failed { message, .. } => {
                assert!(message.contains("8.8.8.0/24"), "the refusal names the range: {message}");
                assert!(message.contains("Nothing was signed"), "{message}");
            }
            other => panic!("a public range must be refused, got {other:?}"),
        }
        assert!(
            service.named(&Label::new("pubblico").unwrap()).await.is_err(),
            "no network was founded"
        );
        assert_eq!(service.all().await.len(), 3);
    }

    /// Founding twice on one device gives two networks with different prefixes.
    ///
    /// The prefix is seeded from the founding device's identity. With one
    /// identity per machine the two would be **the same** — a guaranteed
    /// collision on the one machine that is in both, and the reason the identity
    /// moved into the network's own directory.
    #[tokio::test]
    async fn two_networks_founded_here_do_not_share_a_prefix() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");

        let service = Service::holding(
            home,
            Vec::new(),
            Lifecycle::new(Arc::new(Recording::new()) as Arc<dyn Machine>),
            Arc::new(InProcess::new()) as Arc<dyn Connectivity>,
            Arc::new(Names::new()) as Arc<dyn Resolving>,
        );

        for name in ["casa", "lavoro"] {
            let outcome = service
                .handle(Command::Found {
                    label: name.to_owned(),
                    name: "nas".to_owned(),
                    suffix: format!("{name}.internal"),
                    relay: None,
                    rendezvous: None,
                    certificate: crate::control::Certificate::None,
                    ipv4_range: None,
                })
                .await;
            assert!(matches!(outcome, Outcome::Reported(_)), "founding {name}: {outcome:?}");
        }

        let casa = service.named(&label("casa")).await.expect("held");
        let lavoro = service.named(&label("lavoro")).await.expect("held");

        let one = casa.node().state().await.expect("a network");
        let other = lavoro.node().state().await.expect("a network");
        assert_ne!(one.params.ula, other.params.ula, "the prefixes must differ");
        assert_ne!(
            casa.node().identity().device_id(),
            lavoro.node().identity().device_id(),
            "because the identities do"
        );
    }

    /// An identity that will not open stops its own network and no other.
    ///
    /// Stopping the daemon would mean one unreadable folder taking the rest of a
    /// person's networks off the air, and replacing the identity would make this
    /// a different device in a network whose roster would load regardless.
    #[tokio::test]
    async fn an_unreadable_identity_stops_one_network_and_no_other() {
        let (service, _machine, scratch) = two_networks().await;
        drop(service);

        let home = Home::under(scratch.path());
        let casa = home.paths_for(&label("casa"));
        let before = std::fs::read(casa.identity()).expect("an identity was written");
        std::fs::write(casa.identity(), b"this will not unseal").expect("writes");

        let service = Service::over(
            home,
            Lifecycle::new(Arc::new(Recording::new()) as Arc<dyn Machine>),
            Arc::new(InProcess::new()) as Arc<dyn Connectivity>,
            Arc::new(Names::new()) as Arc<dyn Resolving>,
        )
        .expect("a daemon with one bad network still starts");

        let broken = service.broken().await;
        assert_eq!(broken.len(), 1, "one network could not be carried: {broken:?}");
        assert_eq!(broken.first().expect("one").label, "casa");

        assert!(service.named(&label("casa")).await.is_err(), "and it is not held");
        let lavoro = service.named(&label("lavoro")).await.expect("the other still is");
        service.bring_up(Some(&label("lavoro"))).await.expect("and still comes up");
        assert_eq!(lavoro.tunnel().await, Tunnel::Up);

        assert_eq!(
            std::fs::read(Home::under(scratch.path()).paths_for(&label("casa")).identity())
                .expect("still there"),
            b"this will not unseal".to_vec(),
            "the identity is left exactly as it was, not replaced"
        );
        assert_ne!(before, b"this will not unseal".to_vec());
    }

    /// One icon, several networks: it says something is on when something is.
    ///
    /// Reading the only network would answer "down" on a device holding two that
    /// are both carrying traffic, and an icon that says the network is off while
    /// it is on is worse than no icon at all.
    #[tokio::test]
    async fn the_tray_says_up_when_any_network_is_up() {
        let (service, _machine, _scratch) = two_networks().await;

        assert_eq!(service.anything_up().await, Tunnel::Down, "nothing is up yet");

        service.bring_up(Some(&label("casa"))).await.expect("comes up");
        assert_eq!(
            service.anything_up().await,
            Tunnel::Up,
            "one network carrying traffic is something being on"
        );

        service.bring_up(Some(&label("lavoro"))).await.expect("comes up");
        service.take_down(Some(&label("casa"))).await.expect("goes down");
        assert_eq!(service.anything_up().await, Tunnel::Up, "and so is the other one");

        service.take_down(Some(&label("lavoro"))).await.expect("goes down");
        assert_eq!(service.anything_up().await, Tunnel::Down, "only now is it off");
    }

    /// Admitting a device names the network it is admitted into, and the answer
    /// is fixed when the enrolment opens rather than asked again at confirming.
    #[tokio::test]
    async fn admitting_on_a_device_holding_several_networks_names_one() {
        let (service, _machine, _scratch) = two_networks().await;

        // With no network named and more than one held, the daemon refuses with
        // the choices rather than admitting into whichever it finds first.
        let outcome = service
            .handle(Command::Admit { network: None, payload: "peerfectly-join-v1:zz".to_owned() })
            .await;
        match outcome {
            Outcome::Failed { message, .. } => {
                assert!(message.contains("casa") && message.contains("lavoro"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }

        // Named, it gets past the choice and fails on the payload instead —
        // which is the next thing wrong with it, and proof the network resolved.
        let outcome = service
            .handle(Command::Admit {
                network: Some("casa".to_owned()),
                payload: "peerfectly-join-v1:zz".to_owned(),
            })
            .await;
        match outcome {
            Outcome::Failed { message, .. } => {
                assert!(
                    !message.contains("which network"),
                    "the network was chosen, so the refusal is about the payload: {message}"
                );
            }
            other => panic!("expected a refusal about the payload, got {other:?}"),
        }
    }

    /// A joining device whose IPv4 candidate a revoked device already derives is
    /// refused before any code is shown, and nothing is signed.
    ///
    /// The network is founded in a range of fourteen assignable addresses with
    /// one device admitted and revoked, and joining identities are generated
    /// until one lands on the revoked device's address — a few tries.
    #[tokio::test]
    async fn an_admission_whose_ipv4_address_would_collide_is_refused_before_the_code() {
        use roster::sign::sign_operation;
        use roster::types::{NetworkParams, OperationBody, OperationCore, Role};

        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");
        let casa = label("casa");
        let paths = home.paths_for(&casa);
        paths.create().expect("creates");

        let founder = Arc::new(NodeIdentity::generate().expect("generates"));
        let params = NetworkParams::new(
            vec![0xfd, 0x11, 0, 0, 0x00, 0x00, 0x00, 0x00],
            "casa.internal",
            2_592_000,
        )
        .expect("valid")
        .in_ipv4_range("10.9.8.0/28".parse().expect("allowed"));
        let sign = |body: OperationBody, parents: Vec<roster::id::OperationId>, network| {
            let core = OperationCore::new(
                1,
                founder.signing_key().algorithm(),
                body,
                parents,
                founder.signing_key().key_id(),
                network,
            )
            .expect("well-formed");
            (core.id(), sign_operation(&core, founder.signer()).expect("signs"))
        };
        let (genesis, genesis_bytes) = sign(
            OperationBody::CreateNetwork {
                device: founder.device_spec("nas", Role::Admin, true, vec![]).expect("spec"),
                params,
            },
            vec![],
            NetworkId::from_bytes([0; 32]),
        );
        let network = NetworkId::from_bytes(*genesis.as_bytes());
        let lost = NodeIdentity::generate().expect("generates");
        let (added, added_bytes) = sign(
            OperationBody::AddDevice(
                lost.device_spec("old-phone", Role::Member, false, vec![]).expect("spec"),
            ),
            vec![genesis],
            network,
        );
        let (_, revoked_bytes) = sign(
            OperationBody::RevokeDevice { device: lost.device_id(), reason: "lost".to_owned() },
            vec![added],
            network,
        );

        let log = Log::at(paths.roster());
        let mut roster = Roster::new();
        for bytes in [&genesis_bytes, &added_bytes, &revoked_bytes] {
            log.append(bytes).expect("writes");
            assert!(roster.offer_bytes(bytes).is_accepted());
        }
        let state = roster.state().expect("derives");
        assert!(state.revoked.contains(&lost.device_id()));
        let prefix = Prefix::from_parameter(&state.params.ula).expect("usable");
        let node = Arc::new(Node::new(
            Arc::clone(&founder),
            Syncer::new(roster),
            Arc::new(Gateway::new(Rules::new(prefix, founder.device_id()))),
            Router::new(prefix),
            log,
            Schedule::provisional(),
        ));
        identity::store::save(&founder, &paths.identity()).expect("seals the identity");
        let record = Record { label: casa, network: state.network };
        record.write(&paths).expect("writes");
        let service = Service::holding(
            home,
            vec![Network::new(record, paths, node)],
            Lifecycle::new(Arc::new(Recording::new()) as Arc<dyn Machine>),
            Arc::new(InProcess::new()) as Arc<dyn Connectivity>,
            Arc::new(Names::new()) as Arc<dyn Resolving>,
        );

        let range = state.params.ipv4_range();
        let taken = tunnel::ipv4_candidate(&network, &lost.device_id(), &range);
        let joining = (0..2_000)
            .map(|_| NodeIdentity::generate().expect("generates"))
            .find(|candidate| {
                tunnel::ipv4_candidate(&network, &candidate.device_id(), &range) == taken
            })
            .expect("fourteen addresses are found within a few tries");
        let payload = enrollment::payload::Joining::new(
            joining.signing_key().public_key(),
            joining.transport_key().public_key(),
            joining.attestation_key().public_key(),
            "new-phone",
            "https://relay.invalid",
        )
        .expect("well-formed");

        let before = service.named(&label("casa")).await.expect("held").node().state().await;
        let outcome = service
            .handle(Command::Admit { network: Some("casa".to_owned()), payload: payload.to_text() })
            .await;

        match outcome {
            Outcome::Failed { message, .. } => {
                assert!(message.contains("would collide"), "{message}");
                assert!(message.contains("start the join again"), "{message}");
                // The founder may derive the same address as the revoked device,
                // one time in fourteen; then either is the device it collides with.
                let founder_too =
                    tunnel::ipv4_candidate(&network, &founder.device_id(), &range) == taken;
                assert!(
                    message.contains(&crate::control::short_id(&lost.device_id()))
                        || (founder_too
                            && message.contains(&crate::control::short_id(&founder.device_id()))),
                    "the refusal names the device it collides with: {message}"
                );
            }
            other => panic!("a colliding admission must be refused before the code, got {other:?}"),
        }
        assert!(service.pending.lock().await.is_none(), "nothing waits for a confirmation");
        let after = service.named(&label("casa")).await.expect("held").node().state().await;
        assert_eq!(
            before.map(|state| state.to_bytes()).ok(),
            after.map(|state| state.to_bytes()).ok(),
            "nothing was signed"
        );
    }

    /// A member of one network cannot reach a member of another, and five
    /// separate things stop it.
    ///
    /// Each was decided for its own reason and none of them was decided for
    /// this, which is the good kind of redundancy — and exactly the kind that
    /// erodes when somebody adds a convenience that looks local. Named here so
    /// that removing any one of them fails against something.
    #[tokio::test]
    async fn nothing_crosses_between_two_networks_on_one_device() {
        let (service, machine, _scratch) = two_networks().await;
        service.bring_up(Some(&label("casa"))).await.expect("comes up");
        service.bring_up(Some(&label("lavoro"))).await.expect("comes up");

        let casa = service.named(&label("casa")).await.expect("held");
        let lavoro = service.named(&label("lavoro")).await.expect("held");
        let here = casa.node().state().await.expect("a network");
        let there = lavoro.node().state().await.expect("a network");

        // 1. A name under the other network's suffix does not reach this
        //    resolver: the rules claim suffixes that do not overlap.
        assert!(
            !crate::rule::overlapping(&here.params.suffix, &there.params.suffix),
            "one resolver would answer for the other's devices"
        );

        // 2. A destination outside this network's prefix is not carried.
        let theirs = tunnel::address_of(
            &lavoro.node().identity().device_id(),
            &Prefix::from_parameter(&there.params.ula).expect("usable"),
        );
        let ours = Prefix::from_parameter(&here.params.ula).expect("usable");
        assert!(!ours.contains(theirs), "the other network's address is off this one's prefix");

        // 3. A key that names nobody in this roster is a stranger to it.
        assert!(
            !here.devices.contains_key(&lavoro.node().identity().device_id()),
            "the other network's device is not a member of this one"
        );

        // 4. An operation carrying another network's identifier is refused.
        assert_ne!(here.network, there.network);

        // 5. And a source outside the prefix is refused where it arrives, which
        //    is the defence that holds even if something upstream forwarded.
        let packet = a_packet_from(theirs);
        let verdict = casa.node().gateway().inbound(lavoro.node().identity().device_id(), &packet);
        assert!(
            verdict.await.is_ok_and(|outcome| !outcome.is_accepted()),
            "a packet whose source belongs to another network is refused"
        );

        // And on the machine: two routes, each for its own prefix, neither
        // covering the other.
        let routes = machine.installed().routes;
        assert_eq!(routes.len(), 2);
        assert_ne!(
            routes.first().map(crate::routes::Route::prefix_text),
            routes.get(1).map(crate::routes::Route::prefix_text),
            "two networks, two prefixes, and no route between them"
        );
    }

    /// A packet that is well-formed enough to be judged, from a given source.
    fn a_packet_from(source: Ipv6Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        // Version 6 in the top nibble; the rest of the header may be zero, since
        // what is under test is the source check and it happens before anything
        // else is read.
        if let Some(first) = packet.first_mut() {
            *first = 0x60;
        }
        let at = tunnel::limits::SOURCE_OFFSET;
        if let Some(slot) = packet.get_mut(at..at.saturating_add(16)) {
            slot.copy_from_slice(&source.octets());
        }
        packet
    }

    /// Neither roster learns of the other, however long both run.
    #[tokio::test]
    async fn neither_roster_learns_of_the_other() {
        let (service, _machine, _scratch) = two_networks().await;
        service.bring_up(Some(&label("casa"))).await.expect("comes up");
        service.bring_up(Some(&label("lavoro"))).await.expect("comes up");

        let casa = service.named(&label("casa")).await.expect("held");
        let lavoro = service.named(&label("lavoro")).await.expect("held");

        // Both are driven, so anything that was going to cross has had its
        // chance to.
        assert!(casa.is_driving().await && lavoro.is_driving().await);

        let here = casa.node().state().await.expect("a network");
        let there = lavoro.node().state().await.expect("a network");

        for device in there.devices.keys() {
            assert!(!here.devices.contains_key(device), "a device crossed");
        }
        for device in here.devices.keys() {
            assert!(!there.devices.contains_key(device), "a device crossed the other way");
        }
        assert_ne!(here.params.ula, there.params.ula, "nor a parameter");
        assert_ne!(here.params.suffix, there.params.suffix);

        // No session either: each node holds sessions with its own members, and
        // neither has one with the other's device.
        assert!(!casa.node().has_session(&lavoro.node().identity().device_id()).await);
        assert!(!lavoro.node().has_session(&casa.node().identity().device_id()).await);
    }

    /// Every network, named, with whether it is up.
    #[tokio::test]
    async fn the_report_covers_every_network() {
        let (service, _machine, _scratch) = two_networks().await;
        service.bring_up(Some(&label("casa"))).await.expect("comes up");

        let report = service.report().await;
        assert!(report.holds_a_network());
        assert_eq!(report.networks.len(), 2);

        let shown = report.to_string();
        assert!(shown.contains("casa"), "{shown}");
        assert!(shown.contains("lavoro"), "{shown}");

        let casa = report.networks.iter().find(|one| one.label == "casa").expect("reported");
        let lavoro = report.networks.iter().find(|one| one.label == "lavoro").expect("reported");
        assert_eq!(casa.tunnel, Tunnel::Up);
        assert_eq!(lavoro.tunnel, Tunnel::Down, "and which is up is said per network");

        // Each describes its own network and no other.
        assert_ne!(casa.address, lavoro.address);
    }

    /// **An act is logged with who asked, its word, the network and the kind of
    /// outcome — refused ones too.** A read is not an act: a tray asks one every
    /// two seconds.
    #[tokio::test]
    async fn an_act_is_logged_with_who_asked_and_the_outcome() {
        let (service, _machine, _scratch) = two_networks().await;
        let (lines, _guard) = crate::logging::captured::capture();

        service.handle(Command::Up { network: Some("casa".to_owned()) }).await;
        let bob = crate::control::Caller::Identified {
            name: "bob".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };
        service.handle_for(&bob, Command::Down { network: Some("casa".to_owned()) }).await;
        service.handle(Command::Status).await;

        let asked: Vec<String> =
            lines.all().into_iter().filter(|line| line.contains("message=asked")).collect();
        let [up, down] = asked.as_slice() else { panic!("two acts, no read: {asked:?}") };
        for field in ["act=\"up\"", "network=\"casa\"", "outcome=\"done\""] {
            assert!(up.contains(field), "{field} in {up}");
        }
        for field in ["who=\"bob\"", "act=\"down\"", "outcome=\"not allowed\""] {
            assert!(down.contains(field), "{field} in {down}");
        }
    }

    /// **One prompt away is offered stopping, and still refused it.** The offer
    /// is for a tray that is never elevated; what decides is the caller's token.
    #[tokio::test]
    async fn one_prompt_away_is_offered_stopping_and_still_refused_it() {
        let (service, _machine, _scratch) = two_networks().await;
        let unelevated = crate::control::Caller::Identified {
            name: "S-1-5-21-admin".to_owned(),
            privileged: false,
            could_be_privileged: true,
        };

        let Outcome::Reported(report) = service.handle_for(&unelevated, Command::Status).await
        else {
            panic!("a report")
        };
        assert!(!report.may_stop_the_daemon, "not now");
        assert!(report.could_stop_the_daemon, "but after the prompt");

        let refused = service.handle_for(&unelevated, Command::Stop).await;
        assert!(matches!(refused, Outcome::NotAllowed { .. }), "{refused:?}");
        assert!(!service.is_stopping().await, "and nothing stopped");
    }

    /// **A fault is logged once, with its network, subsystem and cause, and an
    /// identifier in it reaches the log as a prefix.** A repeat renews the
    /// problem without a second line.
    #[tokio::test]
    async fn a_fault_is_logged_once_and_a_repeat_renews_it() {
        let (service, _machine, _scratch) = two_networks().await;
        let casa = service.named(&label("casa")).await.expect("held");
        let (lines, _guard) = crate::logging::captured::capture();

        let id = "3d4e5f6a7b8c9d0e".repeat(4);
        let cause = format!("DeviceId({id}): the relay would not answer");
        casa.node().record(crate::node::Severity::Problem, "transport", &cause).await;
        let first = casa.node().fault().await.expect("kept").at;
        casa.node().record(crate::node::Severity::Problem, "transport", &cause).await;

        let faults: Vec<String> =
            lines.all().into_iter().filter(|line| line.contains("message=fault")).collect();
        let [fault] = faults.as_slice() else { panic!("logged once: {faults:?}") };
        for field in ["network=casa", "subsystem=\"transport\"", "the relay would not answer"] {
            assert!(fault.contains(field), "{field} in {fault}");
        }
        assert!(!fault.contains(&id), "a full identifier reached the log: {fault}");
        assert!(casa.node().fault().await.expect("kept").at >= first, "renewed");
    }

    /// **An event is logged once and is never the network's problem**: a peer
    /// switching off, or an application sending to a device that is off for as
    /// long as it likes. A problem still is.
    #[tokio::test]
    async fn an_event_is_logged_once_and_is_never_the_problem() {
        use crate::node::Severity;

        let (service, _machine, _scratch) = two_networks().await;
        let casa = service.named(&label("casa")).await.expect("held");
        let (lines, _guard) = crate::logging::captured::capture();
        let problem_of = |report: &crate::control::Report| {
            report
                .networks
                .iter()
                .find(|one| one.label == "casa")
                .and_then(|one| one.problem.clone())
        };

        for _ in 0..50 {
            casa.node().record(Severity::Event, "tunnel", "no session for fd01::9").await;
        }
        casa.node().record(Severity::Event, "session", "the peer closed the session").await;

        let events: Vec<String> =
            lines.all().into_iter().filter(|line| line.contains("message=event")).collect();
        assert_eq!(2, events.len(), "each logged once, at the level of an event: {events:?}");
        assert!(lines.all().iter().all(|line| !line.contains("message=fault")), "and no fault");
        assert!(casa.node().fault().await.is_none(), "an event is not the latest problem");
        assert!(casa.node().event().await.is_some(), "it is kept only as the latest event");
        assert_eq!(None, problem_of(&service.report().await), "so the network shows none");

        casa.node().record(Severity::Problem, "routes", "the routes could not be installed").await;
        let shown = problem_of(&service.report().await).expect("a problem is shown");
        assert_eq!("routes", shown.subsystem);
    }

    /// A fault in one network is not shown against another. Gathering them would
    /// attribute one network's trouble to a network that is working.
    #[tokio::test]
    async fn a_fault_belongs_to_the_network_it_happened_in() {
        let (service, _machine, _scratch) = two_networks().await;

        let casa = service.named(&label("casa")).await.expect("held");
        casa.node()
            .record(crate::node::Severity::Problem, "transport", "the relay would not answer")
            .await;

        let report = service.report().await;
        let shown_in = |label: &str| {
            report
                .networks
                .iter()
                .find(|one| one.label == label)
                .map(|one| usize::from(one.problem.is_some()))
                .expect("reported")
        };

        assert_eq!(shown_in("casa"), 1, "where it happened");
        assert_eq!(shown_in("lavoro"), 0, "and nowhere else");
    }

    /// A device holding none says so, in the words it already used, and
    /// describes no network at all.
    #[tokio::test]
    async fn a_device_holding_no_network_describes_none() {
        let (service, _machine, _scratch) = unjoined().await;

        let report = service.report().await;
        assert!(!report.holds_a_network());
        assert!(report.networks.is_empty());
        assert!(
            report.note.as_ref().is_some_and(|note| note.contains("no network")),
            "{:?}",
            report.note
        );
    }

    /// A directory that could not be carried is reported rather than omitted,
    /// and the networks that were carried are unaffected.
    #[tokio::test]
    async fn a_network_that_could_not_be_carried_is_named_in_the_report() {
        let (service, _machine, scratch) = two_networks().await;
        drop(service);

        let home = Home::under(scratch.path());
        std::fs::write(home.paths_for(&label("casa")).identity(), b"will not unseal")
            .expect("writes");

        let service = Service::over(
            home,
            Lifecycle::new(Arc::new(Recording::new()) as Arc<dyn Machine>),
            Arc::new(InProcess::new()) as Arc<dyn Connectivity>,
            Arc::new(Names::new()) as Arc<dyn Resolving>,
        )
        .expect("starts");

        let report = service.report().await;
        assert_eq!(report.networks.len(), 1, "the one that could be carried");
        assert_eq!(report.unusable.len(), 1, "and the one that could not, said out loud");
        assert_eq!(report.unusable.first().expect("one").label, "casa");
        assert!(report.to_string().contains("casa"), "{report}");
    }

    /// Nothing the daemon keeps says that a device in one network is a device in
    /// another. Such a record, on a stolen machine, hands over the map that
    /// separate identities exist to deny.
    #[tokio::test]
    async fn nothing_links_a_device_across_networks() {
        let (service, _machine, scratch) = two_networks().await;

        let casa = service.named(&label("casa")).await.expect("held");
        let lavoro = service.named(&label("lavoro")).await.expect("held");
        let theirs = lavoro.node().identity().device_id();

        // Not in the other network's derived state.
        let state = casa.node().state().await.expect("a network");
        assert!(!state.devices.contains_key(&theirs));

        // Not in anything written beside it either.
        let hex = theirs.to_hex();
        let directory = Home::under(scratch.path()).paths_for(&label("casa"));
        for file in [directory.record(), directory.roster(), directory.identity()] {
            let Ok(bytes) = std::fs::read(&file) else { continue };
            let written = String::from_utf8_lossy(&bytes);
            assert!(
                !written.contains(&hex) && !written.contains("lavoro"),
                "{} must say nothing about the other network",
                file.display()
            );
        }
    }

    /// A device that already held a network keeps it, its keys and its roster.
    ///
    /// The whole risk of this change, as an existing machine meets it: a daemon
    /// that surveyed the new layout and found nothing would be a daemon whose
    /// owner's network had silently vanished.
    #[tokio::test]
    async fn a_network_in_the_old_shape_is_adopted_with_its_keys_and_its_roster() {
        use roster::sign::sign_operation;
        use roster::types::{NetworkParams, OperationBody, OperationCore, Role};

        let scratch = tempfile::tempdir().expect("a scratch directory");

        // The old layout: everything in the root, because the root was the
        // network's directory.
        let old = Paths::under(scratch.path());
        old.create().expect("creates");

        let founder = Arc::new(NodeIdentity::generate().expect("generates"));
        let was = founder.device_id();
        identity::store::save(&founder, &old.identity()).expect("seals");

        let params = NetworkParams::new(
            vec![0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "casa.internal",
            2_592_000,
        )
        .expect("valid");
        let genesis = OperationCore::new(
            1,
            founder.signing_key().algorithm(),
            OperationBody::CreateNetwork {
                device: founder.device_spec("nas", Role::Admin, true, vec![]).expect("spec"),
                params,
            },
            vec![],
            founder.signing_key().key_id(),
            NetworkId::from_bytes([0; 32]),
        )
        .expect("well-formed");
        let bytes = sign_operation(&genesis, founder.signer()).expect("signs");
        Log::at(old.roster()).append(&bytes).expect("writes");

        let service = Service::over(
            Home::under(scratch.path()),
            Lifecycle::new(Arc::new(Recording::new()) as Arc<dyn Machine>),
            Arc::new(InProcess::new()) as Arc<dyn Connectivity>,
            Arc::new(Names::new()) as Arc<dyn Resolving>,
        )
        .expect("starts");

        assert!(
            service.broken().await.is_empty(),
            "nothing was lost: {:?}",
            service.broken().await
        );
        let held = service.all().await;
        assert_eq!(held.len(), 1, "the network it had, and only that");

        let network = held.first().expect("one");
        assert_eq!(network.label().to_string(), "casa", "named from its own suffix");
        assert_eq!(
            network.node().identity().device_id(),
            was,
            "the identity is moved, never regenerated — new keys would make this a different \
             device in a network whose roster would load regardless"
        );

        let state = network.node().state().await.expect("a network");
        assert_eq!(state.params.suffix, "casa.internal", "and the roster came with it");

        // The old layout is gone rather than left as a second copy.
        assert!(!old.roster().exists(), "nothing is left in the root to be found twice");
        assert!(!old.identity().exists());

        // And a second start changes nothing.
        drop(service);
        let again = Service::over(
            Home::under(scratch.path()),
            Lifecycle::new(Arc::new(Recording::new()) as Arc<dyn Machine>),
            Arc::new(InProcess::new()) as Arc<dyn Connectivity>,
            Arc::new(Names::new()) as Arc<dyn Resolving>,
        )
        .expect("starts again");
        assert_eq!(again.all().await.len(), 1, "adoption happens once");
        assert_eq!(again.all().await.first().expect("one").node().identity().device_id(), was);
    }

    /// The network's name and the device's name are different things and go to
    /// different places: one names the folder, the other is signed into the
    /// roster for every other member to see.
    #[tokio::test]
    async fn the_network_is_named_here_and_the_device_is_named_in_the_roster() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        home.create().expect("creates");

        let service = Service::holding(
            home,
            Vec::new(),
            Lifecycle::new(Arc::new(Recording::new()) as Arc<dyn Machine>),
            Arc::new(InProcess::new()) as Arc<dyn Connectivity>,
            Arc::new(Names::new()) as Arc<dyn Resolving>,
        );

        service
            .handle(Command::Found {
                label: "casa".to_owned(),
                name: "nas".to_owned(),
                suffix: "casa.internal".to_owned(),
                relay: None,
                rendezvous: None,
                certificate: crate::control::Certificate::None,
                ipv4_range: None,
            })
            .await;

        let network = service.named(&label("casa")).await.expect("held under its own name");
        assert!(
            network.paths.root().ends_with("casa"),
            "the network's name is the folder: {:?}",
            network.paths.root()
        );

        let state = network.node().state().await.expect("a network");
        let named: Vec<&str> = state.devices.values().map(|device| device.name.as_str()).collect();
        assert_eq!(named, vec!["nas"], "and the device's name is what the roster carries");

        // Neither name is the other's, and the label reaches no roster.
        assert!(!named.contains(&"casa"));
    }

    /// A suffix beneath one already held is refused, naming what holds it.
    #[tokio::test]
    async fn an_overlapping_suffix_is_refused_by_name() {
        let (service, _machine, _scratch) = two_networks().await;

        for overlapping in ["casa.internal", "ufficio.casa.internal", "internal"] {
            let outcome = service
                .handle(Command::Found {
                    label: "terza".to_owned(),
                    name: "nas".to_owned(),
                    suffix: overlapping.to_owned(),
                    relay: None,
                    rendezvous: None,
                    certificate: crate::control::Certificate::None,
                    ipv4_range: None,
                })
                .await;

            match outcome {
                Outcome::Failed { message, .. } => {
                    assert!(message.contains("casa"), "{overlapping}: {message}");
                }
                other => panic!("`{overlapping}` must be refused, got {other:?}"),
            }
        }

        assert_eq!(service.all().await.len(), 2, "and nothing was founded");
    }

    /// One that does not overlap is founded, so the check refuses the fault and
    /// not the feature.
    #[tokio::test]
    async fn an_unrelated_suffix_is_founded() {
        let (service, _machine, _scratch) = two_networks().await;

        let outcome = service
            .handle(Command::Found {
                label: "terza".to_owned(),
                name: "nas".to_owned(),
                suffix: "cliente.internal".to_owned(),
                relay: None,
                rendezvous: None,
                certificate: crate::control::Certificate::None,
                ipv4_range: None,
            })
            .await;

        assert!(matches!(outcome, Outcome::Reported(_)), "{outcome:?}");
        assert_eq!(service.all().await.len(), 3);
    }

    /// A label already in use names what holds it, because the person has to
    /// pick a different one and needs to know why.
    #[tokio::test]
    async fn a_label_already_in_use_is_refused_by_name() {
        let (service, _machine, _scratch) = two_networks().await;

        let outcome = service
            .handle(Command::Found {
                label: "casa".to_owned(),
                name: "nas".to_owned(),
                suffix: "altro.internal".to_owned(),
                relay: None,
                rendezvous: None,
                certificate: crate::control::Certificate::None,
                ipv4_range: None,
            })
            .await;

        match outcome {
            Outcome::Failed { message, .. } => assert!(message.contains("casa"), "{message}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(service.all().await.len(), 2, "and nothing was created");
    }

    #[tokio::test]
    async fn bringing_up_and_down_records_the_choice() {
        let fixture = fixture(None).await;

        assert_eq!(fixture.service.tunnel().await, Tunnel::Down);
        fixture.service.bring_up(None).await.expect("comes up");
        assert_eq!(fixture.service.tunnel().await, Tunnel::Up);
        assert!(!fixture.machine.installed().adapters.is_empty());

        fixture.service.take_down(None).await.expect("goes down");
        assert_eq!(fixture.service.tunnel().await, Tunnel::Down);
        assert!(fixture.machine.installed().routes.is_empty());
    }

    /// A failure after a route is installed must leave no route, and must say
    /// which step failed.
    #[tokio::test]
    async fn a_failed_bring_up_says_the_step_and_leaves_nothing() {
        let fixture = fixture(Some(Fail::Rule)).await;

        match fixture.service.handle(Command::Up { network: None }).await {
            Outcome::Failed { message, left_behind } => {
                assert!(message.contains("installing the resolution rule"), "{message}");
                assert!(left_behind.is_empty(), "{left_behind:?}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }

        assert!(fixture.machine.installed().routes.is_empty(), "the route was taken back out");
        assert_eq!(fixture.service.tunnel().await, Tunnel::Down);
    }

    /// The distinction §2.6c forces: with the tunnel down nothing is current.
    #[tokio::test]
    async fn a_report_while_down_is_marked_remembered() {
        let fixture = fixture(None).await;
        let report = fixture.service.report().await;

        assert_eq!(report.only().expect("one network").tunnel, Tunnel::Down);
        assert!(
            !report.only().expect("one network").standing.is_current(),
            "nothing is current while the tunnel is down"
        );
    }

    #[tokio::test]
    async fn a_report_while_up_is_marked_current() {
        let fixture = fixture(None).await;
        fixture.service.bring_up(None).await.expect("comes up");

        assert!(fixture.service.report().await.only().expect("one network").standing.is_current());
    }

    #[tokio::test]
    async fn the_report_carries_this_devices_own_address() {
        let fixture = fixture(None).await;
        let report = fixture.service.report().await;

        let address =
            report.only().expect("one network").address.expect("this device is in its own roster");
        let prefix = Prefix::from_parameter(&[0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            .expect("valid");
        assert!(prefix.contains(address), "{address}");
    }

    /// The report says who this device is in each network and whether it may
    /// admit there, so a surface offers admin acts only where they would be taken.
    #[tokio::test]
    async fn the_report_carries_this_devices_name_id_and_role() {
        let fixture = fixture(None).await;
        let report = fixture.service.report().await;
        let network = report.only().expect("one network");

        let name = network.name.as_deref().expect("this device is in its own roster");
        assert!(name.ends_with(".example.internal"), "{name}");
        assert_eq!(network.id.len(), 19, "a short id: {}", network.id);
        assert!(
            network.peers.iter().all(|peer| peer.id != network.id),
            "this device is not its own peer"
        );
        assert!(network.admin, "the founder administers its network");
    }

    /// The choice is written after the act succeeded, not before. Otherwise a
    /// failed bring-up would bring the tunnel up on the next start.
    #[tokio::test]
    async fn a_failed_bring_up_does_not_record_a_choice_to_be_up() {
        let fixture = fixture(Some(Fail::Adapter)).await;
        assert!(fixture.service.bring_up(None).await.is_err());

        assert_eq!(
            Choice::read(&Paths::under(fixture._scratch.path()).choice()),
            Choice::Down,
            "a bring-up that failed is not a choice to be up"
        );
    }

    /// A network that was on and went off reads as last known at that moment,
    /// and still does after the process starts again.
    #[tokio::test]
    async fn last_known_survives_a_restart() {
        let fixture = fixture(None).await;
        let paths = Paths::under(fixture._scratch.path());
        let before =
            SystemTime::now().checked_sub(Duration::from_secs(1)).expect("after the epoch");
        fixture.service.bring_up(None).await.expect("comes up");
        fixture.service.take_down(None).await.expect("goes down");

        let known = crate::state::read_known(&paths.known());
        assert!(known >= before, "recorded when it went down");
        match fixture.service.report().await.only().expect("one network").standing {
            Standing::LastKnown { at } => assert_eq!(
                at.duration_since(SystemTime::UNIX_EPOCH).expect("after").as_secs(),
                known.duration_since(SystemTime::UNIX_EPOCH).expect("after").as_secs()
            ),
            Standing::Current => panic!("a network that is down is not current"),
        }
        assert_eq!(
            crate::state::read_known(&paths.root().join("absent")),
            SystemTime::UNIX_EPOCH,
            "nothing recorded is nothing known"
        );
    }

    /// Stopping keeps what the person chose; taking one network down records it.
    #[tokio::test]
    async fn stopping_keeps_the_choice_a_person_made() {
        let fixture = fixture(None).await;
        let choice = Paths::under(fixture._scratch.path()).choice();
        fixture.service.bring_up(None).await.expect("comes up");

        fixture.service.take_all_down().await.expect("stops");
        assert!(fixture.machine.installed().routes.is_empty(), "stopping still cleans up");
        assert_eq!(Choice::read(&choice), Choice::Up, "a stop is not a choice to be down");
        assert_eq!(
            fixture.service.left_on().await.len(),
            1,
            "and it is what a restore brings back"
        );

        fixture.service.bring_up(None).await.expect("comes up again");
        fixture.service.take_down(None).await.expect("goes down");
        assert_eq!(Choice::read(&choice), Choice::Down, "a person's down is recorded");
    }

    #[tokio::test]
    async fn stopping_takes_the_tunnel_down() {
        let fixture = fixture(None).await;
        fixture.service.bring_up(None).await.expect("comes up");

        assert!(!fixture.service.is_stopping().await);
        let outcome = fixture.service.handle(Command::Stop).await;

        assert_eq!(outcome, Outcome::Done);
        assert!(fixture.service.is_stopping().await);
        assert!(fixture.machine.installed().routes.is_empty(), "stopping cleans up");
        assert!(fixture.machine.installed().rules.is_empty());
    }

    #[tokio::test]
    async fn bringing_up_twice_is_not_an_error() {
        let fixture = fixture(None).await;
        fixture.service.bring_up(None).await.expect("comes up");
        fixture.service.bring_up(None).await.expect("already up is not a failure");
        assert_eq!(fixture.machine.installed().routes.len(), 1, "and does not install twice");
    }

    #[tokio::test]
    async fn taking_down_something_that_is_already_down_is_not_an_error() {
        let fixture = fixture(None).await;
        fixture.service.take_down(None).await.expect("already down is not a failure");
    }

    /// §2.6c: with the network off there is no transport, so there is nothing to
    /// reach the rendezvous or the relay with. The property holds by
    /// construction rather than by a check somebody has to remember.
    #[tokio::test]
    async fn a_down_daemon_has_no_transport_at_all() {
        let fixture = fixture(None).await;

        assert!(
            !fixture
                .service
                .node()
                .await
                .expect("the fixture holds a network")
                .is_reachable()
                .await,
            "nothing before it is asked for"
        );
        assert_eq!(fixture.connectivity.started(), 0, "and nothing was ever started");

        fixture.service.bring_up(None).await.expect("comes up");
        assert!(
            fixture.service.node().await.expect("the fixture holds a network").is_reachable().await
        );
        assert_eq!(fixture.connectivity.started(), 1, "started when the person asked");

        fixture.service.take_down(None).await.expect("goes down");
        assert!(
            !fixture
                .service
                .node()
                .await
                .expect("the fixture holds a network")
                .is_reachable()
                .await,
            "and gone again the moment they said stop"
        );
    }

    /// The address is on the adapter, and the resolver answers at it.
    ///
    /// Both were missing at first: the adapter had no address, so the machine did
    /// not know the address was its own, and nothing called the resolver at all.
    /// `peerfectly up` reported success and the network could do nothing.
    #[tokio::test]
    async fn coming_up_gives_the_adapter_an_address_and_starts_the_resolver() {
        let fixture = fixture(None).await;
        fixture.service.bring_up(None).await.expect("comes up");

        let address = fixture
            .service
            .report()
            .await
            .only()
            .expect("one network")
            .address
            .expect("this device is in its own roster");

        let addresses = fixture.machine.installed().addresses;
        assert_eq!(
            addresses.first(),
            Some(&std::net::IpAddr::V6(address)),
            "the machine holds this device's own address, or it is not local to it"
        );
        assert!(
            addresses.get(1).is_some_and(|held| held.is_ipv4()),
            "and its IPv4 address beside it: {addresses:?}"
        );
        assert_eq!(addresses.len(), 2);

        let serving = fixture.names.serving();
        assert!(serving.running, "and something is answering names");
        assert_eq!(serving.at, Some(address), "at that same address, not on loopback");
    }

    /// Both go away again, and the resolver goes first: a socket outliving its
    /// address is a socket nothing can reach and nothing will close.
    #[tokio::test]
    async fn going_down_stops_the_resolver_and_takes_the_address_back() {
        let fixture = fixture(None).await;
        fixture.service.bring_up(None).await.expect("comes up");
        fixture.service.take_down(None).await.expect("goes down");

        assert!(!fixture.names.serving().running, "nothing answers names while down");
        assert!(
            fixture.machine.installed().addresses.is_empty(),
            "and the adapter no longer holds the address"
        );
    }

    /// A tunnel whose names do not resolve is a tunnel a person cannot use, so a
    /// resolver that will not start undoes the rest rather than being shrugged off.
    #[tokio::test]
    async fn a_tunnel_that_cannot_answer_names_does_not_come_up() {
        struct Refuses;

        #[async_trait::async_trait]
        impl Resolving for Refuses {
            async fn start(
                &self,
                _address: std::net::Ipv6Addr,
                _node: Arc<Node>,
            ) -> Result<Box<dyn crate::resolving::Answering>> {
                Err(Error::BringUp {
                    step: crate::error::Step::StartingResolver,
                    cause: "told to fail".to_owned(),
                    left: Vec::new(),
                })
            }
        }

        let fixture = fixture(None).await;
        let paths = Paths::under(fixture._scratch.path());
        let service = Service::holding(
            Home::under(fixture._scratch.path()),
            fixture.service.node().await.map(|node| one_network(node, paths)).unwrap_or_default(),
            Lifecycle::new(Arc::clone(&fixture.machine) as Arc<dyn Machine>),
            Arc::clone(&fixture.connectivity) as Arc<dyn Connectivity>,
            Arc::new(Refuses) as Arc<dyn Resolving>,
        );

        assert!(service.bring_up(None).await.is_err());
        assert_eq!(service.tunnel().await, Tunnel::Down, "and it did not stay half up");

        let installed = fixture.machine.installed();
        assert!(installed.routes.is_empty(), "the route was taken back out");
        assert!(installed.addresses.is_empty(), "and so was the address");
        assert!(
            !service.node().await.expect("the fixture holds a network").is_reachable().await,
            "and the transport was stopped"
        );
    }

    /// The device follows the tunnel too: no adapter attached while down.
    #[tokio::test]
    async fn the_packet_path_exists_only_while_the_tunnel_is_up() {
        let fixture = fixture(None).await;

        assert!(
            !fixture
                .service
                .node()
                .await
                .expect("the fixture holds a network")
                .gateway()
                .is_up()
                .await
        );
        fixture.service.bring_up(None).await.expect("comes up");
        assert!(
            fixture
                .service
                .node()
                .await
                .expect("the fixture holds a network")
                .gateway()
                .is_up()
                .await
        );
        fixture.service.take_down(None).await.expect("goes down");
        assert!(
            !fixture
                .service
                .node()
                .await
                .expect("the fixture holds a network")
                .gateway()
                .is_up()
                .await
        );
    }

    /// A daemon that came back down after a reboot would have overruled someone
    /// who left the network on.
    #[tokio::test]
    async fn a_restart_comes_back_to_what_was_chosen() {
        let fixture = fixture(None).await;
        fixture.service.bring_up(None).await.expect("comes up");

        // A second service over the same state directory: a restart, in effect.
        let restarted = restart(&fixture).await;
        assert_eq!(restarted.tunnel().await, Tunnel::Down, "it starts down");

        assert!(restarted.resume().await.expect("resumes"), "and then restores the choice");
        assert_eq!(restarted.tunnel().await, Tunnel::Up);
    }

    /// And one that came back up would have done something worse.
    #[tokio::test]
    async fn a_restart_after_being_turned_off_stays_off() {
        let fixture = fixture(None).await;
        fixture.service.bring_up(None).await.expect("comes up");
        fixture.service.take_down(None).await.expect("goes down");

        let restarted = restart(&fixture).await;
        assert!(!restarted.resume().await.expect("resumes"), "nothing to restore");
        assert_eq!(restarted.tunnel().await, Tunnel::Down);
    }

    /// A daemon that has never been told anything does not turn the network on.
    #[tokio::test]
    async fn a_first_start_does_not_bring_the_network_up() {
        let fixture = fixture(None).await;
        assert!(!fixture.service.resume().await.expect("resumes"));
        assert_eq!(fixture.service.tunnel().await, Tunnel::Down);
    }

    /// A peer with no session shows no path: the report says what the transport
    /// said about an open session, and never guesses one.
    #[tokio::test]
    async fn a_peer_without_a_session_has_no_path() {
        let fixture = fixture(None).await;
        let founder = Arc::clone(
            fixture.service.node().await.expect("the fixture holds a network").identity(),
        );
        let operation = add_a_device(&fixture.service, &founder).await;
        fixture.service.admit(&operation).await.expect("the founder may add a device");

        let report = fixture.service.report().await;
        let peer = report.only().expect("one network").peers.first().expect("the added device");
        assert!(!peer.reachable, "the added device has no session");
        assert_eq!(peer.path, None);
    }

    /// §2.6c's consequence: an administrative act with the network down turns it
    /// on, rather than sitting in a queue the person believes has taken effect.
    #[tokio::test]
    async fn an_administrative_action_brings_the_network_up() {
        let fixture = fixture(None).await;
        let founder = Arc::clone(
            fixture.service.node().await.expect("the fixture holds a network").identity(),
        );

        assert_eq!(fixture.service.tunnel().await, Tunnel::Down);

        let operation = add_a_device(&fixture.service, &founder).await;
        let woke = fixture.service.admit(&operation).await.expect("the founder may add a device");

        assert!(woke, "the caller is told, so it can say so");
        assert_eq!(fixture.service.tunnel().await, Tunnel::Up, "and the network is on");
        assert_eq!(
            fixture
                .service
                .node()
                .await
                .expect("the fixture holds a network")
                .state()
                .await
                .expect("derives")
                .devices
                .len(),
            2,
            "the operation took effect rather than waiting"
        );
    }

    /// Revoking is an administrative action too, and it was the one that did not
    /// do this. It called `admit_without_activating` directly, so a person expelling a stolen
    /// laptop while the tunnel was down signed the revocation and left the
    /// machine believing it had gone out.
    #[tokio::test]
    async fn revoking_brings_the_network_up() {
        let fixture = fixture(None).await;
        let founder = Arc::clone(
            fixture.service.node().await.expect("the fixture holds a network").identity(),
        );

        // A device to expel, admitted while the network is up, then the tunnel
        // taken back down — a person's ordinary evening.
        let operation = add_a_device(&fixture.service, &founder).await;
        fixture.service.admit(&operation).await.expect("the founder may add a device");
        fixture.service.take_down(None).await.expect("goes down");
        assert_eq!(fixture.service.tunnel().await, Tunnel::Down);

        let outcome = fixture
            .service
            .handle(Command::Revoke {
                network: None,
                target: crate::control::Target::Name("laptop".to_owned()),
                reason: "the machine was lost".to_owned(),
            })
            .await;

        match outcome {
            Outcome::Reported(report) => {
                let network = report.only().expect("one network").clone();
                let revoked = network.revoked.first().expect("the expelled device is listed");
                assert_eq!(revoked.device.name.as_deref(), Some("laptop"), "as it was admitted");
                assert_eq!(revoked.device.id.len(), 19, "with its short id");
                let revocation = revoked.revocations.first().expect("with the revocation");
                assert_eq!(revocation.reason, "the machine was lost");
                assert!(revocation.by.name.is_some(), "and the admin that signed it, by name");
                assert!(
                    matches!(revocation.signer_clock, crate::control::Signed::At { .. }),
                    "signed here, so its time is recorded"
                );
                assert!(
                    !network.peers.iter().any(|peer| peer.id == revoked.device.id),
                    "and it is not listed among the members"
                );
                assert!(
                    network.waiting.iter().all(|waiting| {
                        !waiting.owed.iter().any(|owed| owed.device.id == revoked.device.id)
                    }),
                    "nor waited for"
                );
                assert!(
                    report.note.is_some_and(|note| note.contains("brought up")),
                    "the person is told the network was turned on to carry it"
                );
            }
            other => panic!("expected a report, got {other:?}"),
        }
        assert_eq!(fixture.service.tunnel().await, Tunnel::Up, "and it is on");
    }

    /// A tunnel that will not start is not a reason to lose the revocation. It
    /// is signed, it is in the log, and it is still owed to every member.
    #[tokio::test]
    async fn a_revocation_survives_a_tunnel_that_will_not_come_up() {
        let fixture = fixture(Some(Fail::Adapter)).await;
        let node = fixture.service.node().await.expect("the fixture holds a network");
        let founder = Arc::clone(node.identity());

        // Admitted straight into the roster, because this machine cannot bring a
        // tunnel up at all and the point of the test is what happens afterwards.
        let operation = add_a_device(&fixture.service, &founder).await;
        node.admit_without_activating(&operation).await.expect("the founder may add a device");
        assert_eq!(fixture.service.tunnel().await, Tunnel::Down);

        let log = Log::at(Paths::under(fixture._scratch.path()).roster());
        let before = log.read().expect("a readable log").len();

        let outcome = fixture
            .service
            .handle(Command::Revoke {
                network: None,
                target: crate::control::Target::Name("laptop".to_owned()),
                reason: "the machine was lost".to_owned(),
            })
            .await;

        match outcome {
            Outcome::Failed { message, .. } => {
                assert!(
                    message.contains("signed and held"),
                    "the failure says the revocation was kept: {message}"
                );
            }
            other => panic!("expected a reported failure, got {other:?}"),
        }

        assert_eq!(
            node.state().await.expect("derives").devices.len(),
            1,
            "the revocation took effect on this device even though the tunnel would not start"
        );
        assert_eq!(
            log.read().expect("a readable log").len(),
            before.saturating_add(1),
            "and it is on disk rather than discarded because the tunnel refused"
        );
        // Nothing is outstanding, and that is correct rather than a loss: the
        // device just revoked was this network's only other member, so there is
        // nobody left for the revocation to be owed to. A report that invented a
        // warning here would be describing a peer that does not exist.
        assert!(
            node.outstanding().await.is_empty(),
            "a network of one has nobody to be waiting on"
        );
    }

    /// With the network already on, admitting changes nothing about it.
    #[tokio::test]
    async fn an_administrative_action_with_the_network_on_does_not_report_waking_it() {
        let fixture = fixture(None).await;
        let founder = Arc::clone(
            fixture.service.node().await.expect("the fixture holds a network").identity(),
        );
        fixture.service.bring_up(None).await.expect("comes up");

        let operation = add_a_device(&fixture.service, &founder).await;
        assert!(!fixture.service.admit(&operation).await.expect("admits"));
        assert_eq!(fixture.service.tunnel().await, Tunnel::Up);
    }

    /// An operation the roster refuses does not turn the network on either.
    #[tokio::test]
    async fn a_refused_operation_does_not_wake_the_network() {
        let fixture = fixture(None).await;

        assert!(fixture.service.admit(b"not an operation").await.is_err());
        assert_eq!(
            fixture.service.tunnel().await,
            Tunnel::Down,
            "nothing was decided, so nothing needs to propagate"
        );
    }

    /// Turning it on, off and on again works. A daemon that could only come up
    /// once would fail the first time somebody used it as intended.
    #[tokio::test]
    async fn the_network_can_be_turned_on_again() {
        let fixture = fixture(None).await;

        fixture.service.bring_up(None).await.expect("comes up");
        fixture.service.take_down(None).await.expect("goes down");
        fixture.service.bring_up(None).await.expect("comes up again");

        assert!(
            fixture.service.node().await.expect("the fixture holds a network").is_reachable().await
        );
        assert_eq!(fixture.connectivity.started(), 2, "a fresh transport each time");
        assert_eq!(fixture.machine.installed().routes.len(), 1, "and one route, not two");
    }

    // ---- changing a network's relay ----------------------------------------

    /// A TLS server on this machine that presents one certificate to one client.
    ///
    /// Its port, and the certificate — the same arrangement the founding test
    /// uses, because a fetch that returned anything but the presented bytes would
    /// pin a certificate nobody has.
    fn a_relay_presenting_a_certificate() -> (u16, Vec<u8>) {
        let issued = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
            .expect("a certificate");
        let presented = issued.cert.der().to_vec();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(issued.signing_key.serialize_der());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocols supported by ring")
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(presented.clone())],
            key.into(),
        )
        .expect("a usable key pair");
        let listener =
            std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("binds");
        let port = listener.local_addr().expect("bound").port();
        std::thread::spawn(move || {
            let Ok((mut socket, _)) = listener.accept() else { return };
            let Ok(mut server) = rustls::ServerConnection::new(Arc::new(config)) else { return };
            let _ = server.complete_io(&mut socket);
        });
        (port, presented)
    }

    fn change(relay: &str, pin: bool, immediately: bool) -> Command {
        Command::ChangeRelay { network: None, relay: relay.to_owned(), pin, immediately }
    }

    async fn params_of(fixture: &Fixture) -> NetworkParams {
        fixture.service.node().await.expect("a network").state().await.expect("derives").params
    }

    /// A network with no relay is given one, and has nothing to leave.
    #[tokio::test]
    async fn a_network_with_no_relay_is_given_one() {
        let fixture = fixture(None).await;
        let done = fixture.service.handle(change("https://a.example:443", false, false)).await;
        assert!(matches!(done, Outcome::Reported(_)), "{done:?}");

        let params = params_of(&fixture).await;
        assert_eq!(Some("https://a.example:443"), params.relay.as_deref());
        assert!(params.leaving.is_none(), "there was nothing to leave");
    }

    /// **A second change is a move, leaving the first for one freshness window.**
    #[tokio::test]
    async fn a_change_of_relay_is_a_move_that_leaves_the_old_one() {
        let fixture = fixture(None).await;
        fixture.service.handle(change("https://a.example:443", false, false)).await;
        let done = fixture.service.handle(change("https://b.example:443", false, false)).await;
        assert!(matches!(done, Outcome::Reported(_)), "{done:?}");

        let params = params_of(&fixture).await;
        assert_eq!(Some("https://b.example:443"), params.relay.as_deref());
        let leaving = params.leaving.expect("leaving the one it was on");
        assert_eq!("https://a.example:443", leaving.relay);
        assert!(leaving.until > crate::clock::now_ms(), "for a while yet");
    }

    /// An immediate change leaves nothing behind.
    #[tokio::test]
    async fn an_immediate_change_leaves_nothing_behind() {
        let fixture = fixture(None).await;
        fixture.service.handle(change("https://a.example:443", false, false)).await;
        fixture.service.handle(change("https://b.example:443", false, true)).await;

        let params = params_of(&fixture).await;
        assert_eq!(Some("https://b.example:443"), params.relay.as_deref());
        assert!(params.leaving.is_none(), "nobody waits on the old one");
    }

    /// The same relay, however spelled, is not a move.
    #[tokio::test]
    async fn the_same_relay_is_not_a_move() {
        let fixture = fixture(None).await;
        fixture.service.handle(change("https://a.example:443", false, false)).await;
        let before = params_of(&fixture).await;

        let refused = fixture.service.handle(change("https://A.example", false, false)).await;
        assert!(matches!(refused, Outcome::Failed { .. }), "{refused:?}");
        assert_eq!(before, params_of(&fixture).await, "nothing changed");
    }

    fn meeting(rendezvous: Option<&str>) -> Command {
        Command::ChangeRendezvous { network: None, rendezvous: rendezvous.map(str::to_owned) }
    }

    /// **A rendezvous is set and removed by a signed parameter change**, and the
    /// relay is untouched by either.
    #[tokio::test]
    async fn a_rendezvous_is_set_and_removed() {
        let fixture = fixture(None).await;
        fixture.service.handle(change("https://a.example:443", false, false)).await;

        let set = fixture.service.handle(meeting(Some("https://a.example:8444"))).await;
        assert!(matches!(set, Outcome::Reported(_)), "{set:?}");
        let params = params_of(&fixture).await;
        assert_eq!(Some("https://a.example:8444"), params.rendezvous.as_deref());
        assert_eq!(Some("https://a.example:443"), params.relay.as_deref(), "the relay stays");

        let removed = fixture.service.handle(meeting(None)).await;
        assert!(matches!(removed, Outcome::Reported(_)), "{removed:?}");
        assert_eq!(None, params_of(&fixture).await.rendezvous);
    }

    /// **Not HTTPS, or the one it already has: refused, and nothing signed.**
    /// The daemon checks it too: whoever sent the command need not have.
    #[tokio::test]
    async fn a_rendezvous_that_is_not_https_or_unchanged_is_refused() {
        let fixture = fixture(None).await;
        fixture.service.handle(meeting(Some("https://a.example:8444"))).await;
        let before = params_of(&fixture).await;

        for refused in
            [meeting(Some("http://a.example:8444")), meeting(Some("https://a.example:8444"))]
        {
            let answered = fixture.service.handle(refused).await;
            assert!(matches!(answered, Outcome::Failed { .. }), "{answered:?}");
        }
        assert_eq!(before, params_of(&fixture).await, "nothing changed");
    }

    /// **Somebody who does not own the network is refused for want of
    /// authority**, and nothing is signed.
    #[tokio::test]
    async fn a_rendezvous_is_the_owners_to_change() {
        let fixture = fixture(None).await;
        let before = params_of(&fixture).await;
        let bob = crate::control::Caller::Identified {
            name: "S-1-5-21-bob".to_owned(),
            privileged: true,
            could_be_privileged: false,
        };

        let refused =
            fixture.service.handle_for(&bob, meeting(Some("https://a.example:8444"))).await;
        assert!(matches!(refused, Outcome::NotAllowed { .. }), "{refused:?}");
        assert_eq!(before, params_of(&fixture).await, "nothing changed");
    }

    /// **Nothing is signed before the certificate is confirmed, and a declined
    /// one changes nothing.**
    #[tokio::test]
    async fn nothing_is_signed_before_the_certificate_is_confirmed() {
        let fixture = fixture(None).await;
        let before = params_of(&fixture).await;

        let (port, _) = a_relay_presenting_a_certificate();
        let asked =
            fixture.service.handle(change(&format!("https://127.0.0.1:{port}"), true, false)).await;
        let Outcome::Pinning { moving, .. } = &asked else { panic!("it asks first: {asked:?}") };
        assert_eq!(Some("test"), moving.as_deref(), "and says it is a move, not a founding");
        let resumed = fixture.service.handle(Command::Waiting).await;
        assert_eq!(format!("{asked:?}"), format!("{resumed:?}"), "the same when resumed");
        assert_eq!(before, params_of(&fixture).await, "and has signed nothing");

        fixture.service.handle(Command::Abandon).await;
        assert_eq!(before, params_of(&fixture).await, "and declining changes nothing");

        let (port, presented) = a_relay_presenting_a_certificate();
        let relay = format!("https://127.0.0.1:{port}");
        fixture.service.handle(change(&relay, true, false)).await;
        let done = fixture.service.handle(Command::Confirm).await;
        assert!(matches!(done, Outcome::Reported(_)), "{done:?}");

        let params = params_of(&fixture).await;
        assert_eq!(Some(relay.as_str()), params.relay.as_deref());
        assert_eq!(Some(presented), params.relay_cert, "pinned: the bytes it presented");
    }

    /// Changing a relay is the network's owner's.
    #[test]
    fn changing_a_relay_needs_the_networks_owner() {
        assert_eq!(
            crate::control::Needs::TheOwnerOf(Some("casa".to_owned())),
            Command::ChangeRelay {
                network: Some("casa".to_owned()),
                relay: String::new(),
                pin: true,
                immediately: false,
            }
            .needs()
        );
    }

    // ---- a relay that moves ------------------------------------------------

    fn elsewhere() -> RelayPlan {
        RelayPlan {
            relay: Some("https://elsewhere.example:443".to_owned()),
            pinned: None,
            leaving: None,
        }
    }

    /// **A relay that moved rebuilds the transport, and not the tunnel.**
    #[tokio::test]
    async fn a_relay_that_moved_rebuilds_the_transport_and_not_the_tunnel() {
        let fixture = fixture(None).await;
        fixture.service.bring_up(None).await.expect("comes up");
        let routes = fixture.machine.installed().routes.len();
        assert_eq!(1, fixture.connectivity.started());

        // As though the transport had been built for another relay.
        let network = fixture.service.all().await.into_iter().next().expect("one network");
        *network.plan.lock().await = Some(elsewhere());

        fixture.service.follow_relays().await;

        assert_eq!(2, fixture.connectivity.started(), "a new transport");
        assert!(network.up.lock().await.is_some(), "and the tunnel never went down");
        assert_eq!(routes, fixture.machine.installed().routes.len(), "nor did its routes");
        assert!(network.node().is_reachable().await);
        assert_ne!(Some(elsewhere()), *network.plan.lock().await, "and it knows what it has now");
    }

    /// Nothing moved, nothing rebuilt: the reconciler wakes every few seconds.
    #[tokio::test]
    async fn a_relay_that_did_not_move_rebuilds_nothing() {
        let fixture = fixture(None).await;
        fixture.service.bring_up(None).await.expect("comes up");
        fixture.service.follow_relays().await;
        fixture.service.follow_relays().await;
        assert_eq!(1, fixture.connectivity.started());
    }

    /// A network that is down reaches no relay, moving or not.
    #[tokio::test]
    async fn a_network_that_is_down_is_not_rebuilt() {
        let fixture = fixture(None).await;
        fixture.service.bring_up(None).await.expect("comes up");
        fixture.service.take_down(None).await.expect("goes down");

        fixture.service.follow_relays().await;
        assert_eq!(1, fixture.connectivity.started(), "§2.6c: nothing started for a down network");
    }

    /// Lowered after its plan was read: `rebind` looks again, so a network that
    /// went down in between still reaches no relay.
    #[tokio::test]
    async fn a_network_lowered_mid_move_is_not_rebuilt() {
        let fixture = fixture(None).await;
        fixture.service.bring_up(None).await.expect("comes up");
        fixture.service.take_down(None).await.expect("goes down");
        let network = fixture.service.all().await.into_iter().next().expect("one network");
        // What the race leaves: a plan that differs, on a network that is down.
        *network.plan.lock().await = Some(elsewhere());

        fixture.service.follow_relays().await;
        assert_eq!(1, fixture.connectivity.started(), "§2.6c: nothing started for a down network");
    }

    /// The reconciler's own wake follows a move: nothing arrives to say one ended.
    #[tokio::test]
    async fn the_reconciler_follows_a_move_on_its_own() {
        let fixture = fixture(None).await;
        fixture.service.bring_up(None).await.expect("comes up");
        let network = fixture.service.all().await.into_iter().next().expect("one network");
        *network.plan.lock().await = Some(elsewhere());

        let service = Arc::new(fixture.service);
        let running = tokio::spawn(Arc::clone(&service).reconcile_forever());
        service.reconciling.notify_one();
        for _ in 0..500 {
            if fixture.connectivity.started() == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        running.abort();
        assert_eq!(
            2,
            fixture.connectivity.started(),
            "rebuilt by the loop, with nobody calling it"
        );
    }

    /// **A move changes what a transport should be at its end, and not before**
    /// — with nothing signed at that moment. The clock is supplied.
    #[test]
    fn a_move_asks_for_a_new_transport_at_its_end_and_not_before() {
        let moving = NetworkParams::with_relay(
            vec![0xfd, 0, 0, 0, 0, 0, 0, 0],
            Some("https://old.example:443"),
            "example.internal",
            600,
        )
        .expect("valid")
        .moving_to("https://new.example:443", None, 1_000)
        .expect("moves");
        let end = 1_000 + 600 * 1_000;

        assert_eq!(RelayPlan::of(&moving, end - 2), RelayPlan::of(&moving, end - 1));
        assert_ne!(
            RelayPlan::of(&moving, end - 1),
            RelayPlan::of(&moving, end),
            "the end is a different transport"
        );
    }

    /// Taking a network is an administrator's act, and refused to anyone else.
    #[tokio::test]
    async fn taking_a_network_needs_leave_to_act_on_the_machine() {
        let (service, _machine, _scratch) = unjoined().await;
        let alice = crate::control::Caller::Identified {
            name: "S-1-5-21-alice".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };
        let bob = crate::control::Caller::Identified {
            name: "S-1-5-21-bob".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };

        service.handle_for(&alice, founding_casa()).await;
        let paths = service.home().paths_for(&Label::new("casa").expect("valid"));

        let refused = service.handle_for(&bob, Command::TakeOwnership { network: None }).await;
        let Outcome::NotAllowed { message } = refused else {
            panic!("an ordinary person may not take it, and that is not a failure: {refused:?}");
        };
        assert!(message.contains("administrator"), "naming why: {message}");
        assert!(
            message.contains(crate::control::AUTHORISATION),
            "and naming authority rather than anything about the network: {message}"
        );
        assert_eq!(
            Some("S-1-5-21-alice".to_owned()),
            crate::state::read_owner(&paths),
            "and it is still hers"
        );
        assert!(!crate::state::was_taken(&paths), "and nothing was taken");
    }

    /// **A network that changes hands says so.**
    ///
    /// It is how one survives the account that made it being deleted — and,
    /// because it is also how one person takes another's, a report that showed
    /// only the result would make a quiet act of a deliberate one.
    #[tokio::test]
    async fn a_network_that_was_taken_says_it_was_taken() {
        let (service, _machine, _scratch) = unjoined().await;
        let alice = crate::control::Caller::Identified {
            name: "S-1-5-21-alice".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };
        let root = crate::control::Caller::Identified {
            name: "S-1-5-21-root".to_owned(),
            privileged: true,
            could_be_privileged: false,
        };

        service.handle_for(&alice, founding_casa()).await;
        let paths = service.home().paths_for(&Label::new("casa").expect("valid"));
        assert!(!crate::state::was_taken(&paths), "founded, not taken");

        let taken = service.handle_for(&root, Command::TakeOwnership { network: None }).await;
        let Outcome::Reported(report) = taken else { panic!("it is taken: {taken:?}") };
        assert!(
            report.note.as_deref().is_some_and(|note| note.contains("taken")),
            "and the answer says so: {:?}",
            report.note
        );

        assert_eq!(Some("S-1-5-21-root".to_owned()), crate::state::read_owner(&paths));
        assert!(crate::state::was_taken(&paths), "and it is marked as taken, not as always so");
        assert!(
            report.networks.iter().any(|network| network.owner_taken),
            "which the report carries"
        );
    }

    /// **What `Service::pending` serialises stays serialised, now that the
    /// channel does not.**
    ///
    /// The control channel used to answer one connection at a time, which
    /// serialised everything by accident — including enrolment, which must be
    /// serial for a reason. Now each connection is its own task, so the two are
    /// separated, and the question is whether the deliberate one survived on its
    /// own. Asked by firing both at once rather than one after the other, which
    /// is the shape that could not happen before.
    #[tokio::test]
    async fn enrolment_is_still_serial_when_two_arrive_at_once() {
        let (service, _machine, _scratch) = unjoined().await;
        let service = Arc::new(service);
        let alice = crate::control::Caller::Identified {
            name: "S-1-5-21-alice".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };
        service.handle_for(&alice, founding_casa()).await;

        let admit = || Command::Admit {
            network: Some("casa".to_owned()),
            payload: "not a payload".to_owned(),
        };
        let one = Arc::clone(&service);
        let other = Arc::clone(&service);
        let who = alice.clone();
        let also = alice.clone();

        let (first, second) = tokio::join!(
            tokio::spawn(async move { one.handle_for(&who, admit()).await }),
            tokio::spawn(async move { other.handle_for(&also, admit()).await }),
        );
        let first = first.expect("the task finished");
        let second = second.expect("the task finished");

        // Both payloads are nonsense, so neither opens an enrolment — what is
        // asserted is that nothing raced into one: after two at once, there is
        // still no enrolment open, and a third is answered rather than wedged.
        assert!(service.pending.lock().await.is_none(), "neither left one half-open");
        for answered in [&first, &second] {
            assert!(
                !matches!(answered, Outcome::NotAllowed { .. }),
                "both were hers to ask: {answered:?}"
            );
        }

        let third = service.handle_for(&alice, Command::Status).await;
        assert!(matches!(third, Outcome::Reported(_)), "and the daemon answers on: {third:?}");
    }

    // ---- one test per row of the table -------------------------------------

    /// Two people, and a network that is one of theirs.
    async fn alices_casa() -> (
        Service,
        crate::control::Caller,
        crate::control::Caller,
        crate::state::Paths,
        tempfile::TempDir,
    ) {
        let (service, _machine, scratch) = unjoined().await;
        let alice = crate::control::Caller::Identified {
            name: "S-1-5-21-alice".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };
        let bob = crate::control::Caller::Identified {
            name: "S-1-5-21-bob".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };

        service.handle_for(&alice, founding_casa()).await;
        let paths = service.home().paths_for(&Label::new("casa").expect("valid"));
        assert_eq!(Some("S-1-5-21-alice".to_owned()), crate::state::read_owner(&paths));

        (service, alice, bob, paths, scratch)
    }

    /// **Reading is answered for a person who owns nothing.**
    ///
    /// The row that is easy to get wrong in the safe-looking direction: refusing
    /// a `Status` would mean the second person on a machine could not find out
    /// why nothing works. They are answered — and what they are shown is theirs,
    /// which here is nothing.
    #[tokio::test]
    async fn reading_is_answered_and_shows_only_what_is_yours() {
        let (service, _alice, bob, _paths, _scratch) = alices_casa().await;

        let seen = service.handle_for(&bob, Command::Status).await;
        let Outcome::Reported(report) = seen else { panic!("he is answered: {seen:?}") };

        assert!(report.networks.is_empty(), "and shown none of hers: {:?}", report.networks);
        assert_eq!(1, report.elsewhere, "but told that one is somebody's");
        let note = report.note.unwrap_or_default();
        assert!(note.contains("somebody else"), "in words: {note}");
        assert!(!note.contains("casa"), "and not by name, which is the telling part: {note}");
    }

    /// **Changing a tunnel is the owner's.**
    #[tokio::test]
    async fn changing_a_tunnel_is_refused_to_anybody_else() {
        let (service, _alice, bob, _paths, _scratch) = alices_casa().await;

        for asked in [
            Command::Up { network: Some("casa".to_owned()) },
            Command::Down { network: Some("casa".to_owned()) },
        ] {
            let refused = service.handle_for(&bob, asked.clone()).await;
            let Outcome::NotAllowed { message } = refused else {
                panic!("`{asked:?}` is not his to ask: {refused:?}");
            };
            assert!(message.contains("casa"), "naming which: {message}");
            assert!(message.contains(crate::control::AUTHORISATION), "and why: {message}");
        }
    }

    /// **Acting on a roster is the owner's.**
    #[tokio::test]
    async fn acting_on_a_roster_is_refused_to_anybody_else() {
        let (service, _alice, bob, _paths, _scratch) = alices_casa().await;

        for asked in [
            Command::Admit { network: Some("casa".to_owned()), payload: "anything".to_owned() },
            Command::Revoke {
                network: Some("casa".to_owned()),
                target: crate::control::Target::Name("laptop".to_owned()),
                reason: "because".to_owned(),
            },
            Command::Forget { label: "casa".to_owned(), last_admin: false },
        ] {
            let refused = service.handle_for(&bob, asked.clone()).await;
            assert!(
                matches!(refused, Outcome::NotAllowed { .. }),
                "`{asked:?}` is not his to ask: {refused:?}"
            );
        }
    }

    /// **Stopping the daemon is an administrator's, and it keeps running.**
    ///
    /// The refusal is worth nothing if the daemon stops anyway — so what is
    /// asserted is the machine afterwards, not only the answer.
    #[tokio::test]
    async fn stopping_is_refused_to_anybody_who_may_not_act_on_the_machine() {
        let (service, alice, bob, _paths, _scratch) = alices_casa().await;

        for who in [&alice, &bob] {
            let refused = service.handle_for(who, Command::Stop).await;
            let Outcome::NotAllowed { message } = refused else {
                panic!("an ordinary person does not stop the daemon: {refused:?}");
            };
            assert!(message.contains("administrator"), "naming who may: {message}");
            assert!(!service.is_stopping().await, "and it is still running");
        }

        // And it is not a bar nobody can clear.
        let root = crate::control::Caller::Identified {
            name: "S-1-5-21-root".to_owned(),
            privileged: true,
            could_be_privileged: false,
        };
        let stopped = service.handle_for(&root, Command::Stop).await;
        assert!(
            !matches!(stopped, Outcome::NotAllowed { .. }),
            "an administrator may: {stopped:?}"
        );
    }

    /// **A refusal for want of authority is not the roster refusing.**
    ///
    /// The two have entirely different remedies — one is an account on this
    /// machine, the other is an admin somewhere — so a person who cannot tell
    /// them apart goes to the wrong one. This one names authority and says
    /// nothing about membership, and it is not reported as the daemon failing.
    #[tokio::test]
    async fn the_two_refusals_cannot_be_confused() {
        let (service, _alice, bob, _paths, _scratch) = alices_casa().await;

        let refused =
            service.handle_for(&bob, Command::Up { network: Some("casa".to_owned()) }).await;
        let Outcome::NotAllowed { message } = refused else {
            panic!("its own answer, not a failure: {refused:?}");
        };

        assert!(message.contains(crate::control::AUTHORISATION), "it names authority: {message}");
        for roster in ["member", "roster", "revoked", "admitted", "expelled", "device"] {
            assert!(
                !message.to_lowercase().contains(roster),
                "`{roster}` would send a person to an admin over an account: {message}"
            );
        }
    }

    /// Every command has an entry, and the ones that make a network need nobody.
    ///
    /// Pure, so it holds for every variant rather than for the ones a test
    /// happened to exercise. Founding and joining are the pair worth naming: a
    /// network that does not exist has no owner, and needing one would mean
    /// nobody could ever make the first.
    #[test]
    fn what_each_command_needs_is_what_the_table_says() {
        use crate::control::Needs;

        assert_eq!(Needs::Nobody, Command::Status.needs());
        assert_eq!(Needs::Nobody, Command::Waiting.needs());
        assert_eq!(Needs::Nobody, Command::Peers { network: None }.needs());
        assert_eq!(
            Needs::TheOwnerOf(Some("casa".to_owned())),
            Command::Peers { network: Some("casa".to_owned()) }.needs(),
            "naming one is asking about that one"
        );

        assert_eq!(
            Needs::Nobody,
            Command::Join { relay: String::new(), name: String::new() }.needs()
        );
        assert_eq!(
            Needs::TheOwnerOf(None),
            Command::Up { network: None }.needs(),
            "the only one there is, is still somebody's"
        );
        assert_eq!(Needs::WhoeverBeganTheAct, Command::Confirm.needs());
        assert_eq!(Needs::WhoeverBeganTheAct, Command::NotSigned { id: String::new() }.needs());
        assert_eq!(Needs::TheMachine, Command::Stop.needs());
        assert_eq!(Needs::TheMachine, Command::TakeOwnership { network: None }.needs());
    }

    // ---- whose a network is ------------------------------------------------

    /// **A hole found while writing this, not by a test failing.**
    ///
    /// Founding and joining both *pause*: for a certificate to be confirmed, for
    /// an admin to arrive, for a signature. On a machine that holds networks for
    /// more than one person, whoever completes the act is not necessarily
    /// whoever began it — and the pending act is machine-wide, so a second person
    /// can confirm one they did not start.
    ///
    /// Two things stop it, and this is the first: **he may not finish it at
    /// all.** `Needs::WhoeverBeganTheAct` is decided against the caller the
    /// pending act carries, so the second person is refused before anything is
    /// written — and refused naming authority, not told the network failed.
    ///
    /// The second is that the owner is carried rather than read at the end, and
    /// `the_owner_recorded_is_the_one_the_act_carried` is what holds that.
    #[tokio::test]
    async fn a_second_person_cannot_finish_an_act_they_did_not_begin() {
        let (service, _machine, _scratch) = unjoined().await;
        let alice = crate::control::Caller::Identified {
            name: "S-1-5-21-alice".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };
        let bob = crate::control::Caller::Identified {
            name: "S-1-5-21-bob".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };

        // Alice begins a founding that stops to have a certificate confirmed.
        *service.pending.lock().await = Some(Pending::Founding {
            label: Label::new("casa").expect("valid"),
            wanted: crate::founding::Founding {
                name: "desktop".to_owned(),
                suffix: "home.internal".to_owned(),
                relay: None,
                rendezvous: None,
                certificate: None,
                ipv4_range: None,
            },
            for_whom: alice,
        });

        // Bob tries to confirm it, and cannot.
        let refused = service.handle_for(&bob, Command::Confirm).await;
        let Outcome::NotAllowed { message } = refused else {
            panic!("he did not begin it: {refused:?}");
        };
        assert!(message.contains(crate::control::AUTHORISATION), "naming why: {message}");

        let paths = service.home().paths_for(&Label::new("casa").expect("valid"));
        assert_eq!(None, crate::state::read_owner(&paths), "and nothing came into being");
    }

    /// **The owner recorded is the one carried, not the one asking.**
    ///
    /// The belt to the braces above. Whoever is at the keyboard is refused now,
    /// so a network reaching the end with the wrong owner would need that refusal
    /// to be wrong first — and a rule held up by one check is a rule that goes
    /// the moment somebody has a reason to relax it.
    ///
    /// So this asks the question the refusal now hides: finish an act that
    /// belongs to Alice while the daemon believes Bob is asking, and see whose it
    /// is. Read at the end, it would be his.
    #[tokio::test]
    async fn the_owner_recorded_is_the_one_the_act_carried() {
        let (service, _machine, _scratch) = unjoined().await;
        let alice = crate::control::Caller::Identified {
            name: "S-1-5-21-alice".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };
        let bob = crate::control::Caller::Identified {
            name: "S-1-5-21-bob".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };

        // Bob is who the daemon last heard from.
        *service.asking.lock().await = bob;

        // The act being finished is Alice's.
        let founded = service
            .finish_founding(
                Label::new("casa").expect("valid"),
                crate::founding::Founding {
                    name: "desktop".to_owned(),
                    suffix: "home.internal".to_owned(),
                    relay: None,
                    rendezvous: None,
                    certificate: None,
                    ipv4_range: None,
                },
                &alice,
            )
            .await;
        assert!(!matches!(founded, Outcome::Failed { .. }), "{founded:?}");

        let paths = service.home().paths_for(&Label::new("casa").expect("valid"));
        assert_eq!(
            Some("S-1-5-21-alice".to_owned()),
            crate::state::read_owner(&paths),
            "it is hers: she asked for it, and he only happened to be the last one heard from"
        );
    }

    /// A platform that draws no distinction records nobody, and a network there
    /// is not made unusable by having no owner.
    #[tokio::test]
    async fn where_there_is_no_second_person_nothing_is_recorded() {
        let (service, _machine, _scratch) = unjoined().await;
        found_one(&service).await;

        let paths = service.home().paths_for(&Label::new("casa").expect("valid"));
        assert_eq!(None, crate::state::read_owner(&paths), "there is nobody to record");
        assert!(service.node().await.is_some(), "and the network is perfectly usable");
    }

    /// A network founded by somebody the platform can name says so, from the
    /// moment it exists.
    #[tokio::test]
    async fn a_network_founded_by_somebody_named_says_whose_it_is() {
        let (service, _machine, _scratch) = unjoined().await;
        let alice = crate::control::Caller::Identified {
            name: "S-1-5-21-alice".to_owned(),
            privileged: false,
            could_be_privileged: false,
        };

        let founded = service.handle_for(&alice, founding_casa()).await;
        assert!(!matches!(founded, Outcome::Failed { .. }), "{founded:?}");

        let paths = service.home().paths_for(&Label::new("casa").expect("valid"));
        assert_eq!(Some("S-1-5-21-alice".to_owned()), crate::state::read_owner(&paths));
    }

    // ---- a machine that cannot hold an admin's key -------------------------

    /// Keys on a machine whose key store cannot hold a signing key.
    ///
    /// Everything a member needs, and an explicit answer to the one question
    /// such a machine answers differently. The reason travels with the answer,
    /// because a person told *"this machine cannot"* and not why goes looking in
    /// the wrong place.
    struct MemberOnly;

    impl crate::keys::Keys for MemberOnly {
        fn identity(&self, paths: &Paths) -> Result<NodeIdentity> {
            crate::state::identity_of(paths)
        }

        fn admin_refusal(&self) -> Option<String> {
            Some("this machine has no key store that can hold one".to_owned())
        }
    }

    #[tokio::test]
    async fn founding_is_refused_where_the_key_could_not_be_protected() {
        let (service, _machine, scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(MemberOnly));

        let refused = service.handle(founding_casa()).await;
        let (Outcome::Declined { message } | Outcome::Failed { message, .. }) = refused else {
            panic!("founding must be refused: {refused:?}");
        };
        assert!(message.contains("no key store"), "it names the reason: {message}");
        assert!(message.contains("member"), "and says what the device can do: {message}");

        // Before anything was created, which is the difference between a refusal
        // and a rollback.
        let paths = service.home().paths_for(&Label::new("casa").expect("valid"));
        assert!(!paths.root().exists(), "nothing was written");
        let survey = Home::under(scratch.path()).survey().expect("surveys");
        assert!(survey.unreadable.is_empty(), "and nothing is reported as unusable");
    }

    /// An admin role such a machine is given is declared, not exercised.
    ///
    /// A role is not a capability. The roster may say this device is an admin —
    /// another admin may have promoted it — and signing on the strength of that
    /// would put the network's authority behind a key the platform cannot
    /// protect, which is the finding being closed.
    #[tokio::test]
    async fn an_admin_role_this_machine_cannot_hold_is_declared_and_not_used() {
        let fixture = fixture(None).await;
        let founder = Arc::clone(
            fixture.service.node().await.expect("the fixture holds a network").identity(),
        );
        let laptop = add_a_device(&fixture.service, &founder).await;
        fixture.service.admit(&laptop).await.expect("admits");

        // From here this machine cannot hold an admin's key, though the roster
        // still says it is one.
        let service = fixture.service.with_keys(Arc::new(MemberOnly));

        let refused = service
            .handle(Command::Revoke {
                network: None,
                target: crate::control::Target::Name("laptop".to_owned()),
                reason: "sold".to_owned(),
            })
            .await;
        let (Outcome::Declined { message } | Outcome::Failed { message, .. }) = refused else {
            panic!("it must refuse rather than sign: {refused:?}");
        };
        assert!(message.contains("no key store"), "naming why: {message}");
        assert!(message.contains("Nothing was signed"), "and that nothing happened: {message}");

        let node = service.node().await.expect("the fixture holds a network");
        assert!(node.state().await.expect("derives").revoked.is_empty(), "and nothing was");
    }

    /// Being a member is untouched by any of this.
    #[tokio::test]
    async fn a_machine_that_cannot_be_an_admin_is_still_a_member() {
        let fixture = fixture(None).await;
        let service = fixture.service.with_keys(Arc::new(MemberOnly));

        // It holds its network, reports it, and brings it up.
        assert!(service.node().await.is_some(), "it holds the network");
        service.bring_up(None).await.expect("comes up");
        assert_eq!(Tunnel::Up, service.tunnel().await);
        assert!(!service.report().await.networks.is_empty(), "and says so");
    }

    /// A key this process holds takes none of the two-step path.
    ///
    /// The whole of the branch is `answers_here`, so a device that holds its own
    /// key must be exactly as it was: one command, one answer, nobody asked.
    #[tokio::test]
    async fn a_key_held_here_finishes_in_one_exchange() {
        let fixture = fixture(None).await;
        let founder = Arc::clone(
            fixture.service.node().await.expect("the fixture holds a network").identity(),
        );
        let laptop = add_a_device(&fixture.service, &founder).await;
        fixture.service.admit(&laptop).await.expect("admits");

        let done = fixture
            .service
            .handle(Command::Revoke {
                network: None,
                target: crate::control::Target::Name("laptop".to_owned()),
                reason: "sold".to_owned(),
            })
            .await;
        assert!(
            matches!(done, Outcome::Reported(_)),
            "a held key signs where it stands, and is never asked for: {done:?}"
        );

        let node = fixture.service.node().await.expect("the fixture holds a network");
        assert!(!node.state().await.expect("derives").revoked.is_empty(), "and it is revoked");
    }

    /// The report says where each network's key is kept, and says it per network.
    ///
    /// A device may hold one network founded where the key store could keep the
    /// key and another that predates it, so this is not a fact about the device.
    #[tokio::test]
    async fn each_network_says_where_its_signing_key_is_kept() {
        let custodian = Arc::new(Lockable::new(0x3a));
        let (service, _machine, _scratch) = unjoined().await;

        // One network with the key in a store.
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));
        found_one(&service).await;

        // And one with the key held here.
        let service = service.with_keys(Arc::new(crate::keys::PlatformKeys));
        let founded = service
            .handle(Command::Found {
                label: "lavoro".to_owned(),
                name: "desktop".to_owned(),
                suffix: "work.internal".to_owned(),
                relay: None,
                rendezvous: None,
                certificate: crate::control::Certificate::None,
                ipv4_range: None,
            })
            .await;
        assert!(!matches!(founded, Outcome::Failed { .. }), "{founded:?}");

        let report = service.report().await;
        let custody = |label: &str| {
            report
                .networks
                .iter()
                .find(|network| network.label == label)
                .map(|network| network.custody)
        };
        assert_eq!(Some(crate::control::Custody::KeyStore), custody("casa"));
        assert_eq!(Some(crate::control::Custody::HeldHere), custody("lavoro"));
    }

    /// **A passphrase is not a key store**, and the report is the platform's
    /// word for which one it is, not a guess from the identity.
    #[tokio::test]
    async fn a_passphrase_is_reported_as_its_own_custody() {
        struct Sealed(Keystore);

        impl crate::keys::Keys for Sealed {
            fn identity(&self, paths: &Paths) -> Result<NodeIdentity> {
                self.0.identity(paths)
            }

            fn custody_of(&self, _identity: &NodeIdentity) -> crate::control::Custody {
                crate::control::Custody::Passphrase
            }
        }

        let custodian = Arc::new(Lockable::new(0x3b));
        let (service, _machine, _scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Sealed(Keystore { custodian })));
        found_one(&service).await;

        let report = service.report().await;
        let network = report.networks.first().expect("one network");
        assert_eq!(crate::control::Custody::Passphrase, network.custody);
        assert_eq!("in a file sealed with a passphrase", network.custody.to_string());
        assert_ne!(
            crate::control::Custody::KeyStore.to_string(),
            network.custody.to_string(),
            "never worded as a key store"
        );
    }

    /// A machine that cannot be an admin says so, even holding no network.
    ///
    /// It is the answer to why founding was refused, and a device that has just
    /// been refused holds nothing for the answer to hang on.
    #[tokio::test]
    async fn a_machine_that_cannot_be_an_admin_says_so_holding_nothing() {
        let (service, _machine, _scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(MemberOnly));

        let report = service.report().await;
        assert!(report.networks.is_empty(), "it holds nothing");
        let said = report.admin_refusal.clone().expect("and says why it cannot be an admin");
        assert!(said.contains("no key store"), "{said}");

        let drawn = report.to_string();
        assert!(drawn.contains("cannot be an admin"), "and it is drawn: {drawn}");
        assert!(drawn.contains("member"), "with what it can do instead: {drawn}");
    }

    /// And nothing is said about how a peer holds its key.
    ///
    /// This device cannot observe that. Saying it would be presenting an
    /// assumption as an observation, which §2.5 is about.
    #[tokio::test]
    async fn nothing_is_claimed_about_how_a_peer_holds_its_key() {
        let fixture = fixture(None).await;
        let founder = Arc::clone(
            fixture.service.node().await.expect("the fixture holds a network").identity(),
        );
        let laptop = add_a_device(&fixture.service, &founder).await;
        fixture.service.admit(&laptop).await.expect("admits");

        let report = fixture.service.report().await;
        let peers = report.peers(None).to_string();
        assert!(peers.contains("laptop"), "the peer is listed: {peers}");
        assert!(
            !peers.contains("key store") && !peers.contains("signing key"),
            "and nothing is said about its key: {peers}"
        );
    }

    // ---- keys a custodian holds --------------------------------------------

    /// A P-256 key that signs while allowed and declines otherwise, as a phone's
    /// keystore behind the lock screen does.
    struct Lockable {
        key: roster::sign::P256Signer,
        allowed: std::sync::atomic::AtomicBool,
        /// Whether this process can reach the key at all.
        ///
        /// A phone's keystore can: `sign_request` blocks and comes back. A
        /// desktop's machine key store cannot, because it answers only in the
        /// session of the person who owns it, and that is a different process.
        /// Held on one custodian so a test can found a network while the key is
        /// reachable and then take it away — the same identity, seen from the two
        /// sides of that line.
        here: std::sync::atomic::AtomicBool,
        /// How many more times it will sign before a person stops answering.
        left: std::sync::atomic::AtomicUsize,
    }

    impl Lockable {
        /// Reachable and willing: a keystore behind an unlocked phone.
        fn new(scalar: u8) -> Self {
            Self {
                key: roster::sign::P256Signer::from_scalar([scalar; 32]).expect("inside the order"),
                allowed: std::sync::atomic::AtomicBool::new(true),
                here: std::sync::atomic::AtomicBool::new(true),
                left: std::sync::atomic::AtomicUsize::new(usize::MAX),
            }
        }

        /// Signs `count` more times, and declines after that — a person who
        /// answered the first prompts and not the next.
        fn signs_only(&self, count: usize) {
            self.left.store(count, std::sync::atomic::Ordering::SeqCst);
        }

        /// The key stops being usable from this process.
        fn moves_out_of_reach(&self) {
            self.here.store(false, std::sync::atomic::Ordering::SeqCst);
        }

        /// Signs as the component that can reach the key would.
        fn signs(&self, message: &[u8]) -> Vec<u8> {
            roster::sign::Signer::sign(&self.key, message).expect("signs")
        }
    }

    impl identity::detached::KeyCustodian for Lockable {
        fn public_key(&self) -> roster::sign::PublicKey {
            roster::sign::Signer::public_key(&self.key)
        }

        fn answers_here(&self) -> bool {
            self.here.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn sign_request(
            &self,
            request: &identity::detached::SigningRequest,
        ) -> identity::Result<Vec<u8>> {
            // The second net, and it is second on purpose.
            //
            // Whether an act stops and asks is decided from the key — from
            // `answers_here` — never from a list of command names, because a
            // list is a thing somebody forgets to add to. An act that forgets to
            // ask is caught first by `SigningKey::sign_request`, which refuses
            // with `SignedElsewhere` rather than blocking on something that will
            // never answer; `identity`'s own tests hold that, and removing a
            // branch here produces that refusal and not this panic.
            //
            // This one catches the case that net does not: somebody removing the
            // net. It costs one load and it means every test below that puts a
            // key out of reach is also a test that nothing signed with it behind
            // their back — including an act added later that nobody thought to
            // check here.
            assert!(
                self.here.load(std::sync::atomic::Ordering::SeqCst),
                "something signed with a key this process cannot reach. The act must prepare \
                 the request and have somebody else sign it; whatever reached here decided \
                 that from something other than the key."
            );
            let budget = self.left.fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |left| left.checked_sub(1),
            );
            if self.allowed.load(std::sync::atomic::Ordering::SeqCst) && budget.is_ok() {
                Ok(roster::sign::Signer::sign(&self.key, request.message())?)
            } else {
                Err(identity::Error::Declined)
            }
        }
    }

    /// Keys whose signing half only the custodian holds, stored the way a phone
    /// stores them: the public half and a name, never the private material.
    struct Keystore {
        custodian: Arc<Lockable>,
    }

    impl identity::store::Custodians for Keystore {
        fn find(
            &self,
            _reference: &str,
        ) -> identity::Result<Option<Arc<dyn identity::detached::KeyCustodian + Send + Sync>>>
        {
            Ok(Some(Arc::clone(&self.custodian)
                as Arc<dyn identity::detached::KeyCustodian + Send + Sync>))
        }
    }

    impl crate::keys::Keys for Keystore {
        fn identity(&self, paths: &Paths) -> Result<NodeIdentity> {
            let path = paths.identity();
            let failed = |cause: identity::Error| Error::State {
                path: path.clone(),
                cause: cause.to_string(),
            };
            if path.exists() {
                return identity::store::load_with(&path, &identity::store::PlatformSealer, self)
                    .map_err(failed);
            }
            paths.create()?;
            let transport = identity::PrivateKey::generate(roster::types::Algorithm::Ed25519)
                .map_err(failed)?;
            let attestation = identity::PrivateKey::generate(roster::types::Algorithm::Ed25519)
                .map_err(failed)?;
            let custodian = Arc::clone(&self.custodian)
                as Arc<dyn identity::detached::KeyCustodian + Send + Sync>;
            let made = NodeIdentity::with_custodian(
                "peerfectly.test.signing",
                custodian,
                transport,
                attestation,
            )
            .map_err(failed)?;
            identity::store::save_with(&made, &path, &identity::store::PlatformSealer)
                .map_err(failed)?;
            Ok(made)
        }
    }

    /// Keys whose signing key must be **made** somewhere else, not only used
    /// there.
    ///
    /// The machine's key store on Windows behaves like this: it asks a person
    /// before it will protect a key, the asking needs a desktop, and a daemon
    /// running as the machine has none.
    struct Elsewhere {
        inner: Keystore,
        /// Set when the daemon was told the key exists.
        told: std::sync::atomic::AtomicBool,
        /// Every name handed out, in order. Fresh each time, as the platform's are.
        named: std::sync::Mutex<Vec<String>>,
    }

    impl identity::store::Custodians for Elsewhere {
        fn find(
            &self,
            reference: &str,
        ) -> identity::Result<Option<Arc<dyn identity::detached::KeyCustodian + Send + Sync>>>
        {
            self.inner.find(reference)
        }
    }

    impl crate::keys::Keys for Elsewhere {
        fn identity(&self, paths: &Paths) -> Result<NodeIdentity> {
            self.inner.identity(paths)
        }

        fn must_be_made_elsewhere(&self, paths: &Paths) -> Option<crate::keys::Asked> {
            if paths.identity().exists() {
                return None;
            }
            let mut named = self.named.lock().expect("not poisoned");
            let name = format!("peerfectly.casa.{}.signing", named.len());
            named.push(name.clone());
            Some(crate::keys::Asked { name, network: "casa".to_owned() })
        }

        fn identity_from(&self, paths: &Paths, made: &crate::keys::Made) -> Result<NodeIdentity> {
            let asked = self.named.lock().expect("not poisoned").first().cloned();
            assert_eq!(
                asked.as_deref(),
                Some(made.name.as_str()),
                "the key the person was asked to make"
            );
            self.told.store(true, std::sync::atomic::Ordering::SeqCst);
            self.inner.identity(paths)
        }
    }

    /// **A join's key is asked for with no network named**: the network has no
    /// name here until it arrives, and the label it waits under is a
    /// placeholder a person must not be shown as if it were one.
    #[tokio::test]
    async fn a_join_asks_for_its_key_without_naming_a_placeholder() {
        let custodian = Arc::new(Lockable::new(0x3e));
        let keys = Arc::new(Elsewhere {
            inner: Keystore { custodian: Arc::clone(&custodian) },
            told: std::sync::atomic::AtomicBool::new(false),
            named: std::sync::Mutex::default(),
        });
        let (service, _machine, _scratch) = unjoined().await;
        let service = service.with_keys(Arc::clone(&keys) as Arc<dyn crate::keys::Keys>);

        let asked = service
            .handle(Command::Join {
                relay: "https://127.0.0.1:1".to_owned(),
                name: "laptop".to_owned(),
            })
            .await;
        let Outcome::NeedsKey(wanted) = asked else {
            panic!("it must stop and ask for a key: {asked:?}");
        };
        assert_eq!("", wanted.network, "no name, rather than the placeholder");
    }

    /// **A founding stops to have its key made, and nothing exists until it is.**
    ///
    /// Found on a real machine: the daemon became a service, and the key store's
    /// *protect this key* prompt has no desktop in Session 0 — `NCryptFinalizeKey`
    /// came back `0x800706BE`. Making the key had to move to where the person is,
    /// which is where the signature already went, one step earlier.
    #[tokio::test]
    async fn a_founding_stops_to_have_its_key_made_where_a_person_is() {
        let custodian = Arc::new(Lockable::new(0x32));
        let keys = Arc::new(Elsewhere {
            inner: Keystore { custodian: Arc::clone(&custodian) },
            told: std::sync::atomic::AtomicBool::new(false),
            named: std::sync::Mutex::default(),
        });
        let (service, _machine, _scratch) = unjoined().await;
        let service = service.with_keys(Arc::clone(&keys) as Arc<dyn crate::keys::Keys>);

        let asked = service.handle(founding_casa()).await;
        let Outcome::NeedsKey(wanted) = asked else {
            panic!("it must stop and ask for a key: {asked:?}");
        };
        assert_eq!(
            keys.named.lock().expect("not poisoned").first(),
            Some(&wanted.name),
            "the name drawn"
        );
        assert_eq!("casa", wanted.network, "what the key store's prompt will name");

        // **Nothing exists yet**, which is what makes the prompt honest: a person
        // is shown one only for an act that has already passed every refusal.
        let paths = service.home().paths_for(&Label::new("casa").expect("valid"));
        assert!(!paths.identity().exists(), "no identity before the key");
        assert!(!keys.told.load(std::sync::atomic::Ordering::SeqCst));

        // An answer under the wrong name ends nothing.
        let wrong = service
            .handle(Command::KeyMade { id: "k-nonsense".to_owned(), public: vec![1, 2, 3] })
            .await;
        assert!(matches!(wrong, Outcome::Failed { .. }), "{wrong:?}");
        assert!(!keys.told.load(std::sync::atomic::Ordering::SeqCst), "and nothing was built");

        // And the right one takes the founding up where it stopped — which is the
        // next thing this key cannot do here, signing.
        let on =
            service.handle(Command::KeyMade { id: wanted.id.clone(), public: vec![4, 5, 6] }).await;
        assert!(keys.told.load(std::sync::atomic::Ordering::SeqCst), "the key was taken up");
        // This fixture's key does answer here once it exists, so the founding runs
        // to the end. What is asserted is that it **resumed** — the act was taken
        // up where it stopped rather than having to be asked for again.
        assert!(matches!(on, Outcome::Reported(_)), "the founding carries on: {on:?}");
        assert!(paths.identity().exists(), "and the identity is written");
        assert!(service.node().await.is_some(), "and the network exists");

        // The act was taken out: a second answer completes nothing.
        let again = service.handle(Command::KeyMade { id: wanted.id, public: vec![4, 5, 6] }).await;
        assert!(matches!(again, Outcome::Failed { .. }), "{again:?}");
    }

    /// Answers a batch as the component that can reach the key would: one
    /// signature per item, in order.
    async fn answer_batch(
        service: &Service,
        wanted: crate::control::SignaturesWanted,
        custodian: &Lockable,
    ) -> Outcome {
        let signatures = wanted.items.iter().map(|item| custodian.signs(&item.message)).collect();
        service.handle(Command::Signed { id: wanted.id, signatures }).await
    }

    /// A revocation on a device whose key this process cannot reach.
    ///
    /// The exchange end to end: the daemon prepares and stops without signing,
    /// somebody else signs the exact bytes it prepared, and the revocation lands.
    /// Nothing about the roster's rules changes because of where the key lives.
    #[tokio::test]
    async fn a_key_out_of_reach_turns_an_act_into_a_batch() {
        let custodian = Arc::new(Lockable::new(0x32));
        let (service, _machine, _scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));

        found_one(&service).await;
        let founder =
            Arc::clone(service.node().await.expect("the fixture holds a network").identity());
        let laptop = add_a_device_signed_by(&service, &founder, &custodian).await;
        service.admit(&laptop).await.expect("admits");

        // From here the key is where this process cannot reach it.
        custodian.moves_out_of_reach();

        let asked = service.handle(revoking_laptop()).await;
        let Outcome::NeedsSignatures(wanted) = asked else {
            panic!("the daemon must stop and ask, not sign: {asked:?}");
        };
        assert_eq!("casa", wanted.network, "it says whose key");
        // Founded a moment ago with its snapshot, so none is owed: one item.
        assert_eq!(1, wanted.items.len(), "{wanted:?}");
        let item = wanted.items.first().expect("one");
        assert!(!item.message.is_empty(), "there are bytes to sign");
        assert!(!item.payload.is_empty(), "and an act to show a person");
        assert_eq!(crate::control::SigningKind::Operation, item.kind);

        // Nothing has happened yet, which is the whole of what "prepared" means.
        let node = service.node().await.expect("the fixture holds a network");
        assert!(
            node.state().await.expect("derives").revoked.is_empty(),
            "nothing was signed while the request was outstanding"
        );

        let done = answer_batch(&service, wanted, &custodian).await;
        assert!(matches!(done, Outcome::Reported(_)), "{done:?}");

        assert!(
            !node.state().await.expect("derives").revoked.is_empty(),
            "and the revocation is in the roster"
        );
    }

    /// A signature over something else completes nothing.
    ///
    /// The binding is the cryptography's: what was prepared is what verifies, so
    /// a signature obtained for one act cannot finish another.
    #[tokio::test]
    async fn a_signature_over_other_bytes_completes_nothing() {
        let custodian = Arc::new(Lockable::new(0x33));
        let (service, _machine, _scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));

        found_one(&service).await;
        let founder =
            Arc::clone(service.node().await.expect("the fixture holds a network").identity());
        let laptop = add_a_device_signed_by(&service, &founder, &custodian).await;
        service.admit(&laptop).await.expect("admits");
        custodian.moves_out_of_reach();

        let asked = service.handle(revoking_laptop()).await;
        let Outcome::NeedsSignatures(wanted) = asked else { panic!("must ask: {asked:?}") };

        let refused = service
            .handle(Command::Signed {
                id: wanted.id.clone(),
                signatures: vec![custodian.signs(b"some other bytes entirely")],
            })
            .await;
        assert!(matches!(refused, Outcome::Failed { .. }), "{refused:?}");

        let node = service.node().await.expect("the fixture holds a network");
        assert!(node.state().await.expect("derives").revoked.is_empty(), "and nothing was revoked");
    }

    /// One answer, one act. A replayed answer finds nothing left to complete,
    /// which matters because a revocation cannot be withdrawn.
    #[tokio::test]
    async fn the_same_signature_cannot_be_used_twice() {
        let custodian = Arc::new(Lockable::new(0x34));
        let (service, _machine, _scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));

        found_one(&service).await;
        let founder =
            Arc::clone(service.node().await.expect("the fixture holds a network").identity());
        let laptop = add_a_device_signed_by(&service, &founder, &custodian).await;
        service.admit(&laptop).await.expect("admits");
        custodian.moves_out_of_reach();

        let asked = service.handle(revoking_laptop()).await;
        let Outcome::NeedsSignatures(wanted) = asked else { panic!("must ask: {asked:?}") };
        let signatures: Vec<Vec<u8>> =
            wanted.items.iter().map(|item| custodian.signs(&item.message)).collect();

        let first = service
            .handle(Command::Signed { id: wanted.id.clone(), signatures: signatures.clone() })
            .await;
        assert!(matches!(first, Outcome::Reported(_)), "{first:?}");

        let again = service.handle(Command::Signed { id: wanted.id, signatures }).await;
        assert!(
            matches!(again, Outcome::Failed { .. }),
            "the second time finds nothing: {again:?}"
        );
    }

    /// A person declining says so, and the daemon lets the act go at once rather
    /// than holding it until it expires.
    #[tokio::test]
    async fn saying_it_will_not_be_signed_ends_the_act() {
        let custodian = Arc::new(Lockable::new(0x35));
        let (service, _machine, _scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));

        found_one(&service).await;
        let founder =
            Arc::clone(service.node().await.expect("the fixture holds a network").identity());
        let laptop = add_a_device_signed_by(&service, &founder, &custodian).await;
        service.admit(&laptop).await.expect("admits");
        custodian.moves_out_of_reach();

        let asked = service.handle(revoking_laptop()).await;
        let Outcome::NeedsSignatures(wanted) = asked else { panic!("must ask: {asked:?}") };

        assert_eq!(
            Outcome::Done,
            service.handle(Command::NotSigned { id: wanted.id.clone() }).await
        );

        let late = answer_batch(&service, wanted, &custodian).await;
        assert!(matches!(late, Outcome::Failed { .. }), "the act is over: {late:?}");

        let node = service.node().await.expect("the fixture holds a network");
        assert!(
            node.state().await.expect("derives").revoked.is_empty(),
            "and the network is exactly as it was"
        );
    }

    /// **Founding on a device whose key this process cannot reach is one batch.**
    ///
    /// The genesis and the network's first snapshot are prepared together —
    /// the snapshot over a preview, since the genesis is not signed yet — shown
    /// together and answered together. There is no second request: a person is
    /// asked once, and the network exists with its snapshot from the moment it
    /// exists at all.
    #[tokio::test]
    async fn founding_with_a_key_out_of_reach_is_one_batch() {
        let custodian = Arc::new(Lockable::new(0x36));
        custodian.moves_out_of_reach();
        let (service, _machine, scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));

        let asked = service.handle(founding_casa()).await;
        let Outcome::NeedsSignatures(wanted) = asked else {
            panic!("the daemon must stop and ask, not sign: {asked:?}");
        };
        assert_eq!("casa", wanted.network);
        let kinds: Vec<crate::control::SigningKind> =
            wanted.items.iter().map(|item| item.kind).collect();
        assert_eq!(
            vec![crate::control::SigningKind::Operation, crate::control::SigningKind::Snapshot],
            kinds,
            "the network itself, then its first snapshot"
        );
        let genesis = roster::types::OperationCore::decode(
            &wanted.items.first().expect("the genesis").payload,
        )
        .expect("an operation");
        let snapshot =
            roster::snapshot::Snapshot::decode(&wanted.items.get(1).expect("the snapshot").payload)
                .expect("a snapshot");
        assert_eq!(vec![genesis.id()], snapshot.heads, "the snapshot covers the genesis");

        // No network yet, and nothing that a later start would report as one it
        // cannot carry.
        assert!(service.node().await.is_none(), "nothing was founded while the request was out");
        let paths = service.home().paths_for(&Label::new("casa").expect("valid"));
        assert!(!paths.roster().exists(), "and no log was written");

        let done = answer_batch(&service, wanted, &custodian).await;
        assert!(matches!(done, Outcome::Reported(_)), "one answer, and done: {done:?}");

        let node = service.node().await.expect("the network exists now");
        assert_eq!(1, node.state().await.expect("derives").devices.len());
        assert!(
            crate::state::read_snapshot(&paths).is_some(),
            "the network has a snapshot from its first moment, as it must"
        );
        assert!(
            crate::state::read_attestation(&paths).is_some(),
            "and it is dated: the attestation key asks nobody"
        );
        let survey = Home::under(scratch.path()).survey().expect("surveys");
        assert!(survey.unreadable.is_empty(), "and nothing is unusable");
    }

    /// **One bad signature voids the whole batch.** The genesis is signed
    /// properly and the snapshot is not: nothing is founded, and the refusal
    /// names the item — where signing one at a time left the network standing
    /// without its snapshot.
    #[tokio::test]
    async fn one_bad_signature_voids_a_founding() {
        let custodian = Arc::new(Lockable::new(0x39));
        custodian.moves_out_of_reach();
        let (service, _machine, scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));

        let asked = service.handle(founding_casa()).await;
        let Outcome::NeedsSignatures(wanted) = asked else { panic!("must ask: {asked:?}") };
        let genesis = custodian.signs(&wanted.items.first().expect("the genesis").message);

        let refused = service
            .handle(Command::Signed {
                id: wanted.id,
                signatures: vec![genesis, custodian.signs(b"not the snapshot")],
            })
            .await;
        let Outcome::Failed { message, .. } = refused else { panic!("refused: {refused:?}") };
        assert!(message.contains("item 2"), "and says which: {message}");

        assert!(service.node().await.is_none(), "no network");
        let paths = service.home().paths_for(&Label::new("casa").expect("valid"));
        assert!(!paths.root().exists(), "the attempt's directory is gone");
        let survey = Home::under(scratch.path()).survey().expect("surveys");
        assert!(survey.unreadable.is_empty(), "and nothing is reported as unusable");
    }

    /// A founding whose signatures never verify leaves nothing behind.
    ///
    /// The same obligation the synchronous path already carries for a declined
    /// prompt: an attempt that produced nothing must not be reported at the next
    /// start as a network this daemon cannot carry.
    #[tokio::test]
    async fn a_founding_nobody_signs_leaves_no_network_behind() {
        let custodian = Arc::new(Lockable::new(0x37));
        custodian.moves_out_of_reach();
        let (service, _machine, scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));

        let asked = service.handle(founding_casa()).await;
        let Outcome::NeedsSignatures(wanted) = asked else { panic!("must ask: {asked:?}") };

        let signatures = wanted.items.iter().map(|_| custodian.signs(b"not the genesis")).collect();
        let refused = service.handle(Command::Signed { id: wanted.id, signatures }).await;
        assert!(matches!(refused, Outcome::Failed { .. }), "{refused:?}");

        assert!(service.node().await.is_none(), "no network");
        let paths = service.home().paths_for(&Label::new("casa").expect("valid"));
        assert!(!paths.root().exists(), "the attempt's directory is gone");
        let survey = Home::under(scratch.path()).survey().expect("surveys");
        assert!(survey.unreadable.is_empty(), "and nothing is reported as unusable");
    }

    /// **Declining a founding leaves nothing**: no network, and not the
    /// directory and identity the founding had made before it stopped.
    #[tokio::test]
    async fn declining_a_founding_leaves_nothing() {
        let custodian = Arc::new(Lockable::new(0x3d));
        custodian.moves_out_of_reach();
        let (service, _machine, scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));

        let asked = service.handle(founding_casa()).await;
        let Outcome::NeedsSignatures(wanted) = asked else { panic!("must ask: {asked:?}") };
        let paths = service.home().paths_for(&Label::new("casa").expect("valid"));
        assert!(paths.root().exists(), "the founding made its directory before it asked");

        assert_eq!(Outcome::Done, service.handle(Command::NotSigned { id: wanted.id }).await);

        assert!(service.node().await.is_none(), "no network");
        assert!(!paths.root().exists(), "and no directory");
        let survey = Home::under(scratch.path()).survey().expect("surveys");
        assert!(survey.unreadable.is_empty(), "and nothing is reported as unusable");
    }

    /// **A founding left to expire leaves nothing either**, once the daemon next
    /// looks at what is waiting.
    #[tokio::test]
    async fn a_founding_left_to_expire_leaves_nothing() {
        let custodian = Arc::new(Lockable::new(0x3e));
        custodian.moves_out_of_reach();
        let (service, _machine, _scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));

        let asked = service.handle(founding_casa()).await;
        assert!(matches!(asked, Outcome::NeedsSignatures(_)), "{asked:?}");
        let paths = service.home().paths_for(&Label::new("casa").expect("valid"));

        // Something else is prepared after the founding's wait has run out.
        let lapsed = {
            let mut unsigned = service.unsigned.lock().await;
            let _later = unsigned.issue_for(
                Vec::new(),
                Resume::Possession,
                crate::clock::now_ms().saturating_add(crate::signing::WAITS_FOR + 1),
                crate::control::Caller::Unattributed,
            );
            unsigned.lapsed()
        };
        assert_eq!(1, lapsed.len(), "the founding expired");
        service.tidy_after(lapsed).await;

        assert!(!paths.root().exists(), "and its directory is gone");
    }

    /// **A roster that moved while a person decided voids the batch.** Another
    /// admin's operation arrives between preparing a revocation and answering
    /// it: what was shown is no longer what it would do, so nothing is applied
    /// and the person is told to run it again.
    #[tokio::test]
    async fn a_roster_that_moved_voids_the_batch() {
        let custodian = Arc::new(Lockable::new(0x3f));
        let (service, _machine, _scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));

        found_one(&service).await;
        let founder =
            Arc::clone(service.node().await.expect("the fixture holds a network").identity());
        let laptop = add_a_device_signed_by(&service, &founder, &custodian).await;
        service.admit(&laptop).await.expect("admits");
        custodian.moves_out_of_reach();

        let asked = service.handle(revoking_laptop()).await;
        let Outcome::NeedsSignatures(wanted) = asked else { panic!("must ask: {asked:?}") };

        // Meanwhile, an operation arrives.
        let tablet = add_named_device_signed_by(&service, &founder, &custodian, "tablet").await;
        service.admit(&tablet).await.expect("admits");

        let refused = answer_batch(&service, wanted, &custodian).await;
        let Outcome::Failed { message, .. } = refused else { panic!("refused: {refused:?}") };
        assert!(message.contains("changed while you were deciding"), "{message}");
        assert!(message.contains("Nothing was applied"), "{message}");

        let node = service.node().await.expect("the fixture holds a network");
        assert!(node.state().await.expect("derives").revoked.is_empty(), "nothing was revoked");
    }

    /// Founding the network these tests act on.
    /// A firewall held in memory: the rules exposing wrote, and what sweeps kept.
    #[derive(Default)]
    struct Firewalled {
        rules: std::sync::Mutex<Vec<crate::exposing::Rule>>,
    }

    impl Firewalled {
        fn rules(&self) -> Vec<crate::exposing::Rule> {
            self.rules.lock().expect("not poisoned").clone()
        }
    }

    #[async_trait::async_trait]
    impl crate::exposing::Exposing for Firewalled {
        async fn expose(&self, rule: &crate::exposing::Rule) -> core::result::Result<(), String> {
            let mut rules = self.rules.lock().expect("not poisoned");
            rules.retain(|held| {
                (held.network, held.protocol, held.port) != (rule.network, rule.protocol, rule.port)
            });
            rules.push(rule.clone());
            Ok(())
        }
        async fn unexpose(
            &self,
            network: &NetworkId,
            protocol: crate::exposing::Protocol,
            port: u16,
        ) -> core::result::Result<bool, String> {
            let mut rules = self.rules.lock().expect("not poisoned");
            let before = rules.len();
            rules.retain(|held| {
                (held.network, held.protocol, held.port) != (*network, protocol, port)
            });
            Ok(rules.len() != before)
        }
        async fn held(&self) -> core::result::Result<Vec<crate::exposing::Held>, String> {
            Ok(self
                .rules()
                .into_iter()
                .map(|rule| crate::exposing::Held {
                    network: rule.network,
                    protocol: rule.protocol,
                    port: rule.port,
                })
                .collect())
        }
        async fn forget(&self, network: &NetworkId) -> core::result::Result<usize, String> {
            let mut rules = self.rules.lock().expect("not poisoned");
            let before = rules.len();
            rules.retain(|held| held.network != *network);
            Ok(before.saturating_sub(rules.len()))
        }
        async fn sweep(&self, kept: &[NetworkId]) -> core::result::Result<usize, String> {
            let mut rules = self.rules.lock().expect("not poisoned");
            let before = rules.len();
            rules.retain(|held| kept.contains(&held.network));
            Ok(before.saturating_sub(rules.len()))
        }
    }

    fn casa_tcp(verb: &str, port: u16) -> Command {
        let network = Some("casa".to_owned());
        let protocol = crate::exposing::Protocol::Tcp;
        if verb == "expose" {
            Command::Expose { network, protocol, port }
        } else {
            Command::Unexpose { network, protocol, port }
        }
    }

    fn person(name: &str, privileged: bool) -> crate::control::Caller {
        crate::control::Caller::Identified {
            name: format!("S-1-5-21-{name}"),
            privileged,
            could_be_privileged: false,
        }
    }

    /// **The owner, as an administrator, and nobody else.** A firewall rule is
    /// the machine's: the owner without elevation is told the elevation is
    /// missing, and an administrator who is not the owner is told whose it is.
    #[tokio::test]
    async fn exposing_is_the_owners_as_an_administrator() {
        let (service, _machine, _scratch) = unjoined().await;
        let firewall = Arc::new(Firewalled::default());
        let service =
            service.with_exposing(Arc::clone(&firewall) as Arc<dyn crate::exposing::Exposing>);
        service.handle_for(&person("alice", false), founding_casa()).await;
        service.handle_for(&person("alice", false), Command::Up { network: None }).await;

        let unelevated =
            service.handle_for(&person("alice", false), casa_tcp("expose", 8000)).await;
        let Outcome::NotAllowed { message } = unelevated else { panic!("{unelevated:?}") };
        assert!(message.contains("administrator"), "the elevation is what is missing: {message}");

        let stranger = service.handle_for(&person("bob", true), casa_tcp("expose", 8000)).await;
        let Outcome::NotAllowed { message } = stranger else { panic!("{stranger:?}") };
        assert!(message.contains("somebody else"), "and the network is hers: {message}");
        assert!(firewall.rules().is_empty(), "nothing was written for either");

        let opened = service.handle_for(&person("alice", true), casa_tcp("expose", 8000)).await;
        let Outcome::Exposed { rules } = opened else { panic!("{opened:?}") };
        assert_eq!(
            vec![crate::exposing::Exposure {
                network: "casa".to_owned(),
                protocol: crate::exposing::Protocol::Tcp,
                port: 8000
            }],
            rules
        );
    }

    /// What is written is the network's own: its adapter, its prefix, its range.
    /// Exposing twice leaves one rule, and closing what is not open says so.
    #[tokio::test]
    async fn an_exposed_port_is_the_networks_alone() {
        let (service, _machine, _scratch) = unjoined().await;
        let firewall = Arc::new(Firewalled::default());
        let service =
            service.with_exposing(Arc::clone(&firewall) as Arc<dyn crate::exposing::Exposing>);
        let alice = person("alice", true);
        service.handle_for(&alice, founding_casa()).await;

        let off = service.handle_for(&alice, casa_tcp("expose", 8000)).await;
        let Outcome::Failed { message, .. } = off else { panic!("{off:?}") };
        assert!(message.contains("turn it on first"), "{message}");

        service.handle_for(&alice, Command::Up { network: None }).await;
        service.handle_for(&alice, casa_tcp("expose", 8000)).await;
        service.handle_for(&alice, casa_tcp("expose", 8000)).await;
        let [rule] = firewall.rules().try_into().expect("one rule, not two");
        assert_eq!("peerfectly casa", rule.interface);
        let state = service.node().await.expect("a network").state().await.expect("derives");
        assert_eq!(state.network, rule.network);
        assert!(rule.remote_addresses.starts_with("fd"), "its prefix: {}", rule.remote_addresses);
        assert!(rule.remote_addresses.ends_with(",100.64.0.0/10"), "and its range");

        let nothing = service
            .handle_for(
                &alice,
                Command::Unexpose {
                    network: Some("casa".to_owned()),
                    protocol: crate::exposing::Protocol::Udp,
                    port: 8000,
                },
            )
            .await;
        let Outcome::Failed { message, .. } = nothing else { panic!("{nothing:?}") };
        assert!(message.contains("nothing is open"), "{message}");

        let closed = service.handle_for(&alice, casa_tcp("unexpose", 8000)).await;
        assert!(matches!(closed, Outcome::Exposed { ref rules } if rules.is_empty()), "{closed:?}");
        assert!(firewall.rules().is_empty());
    }

    /// A forgotten network takes its ports with it; a rule for a network the
    /// machine does not hold is removed at start, and the held network's is kept.
    #[tokio::test]
    async fn rules_go_with_their_network() {
        let (service, _machine, _scratch) = unjoined().await;
        let firewall = Arc::new(Firewalled::default());
        let service =
            service.with_exposing(Arc::clone(&firewall) as Arc<dyn crate::exposing::Exposing>);
        let alice = person("alice", true);
        service.handle_for(&alice, founding_casa()).await;
        service.handle_for(&alice, Command::Up { network: None }).await;
        service.handle_for(&alice, casa_tcp("expose", 8000)).await;

        let stranger = crate::exposing::rule_for(
            "gone",
            NetworkId::from_bytes([9; 32]),
            crate::exposing::Protocol::Udp,
            53,
            &service.node().await.expect("a network").state().await.expect("derives").params,
        )
        .expect("a rule");
        firewall.rules.lock().expect("not poisoned").push(stranger);

        assert_eq!(Ok(1), service.sweep_exposures().await, "the stranger's, and only it");
        assert_eq!(1, firewall.rules().len(), "casa's is kept");

        service.handle_for(&alice, Command::Down { network: None }).await;
        let forgotten = service
            .handle_for(&alice, Command::Forget { label: "casa".to_owned(), last_admin: true })
            .await;
        assert!(matches!(forgotten, Outcome::Reported(_)), "{forgotten:?}");
        assert!(firewall.rules().is_empty(), "casa's went with casa");
    }

    fn founding_casa() -> Command {
        Command::Found {
            label: "casa".to_owned(),
            name: "desktop".to_owned(),
            suffix: "home.internal".to_owned(),
            relay: None,
            rendezvous: None,
            certificate: crate::control::Certificate::None,
            ipv4_range: None,
        }
    }

    /// A network owed a snapshot: founded where the key signs, with the person
    /// answering the genesis and not the snapshot — the state a founding reached
    /// before founding was one batch, and the state a network predating
    /// snapshots is in. Then the key moves out of reach, and a device is added.
    async fn owed_a_snapshot(service: &Service, custodian: &Lockable) -> Paths {
        custodian.signs_only(1);
        found_one(service).await;
        let paths = service.home().paths_for(&Label::new("casa").expect("valid"));
        assert!(crate::state::read_snapshot(&paths).is_none(), "the network is owed one");

        custodian.moves_out_of_reach();
        let founder =
            Arc::clone(service.node().await.expect("the fixture holds a network").identity());
        let laptop = add_a_device_signed_by(service, &founder, custodian).await;
        service.admit(&laptop).await.expect("admits");
        paths
    }

    /// **Found on a real machine, not here, and that is the point of it.**
    ///
    /// A network's snapshot is kept current by `attest_now`, in the moments after
    /// an act that moved the roster. It signs **synchronously**, so on a device
    /// whose key is out of reach it could not sign at all: when one was due it
    /// recorded a fault and moved on.
    ///
    /// Now the snapshot the network is owed is the last item of the act's own
    /// batch: shown with the revocation, signed with it, and no second request
    /// follows.
    #[tokio::test]
    async fn an_act_asks_for_a_snapshot_the_network_is_owed() {
        let custodian = Arc::new(Lockable::new(0x3b));
        let (service, _machine, _scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));
        let paths = owed_a_snapshot(&service, &custodian).await;

        let asked = service.handle(revoking_laptop()).await;
        let Outcome::NeedsSignatures(wanted) = asked else { panic!("must ask: {asked:?}") };
        let kinds: Vec<crate::control::SigningKind> =
            wanted.items.iter().map(|item| item.kind).collect();
        assert_eq!(
            vec![crate::control::SigningKind::Operation, crate::control::SigningKind::Snapshot],
            kinds,
            "the revocation, and the snapshot the network is owed"
        );
        let revocation = roster::types::OperationCore::decode(
            &wanted.items.first().expect("the revocation").payload,
        )
        .expect("an operation");
        let snapshot =
            roster::snapshot::Snapshot::decode(&wanted.items.get(1).expect("the snapshot").payload)
                .expect("a snapshot");
        assert!(snapshot.heads.contains(&revocation.id()), "covering the revocation");

        let done = answer_batch(&service, wanted, &custodian).await;
        assert!(matches!(done, Outcome::Reported(_)), "{done:?}");
        let node = service.node().await.expect("the fixture holds a network");
        assert!(!node.state().await.expect("derives").revoked.is_empty(), "revoked");
        assert!(crate::state::read_snapshot(&paths).is_some(), "and the network has one at last");
    }

    /// **A change of the network's settings is a batch too**: the change, and
    /// the snapshot the network is then owed.
    #[tokio::test]
    async fn a_settings_change_asks_for_its_snapshot_in_the_same_batch() {
        let custodian = Arc::new(Lockable::new(0x31));
        let (service, _machine, _scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));
        let paths = owed_a_snapshot(&service, &custodian).await;

        let asked = service
            .handle(Command::ChangeRendezvous {
                network: None,
                rendezvous: Some("https://meet.example:8444".to_owned()),
            })
            .await;
        let Outcome::NeedsSignatures(wanted) = asked else { panic!("must ask: {asked:?}") };
        let kinds: Vec<crate::control::SigningKind> =
            wanted.items.iter().map(|item| item.kind).collect();
        assert_eq!(
            vec![crate::control::SigningKind::Operation, crate::control::SigningKind::Snapshot],
            kinds
        );
        let change = roster::types::OperationCore::decode(
            &wanted.items.first().expect("the change").payload,
        )
        .expect("an operation");
        let roster::types::OperationBody::SetNetwork(params) = change.body else {
            panic!("a change of the settings: {change:?}");
        };
        assert_eq!(Some("https://meet.example:8444"), params.rendezvous.as_deref());

        let done = answer_batch(&service, wanted, &custodian).await;
        assert!(matches!(done, Outcome::Reported(_)), "{done:?}");
        let node = service.node().await.expect("the fixture holds a network");
        assert_eq!(
            Some("https://meet.example:8444"),
            node.state().await.expect("derives").params.rendezvous.as_deref()
        );
        assert!(crate::state::read_snapshot(&paths).is_some(), "and the snapshot is kept");
    }

    /// **Declining the batch leaves nothing**: neither the revocation nor the
    /// snapshot. Nothing was applied before the answer, so there is nothing for
    /// declining to undo.
    #[tokio::test]
    async fn declining_the_batch_leaves_nothing() {
        let custodian = Arc::new(Lockable::new(0x3c));
        let (service, _machine, _scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));
        let paths = owed_a_snapshot(&service, &custodian).await;

        let asked = service.handle(revoking_laptop()).await;
        let Outcome::NeedsSignatures(wanted) = asked else { panic!("must ask: {asked:?}") };
        assert_eq!(2, wanted.items.len());

        assert_eq!(Outcome::Done, service.handle(Command::NotSigned { id: wanted.id }).await);

        let node = service.node().await.expect("the fixture holds a network");
        assert!(node.state().await.expect("derives").revoked.is_empty(), "nothing revoked");
        assert!(crate::state::read_snapshot(&paths).is_none(), "and no snapshot");
    }

    /// **The second of two signatures wrong: nothing is applied**, and the
    /// refusal names it.
    #[tokio::test]
    async fn one_bad_signature_voids_the_batch() {
        let custodian = Arc::new(Lockable::new(0x3a));
        let (service, _machine, _scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));
        let paths = owed_a_snapshot(&service, &custodian).await;

        let asked = service.handle(revoking_laptop()).await;
        let Outcome::NeedsSignatures(wanted) = asked else { panic!("must ask: {asked:?}") };
        let first = custodian.signs(&wanted.items.first().expect("the revocation").message);

        let refused = service
            .handle(Command::Signed {
                id: wanted.id,
                signatures: vec![first, custodian.signs(b"not the snapshot")],
            })
            .await;
        let Outcome::Failed { message, .. } = refused else { panic!("refused: {refused:?}") };
        assert!(message.contains("item 2"), "{message}");

        let node = service.node().await.expect("the fixture holds a network");
        assert!(node.state().await.expect("derives").revoked.is_empty(), "nothing revoked");
        assert!(crate::state::read_snapshot(&paths).is_none(), "and no snapshot");
    }

    /// **A snapshot the live roster refuses costs only the snapshot.** The
    /// revocation before it is signed and valid and stands; the person is told
    /// which part did not happen.
    #[tokio::test]
    async fn a_refused_snapshot_leaves_the_act_standing() {
        let custodian = Arc::new(Lockable::new(0x30));
        let (service, _machine, _scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));
        let paths = owed_a_snapshot(&service, &custodian).await;

        let asked = service.handle(revoking_laptop()).await;
        let Outcome::NeedsSignatures(wanted) = asked else { panic!("must ask: {asked:?}") };
        let network = service.named(&Label::new("casa").expect("valid")).await.expect("held");

        // The snapshot is signed and valid, and then the roster takes one at a
        // later sequence from elsewhere — so this one no longer advances it.
        // Applied straight to the roster, past the moment check, which is what a
        // preview that disagreed with derivation would look like here.
        let snapshot_item = wanted.items.get(1).expect("the snapshot");
        let body = roster::snapshot::Snapshot::decode(&snapshot_item.payload).expect("a body");
        let ahead = roster::snapshot::Snapshot::new(
            body.seq.saturating_add(5),
            network.node().state().await.expect("derives").to_bytes(),
            network.node().heads().await,
            vec![1],
            body.author,
            body.network,
        )
        .expect("well-formed");
        let key = roster::sign::Signer::public_key(&custodian.key);
        let request = identity::detached::prepare_snapshot(&ahead, &key);
        let signed =
            identity::detached::finish(&request, &key, &custodian.signs(request.message()))
                .expect("assembles");

        let signatures: Vec<Vec<u8>> =
            wanted.items.iter().map(|item| custodian.signs(&item.message)).collect();
        let requests = vec![
            identity::detached::prepare_operation(
                &roster::types::OperationCore::decode(
                    &wanted.items.first().expect("the revocation").payload,
                )
                .expect("an operation"),
                &key,
            ),
            identity::detached::prepare_snapshot(&body, &key),
        ];
        let artifacts =
            identity::detached::finish_all(&requests, &key, &signatures).expect("they verify");
        assert!(network.node().restore_snapshot(&signed, crate::state::wall_seconds()).await);

        let carried = service
            .carry_revocation(&network, artifacts.first().expect("the revocation").clone())
            .await;
        let done = service.with_the_snapshot(&network, carried, artifacts.get(1).cloned()).await;
        let Outcome::Reported(report) = done else { panic!("the act stands: {done:?}") };
        assert!(
            report.note.as_deref().is_some_and(|note| note.contains("snapshot")),
            "and the person is told which part did not happen: {:?}",
            report.note
        );
        let node = network.node();
        assert!(!node.state().await.expect("derives").revoked.is_empty(), "revoked");
        let _ = paths;
        assert!(
            node.fault().await.is_some_and(|fault| fault.subsystem == "snapshot"),
            "and it is recorded"
        );
    }

    /// Expelling the device these tests admit.
    fn revoking_laptop() -> Command {
        Command::Revoke {
            network: None,
            target: crate::control::Target::Name("laptop".to_owned()),
            reason: "sold".to_owned(),
        }
    }

    /// Founds the one network these tests act on.
    async fn found_one(service: &Service) {
        let founded = service.handle(founding_casa()).await;
        assert!(!matches!(founded, Outcome::Failed { .. }), "{founded:?}");
    }

    /// Adds a device, signed by the custodian rather than by a held key.
    async fn add_a_device_signed_by(
        service: &Service,
        founder: &Arc<NodeIdentity>,
        custodian: &Lockable,
    ) -> Vec<u8> {
        add_named_device_signed_by(service, founder, custodian, "laptop").await
    }

    /// The same, under a chosen name.
    async fn add_named_device_signed_by(
        service: &Service,
        founder: &Arc<NodeIdentity>,
        custodian: &Lockable,
        name: &str,
    ) -> Vec<u8> {
        use roster::types::{OperationBody, OperationCore};

        let node = service.node().await.expect("the fixture holds a network");
        let state = node.state().await.expect("derives");
        let joiner = NodeIdentity::generate().expect("generates");
        let core = OperationCore::new(
            2,
            founder.signing_key().algorithm(),
            OperationBody::AddDevice(
                joiner.device_spec(name, Role::Member, false, vec![]).expect("spec"),
            ),
            node.heads().await,
            founder.signing_key().key_id(),
            state.network,
        )
        .expect("well-formed");

        let key = founder.signing_key().public_key();
        let request = identity::detached::prepare_operation(&core, &key);
        let signature = custodian.signs(request.message());
        identity::detached::finish(&request, &key, &signature).expect("assembles")
    }

    /// A founding the person declines leaves nothing behind: no directory, and no
    /// network reported as unusable on the next start.
    #[tokio::test]
    async fn a_declined_founding_leaves_no_network_behind() {
        let custodian = Arc::new(Lockable::new(0x32));
        custodian.allowed.store(false, std::sync::atomic::Ordering::SeqCst);
        let (service, _machine, scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian }));

        let declined = service
            .handle(Command::Found {
                label: "lavoro".to_owned(),
                name: "pixel".to_owned(),
                suffix: "work.internal".to_owned(),
                relay: None,
                rendezvous: None,
                certificate: crate::control::Certificate::None,
                ipv4_range: None,
            })
            .await;
        assert!(matches!(declined, Outcome::Declined { .. }), "{declined:?}");

        let paths = service.home().paths_for(&Label::new("lavoro").expect("valid"));
        assert!(!paths.root().exists(), "the attempt's directory is gone");
        let survey = Home::under(scratch.path()).survey().expect("surveys");
        assert!(
            survey.unreadable.is_empty(),
            "nothing is reported as unusable: {:?}",
            survey.unreadable.len()
        );
    }

    /// A join the process did not survive leaves nothing behind at the next start.
    #[tokio::test]
    async fn an_attempt_interrupted_by_the_process_dying_is_gone_at_start() {
        let (service, _machine, scratch) = unjoined().await;
        drop(service);
        let home = Home::under(scratch.path());
        let paths = home.paths_for(&Label::new("prova").expect("valid"));
        paths.create().expect("creates");
        std::fs::write(paths.identity(), b"keys and nothing else").expect("writes");

        assert_eq!(home.discard_every_unfounded().expect("reads"), 1);
        assert!(!paths.root().exists());
        assert!(
            home.survey().expect("surveys").unreadable.is_empty(),
            "nothing reported as unusable"
        );
    }

    /// A directory that holds a network is never discarded as an attempt.
    #[test]
    fn a_founded_network_is_never_discarded() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let home = Home::under(scratch.path());
        let label = Label::new("casa").expect("valid");
        let paths = home.paths_for(&label);
        paths.create().expect("creates");
        Log::at(paths.roster()).append(b"an operation").expect("appends");
        assert!(
            !home.discard_unfounded(&label).expect("reads"),
            "a log with an operation is a network"
        );
        assert!(paths.root().exists());

        let empty = Label::new("vuota").expect("valid");
        home.paths_for(&empty).create().expect("creates");
        assert!(
            home.discard_unfounded(&empty).expect("reads"),
            "an attempt with nothing in it goes"
        );
    }

    /// An admission confirmed on a device holding several networks is recorded in
    /// the one it was opened for, not refused for want of a single network.
    #[tokio::test]
    async fn a_confirmed_admission_is_recorded_in_its_own_network_among_several() {
        let (service, _machine, _scratch) = unjoined().await;
        for (label, suffix) in [("casa", "home.internal"), ("lavoro", "work.internal")] {
            let founded = service
                .handle(Command::Found {
                    label: label.to_owned(),
                    name: "pixel".to_owned(),
                    suffix: suffix.to_owned(),
                    relay: None,
                    rendezvous: None,
                    certificate: crate::control::Certificate::None,
                    ipv4_range: None,
                })
                .await;
            assert!(matches!(founded, Outcome::Reported(_)), "{founded:?}");
        }
        let lavoro = service.named(&Label::new("lavoro").expect("valid")).await.expect("held");
        let node = Arc::clone(lavoro.node());
        let founder = Arc::clone(node.identity());
        let state = node.state().await.expect("derives");
        let phone = NodeIdentity::generate().expect("generates");
        let admission = OperationCore::new(
            crate::clock::signing_time(),
            founder.signing_key().algorithm(),
            OperationBody::AddDevice(
                phone.device_spec("phone", Role::Member, false, vec![]).expect("spec"),
            ),
            node.heads().await,
            founder.signing_key().key_id(),
            state.network,
        )
        .expect("well-formed");
        let signed = founder.sign_operation(&admission).expect("signs");

        assert!(service.admit(&signed).await.is_err(), "\"the only network\" is no network here");
        service.admit_to(&lavoro, &signed).await.expect("recorded in its own network");
        assert_eq!(node.state().await.expect("derives").devices.len(), 2);

        // The guard follows what it guards. The recording used to sit in
        // `finish_admitting`; an admission may now stop in the middle waiting for
        // a signature, so the half that records moved to `deliver_admission` —
        // which both paths reach — and this reads that one.
        let source = include_str!("service.rs");
        let delivering = source.split("async fn deliver_admission").nth(1).expect("present");
        let delivering = delivering
            .split(
                "
    }
",
            )
            .next()
            .expect("its body");
        assert!(
            delivering.contains("self.admit_to(network,") && !delivering.contains("self.admit(&"),
            "finishing an admission records it in the network it was opened for"
        );
    }

    /// Founding, admitting and revoking through the service with a key the
    /// process never holds — and a declined prompt arriving as what it is.
    #[tokio::test]
    async fn a_custodian_key_founds_admits_and_revokes_and_a_decline_is_not_a_failure() {
        use std::sync::atomic::Ordering;

        let custodian = Arc::new(Lockable::new(0x31));
        let (service, _machine, _scratch) = unjoined().await;
        let service = service.with_keys(Arc::new(Keystore { custodian: Arc::clone(&custodian) }));

        let founded = service
            .handle(Command::Found {
                label: "casa".to_owned(),
                name: "pixel".to_owned(),
                suffix: "home.internal".to_owned(),
                relay: None,
                rendezvous: None,
                certificate: crate::control::Certificate::None,
                ipv4_range: None,
            })
            .await;
        assert!(matches!(founded, Outcome::Reported(_)), "founded: {founded:?}");

        let node = service.node().await.expect("the founded network");
        let founder = Arc::clone(node.identity());
        assert!(
            founder.signing_key().material().is_none(),
            "the signing key never entered the process"
        );
        assert_eq!(founder.signing_key().algorithm(), roster::types::Algorithm::P256);

        // Admitted through the service, signed by the custodian.
        let state = node.state().await.expect("derives");
        let laptop = NodeIdentity::generate().expect("generates");
        let admission = OperationCore::new(
            crate::clock::signing_time(),
            founder.signing_key().algorithm(),
            OperationBody::AddDevice(
                laptop.device_spec("laptop", Role::Member, false, vec![]).expect("spec"),
            ),
            node.heads().await,
            founder.signing_key().key_id(),
            state.network,
        )
        .expect("well-formed");
        let signed = founder.sign_operation(&admission).expect("the custodian signs");
        service.admit(&signed).await.expect("the roster accepts it");
        assert_eq!(node.state().await.expect("derives").devices.len(), 2);

        // Revoked through the command a person types.
        let revoked = service
            .handle(Command::Revoke {
                network: None,
                target: crate::control::Target::Name("laptop".to_owned()),
                reason: "lost".to_owned(),
            })
            .await;
        assert!(matches!(revoked, Outcome::Reported(_)), "revoked: {revoked:?}");
        assert!(node.state().await.expect("derives").revoked.contains(&laptop.device_id()));

        // The next signature is declined.
        let tablet = NodeIdentity::generate().expect("generates");
        let state = node.state().await.expect("derives");
        let admission = OperationCore::new(
            crate::clock::signing_time(),
            founder.signing_key().algorithm(),
            OperationBody::AddDevice(
                tablet.device_spec("tablet", Role::Member, false, vec![]).expect("spec"),
            ),
            node.heads().await,
            founder.signing_key().key_id(),
            state.network,
        )
        .expect("well-formed");
        service.admit(&founder.sign_operation(&admission).expect("signs")).await.expect("admits");

        custodian.allowed.store(false, Ordering::SeqCst);
        let log = Log::at(service.home().paths_for(&Label::new("casa").expect("valid")).roster());
        let before = log.read().expect("reads").len();

        let declined = service
            .handle(Command::Revoke {
                network: None,
                target: crate::control::Target::Name("tablet".to_owned()),
                reason: "lost".to_owned(),
            })
            .await;
        match declined {
            Outcome::Declined { message } => assert!(message.contains("declined"), "{message}"),
            other => panic!("a decline is not a failure, got {other:?}"),
        }
        assert_eq!(log.read().expect("reads").len(), before, "and nothing was signed");
        assert!(!node.state().await.expect("derives").revoked.contains(&tablet.device_id()));

        // A restart loads the same identity through the same key store.
        custodian.allowed.store(true, Ordering::SeqCst);
        let paths = service.home().paths_for(&Label::new("casa").expect("valid"));
        let again =
            crate::keys::Keys::identity(&Keystore { custodian: Arc::clone(&custodian) }, &paths)
                .expect("loads");
        assert_eq!(again.device_id(), founder.device_id());
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, reason = "a test reports failure by panicking")]
mod driven {
    //! Two whole services, driving themselves.
    //!
    //! Every other test in this crate drives the node by hand: it calls `opened`,
    //! then `received`, then `carry_one`, in the order the daemon would. That
    //! tested every part and missed the only thing that mattered — **the daemon
    //! called none of them.** It brought the tunnel up, installed the address, the
    //! route and the rule, answered names locally, and never spoke to anyone.
    //!
    //! Nothing below touches the node. It brings two services up and waits.

    use std::sync::Arc;
    use std::time::Duration;

    use identity::NodeIdentity;
    use roster::id::NetworkId;
    use roster::roster::Roster;
    use roster::sign::sign_operation;
    use roster::types::{NetworkParams, OperationBody, OperationCore, Role};
    use roster_sync::Syncer;
    use tunnel::{MemoryDevice, Packets, Prefix, Tunnel as Rules};

    use super::*;
    use crate::connectivity::Connectivity;
    use crate::gateway::Gateway;
    use crate::machine::Machine;
    use crate::machine::testing::Recording;
    use crate::resolving::testing::Recording as Names;
    use crate::router::Router;
    use crate::schedule::Schedule;
    use crate::state::Log;

    /// Waits for a condition, or gives up. Better than a fixed sleep: a passing
    /// test is fast and a failing one still finishes.
    async fn within(limit: Duration, mut ready: impl AsyncFnMut() -> bool) -> bool {
        let deadline = tokio::time::Instant::now().checked_add(limit).expect("representable");
        while tokio::time::Instant::now() < deadline {
            if ready().await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    #[tokio::test]
    async fn two_services_find_each_other_and_carry_a_packet() {
        // One network, two devices.
        let founder = Arc::new(NodeIdentity::generate().expect("generates"));
        let joiner = Arc::new(NodeIdentity::generate().expect("generates"));
        let params = NetworkParams::new(
            vec![0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "example.internal",
            2_592_000,
        )
        .expect("valid");

        let genesis = OperationCore::new(
            1,
            founder.signing_key().algorithm(),
            OperationBody::CreateNetwork {
                device: founder.device_spec("nas", Role::Admin, true, vec![]).expect("spec"),
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
                joiner.device_spec("laptop", Role::Member, false, vec![]).expect("spec"),
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
        let state = roster_of().state().expect("derives");
        let prefix = Prefix::from_parameter(&state.params.ula).expect("usable");

        // One fabric, so the two in-process transports can reach each other.
        let fabric = transport::MemoryFabric::new();
        let build = |identity: &Arc<NodeIdentity>| {
            let scratch = tempfile::tempdir().expect("a scratch directory");
            let machine = Arc::new(Recording::new());
            let device = Arc::new(MemoryDevice::new());
            let gateway = Arc::new(Gateway::new(Rules::new(prefix, identity.device_id())));

            let node = Arc::new(Node::new(
                Arc::clone(identity),
                Syncer::new(roster_of()),
                gateway,
                Router::new(prefix),
                Log::at(scratch.path().join("roster.log")),
                Schedule::provisional(),
            ));
            let paths = Paths::under(scratch.path());
            paths.create().expect("creates");

            let service = Service::holding(
                Home::under(scratch.path()),
                vec![super::Network::new(
                    super::Record {
                        label: crate::networks::Label::new("test").expect("a usable label"),
                        network: NetworkId::from_bytes([0; 32]),
                    },
                    paths,
                    node,
                )],
                Lifecycle::new(machine as Arc<dyn Machine>),
                Arc::new(SharedFabric(fabric.clone())) as Arc<dyn Connectivity>,
                Arc::new(Names::new()) as Arc<dyn Resolving>,
            );
            (service, device, scratch)
        };

        let (a, machine_a, _keep_a) = build(&founder);
        let (b, machine_b, _keep_b) = build(&joiner);

        // Nothing below drives the node. Only this.
        a.bring_up(None).await.expect("A comes up");
        b.bring_up(None).await.expect("B comes up");

        // The devices the recording machine handed out are not the ones the
        // gateways got, so attach the ones this test can see into.
        a.node()
            .await
            .expect("the fixture holds a network")
            .gateway()
            .attach(Arc::clone(&machine_a) as Arc<dyn Packets>)
            .await;
        b.node()
            .await
            .expect("the fixture holds a network")
            .gateway()
            .attach(Arc::clone(&machine_b) as Arc<dyn Packets>)
            .await;

        assert!(
            within(Duration::from_secs(5), async || a
                .node()
                .await
                .expect("the fixture holds a network")
                .session_count()
                .await
                > 0)
            .await,
            "the two nodes must find each other with nobody driving them: {:?}",
            a.node().await.expect("the fixture holds a network").fault().await
        );

        // A packet from A's machine, addressed to B, with nothing pumping it but
        // the daemon's own loop.
        let to_b = tunnel::address_of(&joiner.device_id(), &prefix);
        let from_a = tunnel::address_of(&founder.device_id(), &prefix);

        let mut packet = vec![0u8; 40];
        if let Some(first) = packet.first_mut() {
            *first = 0x60;
        }
        packet.splice(8..24, from_a.octets().iter().copied());
        packet.splice(24..40, to_b.octets().iter().copied());
        machine_a.queue(packet.clone()).await;

        assert!(
            within(Duration::from_secs(5), async || !machine_b.delivered().await.is_empty()).await,
            "the packet must reach the other machine: {:?}",
            a.node().await.expect("the fixture holds a network").fault().await
        );
        assert_eq!(machine_b.delivered().await, vec![packet], "unchanged");

        a.take_down(None).await.expect("A goes down");
        b.take_down(None).await.expect("B goes down");
    }

    /// Connectivity over one shared in-process fabric.
    struct SharedFabric(transport::MemoryFabric);

    #[async_trait::async_trait]
    impl Connectivity for SharedFabric {
        async fn start(
            &self,
            identity: &Arc<NodeIdentity>,
            state: roster::state::RosterState,
        ) -> Result<Arc<dyn transport::session::Transport>> {
            let transport =
                transport::MemoryTransport::join(&self.0, Arc::clone(identity), state).await;
            Ok(Arc::new(transport))
        }
    }
}
